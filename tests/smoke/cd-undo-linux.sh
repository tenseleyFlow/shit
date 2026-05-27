#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cd-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR06.1 + DR-CR-50 smoke — `cd /elsewhere` then `shit undo
# --apply-shell-state` queues `cd '<original-pwd>'` into the
# per-session precmd-queue file. The user's bash hook drains
# that file before the next prompt.
#
# A child process (the shitd daemon) cannot mutate the parent
# shell's cwd directly — POSIX makes that impossible. The
# precmd-queue is the workaround: we write the snippet, the
# shell's PROMPT_COMMAND sources it. This smoke exercises the
# queue path end-to-end:
#
#   1. SessionOpen + PreExec + pre-exec-shell-state (pwd=$WATCHED)
#   2. cd to a different dir; capture changed pwd
#   3. PostExec + post-exec-shell-state (pwd=$DIFFERENT)
#   4. shit undo --yes --apply-shell-state
#   5. Assert the precmd-queue file at
#      $XDG_STATE_HOME/shit/precmd-queue/<session> contains
#      `cd '<WATCHED>'`.
#   6. Source that file in a subshell; assert pwd ends at $WATCHED.
#
# Step 6 verifies the SNIPPET WORKS (sourcing it does flip pwd)
# without requiring a live interactive bash. Real interactive
# shells flow this through PROMPT_COMMAND; the snippet content
# is the load-bearing piece.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: cd-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Per-smoke XDG_STATE_HOME so the precmd-queue lives under our
# tmpdir and doesn't collide with the runner's real $HOME.
export XDG_STATE_HOME="${SHIT_SMOKE_TMP}/state"
mkdir -p "${XDG_STATE_HOME}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
DIFFERENT="${SHIT_SMOKE_TMP}/different"
mkdir -p "${WATCHED}" "${DIFFERENT}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${WATCHED}"
PRE_PWD="$(pwd)"
smoke_log "pre-state: PWD=${PRE_PWD}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# THE workload — the user's "wrong cd".
cd "${DIFFERENT}"
POST_PWD="$(pwd)"
smoke_log "post-cmd: PWD=${POST_PWD}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send post-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${DIFFERENT}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# How many ShellStateDiff events landed in the journal?
N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'" 2>/dev/null || echo 0)"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
if [ "${N_SSD}" -lt 1 ]; then
    smoke_fail "expected >= 1 ShellStateDiff event; daemon didn't journal the pwd change"
fi

smoke_log "running: shit undo --yes --apply-shell-state"
set +e
"${SHIT_BIN}" undo --yes --apply-shell-state > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes --apply-shell-state exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Verify the precmd-queue file exists + contains the cd-back snippet.
QUEUE_FILE="${XDG_STATE_HOME}/shit/precmd-queue/${SESSION}"
if [ ! -f "${QUEUE_FILE}" ]; then
    smoke_log "precmd-queue dir contents:"
    ls -la "${XDG_STATE_HOME}/shit/precmd-queue/" 2>&1 | sed 's/^/    /' >&2 || true
    smoke_fail "precmd-queue file missing at ${QUEUE_FILE}"
fi
QUEUE_BODY="$(cat "${QUEUE_FILE}")"
smoke_log "precmd-queue body:"
printf '%s\n' "${QUEUE_BODY}" | sed 's/^/    /' >&2

if ! printf '%s' "${QUEUE_BODY}" | grep -qE "cd '${WATCHED}'"; then
    smoke_fail "precmd-queue file doesn't contain 'cd '\''${WATCHED}'\''"
fi

# Final verdict: source the snippet in a fresh subshell starting
# at DIFFERENT and confirm it lands at WATCHED. This proves the
# snippet body is well-formed bash + does the right thing — the
# actual user-facing PROMPT_COMMAND drain in shell/bash.sh
# exercises the same source path.
RESULT_PWD="$(cd "${DIFFERENT}" && source "${QUEUE_FILE}" && pwd)"
if [ "${RESULT_PWD}" != "${WATCHED}" ]; then
    smoke_fail "sourcing precmd-queue snippet didn't restore pwd: got ${RESULT_PWD}, expected ${WATCHED}"
fi

smoke_log "PASS: cd-undo-linux (pwd ${PRE_PWD} → ${POST_PWD} → snippet sources back to ${RESULT_PWD})"
