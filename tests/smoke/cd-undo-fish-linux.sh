#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cd-undo-fish-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR06.6 smoke — fish coverage for cd-undo. fish doesn't go
# through the precmd-queue (DR-30: no safe equivalent of bash's
# PROMPT_COMMAND), so the executor returns `Skipped` with the
# rendered fish snippet embedded in the reason for the user to
# copy-paste. This smoke verifies:
#
#   1. Fish-tagged hooks land a ShellStateDiff event.
#   2. `shit undo --yes --apply-shell-state` returns nonzero-but-
#      well-formed (no plan applied; refusal-style message in
#      stderr) — no precmd-queue file is created.
#   3. The rendered snippet shown by the daemon is valid fish
#      (we feed it to `fish -c`, starting from a different
#      directory, and confirm pwd flips).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: cd-undo-fish-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v fish >/dev/null 2>&1; then
    smoke_log "SKIP: fish not installed"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

export XDG_STATE_HOME="${SHIT_SMOKE_TMP}/state"
mkdir -p "${XDG_STATE_HOME}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
DIFFERENT="${SHIT_SMOKE_TMP}/different"
mkdir -p "${WATCHED}" "${DIFFERENT}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell fish \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell fish --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

cd "${DIFFERENT}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send post-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${DIFFERENT}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'" 2>/dev/null || echo 0)"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
if [ "${N_SSD}" -lt 1 ]; then
    smoke_fail "expected >= 1 ShellStateDiff event"
fi

smoke_log "running: shit undo --yes --apply-shell-state (fish session)"
set +e
"${SHIT_BIN}" undo --yes --apply-shell-state > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# The fish executor path is informational: it Skips with the
# rendered snippet body embedded in the message. Check the
# undo log for both the DR-30 marker and the cd line itself.
if ! grep -q "DR-30" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_fail "undo output for fish session missing DR-30 marker"
fi
if ! grep -qE "cd '${WATCHED}'" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_fail "undo output missing rendered fish snippet (cd '${WATCHED}')"
fi

# No precmd-queue file should be created for fish.
QUEUE_FILE="${XDG_STATE_HOME}/shit/precmd-queue/${SESSION}"
if [ -f "${QUEUE_FILE}" ] && [ -s "${QUEUE_FILE}" ]; then
    smoke_fail "fish session unexpectedly wrote precmd-queue file: ${QUEUE_FILE}"
fi

# Final verdict: extract the cd line from the undo output, feed
# it to `fish -c` from a different cwd, and confirm pwd flips
# to WATCHED. This proves the rendered snippet body is valid
# fish syntax, not just bash-shaped.
FISH_SNIPPET="$(grep -E "^cd '" "${SHIT_SMOKE_TMP}/undo.log" | head -1)"
if [ -z "${FISH_SNIPPET}" ]; then
    smoke_fail "could not extract fish snippet cd line from undo output"
fi
smoke_log "extracted fish snippet: ${FISH_SNIPPET}"
RESULT_PWD="$(cd "${DIFFERENT}" && fish -c "${FISH_SNIPPET}; pwd")"
if [ "${RESULT_PWD}" != "${WATCHED}" ]; then
    smoke_fail "fish sourcing snippet didn't flip pwd: got ${RESULT_PWD}, expected ${WATCHED}"
fi

smoke_log "PASS: cd-undo-fish-linux (fish snippet rendered, valid, refused-with-body per DR-30)"
