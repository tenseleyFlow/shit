#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: set-e-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR06.2 smoke — `set +o errexit` flips errexit off; `shit undo
# --apply-shell-state` queues `set -o errexit` into the per-
# session precmd-queue so the next prompt cycle restores it.
#
# We exercise opts-only diff here (pwd held constant) to prove
# the snippet renderer + executor are wired independently of
# AR06.1's pwd path. End-to-end shape mirrors cd-undo-linux.sh.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: set-e-undo-linux is Linux-only (uname=$(uname -s))"
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
mkdir -p "${WATCHED}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${WATCHED}"
smoke_log "pre-state: PWD=$(pwd) errexit=on (simulated)"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Pre-state opts: errexit=on. NUL-separated records on stdin.
printf 'OPT\terrexit\ton\0' | "${SHIT_BIN}" hook-send pre-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}" --from-stdin
sleep 0.3

# THE workload — `set +o errexit` (flips errexit off).
set +o errexit

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Post-state opts: errexit=off. Same pwd.
printf 'OPT\terrexit\toff\0' | "${SHIT_BIN}" hook-send post-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}" --from-stdin
sleep 0.5

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'" 2>/dev/null || echo 0)"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
if [ "${N_SSD}" -lt 1 ]; then
    smoke_fail "expected >= 1 ShellStateDiff event; daemon didn't journal the opt change"
fi

smoke_log "running: shit undo --yes --apply-shell-state"
set +e
"${SHIT_BIN}" undo --yes --apply-shell-state > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes --apply-shell-state exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

QUEUE_FILE="${XDG_STATE_HOME}/shit/precmd-queue/${SESSION}"
if [ ! -f "${QUEUE_FILE}" ]; then
    smoke_log "precmd-queue dir contents:"
    ls -la "${XDG_STATE_HOME}/shit/precmd-queue/" 2>&1 | sed 's/^/    /' >&2 || true
    smoke_fail "precmd-queue file missing at ${QUEUE_FILE}"
fi
QUEUE_BODY="$(cat "${QUEUE_FILE}")"
smoke_log "precmd-queue body:"
printf '%s\n' "${QUEUE_BODY}" | sed 's/^/    /' >&2

if ! printf '%s' "${QUEUE_BODY}" | grep -qE '^set -o errexit$'; then
    smoke_fail "precmd-queue file doesn't contain 'set -o errexit'"
fi

# Final verdict: source the snippet in a fresh subshell where
# errexit is OFF and confirm it flips ON.
RESULT="$(set +o errexit; source "${QUEUE_FILE}"; case $- in *e*) echo on ;; *) echo off ;; esac)"
if [ "${RESULT}" != "on" ]; then
    smoke_fail "sourcing precmd-queue snippet didn't restore errexit: got ${RESULT}, expected on"
fi

smoke_log "PASS: set-e-undo-linux (errexit on → off → snippet restores to on)"
