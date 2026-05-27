#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: set-e-undo-zsh-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR06.6 smoke — zsh parity for set-e-undo. zsh's option-restore
# snippet uses `setopt` / `unsetopt`, not bash's `set ±o`. We
# verify both the journal path AND that the rendered body
# actually flips the option when sourced under zsh.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: set-e-undo-zsh-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v zsh >/dev/null 2>&1; then
    smoke_log "SKIP: zsh not installed"
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
mkdir -p "${WATCHED}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell zsh \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell zsh --sock "${SHIT_HOOK_SOCK}"

# Pre-state: errexit=on.
printf 'OPT\terrexit\ton\0' | "${SHIT_BIN}" hook-send pre-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}" --from-stdin
sleep 0.3

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Post-state: errexit=off.
printf 'OPT\terrexit\toff\0' | "${SHIT_BIN}" hook-send post-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}" --from-stdin
sleep 0.5

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'" 2>/dev/null || echo 0)"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
if [ "${N_SSD}" -lt 1 ]; then
    smoke_fail "expected >= 1 ShellStateDiff event"
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
    smoke_fail "precmd-queue file missing at ${QUEUE_FILE}"
fi
QUEUE_BODY="$(cat "${QUEUE_FILE}")"
smoke_log "precmd-queue body:"
printf '%s\n' "${QUEUE_BODY}" | sed 's/^/    /' >&2

# zsh-flavored: must contain `setopt errexit`, not `set -o errexit`.
if ! printf '%s' "${QUEUE_BODY}" | grep -qE '^setopt errexit$'; then
    smoke_fail "precmd-queue file doesn't contain 'setopt errexit' (zsh syntax)"
fi
if printf '%s' "${QUEUE_BODY}" | grep -qE '^set -o errexit$'; then
    smoke_fail "precmd-queue file contains bash 'set -o errexit' for a zsh session"
fi

# Source under zsh, starting with errexit OFF, and confirm it
# flips back ON.
RESULT="$(zsh -c "unsetopt errexit; source ${QUEUE_FILE}; setopt | grep -qE '^errexit\$' && echo on || echo off")"
if [ "${RESULT}" != "on" ]; then
    smoke_fail "zsh sourcing precmd-queue snippet didn't restore errexit: got ${RESULT}, expected on"
fi

smoke_log "PASS: set-e-undo-zsh-linux (zsh restores errexit via setopt)"
