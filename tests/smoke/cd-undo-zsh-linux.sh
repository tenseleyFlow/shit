#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cd-undo-zsh-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR06.6 smoke — zsh parity for cd-undo. End-to-end shape
# mirrors cd-undo-linux.sh, but:
#   * SessionOpen + Pre/Post-Exec announce --shell zsh
#   * After `shit undo --yes --apply-shell-state` we read the
#     precmd-queue snippet and source it in a fresh `zsh -c`
#     invocation to confirm the rendered body actually flips pwd
#     when zsh sources it.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: cd-undo-zsh-linux is Linux-only (uname=$(uname -s))"
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
DIFFERENT="${SHIT_SMOKE_TMP}/different"
mkdir -p "${WATCHED}" "${DIFFERENT}"

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

if ! printf '%s' "${QUEUE_BODY}" | grep -qE "cd '${WATCHED}'"; then
    smoke_fail "precmd-queue file doesn't contain 'cd '\''${WATCHED}'\''"
fi

# Final verdict: actually source the snippet in zsh and verify pwd
# lands at WATCHED. This is the load-bearing check — bash and zsh
# share `cd 'X'` syntax, but the snippet has to be valid zsh too.
RESULT_PWD="$(zsh -c "cd ${DIFFERENT}; source ${QUEUE_FILE}; pwd")"
if [ "${RESULT_PWD}" != "${WATCHED}" ]; then
    smoke_fail "zsh sourcing precmd-queue snippet didn't restore pwd: got ${RESULT_PWD}, expected ${WATCHED}"
fi

smoke_log "PASS: cd-undo-zsh-linux (zsh restores pwd via precmd-queue snippet)"
