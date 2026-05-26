#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR06.3 smoke — `alias ll='ls -la'` adds a new alias; `shit
# undo --apply-shell-state` queues `unalias ll …` into the per-
# session precmd-queue so the next prompt cycle drops it.
#
# Exercises aliases-only diff (pwd held constant). End-to-end
# shape mirrors cd-undo-linux.sh / set-e-undo-linux.sh.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: alias-undo-linux is Linux-only (uname=$(uname -s))"
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
smoke_log "pre-state: PWD=$(pwd) aliases={}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Pre-state: no aliases (empty stdin still drives --from-stdin path).
printf '' | "${SHIT_BIN}" hook-send pre-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}" --from-stdin
sleep 0.3

# THE workload — `alias ll='ls -la'`.
alias ll='ls -la'

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Post-state: one new alias `ll`. Same pwd.
printf 'ALIAS\tll\tls -la\0' | "${SHIT_BIN}" hook-send post-exec-shell-state \
    --session "${SESSION}" --seq 1 --pwd "${WATCHED}" \
    --sock "${SHIT_HOOK_SOCK}" --from-stdin
sleep 0.5

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'" 2>/dev/null || echo 0)"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
if [ "${N_SSD}" -lt 1 ]; then
    smoke_fail "expected >= 1 ShellStateDiff event; daemon didn't journal the alias add"
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

if ! printf '%s' "${QUEUE_BODY}" | grep -qE '^unalias ll'; then
    smoke_fail "precmd-queue file doesn't contain 'unalias ll'"
fi

# Final verdict: source the snippet in a fresh subshell that has
# `ll` defined; confirm it's gone after.
RESULT="$(alias ll='ls -la'; source "${QUEUE_FILE}" 2>/dev/null; if alias ll >/dev/null 2>&1; then echo present; else echo absent; fi)"
if [ "${RESULT}" != "absent" ]; then
    smoke_fail "sourcing precmd-queue snippet didn't unalias ll: got ${RESULT}, expected absent"
fi

smoke_log "PASS: alias-undo-linux (alias ll added → snippet unaliases)"
