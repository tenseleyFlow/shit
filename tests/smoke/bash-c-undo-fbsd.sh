#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: bash-c-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.9.bash-c smoke — `bash -c "rm foo"` runs the command in a
# nested shell. Process tree:
#     outer-shell (tracked) → bash -c (intermediate) → rm (exec'd)
# Tests the shim's pid→CommandId resolver through one extra
# ancestry hop beyond xargs (which was the 3-hop case). Each
# extra hop is one more `ps -p` shell-out; we want to confirm
# the synchronous pre-ack resolver still finds the tracked shell.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: bash-c-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/foo.txt"
printf 'i should come back\n' > "${SUBJECT}"
PRE_SHA="$(/sbin/sha256 -q "${SUBJECT}")"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# THE workload: nested shell.
smoke_log "bash -c 'rm ${SUBJECT}'"
bash -c "rm '${SUBJECT}'"
[ ! -e "${SUBJECT}" ] || smoke_fail "rm didn't delete subject"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

[ -f "${SUBJECT}" ] || smoke_fail "subject not restored"
POST_SHA="$(/sbin/sha256 -q "${SUBJECT}")"

if [ "${POST_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: bash-c-undo-fbsd (subject restored via deeper ancestry)"
    exit 0
fi

smoke_fail "byte mismatch: ${POST_SHA} != ${PRE_SHA}"
