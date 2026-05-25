#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.10.bg smoke — `(rm file &); wait` runs `rm` in a background
# subshell, then waits. PostExec doesn't fire until the wait
# completes. Tests:
#   - Background process's events are correctly attributed to the
#     command window (its ppid chain goes through the subshell, not
#     the foreground shell — extra ancestry hop).
#   - All events the bg process produces land in the journal before
#     PostExec is sent.
#   - Undo restores the file.
#
# The `wait` is critical — without it the shell returns to the user
# before the background `rm` finishes, and post-exec fires while
# rm is still mid-syscall. With `wait` we serialize the journal-
# completeness invariant.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: background-job-undo-fbsd is FreeBSD-only"
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
printf 'background restore me\n' > "${SUBJECT}"
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

# THE workload: detached bg rm via setsid+nohup so it survives
# the smoke shell's job control, then poll until done. Using
# bash's `wait` builtin with a `()` subshell + `&` interacts
# poorly with the smoke harness's `set -o pipefail` and the
# safety-net cleanup, so we use a portable poll instead.
smoke_log "(rm ${SUBJECT} &) — detached background"
( rm "${SUBJECT}" >/dev/null 2>&1 & )
# Poll up to 5s for the rm to take effect.
for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -e "${SUBJECT}" ] || break
    sleep 0.5
done
[ ! -e "${SUBJECT}" ] || smoke_fail "rm didn't take effect after 5s"

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

[ -f "${SUBJECT}" ] || smoke_fail "background rm not restored by undo (ancestry attribution miss?)"
POST_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
if [ "${POST_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: background-job-undo-fbsd (bg rm captured + restored)"
    exit 0
fi
smoke_fail "byte mismatch: ${POST_SHA} != ${PRE_SHA}"
