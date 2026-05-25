#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.8.mv-noop smoke — `mv foo foo` is a no-op rename. POSIX
# says rename(2) of a file to itself is a no-op; the kernel
# doesn't fire any notification (kqueue / fanotify / LSM hooks
# may or may not surface this depending on implementation).
#
# `shit undo` should: a) not crash, b) leave the file untouched.
# The interesting edge: if the shim fires a Rename(from=to)
# event, the planner's ReverseRename inverse would still be
# Rename(from=to) — a no-op. Either way file content + mode
# must be untouched.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: mv-noop-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/foo.txt"
printf 'i am foo.txt and i should not move\n' > "${SUBJECT}"
chmod 0644 "${SUBJECT}"
PRE_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
PRE_MODE="$(/usr/bin/stat -f '%Op' "${SUBJECT}")"
PRE_INODE="$(/usr/bin/stat -f '%i' "${SUBJECT}")"
smoke_log "pre-cmd sha=${PRE_SHA} mode=${PRE_MODE} inode=${PRE_INODE}"

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

# THE workload: rename to self. LD_PRELOAD the shim to catch any
# notification that might fire.
smoke_log "LD_PRELOAD=${SHIM_LIB} mv ${SUBJECT} ${SUBJECT}"
LD_PRELOAD="${SHIM_LIB}" mv "${SUBJECT}" "${SUBJECT}" || smoke_fail "mv x x failed (rc=$?)"

# File must still exist with same content + inode.
[ -f "${SUBJECT}" ] || smoke_fail "file disappeared after mv x x"
POST_INODE="$(/usr/bin/stat -f '%i' "${SUBJECT}")"
[ "${POST_INODE}" = "${PRE_INODE}" ] || smoke_fail "inode changed: ${PRE_INODE} → ${POST_INODE}"

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

[ -f "${SUBJECT}" ] || smoke_fail "subject file disappeared post-undo (no-op should not have unlinked!)"
POST_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
POST_MODE="$(/usr/bin/stat -f '%Op' "${SUBJECT}")"
POST_INODE2="$(/usr/bin/stat -f '%i' "${SUBJECT}")"
smoke_log "post-undo sha=${POST_SHA} mode=${POST_MODE} inode=${POST_INODE2}"

if [ "${POST_SHA}" = "${PRE_SHA}" ] && [ "${POST_MODE}" = "${PRE_MODE}" ] && [ "${POST_INODE2}" = "${PRE_INODE}" ]; then
    smoke_log "PASS: mv-noop-undo-fbsd (file untouched, no-op preserved)"
    exit 0
fi

smoke_fail "mv-noop undo damaged the file: sha ${PRE_SHA}→${POST_SHA}, mode ${PRE_MODE}→${POST_MODE}, inode ${PRE_INODE}→${POST_INODE2}"
