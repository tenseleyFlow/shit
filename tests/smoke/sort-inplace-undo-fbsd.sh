#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.7.sort smoke — `sort -o file file` sorts a file in-place.
# FreeBSD sort(1) reads the file fully, sorts in memory, then
# writes back to the output path (which equals the input). The
# exact syscall sequence varies: some implementations open(O_TRUNC)
# the output, others write to a tmpfile and rename. Either way
# the captured pre-image should let undo restore.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: sort-inplace-undo-fbsd is FreeBSD-only"
    exit 0
fi

SORT_BIN="$(command -v sort)"
[ -x "${SORT_BIN}" ] || smoke_fail "sort not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/lines.txt"
# Unsorted input — sort will reorder.
{
    printf 'gamma\n'
    printf 'alpha\n'
    printf 'epsilon\n'
    printf 'beta\n'
    printf 'delta\n'
} > "${SUBJECT}"
PRE_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "pre-sort sha: ${PRE_SHA}"

smoke_start_shitd

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

smoke_log "${SORT_BIN} -o ${SUBJECT} ${SUBJECT}"
"${SORT_BIN}" -o "${SUBJECT}" "${SUBJECT}"

POST_SORT_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-sort sha: ${POST_SORT_SHA}"
[ "${POST_SORT_SHA}" != "${PRE_SHA}" ] || smoke_fail "sort didn't change file"
# Sanity: file is actually sorted.
head -1 "${SUBJECT}" | grep -q '^alpha$' || smoke_fail "sort didn't sort"

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

[ -f "${SUBJECT}" ] || smoke_fail "subject file removed by undo"
POST_UNDO_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-undo sha: ${POST_UNDO_SHA}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: sort-inplace-undo-fbsd (lines.txt restored byte-identical, pre-sort order)"
    exit 0
fi

smoke_fail "byte mismatch: got ${POST_UNDO_SHA}, expected ${PRE_SHA}"
