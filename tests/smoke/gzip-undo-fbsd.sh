#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.6.gzip smoke — `gzip foo.txt` creates foo.txt.gz, unlinks
# foo.txt. `shit undo` should: remove foo.txt.gz, restore foo.txt
# with its original content.
#
# Operates in the watched cwd. Tests:
#   - kqueue dir-diff sees the Create of foo.txt.gz → TreeOp::Create
#   - kqueue+baseline (or shim) captures FilePreImage of foo.txt
#     before unlink
#   - kqueue or shim sees the Unlink of foo.txt
#   - planner emits two independent inverses: Unlink(foo.txt.gz)
#     and RecreatePath+RestoreContent(foo.txt)

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: gzip-undo-fbsd is FreeBSD-only"
    exit 0
fi

GZIP_BIN="$(command -v gzip)"
[ -x "${GZIP_BIN}" ] || smoke_fail "gzip not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/foo.txt"
# Use a multi-line payload so gzip's output is meaningfully different.
{
    printf 'line one\n'
    printf 'line two with more text\n'
    printf 'line three is the last\n'
} > "${SUBJECT}"
PRE_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "pre-cmd ${SUBJECT} sha: ${PRE_SHA}"

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
sleep 0.7

smoke_log "${GZIP_BIN} ${SUBJECT}"
"${GZIP_BIN}" "${SUBJECT}"

[ -f "${SUBJECT}.gz" ] || smoke_fail "gzip didn't produce ${SUBJECT}.gz"
[ ! -f "${SUBJECT}" ]  || smoke_fail "gzip didn't unlink ${SUBJECT}"
smoke_log "post-gzip: ${SUBJECT}.gz present, ${SUBJECT} gone"

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

failures=()
if [ -e "${SUBJECT}.gz" ]; then
    failures+=("${SUBJECT}.gz still present post-undo")
fi
if [ ! -f "${SUBJECT}" ]; then
    failures+=("${SUBJECT} not restored")
else
    POST_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
    smoke_log "post-undo ${SUBJECT} sha: ${POST_SHA}"
    if [ "${POST_SHA}" != "${PRE_SHA}" ]; then
        failures+=("${SUBJECT} content mismatch: ${POST_SHA} != ${PRE_SHA}")
    fi
fi

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: gzip-undo-fbsd (foo.txt restored byte-identical; foo.txt.gz removed)"
    exit 0
fi

smoke_fail "gzip undo failed: ${failures[*]}"
