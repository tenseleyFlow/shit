#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.4 smoke — `awk -i inplace` modifies a file in-place via the
# tmpfile-rename atomic pattern. Mirrors the vim/sed-inline shape
# but with awk's specific inplace.gawk extension behavior. We
# only run this if the system awk supports `-i inplace` (BSD awk
# does NOT — gawk does). SKIP cleanly when awk is BSD awk.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: awk-inplace-undo-fbsd is FreeBSD-only"
    exit 0
fi

# Probe for gawk specifically — BSD's one true awk doesn't support
# -i inplace. If gawk is installed (via `pkg install gawk`) we use
# it; otherwise SKIP with a clear note rather than fail.
if AWK_BIN="$(command -v gawk 2>/dev/null)"; then
    smoke_log "found gawk at ${AWK_BIN}"
else
    smoke_log "SKIP: gawk not installed (pkg install gawk to enable); BSD awk lacks -i inplace"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/foo.txt"
printf 'line one\nline two\nline three\n' > "${SUBJECT}"
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

# THE workload — upcase via gawk -i inplace. This invokes the
# inplace.gawk module which writes to a tmpfile then renames.
smoke_log "${AWK_BIN} -i inplace '{print toupper(\$0)}' ${SUBJECT}"
"${AWK_BIN}" -i inplace '{print toupper($0)}' "${SUBJECT}"

POST_AWK_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-awk sha: ${POST_AWK_SHA}"
[ "${POST_AWK_SHA}" != "${PRE_SHA}" ] || smoke_fail "awk didn't modify content"

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

[ -f "${SUBJECT}" ] || smoke_fail "subject file removed by undo"
POST_UNDO_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-undo sha: ${POST_UNDO_SHA}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: awk-inplace-undo-fbsd (${SUBJECT} restored byte-identical)"
    exit 0
fi

smoke_fail "byte mismatch: got ${POST_UNDO_SHA}, expected ${PRE_SHA}"
