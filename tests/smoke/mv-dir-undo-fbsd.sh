#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.9.mv-dir smoke — `mv srcdir/ dstdir/` renames a populated
# directory (single rename(2) on the dir inode; contained files
# come along automatically — same inodes, new parent). `shit undo`
# should rename it back without touching the contained files.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: mv-dir-undo-fbsd is FreeBSD-only"
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
mkdir -p "${WATCHED}/srcdir"

# Populate srcdir with 3 files.
declare -A FILE_SHAS
for name in foo bar baz; do
    f="${WATCHED}/srcdir/${name}.txt"
    printf 'content for %s\n' "${name}" > "${f}"
    FILE_SHAS[$name]="$(/sbin/sha256 -q "${f}")"
done
SRC_INODE="$(/usr/bin/stat -f '%i' "${WATCHED}/srcdir")"
smoke_log "pre-cmd srcdir inode=${SRC_INODE}"

DST="${WATCHED}/dstdir"
[ ! -e "${DST}" ] || smoke_fail "dstdir pre-exists"

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

smoke_log "LD_PRELOAD=${SHIM_LIB} mv srcdir dstdir"
LD_PRELOAD="${SHIM_LIB}" mv srcdir dstdir

[ -d "${DST}" ]               || smoke_fail "mv didn't create dstdir"
[ ! -e "${WATCHED}/srcdir" ]  || smoke_fail "srcdir still exists post-mv"
DST_INODE="$(/usr/bin/stat -f '%i' "${DST}")"
[ "${DST_INODE}" = "${SRC_INODE}" ] || smoke_fail "dir inode changed: ${SRC_INODE} → ${DST_INODE} (rename should preserve)"
# Contained files: same content, same names, in dstdir now.
for name in foo bar baz; do
    [ -f "${DST}/${name}.txt" ] || smoke_fail "file ${name}.txt missing in dstdir post-mv"
    post="$(/sbin/sha256 -q "${DST}/${name}.txt")"
    [ "${post}" = "${FILE_SHAS[$name]}" ] || smoke_fail "${name}.txt content perturbed by dir rename"
done

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

# Post-undo: srcdir back, dstdir gone, all files intact at original paths.
failures=()
[ -d "${WATCHED}/srcdir" ] || failures+=("srcdir NOT restored")
[ ! -e "${DST}" ]          || failures+=("dstdir still present post-undo")
for name in foo bar baz; do
    f="${WATCHED}/srcdir/${name}.txt"
    if [ ! -f "${f}" ]; then
        failures+=("srcdir/${name}.txt MISSING")
        continue
    fi
    post="$(/sbin/sha256 -q "${f}")"
    if [ "${post}" != "${FILE_SHAS[$name]}" ]; then
        failures+=("${name}.txt content mismatch")
    fi
done

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: mv-dir-undo-fbsd (srcdir restored with 3 files; dstdir gone)"
    exit 0
fi

smoke_fail "mv-dir undo failed: ${failures[*]}"
