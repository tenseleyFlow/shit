#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.6.cpio smoke — `cpio -i` extracts over existing files at an
# unwatched destination. Confirms W09.5's unlink-pre-image fix
# generalizes from tar to cpio (FreeBSD bsdcpio uses similar
# unlink-then-create patterns).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: cpio-extract-undo-fbsd is FreeBSD-only"
    exit 0
fi

CPIO_BIN="$(command -v cpio)"
[ -x "${CPIO_BIN}" ] || smoke_fail "cpio not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
UNWATCHED_DIR="${SHIT_SMOKE_TMP}/dst"
ARCHIVE_DIR="${SHIT_SMOKE_TMP}/archive-src"
mkdir -p "${WATCHED}" "${UNWATCHED_DIR}" "${ARCHIVE_DIR}"

# Pre-populate destination with ORIGINAL content.
declare -A PRE_SHAS
for name in one two three; do
    printf 'ORIGINAL %s content\n' "${name}" > "${UNWATCHED_DIR}/${name}.txt"
    PRE_SHAS[$name]="$(/sbin/sha256 -q "${UNWATCHED_DIR}/${name}.txt")"
    smoke_log "pre-cmd ${name}.txt sha: ${PRE_SHAS[$name]}"
done

# Build cpio archive with DIFFERENT content for the same files.
for name in one two three; do
    printf 'NEW %s content from cpio\n' "${name}" > "${ARCHIVE_DIR}/${name}.txt"
done
ARCHIVE="${SHIT_SMOKE_TMP}/payload.cpio"
(cd "${ARCHIVE_DIR}" && printf '%s\n' one.txt two.txt three.txt | "${CPIO_BIN}" -o > "${ARCHIVE}") 2>/dev/null

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

smoke_log "LD_PRELOAD=${SHIM_LIB} cpio -i -u (extracting into ${UNWATCHED_DIR})"
( cd "${UNWATCHED_DIR}" && LD_PRELOAD="${SHIM_LIB}" "${CPIO_BIN}" -i -u < "${ARCHIVE}" ) 2>/dev/null

# Verify extraction overwrote the files.
for name in one two three; do
    post="$(/sbin/sha256 -q "${UNWATCHED_DIR}/${name}.txt")"
    smoke_log "post-cpio ${name}.txt sha: ${post}"
    [ "${post}" != "${PRE_SHAS[$name]}" ] || smoke_fail "cpio didn't change ${name}.txt"
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

failures=()
for name in one two three; do
    f="${UNWATCHED_DIR}/${name}.txt"
    if [ ! -f "${f}" ]; then
        failures+=("${name}.txt MISSING")
        continue
    fi
    post="$(/sbin/sha256 -q "${f}")"
    smoke_log "post-undo ${name}.txt sha: ${post}"
    if [ "${post}" != "${PRE_SHAS[$name]}" ]; then
        failures+=("${name}.txt: ${post} != expected ${PRE_SHAS[$name]}")
    fi
done

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: cpio-extract-undo-fbsd (3 files restored byte-identical)"
    exit 0
fi

smoke_fail "cpio undo failed: ${failures[*]}"
