#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.5 smoke — `tar xf archive.tar` extracts files OVER existing
# ones at unwatched destinations; `shit undo` restores each file's
# prior content byte-identically. This is the "unlink-then-create"
# shape: FreeBSD bsdtar typically `unlink()`s the destination, then
# `open(path, O_CREAT|O_WRONLY)` to write the new bytes.
#
# Pre-W09.5 the shim's `open` interposer's pre-image capture
# returned None for these paths (file already unlinked) and undo
# no-op'd. W09.5 captures the pre-image at the UNLINK interposer
# instead — file still exists at notify time — and the planner's
# `classify_replace_paths` Unlink+PreImage shape kicks in.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: tar-extract-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
TAR_BIN="$(command -v tar)"
[ -x "${TAR_BIN}" ]    || smoke_fail "tar not found"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
UNWATCHED_DIR="${SHIT_SMOKE_TMP}/dst"
ARCHIVE_DIR="${SHIT_SMOKE_TMP}/archive-src"
mkdir -p "${WATCHED}" "${UNWATCHED_DIR}" "${ARCHIVE_DIR}"

# Pre-populate three destination files with ORIGINAL content.
declare -A PRE_SHAS
for name in alpha beta gamma; do
    printf 'ORIGINAL %s content\n' "${name}" > "${UNWATCHED_DIR}/${name}.txt"
    PRE_SHAS[$name]="$(/sbin/sha256 -q "${UNWATCHED_DIR}/${name}.txt")"
    smoke_log "pre-cmd ${name}.txt sha: ${PRE_SHAS[$name]}"
done

# Build an archive with DIFFERENT content for the same paths.
for name in alpha beta gamma; do
    printf 'NEW %s content from tar\n' "${name}" > "${ARCHIVE_DIR}/${name}.txt"
done
ARCHIVE="${SHIT_SMOKE_TMP}/payload.tar"
"${TAR_BIN}" cf "${ARCHIVE}" -C "${ARCHIVE_DIR}" alpha.txt beta.txt gamma.txt

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 cwd=${WATCHED}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

smoke_log "LD_PRELOAD=${SHIM_LIB} tar xf ${ARCHIVE} -C ${UNWATCHED_DIR}"
LD_PRELOAD="${SHIM_LIB}" "${TAR_BIN}" xf "${ARCHIVE}" -C "${UNWATCHED_DIR}"

# Confirm tar actually changed content (sanity invariant).
for name in alpha beta gamma; do
    post="$(/sbin/sha256 -q "${UNWATCHED_DIR}/${name}.txt")"
    smoke_log "post-tar ${name}.txt sha: ${post}"
    [ "${post}" != "${PRE_SHAS[$name]}" ] || smoke_fail "tar didn't change ${name}.txt"
done

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed: ${SHIM_HITS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

failures=()
for name in alpha beta gamma; do
    if [ ! -f "${UNWATCHED_DIR}/${name}.txt" ]; then
        failures+=("${name}.txt MISSING")
        continue
    fi
    post="$(/sbin/sha256 -q "${UNWATCHED_DIR}/${name}.txt")"
    smoke_log "post-undo ${name}.txt sha: ${post}"
    if [ "${post}" != "${PRE_SHAS[$name]}" ]; then
        failures+=("${name}.txt: ${post} != expected ${PRE_SHAS[$name]}")
    fi
done

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: tar-extract-undo-fbsd (3 files restored byte-identical; shim hits=${SHIM_HITS})"
    exit 0
fi

smoke_fail "tar undo failed for: ${failures[*]}"
