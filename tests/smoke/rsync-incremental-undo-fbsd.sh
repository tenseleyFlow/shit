#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: rsync-incremental-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.7.rsync smoke — `rsync -a src/ dst/` syncs into a populated
# destination. rsync uses its own delta-transfer protocol: it
# writes to a tmpfile `.foo.XYZ` in the dst dir and atomic-renames
# over the existing dst path. Exercises the same atomic-replace
# shape as `install` and `mv` but with rsync's tmpfile naming.
#
# Tests both update-existing AND create-new in a single command:
#   alpha.txt — existing in dst, different bytes → updated
#   beta.txt  — existing in dst, different bytes → updated
#   gamma.txt — NOT in dst → created
# Undo should: restore alpha/beta to pre-state, remove gamma.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: rsync-incremental-undo-fbsd is FreeBSD-only"
    exit 0
fi

RSYNC_BIN="$(command -v rsync 2>/dev/null || echo '')"
if [ -z "${RSYNC_BIN}" ]; then
    smoke_log "SKIP: rsync not installed (pkg install rsync to enable)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
SRC_DIR="${SHIT_SMOKE_TMP}/src"
DST_DIR="${SHIT_SMOKE_TMP}/dst"
mkdir -p "${WATCHED}" "${SRC_DIR}" "${DST_DIR}"

# Pre-populate src and dst with overlapping-but-different content.
declare -A SRC_SHAS PRE_DST_SHAS
for name in alpha beta gamma; do
    printf 'SRC %s content for rsync\n' "${name}" > "${SRC_DIR}/${name}.txt"
    SRC_SHAS[$name]="$(/sbin/sha256 -q "${SRC_DIR}/${name}.txt")"
done
for name in alpha beta; do
    printf 'PRE-EXISTING dst %s content\n' "${name}" > "${DST_DIR}/${name}.txt"
    PRE_DST_SHAS[$name]="$(/sbin/sha256 -q "${DST_DIR}/${name}.txt")"
    smoke_log "pre-cmd ${name}.txt sha: ${PRE_DST_SHAS[$name]}"
done
# gamma.txt does NOT exist in dst pre-rsync.
[ ! -e "${DST_DIR}/gamma.txt" ] || smoke_fail "smoke env not clean: gamma.txt pre-exists in dst"

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

smoke_log "LD_PRELOAD=${SHIM_LIB} rsync -a ${SRC_DIR}/ ${DST_DIR}/"
LD_PRELOAD="${SHIM_LIB}" "${RSYNC_BIN}" -a "${SRC_DIR}/" "${DST_DIR}/"

# Confirm rsync changed content.
for name in alpha beta gamma; do
    post="$(/sbin/sha256 -q "${DST_DIR}/${name}.txt")"
    smoke_log "post-rsync ${name}.txt sha: ${post}"
    [ "${post}" = "${SRC_SHAS[$name]}" ] || smoke_fail "rsync didn't sync ${name}.txt to src content"
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

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

failures=()
# alpha + beta restored to pre-rsync content
for name in alpha beta; do
    f="${DST_DIR}/${name}.txt"
    if [ ! -f "${f}" ]; then
        failures+=("${name}.txt MISSING post-undo")
        continue
    fi
    post="$(/sbin/sha256 -q "${f}")"
    smoke_log "post-undo ${name}.txt sha: ${post}"
    if [ "${post}" != "${PRE_DST_SHAS[$name]}" ]; then
        failures+=("${name}.txt: ${post} != expected ${PRE_DST_SHAS[$name]}")
    fi
done
# gamma should be removed (didn't exist pre-rsync).
if [ -e "${DST_DIR}/gamma.txt" ]; then
    failures+=("gamma.txt still present post-undo (should be removed)")
fi

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: rsync-incremental-undo-fbsd (alpha+beta restored, gamma removed; shim hits=${SHIM_HITS})"
    exit 0
fi

smoke_fail "rsync undo failed: ${failures[*]}"
