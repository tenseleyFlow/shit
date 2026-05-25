#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.6.find smoke — `find . -type f -name '*.tmp' -delete` removes
# multiple files in a single command. `shit undo` should restore
# ALL of them with byte-identical content.
#
# Stress test: many unlink events from a single command. Uses
# `-delete` (find's built-in, fires unlinkat) rather than
# `-exec rm` to keep the smoke's process tree simple and the
# shim's ancestry chain short.
#
# This validates:
#   - Multiple sequential unlinks are all attributed to the same command
#   - Live-baseline / shim captures pre-image for EACH file
#   - Planner emits N independent RecreatePath+RestoreContent pairs

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: find-exec-rm-undo-fbsd is FreeBSD-only"
    exit 0
fi

FIND_BIN="$(command -v find)"
[ -x "${FIND_BIN}" ] || smoke_fail "find not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"

# Populate 5 .tmp files with distinct content + 2 non-.tmp files that
# MUST NOT be touched.
declare -A PRE_SHAS
for i in 1 2 3 4 5; do
    f="${WATCHED}/scratch${i}.tmp"
    printf 'content for tmp file %d\n' "${i}" > "${f}"
    PRE_SHAS["scratch${i}.tmp"]="$(/sbin/sha256 -q "${f}")"
    smoke_log "pre-cmd scratch${i}.tmp sha: ${PRE_SHAS[scratch${i}.tmp]}"
done
# Decoys — find should NOT match these.
printf 'i am a keeper\n' > "${WATCHED}/keep.txt"
printf 'i am also a keeper\n' > "${WATCHED}/keep.log"
KEEP_TXT_SHA="$(/sbin/sha256 -q "${WATCHED}/keep.txt")"
KEEP_LOG_SHA="$(/sbin/sha256 -q "${WATCHED}/keep.log")"

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

smoke_log "${FIND_BIN} . -type f -name '*.tmp' -delete"
"${FIND_BIN}" . -type f -name '*.tmp' -delete

# Sanity: all 5 .tmp files gone, decoys intact.
for i in 1 2 3 4 5; do
    [ ! -e "${WATCHED}/scratch${i}.tmp" ] || smoke_fail "find didn't delete scratch${i}.tmp"
done
[ -f "${WATCHED}/keep.txt" ] || smoke_fail "find ate keep.txt"
[ -f "${WATCHED}/keep.log" ] || smoke_fail "find ate keep.log"

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
for i in 1 2 3 4 5; do
    f="${WATCHED}/scratch${i}.tmp"
    if [ ! -f "${f}" ]; then
        failures+=("scratch${i}.tmp MISSING post-undo")
        continue
    fi
    POST_SHA="$(/sbin/sha256 -q "${f}")"
    if [ "${POST_SHA}" != "${PRE_SHAS[scratch${i}.tmp]}" ]; then
        failures+=("scratch${i}.tmp content mismatch: ${POST_SHA} != ${PRE_SHAS[scratch${i}.tmp]}")
    fi
done
# Decoys should still be intact.
[ "$(/sbin/sha256 -q "${WATCHED}/keep.txt")" = "${KEEP_TXT_SHA}" ] || failures+=("keep.txt perturbed")
[ "$(/sbin/sha256 -q "${WATCHED}/keep.log")" = "${KEEP_LOG_SHA}" ] || failures+=("keep.log perturbed")

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: find-exec-rm-undo-fbsd (5 .tmp files restored; 2 decoys intact)"
    exit 0
fi

smoke_fail "find undo failed: ${failures[*]}"
