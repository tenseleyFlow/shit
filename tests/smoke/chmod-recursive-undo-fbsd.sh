#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.8.chmod-R smoke — `chmod -R 0700 dir/` changes mode on a
# directory tree (~10 files). Each fires NOTE_ATTRIB (via the
# kqueue producer's S29.3 metadata capture). `shit undo` should
# restore EACH file's pre-change mode independently.
#
# Tests batch coalescing and per-file MetadataChange tracking.
# Stress: 10 events from one command, all metadata-only.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: chmod-recursive-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
TREE="${WATCHED}/tree"
mkdir -p "${TREE}/sub1" "${TREE}/sub2"

# Build 10 files with explicit pre-chmod modes.
declare -A PRE_MODES
for i in 1 2 3 4 5; do
    f="${TREE}/file${i}.txt"
    printf 'content %d\n' "${i}" > "${f}"
    chmod 0644 "${f}"
    PRE_MODES["file${i}"]="$(/usr/bin/stat -f '%Op' "${f}")"
    smoke_log "pre-cmd file${i}.txt mode: ${PRE_MODES[file${i}]}"
done
for i in 1 2; do
    f="${TREE}/sub1/sub_a${i}.txt"
    printf 'sub_a%d\n' "${i}" > "${f}"
    chmod 0640 "${f}"
    PRE_MODES["sub_a${i}"]="$(/usr/bin/stat -f '%Op' "${f}")"
done
for i in 1 2 3; do
    f="${TREE}/sub2/sub_b${i}.txt"
    printf 'sub_b%d\n' "${i}" > "${f}"
    chmod 0600 "${f}"
    PRE_MODES["sub_b${i}"]="$(/usr/bin/stat -f '%Op' "${f}")"
done

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

smoke_log "chmod -R 0700 ${TREE}"
chmod -R 0700 "${TREE}"

# Sanity: all files now 0700.
for f in "${TREE}"/file*.txt "${TREE}"/sub*/*.txt; do
    m="$(/usr/bin/stat -f '%Op' "${f}")"
    [ "${m}" = "100700" ] || smoke_fail "post-chmod ${f} mode=${m}, expected 100700"
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
for i in 1 2 3 4 5; do
    f="${TREE}/file${i}.txt"
    m="$(/usr/bin/stat -f '%Op' "${f}")"
    if [ "${m}" != "${PRE_MODES[file${i}]}" ]; then
        failures+=("file${i}.txt: ${m} != expected ${PRE_MODES[file${i}]}")
    fi
done
for i in 1 2; do
    f="${TREE}/sub1/sub_a${i}.txt"
    m="$(/usr/bin/stat -f '%Op' "${f}")"
    if [ "${m}" != "${PRE_MODES[sub_a${i}]}" ]; then
        failures+=("sub_a${i}.txt: ${m} != expected ${PRE_MODES[sub_a${i}]}")
    fi
done
for i in 1 2 3; do
    f="${TREE}/sub2/sub_b${i}.txt"
    m="$(/usr/bin/stat -f '%Op' "${f}")"
    if [ "${m}" != "${PRE_MODES[sub_b${i}]}" ]; then
        failures+=("sub_b${i}.txt: ${m} != expected ${PRE_MODES[sub_b${i}]}")
    fi
done

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: chmod-recursive-undo-fbsd (10 files' modes restored independently)"
    exit 0
fi

smoke_fail "chmod -R undo failed: ${failures[*]}"
