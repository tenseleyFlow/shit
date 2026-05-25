#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.7.split smoke — `split -l 2 big.txt part-` creates N output
# files from one input. `shit undo` should remove ALL part-* files
# while leaving big.txt untouched. Stress test for multi-Create.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: split-undo-fbsd is FreeBSD-only"
    exit 0
fi

SPLIT_BIN="$(command -v split)"
[ -x "${SPLIT_BIN}" ] || smoke_fail "split not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SOURCE="${WATCHED}/big.txt"
# 10 lines → split -l 2 → 5 output files.
seq 1 10 | awk '{printf "line%02d\n", $1}' > "${SOURCE}"
SOURCE_SHA="$(/sbin/sha256 -q "${SOURCE}")"
smoke_log "pre-cmd source sha: ${SOURCE_SHA}"

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

smoke_log "${SPLIT_BIN} -l 2 big.txt part-"
"${SPLIT_BIN}" -l 2 big.txt part-

# `ls part-*` returns rc=1 if no matches and `set -o pipefail`
# (set in lib.sh) would silently abort the script. Use `find`
# instead — it returns 0 with empty stdout when no matches.
PART_COUNT="$(find . -maxdepth 1 -name 'part-*' -type f | wc -l | tr -d ' ')"
smoke_log "post-split part-* count: ${PART_COUNT}"
[ "${PART_COUNT}" -ge 5 ] || smoke_fail "split didn't produce expected ≥5 part files (got ${PART_COUNT})"

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

remaining="$(find . -maxdepth 1 -name 'part-*' -type f | wc -l | tr -d ' ')"
if [ "${remaining}" != "0" ]; then
    find . -maxdepth 1 -name 'part-*' -type f | /usr/bin/sed 's/^/    /' >&2
    smoke_fail "${remaining} part-* file(s) remain post-undo"
fi
# Source must be untouched.
POST_SOURCE_SHA="$(/sbin/sha256 -q "${SOURCE}")"
if [ "${POST_SOURCE_SHA}" != "${SOURCE_SHA}" ]; then
    smoke_fail "source perturbed: ${SOURCE_SHA} → ${POST_SOURCE_SHA}"
fi

smoke_log "PASS: split-undo-fbsd (${PART_COUNT} part files removed; big.txt sha=${SOURCE_SHA} intact)"
