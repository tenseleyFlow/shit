#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mkfifo-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M03.x.CREATE (mkfifo portion) gap-validation smoke.
#
# Workload: a tiny C binary that calls `mkfifo(path, 0o644)` to
# create a FIFO special file. macOS shim has NO `mkfifo` interposer
# (the existing shim covers open/unlink/rename/mkdir/chmod family
# but mkfifo/mknod was deferred per the M03.x.CREATE roadmap row).
#
# Hypothesis: real gap. Daemon's `classify_tree_op` already has a
# "mkfifo"/"mkfifoat" arm (W09.10.1 added it for the kqueue
# fall-through case on FreeBSD), so adding a shim interposer is
# all that's needed for end-to-end coverage.
#
# Outcomes:
#   A. Full undo: FIFO removed; no leftover events
#   B. Loud refusal
#   C. Silent stomp (EXPECTED pre-fix) — FIFO survives undo

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: mkfifo-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

CLANG_BIN="$(command -v clang 2>/dev/null || true)"
if [ -z "${CLANG_BIN}" ]; then
    smoke_log "SKIP: clang not on PATH (need Xcode CLT)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.dylib"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
TARGET="${SHIT_SMOKE_TMP}/data/myfifo"
mkdir -p "${WATCHED}" "$(dirname "${TARGET}")"

[ ! -e "${TARGET}" ] || smoke_fail "pre-state invariant: ${TARGET} already exists"

cat > "${WATCHED}/make_fifo.c" <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    if (mkfifo(argv[1], 0644) != 0) {
        perror("mkfifo");
        return 1;
    }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/make_fifo" "${WATCHED}/make_fifo.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/make_fifo" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build make_fifo workload"
fi

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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/make_fifo ${TARGET}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/make_fifo" "${TARGET}" \
    > "${SHIT_SMOKE_TMP}/mkfifo.log" 2>&1
MKFIFO_RC=$?
if [ "${MKFIFO_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/mkfifo.log" >&2 || true
    smoke_fail "make_fifo workload failed (rc=${MKFIFO_RC})"
fi

[ -p "${TARGET}" ] || smoke_fail "workload claimed success but ${TARGET} is not a FIFO"
smoke_log "post-mkfifo: FIFO created at ${TARGET}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "journal events: ${N_EVENTS}; shim hits: ${SHIM_HITS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

FIFO_GONE=no
[ ! -e "${TARGET}" ] && FIFO_GONE=yes
smoke_log "post-undo FIFO gone: ${FIFO_GONE}"

if [ "${FIFO_GONE}" = "yes" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — FIFO removed by undo (shim hits=${SHIM_HITS})"
    smoke_log "PASS: mkfifo-undo-macos (M03.x.CREATE mkfifo portion)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "mkfifo|fifo|refus|conflict|myfifo" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: mkfifo-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (gap confirmed)"
smoke_log "  FIFO gone:      ${FIFO_GONE}"
smoke_log "  undo exit:      ${UNDO_RC}"
smoke_log "  journal events: ${N_EVENTS}"
smoke_log "  shim hits:      ${SHIM_HITS}"
smoke_fail "mkfifo undo did NOT remove the FIFO"
