#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mkdir-out-of-watch-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY: M03.x.CREATE-mkdir-planner-coord-pending
# EXCLUDED_REASON: Initial attempt at routing mkdir/mkdirat → TreeOp::Create{Directory} caused cargo-install-force-undo regression (applied=42 conflicts=6, cargo's incidental parent dirs rmdir-recursive'd alongside FilePreImage restores for files inside). Closing properly needs planner-side coordination — when a Create's path is a Directory AND any other inverse in the plan targets a path UNDER that directory, the rmdir should attempt empty-only (no recursive fallback). Smoke documents the gap; re-enable by clearing this EXCLUDED_BY when the planner coordination lands.
#
# M03.x.CREATE (mkdir out-of-watch portion) gap-validation smoke.
#
# Workload: a tiny C binary that calls `mkdir(path, 0o755)` against
# a path OUTSIDE the watched cwd subtree. The shim's `my_mkdir`
# interposer DOES fire (M07.A.2 landed it), but the daemon's
# `classify_tree_op` doesn't handle "mkdir" syscalls — only
# "mkfifo"/"link"/"linkat"/rename/unlink. So shim notifies are
# dropped silently for mkdir.
#
# On in-watch mkdirs the kqueue dir-diff path (in baseline) catches
# the create (so the gap is invisible in normal workloads). On
# out-of-watch mkdirs (e.g. `make install` creating /usr/local/
# subdirs, or any mkdir outside the user's cwd subtree) the
# journal never sees it.
#
# Outcomes:
#   A. Full undo: out-of-watch dir removed
#   B. Loud refusal
#   C. Silent stomp (EXPECTED pre-fix) — dir survives undo

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: mkdir-out-of-watch-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

CLANG_BIN="$(command -v clang 2>/dev/null || true)"
if [ -z "${CLANG_BIN}" ]; then
    smoke_log "SKIP: clang not on PATH"
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
# CRITICAL: out-of-watch — sibling to WATCHED, NOT under it. Kqueue
# dir-diff only tracks subtrees rooted at WATCHED; this dir is
# invisible to kqueue, so only the shim's mkdir notify path can
# observe its creation.
OOW_DIR="${SHIT_SMOKE_TMP}/out-of-watch"
TARGET="${OOW_DIR}/newdir"
mkdir -p "${WATCHED}" "${OOW_DIR}"

[ ! -e "${TARGET}" ] || smoke_fail "pre-state invariant: ${TARGET} already exists"

cat > "${WATCHED}/make_dir.c" <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    if (mkdir(argv[1], 0755) != 0) {
        perror("mkdir");
        return 1;
    }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/make_dir" "${WATCHED}/make_dir.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/make_dir" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build make_dir workload"
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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/make_dir ${TARGET}  (target is OUT-OF-WATCH)"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/make_dir" "${TARGET}" \
    > "${SHIT_SMOKE_TMP}/mkdir.log" 2>&1
MKDIR_RC=$?
if [ "${MKDIR_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/mkdir.log" >&2 || true
    smoke_fail "make_dir workload failed (rc=${MKDIR_RC})"
fi

[ -d "${TARGET}" ] || smoke_fail "workload claimed success but ${TARGET} is not a directory"
smoke_log "post-mkdir: out-of-watch dir created at ${TARGET}"

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

DIR_GONE=no
[ ! -e "${TARGET}" ] && DIR_GONE=yes
smoke_log "post-undo dir gone: ${DIR_GONE}"

if [ "${DIR_GONE}" = "yes" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — out-of-watch dir removed by undo (shim hits=${SHIM_HITS})"
    smoke_log "PASS: mkdir-out-of-watch-undo-macos (M03.x.CREATE mkdir portion)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "mkdir|newdir|out-of-watch|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: mkdir-out-of-watch-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (gap confirmed)"
smoke_log "  dir gone:       ${DIR_GONE}"
smoke_log "  undo exit:      ${UNDO_RC}"
smoke_log "  journal events: ${N_EVENTS}"
smoke_log "  shim hits:      ${SHIM_HITS}"
smoke_fail "mkdir undo did NOT remove the out-of-watch dir"
