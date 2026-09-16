#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chflags-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M03.x.SETATTR-FAMILY end-to-end smoke (chflags variant).
#
# Workload: a tiny C binary that calls `chflags(path, UF_HIDDEN)`
# directly. UF_HIDDEN is a user-visible-but-restorable flag (it
# only hides the file in Finder; it doesn't prevent deletion or
# any other operation), making it safe for CI.
#
# We use UF_HIDDEN rather than UF_IMMUTABLE because UF_IMMUTABLE
# would block the cleanup `rm -rf $tmpdir` (immutable files
# refuse unlink), and SF_* would need root.
#
# The workload binary is built fresh per-run with clang, so it
# inherits DYLD_INSERT_LIBRARIES (ad-hoc-signed; no SIP strip).
# /usr/bin/chflags is SIP-protected and would NOT pick up the
# shim, which is why we build a non-SIP workload instead.
#
# Validation flow:
#   1. Pre-state: file with no flags (`-`)
#   2. Workload `set_chflags <file> UF_HIDDEN` runs under
#      DYLD_INSERT — shim's my_chflags interposer fires
#      `notify_flags_mutation` BEFORE the syscall,
#      capturing st_flags=0 as the pre-state into the daemon's
#      metadata-only FilePreImage journal.
#   3. Confirm post-mutate flags == "hidden"
#   4. shit undo --yes runs; planner emits RestoreFlags and the
#      field-specific executor calls chflags(path, 0) without
#      unrelated ownership/mode/xattr syscalls.
#   5. Assert post-undo flags == "-"

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: chflags-undo-macos is macOS-only (uname=$(uname -s))"
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

# Capture file flags. `ls -lO` (BSD ls) emits a flags column;
# "-" means no flags, otherwise comma-separated names like "hidden",
# "uchg", etc.
flags_of() {
    /bin/ls -lO "$1" 2>/dev/null | awk '{print $5}'
}

WATCHED="${SHIT_SMOKE_TMP}/watched"
TARGET="${SHIT_SMOKE_TMP}/data/hideme.txt"
mkdir -p "${WATCHED}" "$(dirname "${TARGET}")"

printf 'pre-chflags content\n' > "${TARGET}"
PRE_FLAGS="$(flags_of "${TARGET}")"
smoke_log "pre-state flags: '${PRE_FLAGS}'"
[ "${PRE_FLAGS}" = "-" ] || smoke_fail "pre-state invariant: target has unexpected flags '${PRE_FLAGS}'"

# Cleanup — always clear any flags we set so rm -rf works on
# the tmpdir. Belt-and-suspenders against UF_IMMUTABLE if a
# future variant of this smoke uses it.
cleanup() {
    local rc=$?
    trap - EXIT
    /usr/bin/chflags nohidden "${TARGET}" 2>/dev/null || true
    /usr/bin/chflags nouchg "${TARGET}" 2>/dev/null || true
    smoke_cleanup "${rc}"
}
trap cleanup EXIT

# Tiny C workload that calls chflags() directly. UF_HIDDEN is
# safe — purely cosmetic, doesn't block any other operation.
cat > "${WATCHED}/set_chflags.c" <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    if (chflags(argv[1], UF_HIDDEN) != 0) {
        perror("chflags");
        return 1;
    }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/set_chflags" "${WATCHED}/set_chflags.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/set_chflags" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build set_chflags workload"
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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/set_chflags ${TARGET}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/set_chflags" "${TARGET}" \
    > "${SHIT_SMOKE_TMP}/chflags.log" 2>&1
CHFLAGS_RC=$?
if [ "${CHFLAGS_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/chflags.log" >&2 || true
    smoke_fail "set_chflags workload failed (rc=${CHFLAGS_RC})"
fi

POST_MUTATE_FLAGS="$(flags_of "${TARGET}")"
smoke_log "post-mutate flags: '${POST_MUTATE_FLAGS}'"
if [ "${POST_MUTATE_FLAGS}" != "hidden" ]; then
    smoke_fail "expected hidden flag after chflags, got '${POST_MUTATE_FLAGS}'"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events for command: ${N_EVENTS}"
SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed by daemon: ${SHIM_HITS}"
[ "${SHIM_HITS}" -ge 1 ] || smoke_fail "expected at least one shim notification"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_FLAGS="$(flags_of "${TARGET}")"
smoke_log "post-undo flags: '${POST_UNDO_FLAGS}'"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

[ "${UNDO_RC}" -eq 0 ] || smoke_fail "shit undo exited ${UNDO_RC}"
[ "${POST_UNDO_FLAGS}" = "${PRE_FLAGS}" ] \
    || smoke_fail "flags mismatch after undo: got '${POST_UNDO_FLAGS}', want '${PRE_FLAGS}'"

smoke_log "PASS: chflags-undo-macos (flags restored to '${PRE_FLAGS}'; shim hits=${SHIM_HITS})"
