#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mmap-write-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M03.x.MMAP gap-validation smoke.
#
# Per `feedback-validate-gap-before-building`: before building
# AUTH_MMAP handler in macos_es.rs, write a smoke that should
# FAIL pre-fix and verify it actually fails. If it passes pre-
# fix the gap doesn't exist as framed.
#
# Workload: a tiny C program that
#   1. opens a pre-populated file with O_RDWR
#   2. mmaps PROT_WRITE | MAP_SHARED
#   3. mutates bytes via memory writes
#   4. msync(MS_SYNC) + munmap + close
#
# Then `shit undo --yes`. Outcome A = file bytes restored.
#
# The mmap mutation itself isn't visible to any syscall-layer
# interposer (the writes happen via memory stores after mmap
# returns). The pre-image must be captured at open(O_RDWR) time
# via the M07 shim — that's the hypothesis. If the shim's open
# coverage handles it, this is a non-gap on macOS (same pattern
# as M07.B.4). Otherwise AUTH_MMAP needs landing.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: mmap-write-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

# clang ships with the macOS Command Line Tools / Xcode — always
# present on macos-14 runners. Use it to build the workload binary
# fresh per run (ad-hoc-signed → DYLD_INSERT survives).
CLANG_BIN="$(command -v clang 2>/dev/null || true)"
if [ -z "${CLANG_BIN}" ]; then
    smoke_log "SKIP: clang not on PATH (need Xcode CLT)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.dylib"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB} (cargo build -p shit-preload-shim --release)"
export SHIT_HELPER_BIN="${HELPER_BIN}"

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

# Watched cwd: where the user runs commands.
WATCHED="${SHIT_SMOKE_TMP}/watched"
TARGET_FILE="${SHIT_SMOKE_TMP}/db/data.bin"
mkdir -p "${WATCHED}" "$(dirname "${TARGET_FILE}")"

# Pre-populate target with deterministic bytes — the original
# content that undo should restore.
printf 'AAAAAAAAAAAAAAAA\n' > "${TARGET_FILE}"
# Pad to >4KB so the mmap covers a whole page.
for _ in $(seq 1 256); do
    printf 'AAAAAAAAAAAAAAAA\n' >> "${TARGET_FILE}"
done

PRE_SHA="$(sha256_of "${TARGET_FILE}")"
smoke_log "pre-mutation target sha: ${PRE_SHA}"
smoke_log "pre-mutation target size: $(wc -c < "${TARGET_FILE}" | tr -d ' ') bytes"

# Workload C program. Mutates the first 16 bytes via mmap-write.
cat > "${WATCHED}/mmap_mutate.c" <<'CSRC'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    void *p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
    // Write 16 distinctive bytes at the start of the mapping.
    memcpy(p, "MUTATED-BY-MMAP\n", 16);
    if (msync(p, st.st_size, MS_SYNC) < 0) { perror("msync"); /* continue */ }
    if (munmap(p, st.st_size) < 0) { perror("munmap"); /* continue */ }
    if (close(fd) < 0) { perror("close"); return 1; }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/mmap_mutate" "${WATCHED}/mmap_mutate.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/mmap_mutate" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build mmap_mutate workload"
fi
smoke_log "built workload: ${WATCHED}/mmap_mutate"

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

# THE workload: open(O_RDWR) + mmap(PROT_WRITE|MAP_SHARED) +
# memory writes. DYLD shim sees the open; question is whether
# undo restores the pre-image (Outcome A) or leaves the mutated
# bytes in place (Outcome C, gap confirmed).
smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/mmap_mutate ${TARGET_FILE}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/mmap_mutate" "${TARGET_FILE}" \
    > "${SHIT_SMOKE_TMP}/mutate.log" 2>&1
MUTATE_RC=$?
if [ "${MUTATE_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/mutate.log" >&2 || true
    smoke_fail "mmap_mutate workload failed (rc=${MUTATE_RC})"
fi

POST_MUTATE_SHA="$(sha256_of "${TARGET_FILE}")"
smoke_log "post-mutate target sha: ${POST_MUTATE_SHA}"
if [ "${POST_MUTATE_SHA}" = "${PRE_SHA}" ]; then
    smoke_fail "workload didn't actually mutate the file"
fi
# Sanity check the mutation bytes landed.
if ! head -c 16 "${TARGET_FILE}" | grep -q "MUTATED-BY-MMAP"; then
    head -c 32 "${TARGET_FILE}" | xxd | sed 's/^/    /' >&2 || true
    smoke_fail "expected MUTATED-BY-MMAP marker not in target after workload"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed by daemon: ${SHIM_HITS}"

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_SHA="$(sha256_of "${TARGET_FILE}")"
smoke_log "post-undo target sha: ${POST_UNDO_SHA}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — full undo (mmap-write restored to pre-bytes, shim hits=${SHIM_HITS})"
    smoke_log "PASS: mmap-write-undo-macos (Outcome A — gap closed via shim open-coverage)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "mmap|MUTATED|refus|conflict|data.bin" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: mmap-write-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (M03.x.MMAP gap confirmed)"
smoke_log "  pre sha:       ${PRE_SHA}"
smoke_log "  post-mutate:   ${POST_MUTATE_SHA}"
smoke_log "  post-undo:     ${POST_UNDO_SHA}"
smoke_log "  undo exit:     ${UNDO_RC}"
smoke_log "  shim hits:     ${SHIM_HITS}"
smoke_log "  journal:       ${N_EVENTS}"
smoke_fail "mmap-write undo did NOT restore pre-bytes (M03.x.MMAP gap confirmed)"
