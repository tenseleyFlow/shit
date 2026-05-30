#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cp-clone-overwrite-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M03.x.CLONE-COPYFILE gap-validation smoke.
#
# Per `feedback-validate-gap-before-building`: before building
# AUTH_CLONE / AUTH_COPYFILE handlers in macos_es.rs, write a
# smoke that should FAIL pre-fix and verify it actually fails.
#
# Workload: macOS `cp -c <src> <dst>` invokes `clonefile(2)`
# (APFS CoW clone). When dst already exists, the user expects
# `shit undo` to restore the original dst bytes. The M07 shim
# does NOT interpose clonefile(2) or copyfile(3); the question
# is whether `cp -c` does any open() / unlink() / rename() that
# the shim DOES catch as a side-effect, or whether the clonefile
# syscall lands without any caught pre-image.
#
# Outcomes:
#   A. Full undo: dst content restored to pre-clone bytes.
#       → CLONE-COPYFILE is a non-gap on macOS (cp's syscall mix
#         happens to land within shim coverage).
#   B. Loud refusal.
#   C. Silent stomp: dst stays as src content (or is deleted).
#       → CLONE-COPYFILE is a real gap; M03.x.CLONE-COPYFILE
#         should land an AUTH_CLONE handler (or a clonefile/
#         copyfile shim interposer on the M07 side).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: cp-clone-overwrite-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

# macOS ships `cp` (BSD) supporting `-c` for clonefile on APFS.
# /bin/cp is SIP-protected so DYLD_INSERT_LIBRARIES is stripped.
# Use Homebrew's `gcp` (coreutils) — wait, gcp doesn't have `-c`
# (clonefile is BSD/Apple-specific). The non-SIP path is:
# build a tiny C binary that invokes clonefile(2) directly,
# mirroring what /bin/cp -c does internally. This is the exact
# pattern of M03.x.MMAP's gap-validation smoke.
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
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

WATCHED="${SHIT_SMOKE_TMP}/watched"
SRC="${SHIT_SMOKE_TMP}/data/src.bin"
DST="${SHIT_SMOKE_TMP}/data/dst.bin"
mkdir -p "${WATCHED}" "$(dirname "${SRC}")"

# Distinct contents — different sizes too to make sure we're not
# missing a "same length so same hash" coincidence.
printf 'ORIGINAL-DST-CONTENT-AAAAAA\n' > "${DST}"
printf 'NEW-SRC-CONTENT-FROM-CLONE-BBBBBBBBBBBBBBBB\n' > "${SRC}"

PRE_DST_SHA="$(sha256_of "${DST}")"
PRE_SRC_SHA="$(sha256_of "${SRC}")"
smoke_log "pre-state dst sha: ${PRE_DST_SHA} ($(wc -c < "${DST}" | tr -d ' ') bytes)"
smoke_log "pre-state src sha: ${PRE_SRC_SHA} ($(wc -c < "${SRC}" | tr -d ' ') bytes)"
[ "${PRE_DST_SHA}" != "${PRE_SRC_SHA}" ] || smoke_fail "pre-state invariant: dst/src content collide"

# Tiny C workload that mimics `cp -c <src> <dst>` for an existing
# dst. The /bin/cp implementation:
#   - stat(dst) to see if it exists
#   - unlink(dst) if it does (cp -c can't clone over existing)
#   - clonefile(src, dst, CLONE_NOFOLLOW)
# We replicate the same sequence so the shim sees the same call
# pattern /bin/cp would issue (if /bin/cp weren't SIP-stripped).
cat > "${WATCHED}/clone_overwrite.c" <<'CSRC'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <src> <dst>\n", argv[0]);
        return 2;
    }
    const char *src = argv[1];
    const char *dst = argv[2];
    struct stat st;
    if (stat(dst, &st) == 0) {
        if (unlink(dst) < 0) { perror("unlink"); return 1; }
    }
    if (clonefile(src, dst, CLONE_NOFOLLOW) != 0) {
        perror("clonefile");
        return 1;
    }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/clone_overwrite" "${WATCHED}/clone_overwrite.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/clone_overwrite" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build clone_overwrite workload"
fi
smoke_log "built workload: ${WATCHED}/clone_overwrite"

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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/clone_overwrite ${SRC} ${DST}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/clone_overwrite" "${SRC}" "${DST}" \
    > "${SHIT_SMOKE_TMP}/clone.log" 2>&1
CLONE_RC=$?
if [ "${CLONE_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clone.log" >&2 || true
    smoke_fail "clone_overwrite workload failed (rc=${CLONE_RC})"
fi

POST_CLONE_DST_SHA="$(sha256_of "${DST}")"
smoke_log "post-clone dst sha: ${POST_CLONE_DST_SHA}"
if [ "${POST_CLONE_DST_SHA}" != "${PRE_SRC_SHA}" ]; then
    smoke_fail "workload didn't actually clone src bytes over dst (got ${POST_CLONE_DST_SHA}, want ${PRE_SRC_SHA})"
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

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ ! -e "${DST}" ]; then
    smoke_log "post-undo dst MISSING — undo unlinked it instead of restoring"
    smoke_log "  shim hits: ${SHIM_HITS}; journal: ${N_EVENTS}; undo rc: ${UNDO_RC}"
    smoke_fail "CLONE-COPYFILE gap variant: dst deleted, not content-restored"
fi

POST_UNDO_DST_SHA="$(sha256_of "${DST}")"
smoke_log "post-undo dst sha: ${POST_UNDO_DST_SHA}"

if [ "${POST_UNDO_DST_SHA}" = "${PRE_DST_SHA}" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — dst restored to pre-clone bytes (shim hits=${SHIM_HITS})"
    smoke_log "PASS: cp-clone-overwrite-undo-macos (Outcome A — gap closed via unlink+? shim coverage)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "clone|cp|dst.bin|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: cp-clone-overwrite-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (M03.x.CLONE-COPYFILE gap confirmed)"
smoke_log "  pre dst sha:     ${PRE_DST_SHA}"
smoke_log "  post-clone dst:  ${POST_CLONE_DST_SHA}"
smoke_log "  post-undo dst:   ${POST_UNDO_DST_SHA}"
smoke_log "  undo exit:       ${UNDO_RC}"
smoke_log "  shim hits:       ${SHIM_HITS}"
smoke_log "  journal events:  ${N_EVENTS}"
smoke_fail "cp-clone-overwrite-undo did NOT restore pre-clone dst bytes (gap confirmed)"
