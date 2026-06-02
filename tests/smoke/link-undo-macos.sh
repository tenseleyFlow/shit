#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: link-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M03.x.LINK gap-validation smoke.
#
# Workload: a tiny C binary that calls `link(src, dst)` to create
# a hardlink. The shim has NO `link`/`linkat` interposer (only
# unlink/rename/open/mkdir/chmod/chown/utimes/xattr/chflags).
#
# Hypothesis: real gap. The hardlink-create surface needs:
#   - shim my_link + my_linkat interposers
#   - notify_create-style event (no pre-image; the new path didn't
#     exist before)
#   - planner inverse: unlink(dst) (same as TreeOp::Create)
#
# Outcomes:
#   A. Full undo: hardlink removed; src untouched.
#   B. Loud refusal
#   C. Silent stomp (EXPECTED) — dst hardlink survives undo

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: link-undo-macos is macOS-only (uname=$(uname -s))"
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

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

WATCHED="${SHIT_SMOKE_TMP}/watched"
SRC="${SHIT_SMOKE_TMP}/data/orig.bin"
DST="${SHIT_SMOKE_TMP}/data/alias.bin"
mkdir -p "${WATCHED}" "$(dirname "${SRC}")"

printf 'hardlink source content\n' > "${SRC}"
PRE_SRC_SHA="$(sha256_of "${SRC}")"
smoke_log "pre-state src sha: ${PRE_SRC_SHA}"
[ ! -e "${DST}" ] || smoke_fail "pre-state invariant: dst already exists"

# Tiny C workload: hardlink src → dst via link(2).
cat > "${WATCHED}/make_link.c" <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <src> <dst>\n", argv[0]);
        return 2;
    }
    if (link(argv[1], argv[2]) != 0) {
        perror("link");
        return 1;
    }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/make_link" "${WATCHED}/make_link.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/make_link" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build make_link workload"
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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/make_link ${SRC} ${DST}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/make_link" "${SRC}" "${DST}" \
    > "${SHIT_SMOKE_TMP}/link.log" 2>&1
LINK_RC=$?
if [ "${LINK_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/link.log" >&2 || true
    smoke_fail "make_link workload failed (rc=${LINK_RC})"
fi

[ -e "${DST}" ] || smoke_fail "workload claimed success but dst hardlink not created"
POST_SRC_SHA="$(sha256_of "${SRC}")"
POST_DST_SHA="$(sha256_of "${DST}")"
[ "${POST_SRC_SHA}" = "${PRE_SRC_SHA}" ] || smoke_fail "src content changed after link()"
[ "${POST_DST_SHA}" = "${PRE_SRC_SHA}" ] || smoke_fail "dst doesn't hardlink src bytes"
smoke_log "post-link: dst hardlink created (shares src inode)"

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

DST_REMOVED=no
[ ! -e "${DST}" ] && DST_REMOVED=yes
SRC_INTACT=no
[ -e "${SRC}" ] && [ "$(sha256_of "${SRC}")" = "${PRE_SRC_SHA}" ] && SRC_INTACT=yes
smoke_log "post-undo dst removed: ${DST_REMOVED}; src intact: ${SRC_INTACT}"

if [ "${DST_REMOVED}" = "yes" ] && [ "${SRC_INTACT}" = "yes" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — hardlink removed, src untouched (shim hits=${SHIM_HITS})"
    smoke_log "PASS: link-undo-macos (M03.x.LINK)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "link|hardlink|alias|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: link-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (gap confirmed)"
smoke_log "  pre src sha:    ${PRE_SRC_SHA}"
smoke_log "  dst removed:    ${DST_REMOVED}"
smoke_log "  src intact:     ${SRC_INTACT}"
smoke_log "  undo exit:      ${UNDO_RC}"
smoke_log "  journal events: ${N_EVENTS}"
smoke_log "  shim hits:      ${SHIM_HITS}"
smoke_fail "link undo did NOT remove the hardlink"
