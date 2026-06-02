#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: xattr-mutate-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M03.x.XATTR-MUTATE gap-validation smoke.
#
# Per `feedback-validate-gap-before-building`: before doing any
# AUTH_SETEXTATTR / AUTH_DELETEEXTATTR work, write a smoke that
# should FAIL pre-fix and verify it actually fails.
#
# Workload: a tiny C binary that calls `setxattr(path, name,
# value, ...)` and `removexattr(path, name)` directly. The M07.B.4
# + M07.B.4.1 work landed `my_setxattr` / `my_removexattr` /
# `my_fsetxattr` / `my_fremovexattr` interposers in the shim with
# pre-value capture. Hypothesis: xattr-mutation is already covered
# end-to-end via the shim path; ES adding AUTH_SETEXTATTR would
# be duplicative.
#
# Outcomes:
#   A. Full undo: xattr reverted to pre-state (gap closed by shim)
#   B. Loud refusal
#   C. Silent stomp (real gap; needs investigation)

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: xattr-mutate-undo-macos is macOS-only (uname=$(uname -s))"
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

# Read an xattr's value (or empty when absent — never errors so it
# doesn't trip set -e at the call site's command substitution).
# xattr(1) CLI takes `xattr -p <attr_name> <file>` — name first.
xattr_value() {
    local path="$1"
    local name="$2"
    /usr/bin/xattr -p "${name}" "${path}" 2>/dev/null || true
}
xattr_exists() {
    local path="$1"
    local name="$2"
    /usr/bin/xattr -p "${name}" "${path}" >/dev/null 2>&1
}

WATCHED="${SHIT_SMOKE_TMP}/watched"
TARGET="${SHIT_SMOKE_TMP}/data/xattr.bin"
ATTR_NAME="user.shit.m03x.xmtest"
PRE_VALUE="pre-mutation-value-AAAAAA"
POST_VALUE="post-mutation-value-BBBBBB"
mkdir -p "${WATCHED}" "$(dirname "${TARGET}")"

printf 'file body\n' > "${TARGET}"
# Pre-populate the xattr — workload will OVERWRITE it via setxattr.
# The overwrite is the interesting case: pre-value must be captured
# for undo to restore.
/usr/bin/xattr -w "${ATTR_NAME}" "${PRE_VALUE}" "${TARGET}"

PRE_XATTR_VAL="$(xattr_value "${TARGET}" "${ATTR_NAME}")"
smoke_log "pre-mutation xattr '${ATTR_NAME}' value: '${PRE_XATTR_VAL}'"
[ "${PRE_XATTR_VAL}" = "${PRE_VALUE}" ] || smoke_fail "pre-state invariant: xattr value mismatch (got '${PRE_XATTR_VAL}', want '${PRE_VALUE}')"

cleanup() {
    /usr/bin/xattr -d "${ATTR_NAME}" "${TARGET}" 2>/dev/null || true
}
trap cleanup EXIT

# Tiny C workload: setxattr(path, name, value, ...) directly.
# On macOS the signature is:
#   ssize_t setxattr(const char *path, const char *name,
#                    const void *value, size_t size,
#                    u_int32_t position, int options);
cat > "${WATCHED}/mutate_xattr.c" <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <path> <name> <new-value>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    const char *name = argv[2];
    const char *val = argv[3];
    if (setxattr(path, name, val, strlen(val), 0, 0) != 0) {
        perror("setxattr");
        return 1;
    }
    return 0;
}
CSRC

"${CLANG_BIN}" -O0 -o "${WATCHED}/mutate_xattr" "${WATCHED}/mutate_xattr.c" 2> "${SHIT_SMOKE_TMP}/clang.log"
if [ ! -x "${WATCHED}/mutate_xattr" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/clang.log" >&2 || true
    smoke_fail "clang failed to build mutate_xattr workload"
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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} ${WATCHED}/mutate_xattr ${TARGET} ${ATTR_NAME} ${POST_VALUE}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${WATCHED}/mutate_xattr" "${TARGET}" "${ATTR_NAME}" "${POST_VALUE}" \
    > "${SHIT_SMOKE_TMP}/mutate.log" 2>&1
MUTATE_RC=$?
if [ "${MUTATE_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/mutate.log" >&2 || true
    smoke_fail "mutate_xattr workload failed (rc=${MUTATE_RC})"
fi

POST_MUTATE_VAL="$(xattr_value "${TARGET}" "${ATTR_NAME}")"
smoke_log "post-mutate xattr value: '${POST_MUTATE_VAL}'"
[ "${POST_MUTATE_VAL}" = "${POST_VALUE}" ] || smoke_fail "workload didn't actually mutate xattr"

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

POST_UNDO_VAL="$(xattr_value "${TARGET}" "${ATTR_NAME}")"
smoke_log "post-undo xattr value: '${POST_UNDO_VAL}'"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${POST_UNDO_VAL}" = "${PRE_VALUE}" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — xattr restored to pre-value (shim hits=${SHIM_HITS})"
    smoke_log "PASS: xattr-mutate-undo-macos (M03.x.XATTR-MUTATE)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "xattr|setxattr|refus|conflict|metadata" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: xattr-mutate-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (gap confirmed for setxattr-overwrite)"
smoke_log "  pre value:        '${PRE_VALUE}'"
smoke_log "  post-mutate:      '${POST_MUTATE_VAL}'"
smoke_log "  post-undo:        '${POST_UNDO_VAL}'"
smoke_log "  undo exit:        ${UNDO_RC}"
smoke_log "  journal events:   ${N_EVENTS}"
smoke_log "  shim hits:        ${SHIM_HITS}"
smoke_fail "xattr undo did NOT restore pre-value"
