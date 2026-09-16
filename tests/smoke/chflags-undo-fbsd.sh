#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chflags-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# B09 — exercise the full FreeBSD chflags undo path: metadata-only
# preload-shim pre-image → RestoreFlags plan node → daemon-side
# chflags(2). The field-specific inverse avoids unrelated chown/chmod
# calls, so the helper's Capsicum sandbox is not involved.
#
# Why a direct chflags(2) C workload: modern /bin/chflags traverses with
# dirfd-relative chflagsat(2), while the v1 shim wire has no dirfd field.
# The interposer deliberately skips shapes it cannot faithfully replay.
# This smoke therefore exercises the supported absolute-path API directly.
#
# UFS supports user flags and must round-trip. OpenZFS may return
# EOPNOTSUPP; there the producer notification remains a useful gate,
# but the mutation/undo assertions are explicitly skipped.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: chflags-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "preload shim .so missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
cd "${WATCHED}"

TARGET="${WATCHED}/target.txt"
printf 'shim-chflags-test\n' > "${TARGET}"

CC_BIN="$(command -v cc 2>/dev/null || true)"
[ -n "${CC_BIN}" ] || smoke_fail "cc not on PATH"
cat > "${WATCHED}/set_chflags.c" <<'CSRC'
#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    if (chflags(argv[1], UF_NODUMP) != 0) {
        perror("chflags");
        return 1;
    }
    return 0;
}
CSRC
"${CC_BIN}" -O0 -o "${WATCHED}/set_chflags" "${WATCHED}/set_chflags.c" \
    2> "${SHIT_SMOKE_TMP}/cc.log"
[ -x "${WATCHED}/set_chflags" ] || smoke_fail "cc failed to build chflags workload"

# FS-capability probe. Use UF_NODUMP rather than UF_IMMUTABLE so a
# failed undo never makes smoke cleanup itself fail.
SUPPORTS_CHFLAGS=1
if "${WATCHED}/set_chflags" "${TARGET}" 2>/dev/null; then
    /bin/chflags 0 "${TARGET}" 2>/dev/null \
        || smoke_fail "could not clear probe flag"
else
    SUPPORTS_CHFLAGS=0
    smoke_log "note: chflags returns EOPNOTSUPP on this FS (likely ZFS); shim-emission gate is the load-bearing check"
fi
PRE_FLAGS="$(stat -f '%Of' "${TARGET}")"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# Workload — call chflags(2) with an absolute path under LD_PRELOAD.
# If the FS doesn't support flags, the syscall fails after the shim
# notification, so the producer gate remains meaningful.
smoke_log "workload: LD_PRELOAD=${SHIM_LIB} ${WATCHED}/set_chflags ${TARGET}"
set +e
LD_PRELOAD="${SHIM_LIB}" "${WATCHED}/set_chflags" "${TARGET}" 2>/dev/null
CHFLAGS_RC=$?
set -e
sleep 0.5

if [ "${SUPPORTS_CHFLAGS}" -eq 1 ]; then
    POST_FLAGS="$(stat -f '%Of' "${TARGET}")"
    smoke_log "pre-flags=${PRE_FLAGS} post-flags=${POST_FLAGS}"
    [ "${CHFLAGS_RC}" -eq 0 ] || smoke_fail "chflags nodump exited ${CHFLAGS_RC} on a supported FS"
    [ "${POST_FLAGS}" != "${PRE_FLAGS}" ] \
        || smoke_fail "chflags nodump did not change flags (${PRE_FLAGS})"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

# LOAD-BEARING gate: daemon journaled at least one "chflags"
# shim notification. This is the producer-side parity check.
JSON_LOG="$(ls "${XDG_STATE_HOME}/shit/log/daemon.jsonl"* 2>/dev/null | head -1)"
if [ -z "${JSON_LOG}" ] || [ ! -f "${JSON_LOG}" ]; then
    smoke_fail "daemon JSON log not found under \${XDG_STATE_HOME}/shit/log/"
fi

SHIM_COUNT="$(grep -cE '"syscall":"chflags"' "${JSON_LOG}" 2>/dev/null || true)"
SHIM_COUNT="${SHIM_COUNT:-0}"
smoke_log "shim notifications: chflags=${SHIM_COUNT}"

if [ "${SHIM_COUNT}" -lt 1 ]; then
    smoke_log "regression — no shim 'chflags' notification in daemon log"
    grep -i 'shim\|chflags' "${JSON_LOG}" | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected at least 1 'chflags' notification; got ${SHIM_COUNT}"
fi

if [ "${SUPPORTS_CHFLAGS}" -eq 0 ]; then
    "${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
    smoke_log "SKIP: chflags round-trip unsupported on this FS (producer gate saw ${SHIM_COUNT} notifications)"
    exit 0
fi

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

FINAL_FLAGS="$(stat -f '%Of' "${TARGET}")"
smoke_log "final-flags=${FINAL_FLAGS}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

[ "${UNDO_RC}" -eq 0 ] || smoke_fail "shit undo exited ${UNDO_RC}"
grep -qE 'applied=[1-9][0-9]*' "${SHIT_SMOKE_TMP}/undo.log" \
    || smoke_fail "undo reported no applied operations"
[ "${FINAL_FLAGS}" = "${PRE_FLAGS}" ] \
    || smoke_fail "flags mismatch after undo: got ${FINAL_FLAGS}, want ${PRE_FLAGS}"

smoke_log "PASS: chflags-undo-fbsd (flags ${PRE_FLAGS} -> ${POST_FLAGS} -> ${FINAL_FLAGS}; ${SHIM_COUNT} notifications)"
