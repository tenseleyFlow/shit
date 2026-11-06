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
# Two workloads run under the shim in one command:
#   1. the real /bin/chflags, which traverses with dirfd-relative
#      chflagsat(2) (fts dirfd + relative name, atflag 0). This is the
#      shape users hit; the smoke fails if the shim does not notify.
#   2. a C program calling chflags(2) with an absolute path.
#
# UFS and OpenZFS both store UF_NODUMP and must round-trip. A FS that
# does not (the probe below reads the bit back) keeps only the
# producer notification gate and the smoke ends in SKIP.

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
TARGET2="${WATCHED}/target2.txt"
printf 'shim-chflags-test\n' > "${TARGET}"
printf 'shim-chflags-test-2\n' > "${TARGET2}"

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

# FS-capability probe. It sets the same flag the workloads set
# (UF_NODUMP, which unlike UF_IMMUTABLE cannot make cleanup fail) and
# reads it back, then restores the file's original flags. A probe that
# only ran `chflags 0` succeeded on OpenZFS, where `uchg` is
# EOPNOTSUPP, so the round trip could be skipped or run against a flag
# the FS never stored. Restoring the original value keeps flags the FS
# sets on its own (UF_ARCHIVE on new ZFS files) in PRE_FLAGS.
UF_NODUMP_BIT=1
SUPPORTS_CHFLAGS=0
PROBE_ORIG="$(stat -f '%Of' "${TARGET}")"
if "${WATCHED}/set_chflags" "${TARGET}" 2>"${SHIT_SMOKE_TMP}/probe.err"; then
    PROBE_SET="$(stat -f '%Of' "${TARGET}")"
    /bin/chflags "${PROBE_ORIG}" "${TARGET}" 2>/dev/null \
        || smoke_fail "could not restore probe flags ${PROBE_ORIG}"
    if [ $(( 0${PROBE_SET} & UF_NODUMP_BIT )) -ne 0 ]; then
        SUPPORTS_CHFLAGS=1
    else
        smoke_log "note: chflags(UF_NODUMP) returned 0 but st_flags reads ${PROBE_SET}"
    fi
else
    smoke_log "note: chflags(UF_NODUMP) failed: $(cat "${SHIT_SMOKE_TMP}/probe.err")"
fi
if [ "${SUPPORTS_CHFLAGS}" -eq 0 ]; then
    smoke_log "note: this FS does not store UF_NODUMP; only the shim-emission gate runs and the smoke ends in SKIP"
fi
[ "$(stat -f '%Of' "${TARGET}")" = "${PROBE_ORIG}" ] \
    || smoke_fail "probe left flags at $(stat -f '%Of' "${TARGET}"), want ${PROBE_ORIG}"
smoke_log "flag probe: orig=${PROBE_ORIG} supported=${SUPPORTS_CHFLAGS} fs=$(df -T "${WATCHED}" 2>/dev/null | awk 'NR==2{print $2}')"
PRE_FLAGS="$(stat -f '%Of' "${TARGET}")"
PRE_FLAGS2="$(stat -f '%Of' "${TARGET2}")"

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

# Workload 1 — the real /bin/chflags under LD_PRELOAD. If the FS doesn't
# support flags the syscall fails after the shim notification, so the
# producer gate remains meaningful.
smoke_log "workload 1: LD_PRELOAD=${SHIM_LIB} /bin/chflags nodump ${TARGET}"
set +e
LD_PRELOAD="${SHIM_LIB}" /bin/chflags nodump "${TARGET}" 2>/dev/null
CHFLAGS_RC=$?
set -e
sleep 0.5
NOTIFY_AFTER_BIN="$(grep -cE '"syscall":"chflags"' "$(ls "${XDG_STATE_HOME}/shit/log/daemon.jsonl"* 2>/dev/null | head -1)" 2>/dev/null || true)"
NOTIFY_AFTER_BIN="${NOTIFY_AFTER_BIN:-0}"
smoke_log "shim chflags notifications after /bin/chflags: ${NOTIFY_AFTER_BIN}"
[ "${NOTIFY_AFTER_BIN}" -ge 1 ] \
    || smoke_fail "/bin/chflags produced no shim 'chflags' notification (dirfd-relative chflagsat not captured)"

# Workload 2 — chflags(2) with an absolute path from a C program.
smoke_log "workload 2: LD_PRELOAD=${SHIM_LIB} ${WATCHED}/set_chflags ${TARGET2}"
set +e
LD_PRELOAD="${SHIM_LIB}" "${WATCHED}/set_chflags" "${TARGET2}" 2>/dev/null
CHFLAGS_RC2=$?
set -e
sleep 0.5

if [ "${SUPPORTS_CHFLAGS}" -eq 1 ]; then
    POST_FLAGS="$(stat -f '%Of' "${TARGET}")"
    POST_FLAGS2="$(stat -f '%Of' "${TARGET2}")"
    smoke_log "pre-flags=${PRE_FLAGS}/${PRE_FLAGS2} post-flags=${POST_FLAGS}/${POST_FLAGS2}"
    [ "${CHFLAGS_RC}" -eq 0 ] || smoke_fail "/bin/chflags nodump exited ${CHFLAGS_RC} on a supported FS"
    [ "${CHFLAGS_RC2}" -eq 0 ] || smoke_fail "chflags(2) nodump exited ${CHFLAGS_RC2} on a supported FS"
    [ "${POST_FLAGS}" != "${PRE_FLAGS}" ] \
        || smoke_fail "/bin/chflags nodump did not change flags (${PRE_FLAGS})"
    [ "${POST_FLAGS2}" != "${PRE_FLAGS2}" ] \
        || smoke_fail "chflags(2) nodump did not change flags (${PRE_FLAGS2})"
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

if [ "${SHIM_COUNT}" -lt 2 ]; then
    smoke_log "regression — no shim 'chflags' notification in daemon log"
    grep -i 'shim\|chflags' "${JSON_LOG}" | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected at least 2 'chflags' notifications; got ${SHIM_COUNT}"
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
FINAL_FLAGS2="$(stat -f '%Of' "${TARGET2}")"
smoke_log "final-flags=${FINAL_FLAGS}/${FINAL_FLAGS2}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

[ "${UNDO_RC}" -eq 0 ] || smoke_fail "shit undo exited ${UNDO_RC}"
grep -qE 'applied=[1-9][0-9]*' "${SHIT_SMOKE_TMP}/undo.log" \
    || smoke_fail "undo reported no applied operations"
[ "${FINAL_FLAGS}" = "${PRE_FLAGS}" ] \
    || smoke_fail "flags mismatch after undo (/bin/chflags target): got ${FINAL_FLAGS}, want ${PRE_FLAGS}"
[ "${FINAL_FLAGS2}" = "${PRE_FLAGS2}" ] \
    || smoke_fail "flags mismatch after undo (chflags(2) target): got ${FINAL_FLAGS2}, want ${PRE_FLAGS2}"

smoke_log "PASS: chflags-undo-fbsd (flags ${PRE_FLAGS} -> ${POST_FLAGS} -> ${FINAL_FLAGS}; ${SHIM_COUNT} notifications)"
