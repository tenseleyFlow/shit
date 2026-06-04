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
# B09 — assert that LD_PRELOAD shim's `chflags(2)` interposer
# reaches the daemon's shim_listener and journals a pre-image
# with the OLD st_flags captured via `read_st_flags`.
#
# This is the producer-side parity check. The macOS smoke
# (chflags-undo-macos.sh, PR #171 M03.x.SETATTR-FAMILY) exercises
# the full end-to-end undo path via the daemon overlay + the
# planner's `restore_flags_only` executor; both already in trunk
# and platform-agnostic. The BSD producer just needed an
# interposer to feed it.
#
# Why path-only (no fchflags): FreeBSD has no portable `fd -> path`
# (no F_GETPATH). Fd-based chflags mutations are covered by
# kqueue NOTE_ATTRIB on the underlying vnode + helper-side
# baseline-promotion — the shim's job is the path-based variant.

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

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
cd "${WATCHED}"

TARGET="${WATCHED}/target.txt"
printf 'shim-chflags-test\n' > "${TARGET}"
# Sanity: start with cleared flags (st_flags=0). Some FS-default
# inherits could land non-zero flags from the parent dir.
chflags 0 "${TARGET}" 2>/dev/null || true
PRE_FLAGS="$(stat -f '%Of' "${TARGET}")"
smoke_log "pre-flags=${PRE_FLAGS} (expect 0)"

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

# Workload — set UF_IMMUTABLE (uchg / 0x2) under LD_PRELOAD.
# chflags(8) calls chflags(2) directly (path-based) which the
# shim interposes. We use UF_IMMUTABLE because root + securelevel
# constraints don't apply to UF_* flags — owner can set+clear at
# any securelevel.
smoke_log "workload: LD_PRELOAD=${SHIM_LIB} chflags uchg ${TARGET}"
LD_PRELOAD="${SHIM_LIB}" /bin/chflags uchg "${TARGET}"
sleep 0.5

POST_FLAGS="$(stat -f '%Of' "${TARGET}")"
smoke_log "post-flags=${POST_FLAGS} (expect 2 = UF_IMMUTABLE)"
if [ "${POST_FLAGS}" != "2" ]; then
    smoke_fail "chflags didn't apply UF_IMMUTABLE; flags=${POST_FLAGS}"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

# Assertion 1: daemon journaled at least one "chflags" shim
# notification. The wire syscall name is "chflags" (path-based
# variant); fchflags is not interposed on FreeBSD.
JSON_LOG="$(ls "${XDG_STATE_HOME}/shit/log/daemon.jsonl"* 2>/dev/null | head -1)"
if [ -z "${JSON_LOG}" ] || [ ! -f "${JSON_LOG}" ]; then
    smoke_fail "daemon JSON log not found under \${XDG_STATE_HOME}/shit/log/"
fi

SHIM_COUNT="$(grep -cE '"syscall":"chflags"' "${JSON_LOG}" 2>/dev/null || echo 0)"
smoke_log "shim notifications: chflags=${SHIM_COUNT}"

if [ "${SHIM_COUNT}" -lt 1 ]; then
    smoke_log "regression — no shim 'chflags' notification in daemon log"
    grep -i 'shim\|chflags' "${JSON_LOG}" | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected at least 1 'chflags' notification; got ${SHIM_COUNT}"
fi

# Assertion 2: undo restores st_flags to the pre-mutation value
# (0). This validates the full producer→daemon→planner→executor
# pipeline. The executor's restore_flags_only (file.rs:483) calls
# libc::chflags(path, prior).
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    # Don't fail hard here — the shim-notification gate above is
    # the load-bearing producer-side check. Surface the failure
    # but continue to the flags assertion below to report both.
    smoke_log "warn: shit undo --yes exited non-zero"
}

RESTORED_FLAGS="$(stat -f '%Of' "${TARGET}")"
smoke_log "restored flags=${RESTORED_FLAGS} (expect ${PRE_FLAGS})"
if [ "${RESTORED_FLAGS}" != "${PRE_FLAGS}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "chflags not restored: pre=${PRE_FLAGS} post=${POST_FLAGS} restored=${RESTORED_FLAGS}"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: chflags-undo-fbsd (${SHIM_COUNT} chflags notification; flags ${PRE_FLAGS}->${POST_FLAGS}->${RESTORED_FLAGS})"
