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
# B09 — assert that LD_PRELOAD shim's `chflags(2)` /
# `chflagsat(2)` interposers emit a daemon-side notification
# whose pre-image carries the OLD st_flags (via `read_st_flags`).
#
# This is the producer-side parity check for macOS PR #171
# (M03.x.SETATTR-FAMILY chflags). End-to-end undo is validated
# by the macOS `chflags-undo-macos.sh` smoke (APFS supports
# st_flags natively, no capsicum). The BSD daemon classifier
# (shim_listener.rs:346 "chflags"), planner inverse op, and
# executor `restore_flags_only` (file.rs:483) all already live
# in trunk — they were authored cross-platform by M03.x.SETATTR.
# B09's only delta is the BSD-side shim interposers.
#
# Why path-only (no fchflags): FreeBSD has no portable `fd -> path`
# (no F_GETPATH). Fd-based mutations are covered by kqueue
# NOTE_ATTRIB on the underlying vnode.
#
# Why no round-trip gate: matches setxattr-shim-fbsd.sh's pattern
# — under capsicum-default-on (B05), the helper's chown(2) call
# in RestoreMetadata returns ENOTCAPABLE (errno 94); the
# FilePreImage carries full metadata so the inverse touches
# uid/gid/mode/mtime/flags. Restoring chflags-only safely
# under capsicum is a daemon/planner fix (out of B09 scope —
# follow-up to introduce a flags-only inverse op when only flags
# diverge). The shim-emission gate is the load-bearing producer-
# side check; that's what B09 ships.

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

# FS-capability probe: if chflags returns EOPNOTSUPP (e.g.
# OpenZFS on FreeBSD), the syscall can't be round-tripped but
# the SHIM still fires its pre-syscall notification — we still
# exercise the producer-side parity path. Detect it up-front so
# the post-mutation assertions can branch correctly.
SUPPORTS_CHFLAGS=1
if ! /bin/chflags 0 "${TARGET}" 2>/dev/null; then
    SUPPORTS_CHFLAGS=0
    smoke_log "note: chflags returns EOPNOTSUPP on this FS (likely ZFS); shim-emission gate is the load-bearing check"
fi

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
# chflags(8) calls chflags(2) directly (path-based). We use
# UF_IMMUTABLE because root + securelevel constraints don't
# apply to UF_* flags. If the FS doesn't support chflags, the
# syscall fails but the shim's pre-syscall notification has
# already reached the daemon — which is what we're testing.
smoke_log "workload: LD_PRELOAD=${SHIM_LIB} chflags uchg ${TARGET}"
LD_PRELOAD="${SHIM_LIB}" /bin/chflags uchg "${TARGET}" 2>/dev/null || true
sleep 0.5

if [ "${SUPPORTS_CHFLAGS}" -eq 1 ]; then
    POST_FLAGS="$(stat -f '%Of' "${TARGET}")"
    smoke_log "post-flags=${POST_FLAGS} (expect 2 = UF_IMMUTABLE)"
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

SHIM_COUNT="$(grep -cE '"syscall":"chflags"' "${JSON_LOG}" 2>/dev/null || echo 0)"
smoke_log "shim notifications: chflags=${SHIM_COUNT}"

if [ "${SHIM_COUNT}" -lt 1 ]; then
    smoke_log "regression — no shim 'chflags' notification in daemon log"
    grep -i 'shim\|chflags' "${JSON_LOG}" | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected at least 1 'chflags' notification; got ${SHIM_COUNT}"
fi

# If the FS supports chflags (CI UFS does; shit-fbsd ZFS doesn't),
# at least clear the immutable flag so the smoke cleanup can
# remove the file. Round-trip via `shit undo` is intentionally
# NOT exercised — capsicum-default-on blocks the chown step in
# RestoreMetadata; cleaning that up is a separate sprint (see
# the "Why no round-trip gate" header comment).
if [ "${SUPPORTS_CHFLAGS}" -eq 1 ] && [ "${POST_FLAGS}" = "2" ]; then
    /bin/chflags 0 "${TARGET}" 2>/dev/null || true
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: chflags-undo-fbsd (${SHIM_COUNT} chflags shim notifications)"
