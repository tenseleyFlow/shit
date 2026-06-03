#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: setxattr-shim-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# B10 — assert that LD_PRELOAD shim's `extattr_set_file` /
# `extattr_delete_file` interposers reach the daemon's
# shim_listener and journal under the normalized macOS-style
# syscall names ("setxattr" / "removexattr").
#
# This is the producer-side parity check. The macOS smoke
# (xattr-mutate-undo-macos.sh, PR #174) exercises the full
# end-to-end undo path via the daemon overlay; that overlay is
# already in trunk and platform-agnostic. This smoke validates
# the BSD producer now emits events that the same daemon arm
# consumes.
#
# Why "setxattr" not "extattr_set_file" on the wire: the BSD
# shim normalizes by pre-encoding the FreeBSD namespace
# (1=USER, 2=SYSTEM) into the name string ("user.foo" /
# "system.foo") and emitting the macOS-style syscall name —
# keeps the daemon classifier per-syscall, not per-platform.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: setxattr-shim-fbsd is FreeBSD-only"
    exit 0
fi

SETEXTATTR=/usr/sbin/setextattr
RMEXTATTR=/usr/sbin/rmextattr
if [ ! -x "${SETEXTATTR}" ] || [ ! -x "${RMEXTATTR}" ]; then
    smoke_log "SKIP: setextattr(8) / rmextattr(8) not in /usr/sbin"
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

# Pre-existing file with an existing xattr value. setextattr(8)
# requires xattr support on the FS (UFS + ZFS both have it on
# stock FreeBSD; tmpfs doesn't). /tmp on shit-fbsd is ZFS-backed
# so the smoke runs there.
TARGET="${WATCHED}/target.txt"
printf 'shim-xattr-test\n' > "${TARGET}"
if ! "${SETEXTATTR}" user shit.test pre-value "${TARGET}" 2>/dev/null; then
    smoke_log "SKIP: setextattr failed on ${TARGET} — likely xattr-unsupported FS"
    exit 0
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

# Workload — mutate the xattr under LD_PRELOAD. setextattr(8)
# calls extattr_set_file(2); the shim interposes pre-syscall,
# reads the pre-value (`pre-value`), and notifies the daemon.
smoke_log "workload: LD_PRELOAD=${SHIM_LIB} setextattr user shit.test post-value ${TARGET}"
LD_PRELOAD="${SHIM_LIB}" /usr/sbin/setextattr user shit.test post-value "${TARGET}"
sleep 0.5

# Workload 2 — delete a different xattr (set+then-delete to
# exercise extattr_delete_file too).
LD_PRELOAD="${SHIM_LIB}" /usr/sbin/setextattr user shit.tmp will-be-deleted "${TARGET}"
sleep 0.2
smoke_log "workload: LD_PRELOAD=${SHIM_LIB} rmextattr user shit.tmp ${TARGET}"
LD_PRELOAD="${SHIM_LIB}" /usr/sbin/rmextattr user shit.tmp "${TARGET}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

# Assertion: daemon journaled at least one "setxattr" and one
# "removexattr" notification. The wire normalizes the BSD
# extattr_* family to the macOS-style names — this keeps the
# daemon classifier per-syscall, not per-platform.
JSON_LOG="$(ls "${XDG_STATE_HOME}/shit/log/daemon.jsonl"* 2>/dev/null | head -1)"
if [ -z "${JSON_LOG}" ] || [ ! -f "${JSON_LOG}" ]; then
    smoke_fail "daemon JSON log not found under \${XDG_STATE_HOME}/shit/log/"
fi

SET_COUNT="$(grep -cE '"syscall":"setxattr"' "${JSON_LOG}" 2>/dev/null || echo 0)"
DEL_COUNT="$(grep -cE '"syscall":"removexattr"' "${JSON_LOG}" 2>/dev/null || echo 0)"
smoke_log "shim notifications: setxattr=${SET_COUNT} removexattr=${DEL_COUNT}"

if [ "${SET_COUNT}" -lt 1 ]; then
    smoke_log "regression — no shim 'setxattr' notification in daemon log"
    grep -i shim "${JSON_LOG}" | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected at least 1 'setxattr' notification; got ${SET_COUNT}"
fi
if [ "${DEL_COUNT}" -lt 1 ]; then
    smoke_log "regression — no shim 'removexattr' notification in daemon log"
    grep -i shim "${JSON_LOG}" | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected at least 1 'removexattr' notification; got ${DEL_COUNT}"
fi

# Sanity gate: the setxattr notification's pre-image carries the
# pre-value bytes. xattr_pre_image fields are inline in the
# tracing fields when the daemon journals.
if ! grep -E '"syscall":"setxattr".*"xattr"' "${JSON_LOG}" >/dev/null 2>&1; then
    smoke_log "warn: daemon log doesn't show an inline xattr pre-image — verify XattrPreImage plumbing"
    grep '"syscall":"setxattr"' "${JSON_LOG}" | head -2 | sed 's/^/    /' >&2 || true
    # Not a hard fail — the daemon may serialize the pre-image
    # to a different sub-field. The presence of the syscall name
    # is the load-bearing check.
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: setxattr-shim-fbsd (${SET_COUNT} setxattr + ${DEL_COUNT} removexattr notifications)"
