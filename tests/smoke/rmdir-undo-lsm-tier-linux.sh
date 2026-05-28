#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: rmdir-undo-lsm-tier-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
#
# AU20.2 — LSM-tier-explicit rmdir-undo smoke.
#
# No standalone rmdir-undo smoke exists; git-clean-fd-undo-linux.sh
# touches rmdir transitively. AU20 adds a dedicated one that:
# - creates an empty dir BEFORE pre-exec,
# - rmdirs it inside the watched session,
# - asserts shit undo restores the dir,
# - asserts the LSM inode_rmdir handler fired (routed through
#   handle_lsm_unlink with is_directory=true per G03).
#
# Grep target: tracing::info!("lsm-unlink CapturedPreImage sent")
# with structured field is_directory=true on the same line.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: rmdir-undo-lsm-tier-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

if [ ! -r /sys/kernel/security/lsm ]; then
    smoke_log "SKIP: /sys/kernel/security/lsm unreadable"
    exit 0
fi
ACTIVE_LSMS="$(cat /sys/kernel/security/lsm 2>/dev/null || echo)"
if ! printf '%s' "${ACTIVE_LSMS}" | grep -q "\bbpf\b"; then
    smoke_log "FAIL: kernel boot cmdline lacks bpf LSM (active=${ACTIVE_LSMS})"
    exit 1
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; run: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done

export SHIT_FORCE_TIER=ebpf-lsm
smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

# Create the rmdir target BEFORE pre-exec so it's part of the
# pre_open_tree's snapshot — without that, the inode_rmdir hook
# fires but the daemon has no pre-image to restore from.
TARGET="${SCRATCH}/lsm_rmdir_victim"
mkdir "${TARGET}"
chmod 0755 "${TARGET}"
PRE_MODE="$(python3 -c "import os; print(oct(os.stat('${TARGET}').st_mode & 0o777))")"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Pre-exec ack is async; let the helper finish pre_open_tree so the
# target dir's metadata is in WatchState before we rmdir it.
sleep 0.5

rmdir "${TARGET}"
[ ! -d "${TARGET}" ] || smoke_fail "rmdir didn't remove ${TARGET}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# G03 rmdir route emits FilePreImage with is_delete=true; daemon
# denormalizes as FilePreImage discriminant.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

# AU20 load-bearing assertion: the LSM inode_rmdir handler (which
# routes through handle_lsm_unlink with is_directory=true) MUST
# have logged its emit line. A regression that breaks the rmdir
# BPF prog would fall back to either no capture at all or to the
# inode_unlink hook for regular files only — the dir wouldn't
# round-trip but the smoke would catch the failure shape, not the
# fact that LSM did the work.
if ! grep -E "lsm-unlink CapturedPreImage sent.*is_directory=true" "${SHIT_SMOKE_TMP}/shitd.log" > /dev/null; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "LSM inode_rmdir handler did not emit; expected 'lsm-unlink CapturedPreImage sent' line with is_directory=true in shitd.log"
fi
smoke_log "LSM inode_rmdir handler confirmed fired"

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -d "${TARGET}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "dir not restored by shit undo: ${TARGET}"
fi
RESTORED_MODE="$(python3 -c "import os; print(oct(os.stat('${TARGET}').st_mode & 0o777))")"
if [ "${RESTORED_MODE}" != "${PRE_MODE}" ]; then
    smoke_fail "restored dir mode wrong: pre=${PRE_MODE} restored=${RESTORED_MODE}"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: rmdir-undo-lsm-tier-linux (LSM inode_rmdir handler fired + dir restored to mode ${RESTORED_MODE})"
