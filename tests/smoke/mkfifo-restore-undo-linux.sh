#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mkfifo-restore-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 120
#
# AU22.4 — load-bearing smoke for the mknod-via-helper restore
# path (DR-15.1).
#
# Workload:
# - Pre-create a named pipe BEFORE pre-exec so pre_open_tree
#   captures the inode as a Fifo (mode bits S_IFIFO|perm).
# - `rm` the fifo inside the watched session. The inode_unlink
#   LSM hook fires; the helper journals a CapturedPreImage marker
#   carrying kind=Fifo + mode.
# - `shit undo --yes` outside the session. Planner emits
#   InverseOp::RecreatePath { kind: Fifo, mode: ... }. The
#   FileExecutor's AU22 branch dispatches via
#   PrivilegedOpRouter::mknod → HelperLinkPrivilegedOpRouter →
#   HelperLink::request_priv_op_blocking → helper's apply_mknod
#   → libc::mknod(S_IFIFO | perm, 0).
#
# Assertions:
# - fifo restored (path is a fifo again, mode matches).
# - daemon log contains `apply_mknod` info line proving the wire
#   was hot end-to-end (catches a regression where the dispatch
#   silently NoOps).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: mkfifo-restore-undo-linux is Linux-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

if [ ! -r /sys/kernel/security/lsm ]; then
    smoke_log "SKIP: /sys/kernel/security/lsm unreadable"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin cap_mknod; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; setcap cap_mknod,cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done

export SHIT_FORCE_TIER=ebpf-lsm
smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

FIFO="${SCRATCH}/au22_pre_pipe"
mkfifo "${FIFO}"
chmod 0644 "${FIFO}"
[ -p "${FIFO}" ] || smoke_fail "mkfifo failed to seed ${FIFO}"
PRE_MODE="$(python3 -c "import os; print(oct(os.stat('${FIFO}').st_mode & 0o777))")"

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

# Wait for pre_open_tree to stash the fifo's metadata before
# the rm; LSM inode_unlink needs the held fd to win the race.
sleep 0.5

rm "${FIFO}"
[ ! -e "${FIFO}" ] || smoke_fail "rm did not remove ${FIFO}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Marker-only CapturedPreImage path (dirs and Fifos both go
# through journal_unlink_idempotent → TreeOpUnlink discriminant).
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -p "${FIFO}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    if [ -e "${FIFO}" ]; then
        smoke_fail "${FIFO} restored but wrong kind ($(stat -c %F "${FIFO}"))"
    fi
    smoke_fail "fifo not restored: ${FIFO}"
fi
RESTORED_MODE="$(python3 -c "import os; print(oct(os.stat('${FIFO}').st_mode & 0o777))")"
if [ "${RESTORED_MODE}" != "${PRE_MODE}" ]; then
    smoke_fail "restored fifo mode wrong: pre=${PRE_MODE} restored=${RESTORED_MODE}"
fi

# AU22 load-bearing assertion: the helper's apply_mknod handler
# MUST have logged its emit line. Without this, a regression
# where EitherRouter::mknod silently returns Applied without
# actually dispatching would pass (the fifo would not exist
# post-undo but my -p check above catches that — the log grep
# catches a different regression: a stub that lies about success).
if ! grep -F "apply_mknod" "${SHIT_SMOKE_TMP}/shitd.log" > /dev/null; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "helper apply_mknod did not run; 'apply_mknod' missing from shitd.log"
fi
smoke_log "helper apply_mknod confirmed fired (DR-15.1 wire hot end-to-end)"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: mkfifo-restore-undo-linux (fifo restored to mode ${RESTORED_MODE} via helper-IPC mknod)"
