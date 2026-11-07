#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mknod-restore-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 120
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# L4 / AU14 — load-bearing smoke for block/char device node restore
# through the helper's mknod (DR-15.2).
#
# Workload:
# - As root (passwordless sudo, the apt smokes' pattern), create a
#   char node with /dev/null's number (1:3) under the smoke's temp
#   dir, mode 0666, owned by root. Never a real disk: 1:3 is the
#   null device, harmless to create or read.
# - Open a session, pre-exec, `rm` the node. The LSM inode_unlink
#   hook fires; the helper fstats the held O_PATH fd and ships
#   mode + st_rdev + owner; the daemon journals TreeOp::Unlink with
#   the captured device.
# - `shit undo --yes`. The planner emits RecreatePath { CharDevice,
#   device: Some(..) }; the executor asks the helper for mknod with
#   that rdev, then chowns to the captured owner.
#
# Assertions:
# - the path is a char device again with major:minor 1:3, mode and
#   owner as captured.
# - the daemon log carries the helper's apply_mknod line with the
#   expected dev (0x103 = 259), so a stub that lies about success
#   cannot pass.
#
# The helper needs cap_mknod (create) and cap_chown (owner back to
# root); the workflow's setcap line grants both.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: mknod-restore-undo-linux is Linux-only"
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
for required in cap_bpf cap_perfmon cap_sys_admin cap_mknod cap_chown; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; setcap cap_mknod,cap_chown,cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done

if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
    smoke_log "SKIP: passwordless sudo needed to mknod the seed node"
    exit 0
fi

export SHIT_FORCE_TIER=ebpf-lsm
smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

NODE="${SCRATCH}/l4_null_copy"
# 1:3 is /dev/null. Root-owned so the restore has an owner to put back.
sudo -n mknod -m 0666 "${NODE}" c 1 3 || {
    smoke_log "SKIP: mknod of the seed node failed (nodev mount or no CAP_MKNOD)"
    exit 0
}
[ -c "${NODE}" ] || smoke_fail "seed ${NODE} is not a char device"
PRE="$(stat -c '%t:%T %a %u:%g' "${NODE}")"
smoke_log "seeded ${NODE}: major:minor(hex) mode owner = ${PRE}"
[ "${PRE%% *}" = "1:3" ] || smoke_fail "seed node has wrong number: ${PRE}"

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

# pre_open_tree must have stashed the node's O_PATH fd before the rm.
sleep 0.5

rm "${NODE}"
[ ! -e "${NODE}" ] || smoke_fail "rm did not remove ${NODE}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -c "${NODE}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    if [ -e "${NODE}" ]; then
        smoke_fail "${NODE} restored but wrong kind ($(stat -c %F "${NODE}"))"
    fi
    smoke_fail "device node not restored: ${NODE}"
fi
POST="$(stat -c '%t:%T %a %u:%g' "${NODE}")"
if [ "${POST}" != "${PRE}" ]; then
    smoke_fail "restored node differs: pre='${PRE}' post='${POST}'"
fi

if ! sed 's/\x1b\[[0-9;]*m//g' "${SHIT_SMOKE_TMP}/shitd.log" | grep 'apply_mknod' | grep -Eq 'dev[=":]+ *259.*outcome[=:]+ *Applied'; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "helper apply_mknod with dev=259 did not run; missing from shitd.log"
fi
smoke_log "helper apply_mknod confirmed fired with the captured rdev"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# The seed node is root-owned; remove it with sudo before temp cleanup.
sudo -n rm -f "${NODE}" || true

smoke_log "PASS: mknod-restore-undo-linux (char node 1:3 restored with mode/owner via helper-IPC mknod)"
