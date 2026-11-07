#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mknod-restore-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# L4 / AU14 / L4b — load-bearing smoke for block/char device node
# restore through the helper's mknod (DR-15.2), and for the cases the
# helper must refuse.
#
# Seed nodes are char devices with /dev/null's number (1:3), made with
# passwordless sudo under the smoke's temp dir. Never a real disk.
#
# Phase 1, restore. A node owned by the invoking user, mode 0640, is
# `rm`'d inside a session. The LSM inode_unlink hook fires; the helper
# fstats the held O_PATH fd and ships mode, rdev, owner and a capture
# token; the daemon journals Unlink + DeviceNodeMeta. `shit undo --yes`
# sends the token back with ApplyMknod and the helper recreates the
# node. Asserts: char device 1:3 again with the captured mode and
# owner, and the helper's apply_mknod line with dev=259 and
# outcome=Applied in the daemon log.
#
# Phase 2, foreign owner. A root-owned node is `rm`'d. The helper has
# no cap_chown, so undo must refuse before mknod with the "not the
# invoking user" reason, and no node may appear.
#
# Phase 3, helper restart. A user-owned node is `rm`'d, then shitd and
# its helper are restarted. The new helper has a new key, so undo must
# refuse with "capture evidence expired: helper restarted" and create
# nothing.
#
# The helper needs cap_mknod (create) plus the LSM-tier caps. It must
# not need cap_chown; the workflow's setcap line does not grant it.

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
for required in cap_bpf cap_perfmon cap_sys_admin cap_mknod; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; setcap cap_mknod,cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done
if printf '%s' "${HELPER_CAPS}" | grep -q cap_chown; then
    smoke_log "NOTE: helper has cap_chown; phase 2 still expects a refusal (the helper does not use it here)"
fi

if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
    smoke_log "SKIP: passwordless sudo needed to mknod the seed nodes"
    exit 0
fi

ME="$(id -u):$(id -g)"
export SHIT_FORCE_TIER=ebpf-lsm
smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

# seed <path> <owner uid:gid> <mode>
seed() {
    sudo -n mknod -m "$3" "$1" c 1 3 || {
        smoke_log "SKIP: mknod of the seed node failed (nodev mount or no CAP_MKNOD)"
        exit 0
    }
    sudo -n chown "$2" "$1"
    [ -c "$1" ] || smoke_fail "seed $1 is not a char device"
}

# rm_in_command <seq> <path>: one journaled command that removes <path>.
rm_in_command() {
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "$1" --pid "${PID}" \
        --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
    # pre_open_tree must have stashed the node's O_PATH fd before the rm.
    sleep 0.5
    rm -f "$2" 2>/dev/null || sudo -n rm -f "$2"
    [ ! -e "$2" ] || smoke_fail "rm did not remove $2"
    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq "$1" --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
}

# undo_expect_refusal <log> <reason> <path>
undo_expect_refusal() {
    "${SHIT_BIN}" undo --yes >"$1" 2>&1 || true
    if [ -e "$3" ]; then
        sed 's/^/    /' "$1" >&2
        smoke_fail "$3 was recreated; expected a refusal"
    fi
    if ! grep -q "$2" "$1" "${SHIT_SMOKE_TMP}/shitd.log"; then
        sed 's/^/    /' "$1" >&2
        tail -60 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
        smoke_fail "undo did not refuse with '$2'"
    fi
    smoke_log "refused as expected: $2"
}

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# ---- phase 1: user-owned node is restored ----
NODE="${SCRATCH}/l4_null_mine"
seed "${NODE}" "${ME}" 0640
PRE="$(stat -c '%t:%T %a %u:%g' "${NODE}")"
smoke_log "seeded ${NODE}: major:minor(hex) mode owner = ${PRE}"
[ "${PRE}" = "1:3 640 ${ME}" ] || smoke_fail "seed node is not as made: ${PRE}"

rm_in_command 1 "${NODE}"
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta'" 1 10

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
# The token key must sit in a non-dumpable process.
if ! sed 's/\x1b\[[0-9;]*m//g' "${SHIT_SMOKE_TMP}/shitd.log" | grep 'capture-token key ready' | grep -Eq 'token_key[=":]+ *true.*dumpable[=":]+ *0'; then
    sed 's/\x1b\[[0-9;]*m//g' "${SHIT_SMOKE_TMP}/shitd.log" | grep 'capture-token' >&2 || true
    smoke_fail "helper did not report token_key=true dumpable=0"
fi
smoke_log "phase 1: node restored with captured rdev, mode and owner (helper dumpable=0)"
rm -f "${NODE}"

# ---- phase 2: root-owned node is refused before mknod ----
ROOT_NODE="${SCRATCH}/l4_null_root"
seed "${ROOT_NODE}" 0:0 0666
rm_in_command 2 "${ROOT_NODE}"
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta'" 2 10
undo_expect_refusal "${SHIT_SMOKE_TMP}/undo-root.log" "not the invoking user" "${ROOT_NODE}"
smoke_log "phase 2: foreign owner refused, no node created"

# ---- phase 3: a restarted helper refuses old capture evidence ----
OLD_NODE="${SCRATCH}/l4_null_before_restart"
seed "${OLD_NODE}" "${ME}" 0600
rm_in_command 3 "${OLD_NODE}"
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta'" 3 10
cp "${SHIT_SMOKE_TMP}/shitd.log" "${SHIT_SMOKE_TMP}/shitd-before-restart.log"
smoke_stop_shitd || true
smoke_start_shitd
undo_expect_refusal "${SHIT_SMOKE_TMP}/undo-restart.log" "capture evidence expired: helper restarted" "${OLD_NODE}"
smoke_log "phase 3: token from the previous helper refused"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}" || true

sudo -n rm -f "${NODE}" "${ROOT_NODE}" "${OLD_NODE}" || true

smoke_log "PASS: mknod-restore-undo-linux (restore via capture token; foreign owner and restarted helper refused)"
