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
# Phase 3, both tiers. A user-owned node is `rm`'d with the preload
# shim loaded, so the shim and the LSM tier both report the removal.
# Undo must restore it once (one apply_mknod Applied for this phase).
#
# Phase 4, born in the command. A node made (sudo mknod) and removed
# inside one command is scratch: undo must create nothing.
#
# Phase 5, nodev source. A node on a nodev filesystem (/dev/shm here;
# FUSE always is) gets no token: undo refuses with "source filesystem
# does not allow device nodes".
#
# Phase 6, helper restart. A user-owned node is `rm`'d, then shitd and
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

# rm_in_command <seq> <path> [cwd]: one journaled command that removes
# <path>, watching [cwd] (default the scratch dir).
rm_in_command() {
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "$1" --pid "${PID}" \
        --cwd "${3:-${SCRATCH}}" --shell bash --sock "${SHIT_HOOK_SOCK}"
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
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta' AND path = '${NODE}'" 1 10

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
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta' AND path = '${ROOT_NODE}'" 1 10
undo_expect_refusal "${SHIT_SMOKE_TMP}/undo-root.log" "not the invoking user" "${ROOT_NODE}"
smoke_log "phase 2: foreign owner refused, no node created"

# ---- phase 3: shim and LSM both report one rm ----
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -f "${SHIM_LIB}" ] || smoke_fail "shim missing at ${SHIM_LIB}"
DUAL_NODE="${SCRATCH}/l4_null_dual"
seed "${DUAL_NODE}" "${ME}" 0640
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 3 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5
LD_PRELOAD="${SHIM_LIB}" rm -f "${DUAL_NODE}"
[ ! -e "${DUAL_NODE}" ] || smoke_fail "rm did not remove ${DUAL_NODE}"
sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 3 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta' AND path = '${DUAL_NODE}'" 1 10
# The shim must really have reported this rm, or the phase proves nothing.
# The daemon's JSON log is written asynchronously; give it a moment.
shim_seen=0
for _ in $(seq 1 50); do
    if [ "$(cat "${XDG_STATE_HOME}"/shit/log/daemon.jsonl* 2>/dev/null | grep -a 'shim pre-mutation' | grep -c 'l4_null_dual' || true)" -gt 0 ]; then
        shim_seen=1
        break
    fi
    sleep 0.1
done
[ "${shim_seen}" = 1 ] || smoke_fail "phase 3: no shim notification for ${DUAL_NODE}; LD_PRELOAD shim did not report"
SHIM_UNLINKS="$(smoke_journal_count "discriminant = 'TreeOpUnlink' AND path = '${DUAL_NODE}'")"
smoke_log "phase 3: ${SHIM_UNLINKS} Unlink row(s) journaled for the dual-tier rm"
[ "${SHIM_UNLINKS}" -ge 1 ] || smoke_fail "phase 3: no Unlink journaled for ${DUAL_NODE}"
APPLIED_BEFORE="$(sed 's/\x1b\[[0-9;]*m//g' "${SHIT_SMOKE_TMP}/shitd.log" | grep 'apply_mknod' | grep -Ec 'outcome[=:]+ *Applied' || true)"
"${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo-dual.log" 2>&1 || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-dual.log" >&2
    smoke_fail "dual-tier undo exited non-zero"
}
[ "$(stat -c '%t:%T %a %u:%g' "${DUAL_NODE}" 2>/dev/null)" = "1:3 640 ${ME}" ] || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-dual.log" >&2
    smoke_fail "dual-tier node not restored as captured"
}
APPLIED_AFTER="$(sed 's/\x1b\[[0-9;]*m//g' "${SHIT_SMOKE_TMP}/shitd.log" | grep 'apply_mknod' | grep -Ec 'outcome[=:]+ *Applied' || true)"
[ $((APPLIED_AFTER - APPLIED_BEFORE)) -eq 1 ] || smoke_fail "dual-tier undo ran apply_mknod $((APPLIED_AFTER - APPLIED_BEFORE)) times, want 1"
# One op applied, none failed or conflicted: the twin report planned nothing.
grep -q 'applied=1 skipped=0 refused=0 failed=0 conflicts=0' "${SHIT_SMOKE_TMP}/undo-dual.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-dual.log" >&2
    smoke_fail "dual-tier undo report is not exactly one applied op"
}
smoke_log "phase 3: dual-tier rm restored once"
rm -f "${DUAL_NODE}"

# ---- phase 4: a node made and removed in one command is scratch ----
BORN_NODE="${SCRATCH}/l4_null_born"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 4 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5
sudo -n mknod -m 0640 "${BORN_NODE}" c 1 3
sudo -n chown "${ME}" "${BORN_NODE}"
sleep 0.3
rm -f "${BORN_NODE}"
sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 4 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_wait_for_event "discriminant = 'TreeOpCreate' AND path = '${BORN_NODE}'" 1 10
"${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo-born.log" 2>&1 || true
if [ -e "${BORN_NODE}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-born.log" >&2
    smoke_fail "undo created ${BORN_NODE}, which did not exist before the command"
fi
smoke_log "phase 4: node made and removed in the command; undo created nothing"

# ---- phase 5: a node on a nodev filesystem gets no token ----
# /dev/shm is mounted nodev on the usual Linux setups (FUSE always is).
NODEV_DIR=""
if grep -Eq '^[^ ]+ /dev/shm [^ ]+ [^ ]*\bnodev\b' /proc/mounts; then
    NODEV_DIR="$(mktemp -d /dev/shm/shit-l4b.XXXXXX)"
fi
if [ -n "${NODEV_DIR}" ]; then
    NODEV_NODE="${NODEV_DIR}/l4_null_nodev"
    seed "${NODEV_NODE}" "${ME}" 0640
    rm_in_command 5 "${NODEV_NODE}" "${NODEV_DIR}"
    smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta' AND path = '${NODEV_NODE}'" 1 10
    undo_expect_refusal "${SHIT_SMOKE_TMP}/undo-nodev.log" "source filesystem does not allow device nodes" "${NODEV_NODE}"
    smoke_log "phase 5: nodev source refused"
    rm -rf "${NODEV_DIR}"
else
    smoke_log "phase 5: SKIP (no nodev /dev/shm)"
fi

# ---- phase 6: a restarted helper refuses old capture evidence ----
OLD_NODE="${SCRATCH}/l4_null_before_restart"
seed "${OLD_NODE}" "${ME}" 0600
rm_in_command 6 "${OLD_NODE}"
smoke_wait_for_event "discriminant = 'TreeOpDeviceNodeMeta' AND path = '${OLD_NODE}'" 1 10
cp "${SHIT_SMOKE_TMP}/shitd.log" "${SHIT_SMOKE_TMP}/shitd-before-restart.log"
smoke_stop_shitd || true
smoke_start_shitd
undo_expect_refusal "${SHIT_SMOKE_TMP}/undo-restart.log" "capture evidence expired: helper restarted" "${OLD_NODE}"
smoke_log "phase 6: token from the previous helper refused"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}" || true

sudo -n rm -f "${NODE}" "${ROOT_NODE}" "${OLD_NODE}" "${DUAL_NODE}" "${BORN_NODE}" || true

smoke_log "PASS: mknod-restore-undo-linux (restore via capture token, once under both tiers; foreign owner, nodev source and restarted helper refused)"
