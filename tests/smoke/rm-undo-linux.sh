#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: rm-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L04 end-to-end smoke — rm-undo on Linux. The load-bearing
# milestone for the eBPF-LSM tier.
#
# Why this couldn't be a Linux smoke until L04:
#   fanotify-perm only fires on file OPENS, not unlinks. `rm` calls
#   unlinkat(2) directly — no open — so fanotify-perm cannot observe
#   it. L02 had to pivot to edit-undo for the same reason. L04
#   closes the gap via the eBPF-LSM `inode_unlink` hook that fires
#   synchronously inside `vfs_unlink()` before the dentry is dropped.
#
# Exercises:
#   1. shitd boots; spawns shit-helper. Helper picks the eBPF-LSM
#      tier (SHIT_FORCE_TIER=ebpf-lsm forces it; otherwise
#      `pick_linux_tier` chooses it when prerequisites are met).
#   2. EbpfLoader::load_lsm_unlink attaches the BPF program to
#      `lsm/inode_unlink`. The userspace LsmReader spawns and
#      polls the ringbuf.
#   3. PreExec triggers daemon -> helper WatchTree dispatch. The
#      LSM tier's WatchTree handler updates the tree-map (no
#      fanotify mark — LSM fires globally).
#   4. `rm` of a known-content file fires `lsm/inode_unlink` →
#      ringbuf event → LsmReader → LinuxCaptureSink → handle_lsm_unlink.
#      The handler races to open `/proc/<pid>/cwd/<basename>` before
#      vfs_unlink completes its d_drop, dups the fd, reads pre-image
#      bytes, blake3-hashes, writes a staging file, and sends
#      HelperResponse::CapturedPreImage (is_delete=true) with the
#      staging fd via SCM_RIGHTS.
#   5. The daemon's dispatch_loop journals a FilePreImage event plus
#      a paired TreeOp::Unlink.
#   6. `shit undo --yes` replays the inverse: rewrites the blob back
#      to the original path.
#   7. The restored file is byte-identical to the original
#      (sha256 match).
#
# Linux-only. Requires kernel ≥ 5.7 + CONFIG_BPF_LSM=y +
# `lsm=...,bpf,...` in /proc/cmdline + CAP_BPF + CAP_PERFMON.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: rm-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight: kernel BPF-LSM probe. Without `lsm=bpf` in
# /proc/cmdline the LSM hook load will refuse-attach. Hard-fail
# here with the exact fix so operators don't chase a confusing
# "no events drained" symptom 30 seconds later.
if [ ! -r /sys/kernel/security/lsm ]; then
    smoke_log "SKIP: /sys/kernel/security/lsm unreadable; cannot verify lsm=bpf"
    exit 0
fi
ACTIVE_LSMS="$(cat /sys/kernel/security/lsm 2>/dev/null || echo)"
if ! printf '%s' "${ACTIVE_LSMS}" | grep -q "\bbpf\b"; then
    smoke_log "FAIL: kernel boot cmdline lacks bpf LSM (active=${ACTIVE_LSMS})"
    smoke_log ""
    smoke_log "  On NixOS, add to /etc/nixos/configuration.nix:"
    smoke_log "    boot.kernelParams = [ \"lsm=lockdown,yama,bpf\" ];"
    smoke_log "  Then nixos-rebuild boot && reboot."
    smoke_log ""
    smoke_log "  On Debian/Ubuntu, edit /etc/default/grub:"
    smoke_log "    GRUB_CMDLINE_LINUX=\"lsm=lockdown,yama,apparmor,bpf\""
    smoke_log "  Then update-grub && reboot."
    exit 1
fi
smoke_log "kernel lsm=${ACTIVE_LSMS}"

# Pre-flight: helper caps. eBPF-LSM needs CAP_BPF + CAP_PERFMON
# (CAP_SYS_ADMIN on older kernels for the LSM attach path). Check
# all three — capability sets are wiped on every `cargo build`.
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required} (getcap output: '${HELPER_CAPS}')"
        smoke_log ""
        smoke_log "  Run this on the box first, then re-run the smoke:"
        smoke_log "    sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        smoke_log ""
        smoke_log "  Caps are wiped on every \`cargo build\`."
        exit 1
    fi
done
smoke_log "helper has caps: ${HELPER_CAPS}"

# Force the eBPF-LSM tier. pick_linux_tier should choose it by
# default on a capable kernel, but the smoke makes this explicit so
# a regression in pick_linux_tier surfaces here as a hard failure
# rather than a silent fallback to fanotify (which can't see rm).
export SHIT_FORCE_TIER=ebpf-lsm
smoke_log "SHIT_FORCE_TIER=ebpf-lsm (LSM tier required for rm capture)"

smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

KNOWN_CONTENT="rm-undo-linux canary $(date -u +%Y-%m-%dT%H:%M:%SZ)"
FOO="${SCRATCH}/foo.txt"
printf '%s\n' "${KNOWN_CONTENT}" >"${FOO}"
EXPECTED_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
smoke_log "wrote ${FOO} sha256=${EXPECTED_SHA}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"

# Move our shell into the watched dir. The LSM `inode_unlink` hook
# captures (parent_inode, basename); userspace races to open
# /proc/<pid>/cwd/<basename> for the pre-image read. With our cwd
# set to SCRATCH, the basename `foo.txt` resolves to the right file.
cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" \
    --pid "${PID}" \
    --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=${SEQ} pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --pid "${PID}" \
    --cwd "${SCRATCH}" \
    --shell bash \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "rm ${FOO}"
rm "${FOO}"

# Let the lsm/inode_unlink event propagate: BPF ringbuf submit ->
# LsmReader poll -> LinuxCaptureSink -> handle_lsm_unlink ->
# race-to-open /proc/<pid>/cwd/foo.txt -> read pre-image ->
# staging write -> SCM_RIGHTS send -> daemon recvmsg -> blob put.
# The race window is the LSM hook return → vfs_unlink completion
# (microseconds on an idle system); userspace consumer drains the
# ringbuf in ~50-500µs depending on scheduler.
sleep 0.5

smoke_log "PostExec seq=${SEQ} exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# Sanity: the file IS gone (rm completed).
if [ -e "${FOO}" ]; then
    smoke_fail "foo.txt should have been rm'd but still exists"
fi

# Wait up to 10s for the FilePreImage event to land. Likely
# failure modes:
#   1. Helper degraded (LSM load failed) — check shitd.log for
#      "ebpf-lsm load failed".
#   2. Race lost (handle_lsm_unlink could not open the file before
#      vfs_unlink completed) — the helper logs
#      "lsm unlink race lost — marker-only CapturedPreImage" and
#      the daemon does NOT journal a FilePreImage (no bytes to
#      blake3). Under heavy load this race can be lost; small
#      files on idle systems win it consistently.
#   3. Pid not tracked (WatchTree did not register us) — check the
#      helper log for "untracked pid; dropping lsm unlink event".
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
# Paired TreeOp::Unlink — the daemon emits this when it sees the
# is_delete=true marker on the CapturedPreImage. `shit undo`
# consults it to know "this command unlinked foo.txt" rather than
# just "this command wrote some blob".
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -f "${FOO}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "foo.txt was not restored by shit undo"
fi
GOT_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
if [ "${GOT_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${GOT_SHA}"
    smoke_fail "restored content sha256 mismatch"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: rm-undo-linux (sha256=${EXPECTED_SHA})"
