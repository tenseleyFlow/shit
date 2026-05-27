#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: edit-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L02 end-to-end smoke — edit-undo on Linux. Phase C milestone.
#
# Pivoted from rm-undo (which the BSD smoke does) because Linux
# fanotify-perm only fires on file opens, not unlinks. `rm` calls
# unlinkat directly — no open — so fanotify-perm can't see it.
# L04 closes that gap via the eBPF-LSM `inode_unlink` hook (whose
# DoD explicitly owns rm-undo-linux.sh green); until then this
# smoke validates the load-bearing wire (capture + restore) using
# an open-write workload that exercises the same capture path with
# a different trigger.
#
# Exercises:
#   1. shitd boots and spawns shit-helper. Helper's fanotify_init
#      opens the FAN_CLASS_PRE_CONTENT client and the
#      LinuxCaptureRuntime (L01) attaches to FanotifyState.
#   2. PreExec triggers daemon -> helper WatchTree dispatch. The
#      helper (L01 chunk 5) reads /proc/<root_pid>/cwd and calls
#      fanotify::mark::mark_dir_for_capture (FAN_EVENT_ON_CHILD +
#      ONLYDIR) on the resolved directory.
#   3. An overwrite of a known-content file in the watched dir
#      (open O_WRONLY|O_TRUNC, write new bytes, close) fires
#      FAN_OPEN_PERM. The reader thread (L01 chunks 3-4) dispatches
#      to LinuxCaptureRuntime, which dups the kernel-provided fd
#      and reads the PRE-OVERWRITE bytes (the kernel holds the
#      syscall behind FAN_ALLOW; the file's content is still the
#      pre-mutation state until we respond). It blake3-hashes,
#      writes a staging file, and sends HelperResponse::
#      CapturedPreImage with the staging fd attached via SCM_RIGHTS.
#   4. The daemon's dispatch_loop ingests the blob, verifies the
#      hash, journals a FilePreImage event.
#   5. `shit undo --yes` replays the inverse: rewrites the blob
#      back to the original path. The post-overwrite content is
#      replaced with the pre-overwrite content.
#   6. The restored file is byte-identical to the original
#      (sha256 match).
#
# Linux-only. The wire (CapturedPreImage via SCM_RIGHTS, daemon
# ingest) is identical to BSD; only the producer-side event source
# differs (fanotify-perm vs kqueue NOTE_*).

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

# Pre-flight: confirm the helper has cap_sys_admin. Without it the
# helper degrades to no-fanotify mode and no FilePreImage events fire,
# making the eventual "wait for event" timeout the gating failure —
# slow and confusing. Hard-fail here with the exact fix command.
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing on this system; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
if ! printf '%s' "${HELPER_CAPS}" | grep -q cap_sys_admin; then
    smoke_log "FAIL: helper lacks cap_sys_admin (getcap output: '${HELPER_CAPS}')"
    smoke_log ""
    smoke_log "  Run this on the box first, then re-run the smoke:"
    smoke_log "    sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${HELPER_BIN}"
    smoke_log ""
    smoke_log "  Caps are wiped on every \`cargo build\`. For unattended"
    smoke_log "  smoke runs, configure NOPASSWD for setcap (NixOS:"
    smoke_log "  security.sudo.extraRules)."
    exit 1
fi
smoke_log "helper has caps: ${HELPER_CAPS}"

smoke_start_shitd

# Scratch dir lives INSIDE SHIT_SMOKE_TMP so cleanup is automatic via
# the lib's exit trap. /tmp is typically tmpfs on Linux; fanotify-perm
# works on tmpfs since kernel 4.20 (verified end-to-end during L01
# chunk 5 on hasu, kernel 7.0.8). If a future test environment moves
# /tmp to a non-fanotify-compatible fs, the smoke will degrade
# loudly via the "no FilePreImage event journaled" timeout below.
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

# Move our shell into the watched dir so the helper's WatchTree
# resolves /proc/${PID}/cwd to SCRATCH. mark_dir_for_capture marks
# that exact directory with FAN_EVENT_ON_CHILD; opens of files
# directly within fire perm events.
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

# Overwrite the file: open O_WRONLY|O_TRUNC, write new bytes,
# close. `tee` with no -a is exactly that pattern. The open fires
# FAN_OPEN_PERM on the parent dir's mark; the helper's runtime
# reads the PRE-OVERWRITE content from the kernel-provided fd
# before letting the syscall proceed.
NEW_CONTENT="edit-undo-linux overwritten $(date -u +%Y-%m-%dT%H:%M:%SZ)"
smoke_log "overwriting ${FOO} (open O_WRONLY|O_TRUNC + write)"
printf '%s\n' "${NEW_CONTENT}" | tee "${FOO}" >/dev/null

# Sanity: the file's contents changed.
OVERWRITE_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
if [ "${OVERWRITE_SHA}" = "${EXPECTED_SHA}" ]; then
    smoke_fail "overwrite didn't change content (sha matches pre-overwrite)"
fi

# Let the FAN_OPEN_PERM event propagate: fanotify reader ->
# LinuxCaptureRuntime -> read pre-image -> staging write ->
# SCM_RIGHTS send -> daemon recvmsg -> blob put -> index put_event.
sleep 0.5

smoke_log "PostExec seq=${SEQ} exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# Wait up to 10s for the FilePreImage event to land. Likely causes
# of a timeout here: (1) helper degraded (no caps — pre-flight
# above should have caught this); (2) /tmp on a filesystem where
# fanotify-perm misbehaves; (3) regression in L01's capture wire.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
# NOTE: NO TreeOpUnlink wait — edit-undo doesn't unlink. The L04
# rm-undo smoke (post-eBPF-LSM) will add that wait.

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

smoke_log "PASS: edit-undo-linux (sha256=${EXPECTED_SHA})"
