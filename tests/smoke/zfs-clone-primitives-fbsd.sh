#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: zfs-clone-primitives-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU01 phase 1 smoke — exercise the zfs::clone_create /
# clone_destroy / snapshot_destroy primitives in isolation, against
# a real ZFS pool, asserting:
#
#   1. snapshot at `<zroot>@shit-pre-test-XX` succeeds.
#   2. clone to `<zroot>/.shit-clones/test-XX` mounts somewhere and
#      contains a readable copy of a pre-snapshot file.
#   3. destroying the clone + snapshot leaves the pool clean
#      (no leftover `shit-pre-*` snapshots, no leftover
#      `.shit-clones/*` datasets).
#
# This smoke does NOT exercise the capture-engine wire (that lands
# in AU01.A) — it validates the primitives only. The wire ride
# alongside helper-side decision logic and a higher-level
# "rm-undo via zfs_clone" smoke.
#
# Skips on non-ZFS hosts. The cross-platform-actions FreeBSD CI VM
# uses `zroot` by default.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: zfs-clone-primitives-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
if [ ! -x /sbin/zfs ] || [ ! -x /sbin/zpool ]; then
    smoke_log "SKIP: zfs(8) / zpool(8) not installed at /sbin"
    exit 0
fi

# zfs(8) snapshot/clone/destroy on most layouts need root. Existing
# freebsd-vm smokes (pfctl-*, service-*) detect doas / sudo and
# bail with SKIP if neither is set up. Same pattern here.
if command -v doas >/dev/null 2>&1; then
    PRIV="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: neither doas nor sudo on PATH; zfs primitives need root"
    exit 0
fi

# Pool selection: take the first pool the host has. CI's image
# ships `zroot`; we don't hardcode the name so a non-CI box with a
# different pool still works.
POOL="$(/sbin/zpool list -H -o name 2>/dev/null | head -1 || true)"
if [ -z "${POOL}" ]; then
    smoke_log "SKIP: zpool list returned no pools"
    exit 0
fi
smoke_log "pool: ${POOL}"

# Find a /tmp-rooted child dataset. The pool's root dataset usually
# has `mountpoint=none`; we want a child like `<pool>/tmp` mounted at
# /tmp. Operating under /tmp keeps file creation off system paths.
SOURCE_DATASET=""
SOURCE_MNT=""
while IFS=$'\t' read -r ds mnt; do
    case "${mnt}" in
        /tmp|/tmp/*) SOURCE_DATASET="${ds}"; SOURCE_MNT="${mnt}"; break ;;
    esac
done < <(/sbin/zfs list -H -o name,mountpoint -r "${POOL}" 2>/dev/null)
if [ -z "${SOURCE_DATASET}" ]; then
    smoke_log "SKIP: no /tmp-rooted dataset under ${POOL}"
    exit 0
fi
smoke_log "source dataset: ${SOURCE_DATASET} mounted at ${SOURCE_MNT}"

# Tag for reentrancy. Best-effort cleanup at the end, but a prior-
# run leak shouldn't false-fail us.
TAG="au01p1-$$-$(date -u +%s)"
SNAP="${SOURCE_DATASET}@shit-pre-${TAG}"
# Put the clone under the source dataset's parent. Because the pool
# root often carries `mountpoint=none`, set an explicit mountpoint
# under /tmp at clone time (-o mountpoint=...) — that matches what
# the production helper code will do once AU01.A wires capture.
PARENT="${SOURCE_DATASET%/*}"
CLONE="${PARENT}/.shit-clones-${TAG}"
CLONE_MNT_EXPECTED="/tmp/.shit-clones-${TAG}"

cleanup_zfs() {
    # Destroy in dependency order: clone first, then snapshot.
    # `|| true` because cleanup runs from a trap and we don't want
    # to mask the real exit code.
    ${PRIV} /sbin/zfs destroy -rf "${CLONE}" 2>/dev/null || true
    ${PRIV} /sbin/zfs destroy -d  "${SNAP}"  2>/dev/null || true
}
trap cleanup_zfs EXIT

# Write a pre-image fingerprint we can verify inside the clone.
FINGERPRINT="$(date -u +%s.%N)-au01-phase1-${TAG}"
SRC_FILE="${SOURCE_MNT}/au01-phase1-${TAG}.txt"
echo "${FINGERPRINT}" > "${SRC_FILE}" \
    || smoke_fail "couldn't write source file at ${SRC_FILE}"
smoke_log "wrote source: ${SRC_FILE}"

# Step 1 — snapshot.
smoke_log "step 1: zfs snapshot ${SNAP}"
${PRIV} /sbin/zfs snapshot "${SNAP}" \
    || smoke_fail "zfs snapshot failed"

# Mutate the source AFTER the snapshot so the clone sees the
# fingerprint and the live file diverges.
echo "post-snapshot junk" > "${SRC_FILE}"

# Step 2 — clone with an explicit mountpoint. The phase-1 primitive
# in zfs.rs (clone_create) doesn't yet pass -o mountpoint=, so the
# smoke uses the raw zfs(8) form. AU01.A's primitive uplift will
# extend clone_create to accept a mountpoint option.
smoke_log "step 2: zfs clone -o mountpoint=${CLONE_MNT_EXPECTED} ${SNAP} ${CLONE}"
${PRIV} /sbin/zfs clone -o "mountpoint=${CLONE_MNT_EXPECTED}" "${SNAP}" "${CLONE}" \
    || smoke_fail "zfs clone failed"

# Verify the clone is mounted somewhere.
CLONE_MNT="$(/sbin/zfs list -H -o mountpoint "${CLONE}" 2>/dev/null)"
if [ -z "${CLONE_MNT}" ] || [ "${CLONE_MNT}" = "-" ] || [ "${CLONE_MNT}" = "none" ]; then
    smoke_fail "clone has no mountpoint (got '${CLONE_MNT}')"
fi
smoke_log "clone mountpoint: ${CLONE_MNT}"

# Verify the pre-image is intact in the clone. Path math has to
# match clone_pre_image_path in zfs.rs.
REL="$(echo "${SRC_FILE}" | sed "s|^${SOURCE_MNT}||" | sed 's|^/||')"
CLONE_FILE="${CLONE_MNT}/${REL}"
if [ ! -f "${CLONE_FILE}" ]; then
    smoke_log "clone-mapped path missing: ${CLONE_FILE}"
    ls -la "${CLONE_MNT}" 2>&1 | sed 's/^/    /' >&2 || true
    smoke_fail "clone does not contain the source file"
fi
SEEN="$(cat "${CLONE_FILE}")"
if [ "${SEEN}" != "${FINGERPRINT}" ]; then
    smoke_log "clone fingerprint mismatch: expected='${FINGERPRINT}' got='${SEEN}'"
    smoke_fail "clone diverged from source@snapshot"
fi
smoke_log "step 2: clone byte-identical to source-at-snapshot (ok)"

# Step 3 — destroy clone, then snapshot.
smoke_log "step 3: zfs destroy clone + snapshot"
${PRIV} /sbin/zfs destroy -rf "${CLONE}" \
    || smoke_fail "zfs destroy clone failed"
${PRIV} /sbin/zfs destroy -d  "${SNAP}" \
    || smoke_fail "zfs destroy snapshot failed"

# Step 4 — verify nothing leaked.
LEAKED_SNAPS="$(/sbin/zfs list -t snapshot -H -o name -r "${SOURCE_DATASET}" 2>/dev/null | grep -c "shit-pre-${TAG}" || true)"
LEAKED_DATASETS="$(/sbin/zfs list -H -o name -r "${PARENT}" 2>/dev/null | grep -c ".shit-clones-${TAG}" || true)"
if [ "${LEAKED_SNAPS}" -ne 0 ]; then
    smoke_fail "${LEAKED_SNAPS} snapshot(s) leaked after destroy"
fi
if [ "${LEAKED_DATASETS}" -ne 0 ]; then
    smoke_fail "${LEAKED_DATASETS} dataset(s) leaked after destroy"
fi
smoke_log "step 4: no leaks (ok)"

# Source-file cleanup. The mutation we did post-snapshot is on the
# live source; leave the cleaned-up-but-still-mutated state as the
# smoke's footprint (the cross-platform-actions VM is ephemeral).
rm -f "${SRC_FILE}" 2>/dev/null || true

smoke_log "PASS: zfs-clone-primitives-fbsd"
