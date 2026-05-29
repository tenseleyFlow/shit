#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: zfs-clone-engine-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 360
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU01.A — drives the engine wire from a real ZFS dataset.
#
# Builds the `zfs_clone_e2e` integration test, runs it under
# privilege with SHIT_ZFS_TEST_DIR pointing at a /tmp-rooted ZFS
# dataset, and asserts:
#
#   1. capture_zfs_clone() returns CowTier::ZfsClone for a
#      ZFS-backed source file.
#   2. The blob hash matches an independent blake3 of the bytes.
#   3. The DefaultEngine dispatch picks ZfsClone first when the
#      source path resolves to FsKind::Zfs.
#
# Skips on non-FreeBSD, when /sbin/zfs is missing, or when no
# /tmp-rooted dataset exists. Cleans up its own snapshot/clone via
# capture_zfs_clone's teardown path and a belt-and-suspenders trap.

set -u

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: zfs-clone-engine-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
if [ ! -x /sbin/zfs ] || [ ! -x /sbin/zpool ]; then
    smoke_log "SKIP: zfs(8) / zpool(8) not installed at /sbin"
    exit 0
fi

if command -v doas >/dev/null 2>&1; then
    PRIV="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: neither doas nor sudo on PATH; zfs primitives need root"
    exit 0
fi

POOL="$(/sbin/zpool list -H -o name 2>/dev/null | head -1 || true)"
if [ -z "${POOL}" ]; then
    smoke_log "SKIP: zpool list returned no pools"
    exit 0
fi
smoke_log "pool: ${POOL}"

# Pick a /tmp-rooted child dataset, same as the primitives smoke.
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

TAG="au01a-$$-$(date -u +%s)"
WORK_DIR="${SOURCE_MNT}/${TAG}"
mkdir -p "${WORK_DIR}" \
    || smoke_fail "couldn't create ${WORK_DIR}"

cleanup_zfs_leaks() {
    # Belt and suspenders against a panicking test — destroy
    # anything that matches our id prefix. capture_zfs_clone normally
    # cleans up after itself.
    /sbin/zfs list -H -o name -r "${POOL}" 2>/dev/null \
        | grep -E "(.shit-clones/|@shit-)" \
        | xargs -I{} ${PRIV} /sbin/zfs destroy -rf {} 2>/dev/null || true
    rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup_zfs_leaks EXIT

# Step 1 — compile the integration test (--no-run produces the
# test binary; we'll invoke it directly under privilege).
smoke_log "step 1: cargo test --no-run"
cd "${SHIT_REPO_ROOT}" \
    || smoke_fail "couldn't cd to ${SHIT_REPO_ROOT}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${SHIT_REPO_ROOT}/target}"
export CARGO_TARGET_DIR

if ! cargo test \
        -p shit-capture \
        --test zfs_clone_e2e \
        --no-run \
        --message-format=json \
        > "${WORK_DIR}/cargo.json" 2>"${WORK_DIR}/cargo.err"; then
    smoke_log "cargo test --no-run failed; stderr:"
    sed 's/^/    /' "${WORK_DIR}/cargo.err" >&2 || true
    smoke_fail "cargo build of zfs_clone_e2e failed"
fi

# Pull the test executable path out of cargo's JSON output.
TEST_BIN="$(
    grep '"profile"' "${WORK_DIR}/cargo.json" \
        | grep '"test":true' \
        | grep 'zfs_clone_e2e' \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' \
        | head -1
)"
if [ -z "${TEST_BIN}" ] || [ ! -x "${TEST_BIN}" ]; then
    smoke_fail "couldn't locate zfs_clone_e2e test binary (TEST_BIN='${TEST_BIN}')"
fi
smoke_log "test binary: ${TEST_BIN}"

# Step 2 — run the binary under privilege with the env var set.
# --test-threads=1 keeps the snapshot/clone dataset namespace
# uncontended.
smoke_log "step 2: run integration test under ${PRIV}"
if ! ${PRIV} env \
        SHIT_ZFS_TEST_DIR="${WORK_DIR}" \
        RUST_BACKTRACE=1 \
        "${TEST_BIN}" \
        --ignored \
        --nocapture \
        --test-threads=1; then
    smoke_fail "zfs_clone_e2e integration test failed"
fi

# Step 3 — confirm cleanup (capture_zfs_clone's own teardown
# should have removed clones + snapshots).
LEAKED_SNAPS="$(/sbin/zfs list -t snapshot -H -o name -r "${SOURCE_DATASET}" 2>/dev/null | grep -c "shit-" || true)"
LEAKED_DATASETS="$(/sbin/zfs list -H -o name -r "${POOL}" 2>/dev/null | grep -c ".shit-clones/" || true)"
if [ "${LEAKED_SNAPS}" -ne 0 ]; then
    /sbin/zfs list -t snapshot -H -o name -r "${SOURCE_DATASET}" 2>/dev/null | sed 's/^/    /' >&2
    smoke_fail "${LEAKED_SNAPS} shit- snapshot(s) leaked after engine run"
fi
if [ "${LEAKED_DATASETS}" -ne 0 ]; then
    /sbin/zfs list -H -o name -r "${POOL}" 2>/dev/null | grep ".shit-clones/" | sed 's/^/    /' >&2
    smoke_fail "${LEAKED_DATASETS} .shit-clones dataset(s) leaked after engine run"
fi

smoke_log "PASS: zfs-clone-engine-fbsd"
