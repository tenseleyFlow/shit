#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: zfs-snapshot-preimage-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# B6 - pre-images from a per-command ZFS snapshot.
#
# kqueue reports a write after it happened. Read-time capture covers a
# file only through the live-baseline walk, which skips files over its
# 1 GiB stream cap, so an in-place write to such a file has no
# pre-image at all. With the cwd on a dataset the user may snapshot,
# the daemon snapshots it at PreExec and the pre-image comes from
# there.
#
#   1. doctor reports the zfs-snapshot source for the watched dir.
#   2. `dd conv=notrunc` over a 1.1 GiB sparse file and a rewrite of a
#      small file: both pre-images are journaled from the snapshot; the
#      small one is copied into the blob store, the large one is not.
#   3. The daemon restarts. At start it destroys an orphan snapshot of
#      its own (a command it never journaled, as after a crash) and
#      keeps the command's.
#   4. Undo restores both files, the large one streamed from the
#      snapshot.
#   5. Contrast: with SHIT_ZFS_SNAPSHOTS=0 the same command leaves the
#      large file unrestorable. This is the case the snapshot fixes.
#   6. No snapshot of this daemon survives the smoke.
#
# Runs only with TMPDIR on ZFS. Skips when the user may not snapshot
# the dataset, unless SHIT_SMOKE_REQUIRE_ZFS_SNAPSHOT=1 (the CI zfs
# leg, which delegates snapshot,destroy,mount to the runner).

set -u

SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: zfs-snapshot-preimage-fbsd is FreeBSD-only"
    exit 0
fi
if [ ! -x /sbin/zfs ]; then
    smoke_log "SKIP: zfs(8) not installed"
    exit 0
fi
WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
DATASET="$(/sbin/zfs list -H -o name "${WATCHED}" 2>/dev/null || true)"
if [ -z "${DATASET}" ]; then
    smoke_log "SKIP: ${WATCHED} is not on ZFS (run with TMPDIR on a ZFS dataset)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# 1. doctor, from the watched dir.
SOURCE="$(cd "${WATCHED}" && "${SHIT_BIN}" doctor --json 2>/dev/null \
    | python3 -c 'import json,sys; s=json.load(sys.stdin)["bsd"]["pre_image_source"]; print(s["source"], s.get("dataset") or "-", s.get("reason") or "")')"
smoke_log "doctor pre_image_source: ${SOURCE}"
case "${SOURCE}" in
    "zfs-snapshot ${DATASET} "*) ;;
    read-time*)
        if [ "${SHIT_SMOKE_REQUIRE_ZFS_SNAPSHOT:-0}" = "1" ]; then
            smoke_fail "doctor reports read-time on ${DATASET}; the zfs leg requires snapshots"
        fi
        smoke_log "SKIP: no snapshot permission on ${DATASET} (zfs allow -u $(id -un) snapshot,destroy,mount ${DATASET})"
        exit 0
        ;;
    *) smoke_fail "unexpected doctor pre_image_source: ${SOURCE}" ;;
esac

BIG="${WATCHED}/big.img"
SMALL="${WATCHED}/small.conf"
# 1.1 GiB, sparse: past the 1 GiB stream cap, nearly no disk.
truncate -s 1100M "${BIG}"
printf 'old-head' | dd of="${BIG}" conv=notrunc status=none
printf 'old-tail' | dd of="${BIG}" bs=1 seek=$((1100 * 1024 * 1024 - 8)) conv=notrunc status=none
printf 'key=old\n' > "${SMALL}"
PRE_BIG="$(/sbin/sha256 -q "${BIG}")"
PRE_SMALL="$(/sbin/sha256 -q "${SMALL}")"

daemon_log() {
    cat "${XDG_STATE_HOME}"/shit/log/daemon.jsonl* 2>/dev/null || true
}

# Run the mutating command as journaled command <seq> of <session>.
run_command() {
    local session="$1"
    "${SHIT_BIN}" hook-send session-open --session "${session}" --pid "$$" --shell bash \
        --tty /dev/null --sock "${SHIT_HOOK_SOCK}"
    "${SHIT_BIN}" hook-send pre-exec --session "${session}" --seq 1 --pid "$$" \
        --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
    sleep 0.5
    bash -c "cd '${WATCHED}' && printf 'new-head' | dd of=big.img conv=notrunc status=none \
        && printf 'key=new\n' > small.conf"
    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec --session "${session}" --seq 1 --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"
    sleep 1.0
}

new_session() {
    python3 -c 'import uuid; print(uuid.uuid4())'
}

# 2. the command, with snapshots.
smoke_start_shitd
OWNER="$(tr -d '[:space:]' < "${XDG_STATE_HOME}/shit/zfs-snapshot-owner" 2>/dev/null || true)"
[ -n "${OWNER}" ] || smoke_fail "daemon wrote no zfs-snapshot-owner (snapshots not enabled?)"
S1="$(new_session)"
run_command "${S1}"
[ "$(/sbin/sha256 -q "${BIG}")" != "${PRE_BIG}" ] || smoke_fail "dd did not change ${BIG}"
SNAP="${DATASET}@shitd-${OWNER}-$(printf '%s' "${S1}" | tr -d -)-1"
/sbin/zfs list -H -t snapshot "${SNAP}" >/dev/null 2>&1 \
    || smoke_fail "no snapshot ${SNAP} after the command"
smoke_log "snapshot taken: ${SNAP}"
daemon_log | grep -q '"pre-image from zfs snapshot".*big.img.*"copied":false' \
    || smoke_fail "big.img pre-image not journaled from the snapshot (uncopied)"
daemon_log | grep -q '"pre-image from zfs snapshot".*small.conf.*"copied":true' \
    || smoke_fail "small.conf pre-image not journaled from the snapshot (copied)"

# 3. restart; an orphan of ours (never journaled) goes, the command's stays.
ORPHAN="${DATASET}@shitd-${OWNER}-0000000000000000000000000000beef-1"
/sbin/zfs snapshot "${ORPHAN}" || smoke_fail "could not make the orphan snapshot"
smoke_stop_shitd || smoke_fail "daemon did not stop"
smoke_start_shitd
/sbin/zfs list -H -t snapshot "${ORPHAN}" >/dev/null 2>&1 \
    && smoke_fail "orphan snapshot ${ORPHAN} survived daemon start"
/sbin/zfs list -H -t snapshot "${SNAP}" >/dev/null 2>&1 \
    || smoke_fail "daemon start released ${SNAP}, whose command is journaled"

# 4. undo across the restart.
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
[ "${UNDO_RC}" -eq 0 ] || smoke_fail "undo exited ${UNDO_RC}"
[ "$(/sbin/sha256 -q "${SMALL}")" = "${PRE_SMALL}" ] || smoke_fail "small.conf not restored"
[ "$(/sbin/sha256 -q "${BIG}")" = "${PRE_BIG}" ] || smoke_fail "big.img not restored from the snapshot"
smoke_log "undo restored both files"
"${SHIT_BIN}" hook-send session-close --session "${S1}" --sock "${SHIT_HOOK_SOCK}"

# 5. contrast: read-time only.
smoke_stop_shitd || smoke_fail "daemon did not stop"
export SHIT_ZFS_SNAPSHOTS=0
smoke_start_shitd
S2="$(new_session)"
run_command "${S2}"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo-readtime.log" 2>&1
set -e
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-readtime.log" >&2
if [ "$(/sbin/sha256 -q "${BIG}")" = "${PRE_BIG}" ]; then
    smoke_fail "read-time capture restored big.img; this smoke no longer shows what the snapshot adds"
fi
smoke_log "read-time capture could not restore big.img, as expected"
"${SHIT_BIN}" hook-send session-close --session "${S2}" --sock "${SHIT_HOOK_SOCK}"
unset SHIT_ZFS_SNAPSHOTS

# 6. nothing of ours is left once the smoke releases its snapshots.
smoke_stop_shitd || true
smoke_release_zfs_snapshots
LEFT="$(smoke_zfs_snapshots)"
[ -z "${LEFT}" ] || smoke_fail "snapshots left behind: ${LEFT}"

smoke_log "PASS: zfs-snapshot-preimage-fbsd"
