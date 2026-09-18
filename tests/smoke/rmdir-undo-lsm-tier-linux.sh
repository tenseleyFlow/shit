#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: rmdir-undo-lsm-tier-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
#
# Linux LSM directory-deletion honesty gate.
#
# The inode_rmdir hook can hold the deleted directory inode and capture the
# metadata currently represented by FileMetadataWire. That model is not yet
# complete enough to replay a directory exactly (notably atime/ACL state), so
# the daemon must convert the typed metadata-only deletion marker into
# CaptureRefused. This smoke proves all three load-bearing properties:
# - the LSM inode_rmdir path really emitted deletion evidence;
# - the journal and CLI surface an explicit, command-atomic refusal; and
# - undo does not synthesize a lossy replacement directory.

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

# The helper emits CapturedDeletionMarker for metadata-only evidence. The
# daemon deliberately converts that to CaptureRefused instead of the old,
# lossy TreeOpUnlink action.
smoke_wait_for_event \
    "discriminant = 'CaptureRefused' AND path LIKE '%/lsm_rmdir_victim'" 1 10

N_ACTIONABLE="$(smoke_journal_count "discriminant = 'TreeOpUnlink' AND path LIKE '%/lsm_rmdir_victim'")"
if [ "${N_ACTIONABLE}" -ne 0 ]; then
    smoke_fail "directory deletion also journaled ${N_ACTIONABLE} actionable TreeOpUnlink event(s)"
fi

# AU20 load-bearing assertion: the LSM inode_rmdir handler MUST
# have logged its emit line. The handler's success info line is
# `lsm-unlink deletion evidence sent`. We can't match on structured fields
# (basename, path) because tracing's pretty-formatter interleaves
# ANSI escape codes between the field name and value when stderr
# is a tty-like sink. The smoke's workload contains exactly one
# rmdir and no file unlinks of our own, so the deletion-evidence line in
# shitd.log is necessarily ours; the path-specific CaptureRefused journal
# entry above closes the identification loop.
if ! grep -F "lsm-unlink deletion evidence sent" "${SHIT_SMOKE_TMP}/shitd.log" > /dev/null; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "LSM inode_rmdir handler did not emit deletion evidence"
fi
smoke_log "LSM inode_rmdir handler confirmed fired"

UNDO_RC=0
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || UNDO_RC=$?
if [ "${UNDO_RC}" -eq 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "directory deletion CaptureRefused unexpectedly exited 0"
fi

if ! grep -qiE "Refused|capture-incomplete|metadata-only deletion marker" "${SHIT_SMOKE_TMP}/undo.log"; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "undo failed without surfacing the directory capture refusal"
fi
if ! grep -q "applied=0" "${SHIT_SMOKE_TMP}/undo.log"; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "refused directory undo reported an applied inverse"
fi

# Fail closed means leaving the successful rmdir in place. Recreating even an
# empty directory here would be a lossy synthetic inverse.
if [ -e "${TARGET}" ]; then
    smoke_fail "refused undo synthesized a replacement at ${TARGET}"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: rmdir-undo-lsm-tier-linux (LSM evidence captured; undo refused atomically; no directory synthesized)"
