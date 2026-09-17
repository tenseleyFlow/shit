#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mkfifo-restore-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 120
#
# Linux LSM deleted-FIFO honesty gate.
#
# Workload:
# - Pre-create a named pipe BEFORE pre-exec so pre_open_tree
#   captures the inode as a Fifo (mode bits S_IFIFO|perm).
# - `rm` the fifo inside the watched session. The inode_unlink
#   LSM hook fires; the helper sends a typed metadata-only deletion
#   marker carrying kind=Fifo.
# - The daemon journals CaptureRefused because FileMetadataWire does
#   not yet carry every field needed for exact replay. The planner
#   refuses the whole command instead of dispatching helper mknod.
#
# Assertions:
# - the path-specific CaptureRefused event is present and no
#   actionable TreeOpUnlink was synthesized;
# - undo exits non-zero, renders the refusal, and reports applied=0;
# - the deleted FIFO stays absent and apply_mknod never runs.

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
for required in cap_bpf cap_perfmon cap_sys_admin; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
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

# The typed marker must become a refusal, never the old lossy unlink inverse.
smoke_wait_for_event \
    "discriminant = 'CaptureRefused' AND path LIKE '%/au22_pre_pipe'" 1 10

N_ACTIONABLE="$(smoke_journal_count "discriminant = 'TreeOpUnlink' AND path LIKE '%/au22_pre_pipe'")"
if [ "${N_ACTIONABLE}" -ne 0 ]; then
    smoke_fail "FIFO deletion also journaled ${N_ACTIONABLE} actionable TreeOpUnlink event(s)"
fi

if ! grep -F "lsm-unlink deletion evidence sent" "${SHIT_SMOKE_TMP}/shitd.log" > /dev/null; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "LSM inode_unlink handler did not emit FIFO deletion evidence"
fi

UNDO_RC=0
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || UNDO_RC=$?
if [ "${UNDO_RC}" -eq 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "deleted-FIFO CaptureRefused unexpectedly exited 0"
fi

if ! grep -qiE "Refused|capture-incomplete|metadata-only deletion marker" "${SHIT_SMOKE_TMP}/undo.log"; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "undo failed without surfacing the FIFO capture refusal"
fi
if ! grep -q "applied=0" "${SHIT_SMOKE_TMP}/undo.log"; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "refused FIFO undo reported an applied inverse"
fi

# A recreated FIFO or any other path kind would be a lossy synthesis.
if [ -e "${FIFO}" ]; then
    smoke_fail "refused undo synthesized a replacement at ${FIFO}"
fi
if grep -F "apply_mknod" "${SHIT_SMOKE_TMP}/shitd.log" > /dev/null; then
    smoke_fail "helper apply_mknod ran despite command-atomic CaptureRefused"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: mkfifo-restore-undo-linux (LSM evidence captured; undo refused atomically; no FIFO synthesized; pre-mode was ${PRE_MODE})"
