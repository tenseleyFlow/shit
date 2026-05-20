#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# L04 phase 4 — mkdir-undo on Linux via eBPF-LSM `inode_mkdir`.
#
# Exercises the TreeMutation wire (HelperResponse::TreeMutation with
# op=TreeOpWire::Create kind=Directory). The BPF program captures
# (parent_inode, basename, mode); userspace stats the resolved path
# post-syscall to fill the (dev, inode) of the freshly-created dir;
# daemon journals a TreeOp::Create event; `shit undo` rmdirs it.
#
# Linux-only. Same kernel prerequisites as rm-undo-linux.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: mkdir-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing"
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

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Wait for WatchTree to land. mkdir doesn't need pre_open_tree fds
# (the dir doesn't exist yet) but the LSM tier still needs the pid
# tree-tracking to be set up.
sleep 0.5

NEWDIR="${SCRATCH}/created_by_smoke"
mkdir "${NEWDIR}"
smoke_log "mkdir ${NEWDIR}"
if [ ! -d "${NEWDIR}" ]; then
    smoke_fail "mkdir didn't create the dir"
fi
sleep 0.5

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Daemon denormalizes `TreeOp::Create` as `TreeOpCreate`.
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ -d "${NEWDIR}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "dir was not removed by shit undo: ${NEWDIR}"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: mkdir-undo-linux"
