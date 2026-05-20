#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# L04 phase 3 — chmod-undo on Linux via eBPF-LSM `inode_setattr`.
#
# Exercises the same wire as rm-undo-linux (CapturedPreImage +
# is_delete=false) but driven by a `chmod(2)` instead of `unlink(2)`.
# The BPF program reads the pre-change `i_mode` from the inode at
# LSM hook time; userspace journals it; `shit undo` restores.
#
# Linux-only. Requires the same kernel prerequisites as rm-undo-linux
# (CONFIG_BPF_LSM=y + lsm=bpf in cmdline + CAP_BPF/CAP_PERFMON).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: chmod-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Same pre-flight checks as rm-undo-linux.
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

FOO="${SCRATCH}/foo.txt"
printf 'metadata-target content\n' > "${FOO}"
chmod 0644 "${FOO}"
PRE_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
PRE_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
smoke_log "wrote ${FOO} pre-mode=${PRE_MODE} pre-sha=${PRE_SHA}"

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

# Wait for WatchTree to land and pre_open_tree to grab an fd on foo.
sleep 0.5

smoke_log "chmod 0755 ${FOO}"
chmod 0755 "${FOO}"
POST_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
if [ "${POST_MODE}" != "0o755" ]; then
    smoke_fail "chmod didn't change mode (got ${POST_MODE})"
fi
sleep 0.5

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# eBPF-LSM setattr emits the same FilePreImage event wire as fanotify-perm
# does for open-then-write. The daemon's metadata-restore path reads the
# old mode/uid/gid from the FilePreImage record on undo.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

RESTORED_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
RESTORED_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
if [ "${RESTORED_MODE}" != "${PRE_MODE}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "mode not restored: pre=${PRE_MODE} restored=${RESTORED_MODE}"
fi
# Content should not have changed across the chmod or the undo.
if [ "${RESTORED_SHA}" != "${PRE_SHA}" ]; then
    smoke_fail "content changed: pre-sha=${PRE_SHA} restored-sha=${RESTORED_SHA}"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: chmod-undo-linux (mode ${POST_MODE} → ${RESTORED_MODE}, sha=${PRE_SHA})"
