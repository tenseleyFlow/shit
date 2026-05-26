#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# G03 smoke — `rmdir` deletes an empty directory with a non-default
# mode; `shit undo` recreates it at the captured mode.
#
# Exercises:
#   1. `mkdir -m 0700 sekrit` — dir with non-umask-default mode.
#   2. `rmdir sekrit` fires `lsm/inode_rmdir`. The BPF program reads
#      `dentry->d_inode->i_mode` (S_IFDIR | 0o700) before the kernel
#      commits the rmdir; the userspace handler masks off S_IFDIR
#      and sends `TreeOpWire::Unlink { kind: Directory, mode: 0o700 }`.
#   3. The daemon journals a TreeOp::Unlink with kind=Directory.
#   4. `shit undo --yes` invokes the planner's RecreatePath inverse;
#      executor calls `mkdir(path, mode=0o700)`. The captured mode
#      lands.
#   5. Post-undo `stat -c %a sekrit` MUST equal 700.
#
# Linux-only. Same kernel prerequisites as rm-undo-linux:
# CONFIG_BPF_LSM=y + lsm=bpf in /proc/cmdline + CAP_BPF/PERFMON on
# the helper.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: rmdir-mode-undo-linux is Linux-only"
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
ACTIVE_LSMS="$(cat /sys/kernel/security/lsm 2>/dev/null || echo)"
if ! printf '%s' "${ACTIVE_LSMS}" | grep -q "\bbpf\b"; then
    smoke_log "SKIP: kernel lacks bpf LSM (active=${ACTIVE_LSMS})"
    exit 0
fi

if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}"
        smoke_log "  Run: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done

export SHIT_FORCE_TIER=ebpf-lsm

smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

# Use a mode with all three permission triads distinct so a regression
# that loses one triad (umask-moderation, S_IFDIR bleed, etc.) shows up.
SEKRIT="${SCRATCH}/sekrit"
mkdir -m 0710 "${SEKRIT}"
MODE_BEFORE="$(stat -c '%a' "${SEKRIT}")"
if [ "${MODE_BEFORE}" != "710" ]; then
    smoke_fail "pre-condition: expected mode 710, got ${MODE_BEFORE} (umask interference?)"
fi
smoke_log "pre-rmdir: ${SEKRIT} mode=${MODE_BEFORE}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"

cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq "${SEQ}" --pid "${PID}" --cwd "${SCRATCH}" \
    --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "rmdir ${SEKRIT}"
rmdir "${SEKRIT}"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq "${SEQ}" --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

if [ -e "${SEKRIT}" ]; then
    smoke_fail "sekrit/ should have been rmdir'd but still exists"
fi

# Wait for the TreeOp::Unlink (Directory) event. There's no
# FilePreImage — dirs have no content; G03's design is wire-only.
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -d "${SEKRIT}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "sekrit/ was not restored by shit undo"
fi
MODE_AFTER="$(stat -c '%a' "${SEKRIT}")"
if [ "${MODE_AFTER}" != "${MODE_BEFORE}" ]; then
    smoke_log "expected mode=${MODE_BEFORE}"
    smoke_log "got      mode=${MODE_AFTER}"
    smoke_fail "dir mode mismatch — G03 should have restored 0o710"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: rmdir-mode-undo-linux (mode=${MODE_AFTER} preserved)"
