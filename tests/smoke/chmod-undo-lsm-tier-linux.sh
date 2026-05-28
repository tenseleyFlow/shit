#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chmod-undo-lsm-tier-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
#
# AU20.3 — LSM-tier-explicit chmod-undo smoke.
#
# `chmod-undo-linux.sh` exists but doesn't prove the LSM
# inode_setattr handler did the work (vs fanotify FAN_OPEN_PERM
# on the parent dir mark catching the chmod's open-for-write).
# Lock in the LSM path here.
#
# Asserts shitd.log contains the tracing::info!("lsm-setattr
# CapturedPreImage sent") line at capture/linux.rs (handle_lsm_setattr).
# That message lands ONLY when the LSM path ran end-to-end.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: chmod-undo-lsm-tier-linux is Linux-only (uname=$(uname -s))"
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

FOO="${SCRATCH}/foo.txt"
printf 'au20 chmod target\n' > "${FOO}"
chmod 0644 "${FOO}"
PRE_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"

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

chmod 0755 "${FOO}"
POST_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
[ "${POST_MODE}" = "0o755" ] || smoke_fail "chmod no-op: post=${POST_MODE}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

# AU20 load-bearing assertion: the LSM inode_setattr handler MUST
# have logged its emit line. Without this grep, an inode_setattr
# BPF regression (v1/v2 dispatch breaks, verifier accepts but
# emission silently drops, etc.) would still produce a passing
# chmod round-trip via the fanotify-perm fallback.
if ! grep -q "lsm-setattr CapturedPreImage sent" "${SHIT_SMOKE_TMP}/shitd.log"; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "LSM inode_setattr handler did not emit; 'lsm-setattr CapturedPreImage sent' missing from shitd.log"
fi
smoke_log "LSM inode_setattr handler confirmed fired"

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

RESTORED_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
if [ "${RESTORED_MODE}" != "${PRE_MODE}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "mode not restored: pre=${PRE_MODE} restored=${RESTORED_MODE}"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: chmod-undo-lsm-tier-linux (LSM inode_setattr handler fired, mode ${POST_MODE} → ${RESTORED_MODE})"
