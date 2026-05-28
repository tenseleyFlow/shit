#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mkdir-undo-lsm-tier-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
#
# AU20.1 — LSM-tier-explicit mkdir-undo smoke.
#
# `mkdir-undo-linux.sh` already exercises the round-trip but does
# NOT assert WHICH tier produced the journal event — if the LSM
# `inode_mkdir` BPF program regressed (verifier accepts it, but it
# silently never emits), fanotify-perm would still capture the
# parent dir's open and the round-trip would pass anyway, hiding
# the LSM regression. AU20 closes that gap.
#
# The assertion: helper's tracing::info!("lsm-mkdir TreeMutation sent")
# at capture/linux.rs (handle_lsm_mkdir) must appear in shitd.log.
# That string lands only when the LSM path actually fired.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: mkdir-undo-lsm-tier-linux is Linux-only (uname=$(uname -s))"
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

NEWDIR="${SCRATCH}/lsm_mkdir_target"
mkdir "${NEWDIR}"
[ -d "${NEWDIR}" ] || smoke_fail "mkdir did not create ${NEWDIR}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10

# AU20 load-bearing assertion: the LSM handler MUST have logged its
# emit line. Without this grep, a regression that silently drops
# inode_mkdir events would pass — fanotify-perm (or the open-time
# pre_open_tree snapshot path) would carry the round-trip alone.
if ! grep -q "lsm-mkdir TreeMutation sent" "${SHIT_SMOKE_TMP}/shitd.log"; then
    smoke_log "shitd.log tail:"
    tail -100 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "LSM inode_mkdir handler did not emit; 'lsm-mkdir TreeMutation sent' missing from shitd.log"
fi
smoke_log "LSM inode_mkdir handler confirmed fired (shitd.log contains 'lsm-mkdir TreeMutation sent')"

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ -d "${NEWDIR}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "dir not removed by shit undo: ${NEWDIR}"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: mkdir-undo-lsm-tier-linux (LSM inode_mkdir handler fired + undo removed dir)"
