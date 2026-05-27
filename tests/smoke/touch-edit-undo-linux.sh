#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: touch-edit-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L04 phase 5 — touch-edit-undo on Linux via eBPF-LSM `inode_create`
# (+ `inode_unlink`).
#
# Sequence:
#   1. touch newfile — fires lsm/inode_create → TreeOp::Create
#      (kind=Regular). Helper stashes the new fd in pre_opens.
#   2. echo > newfile — writes content. No LSM hook captures
#      content-changes (no file_open hook in v1); pre-image content
#      from the prior pre_opens fd remains "empty file at create
#      time" — which is exactly the pre-mutation state we want for
#      the unlink-reversal step.
#   3. rm newfile — fires lsm/inode_unlink. handle_lsm_unlink dups
#      the pre-opens fd (race_won=true), reads the *current* (post-
#      echo) content as the pre-unlink image, emits CapturedPreImage.
#
# Undo plan:
#   - Reverse rm (TreeOp::Unlink) → recreate file with the captured
#     content blob.
#   - Reverse touch (TreeOp::Create) → unlink the file.
#   - Net: file absent.
#
# Linux-only. Same prerequisites as the rm-undo-linux smoke.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: touch-edit-undo-linux is Linux-only (uname=$(uname -s))"
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

NEW_FILE="${SCRATCH}/created_by_smoke.txt"
touch "${NEW_FILE}"
sleep 0.2
echo "smoke content" > "${NEW_FILE}"
sleep 0.2
rm "${NEW_FILE}"
smoke_log "touch+echo+rm complete"
sleep 0.5

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# We expect both a Create (from touch) and an Unlink (from rm).
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

if [ -e "${NEW_FILE}" ]; then
    smoke_fail "file should have been rm'd: ${NEW_FILE}"
fi

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# End-state: file must be absent (pre-command state had no such file;
# undo reverses both the rm and the touch).
if [ -e "${NEW_FILE}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "file still present after undo (expected absent): ${NEW_FILE}"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: touch-edit-undo-linux"
