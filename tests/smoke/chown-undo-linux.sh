#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR08.2.chown smoke (Linux twin of chown-undo-fbsd.sh) — closes
# the "covered, smoke-gap" entry the AR08.1 coverage audit flagged.
# The LSM tier already emits `MetadataChange` with uid/gid for any
# chown(2), and the planner already maps that to `RestoreMetadata`;
# this smoke pins the contract on Linux specifically so a future
# regression doesn't slip past CI.
#
# Cannot reliably change UID without root, so we change the
# file's group via `chown :GID`. We pick an alt group from the
# user's `id -G` so the chown is permitted without privilege.
#
# GNU coreutils differences from BSD:
#   - `stat -c '%g'` instead of `stat -f '%g'` for numeric gid
#   - `chown` lives at `/usr/bin/chown` (BSD: /usr/sbin/chown)

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: chown-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight (mirrors chmod-undo-linux.sh): require lsm=bpf in
# kernel cmdline + helper file caps. Skipping on missing kernel
# config; failing loud on missing caps so misconfigured runners
# don't silently degrade.
if [ ! -r /sys/kernel/security/lsm ]; then
    smoke_log "SKIP: /sys/kernel/security/lsm unreadable"
    exit 0
fi
ACTIVE_LSMS="$(cat /sys/kernel/security/lsm 2>/dev/null || echo)"
if ! printf '%s' "${ACTIVE_LSMS}" | grep -q "\bbpf\b"; then
    smoke_log "SKIP: kernel boot cmdline lacks bpf LSM (active=${ACTIVE_LSMS})"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; run: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done
export SHIT_FORCE_TIER=ebpf-lsm

# Pick a group the current user is a member of OTHER than the
# file's default group. `id -G` lists numeric group ids.
USER_GROUPS=( $(id -G) )
if [ "${#USER_GROUPS[@]}" -lt 2 ]; then
    smoke_log "SKIP: user is in <2 groups; cannot chown to a different group without root"
    exit 0
fi

CHOWN_BIN="$(command -v chown)"
[ -x "${CHOWN_BIN}" ] || smoke_fail "chown not on PATH"
STAT_BIN="$(command -v stat)"
[ -x "${STAT_BIN}" ]  || smoke_fail "stat not on PATH"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/owned.txt"
printf 'ownership test\n' > "${SUBJECT}"

PRE_GID="$("${STAT_BIN}" -c '%g' "${SUBJECT}")"
ALT_GID=""
for g in "${USER_GROUPS[@]}"; do
    if [ "${g}" != "${PRE_GID}" ]; then
        ALT_GID="${g}"
        break
    fi
done
[ -n "${ALT_GID}" ] || smoke_fail "no alternate group available (all user groups match file gid ${PRE_GID})"
smoke_log "pre-cmd gid: ${PRE_GID}, will chown to: ${ALT_GID}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

smoke_log "${CHOWN_BIN} :${ALT_GID} ${SUBJECT}"
"${CHOWN_BIN}" ":${ALT_GID}" "${SUBJECT}"

POST_GID="$("${STAT_BIN}" -c '%g' "${SUBJECT}")"
[ "${POST_GID}" = "${ALT_GID}" ] || smoke_fail "chown didn't change gid (got ${POST_GID})"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

POST_UNDO_GID="$("${STAT_BIN}" -c '%g' "${SUBJECT}")"
if [ "${POST_UNDO_GID}" = "${PRE_GID}" ]; then
    smoke_log "PASS: chown-undo-linux (gid ${PRE_GID} → ${ALT_GID} → ${POST_UNDO_GID})"
    exit 0
fi

smoke_fail "gid not restored: got ${POST_UNDO_GID}, expected ${PRE_GID}"
