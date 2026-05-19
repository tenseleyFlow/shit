#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# S29.6 smoke — `service <unit> stop; shit undo` restarts the unit.
#
# Exercises:
#   1. helper's `svc-event service pre` snapshots ActiveState/EnabledFlag
#      via `service <unit> onestatus` + `service -e`.
#   2. The real `service <unit> stop` runs (as root).
#   3. helper's `svc-event service post` snapshots the post state.
#   4. Daemon diffs pre/post (parse_freebsd_service) → journals a
#      SystemdOp event with scope=RcBase and the before/after diff.
#   5. `shit undo` plans `InverseOp::SystemdRollback { scope: RcBase, ... }`
#      and executes via the ServiceExecutor (shells out to
#      `service <unit> start` through doas/sudo).
#
# Prereqs on the FreeBSD VM:
#   - `doas` or `sudo` configured for the test user.
#   - `cron` available in /etc/rc.d (always present on FreeBSD base).
#   - `python3`, `sqlite3`.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: service-restart-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

PRIV=""
if command -v doas >/dev/null 2>&1; then
    PRIV="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: neither doas nor sudo on PATH; service-restart smoke needs root"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Choose an rc.d unit that's safe to bounce. `cron` is always present
# on FreeBSD base, runs as a stub when no user crontabs exist, and is
# enabled by default in rc.conf — so `service cron stop` produces a
# clear ActiveState transition.
TARGET_UNIT="cron"
if ! [ -f "/etc/rc.d/${TARGET_UNIT}" ]; then
    smoke_fail "/etc/rc.d/${TARGET_UNIT} missing — unexpected on FreeBSD base"
fi

# Capture baseline so we can restore even if the smoke aborts mid-way.
PRE_ACTIVE="$(/usr/sbin/service "${TARGET_UNIT}" onestatus >/dev/null 2>&1 && echo running || echo stopped)"
smoke_log "baseline: ${TARGET_UNIT}=${PRE_ACTIVE}"
if [ "${PRE_ACTIVE}" != "running" ]; then
    smoke_log "starting ${TARGET_UNIT} first (need a running→stopped transition to reverse)"
    ${PRIV} /usr/sbin/service "${TARGET_UNIT}" start >/dev/null 2>&1 || true
fi

cleanup() {
    # Best-effort restore.
    ${PRIV} /usr/sbin/service "${TARGET_UNIT}" start >/dev/null 2>&1 || true
}
trap cleanup EXIT

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Let escalated children reach the ctl socket.
chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

# Pre-snapshot via helper's svc-event (mirrors what the
# /etc/rc.subr-aware wrapper would do — for the smoke we drive the
# wire directly).
smoke_log "svc-event pre"
"${HELPER_BIN}" svc-event service pre \
    --scope rc-base --unit "${TARGET_UNIT}" --verb stop \
    --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} service ${TARGET_UNIT} stop"
${PRIV} /usr/sbin/service "${TARGET_UNIT}" stop >/dev/null 2>&1 || smoke_fail "service stop failed"

# Verify it really stopped.
if /usr/sbin/service "${TARGET_UNIT}" onestatus >/dev/null 2>&1; then
    smoke_fail "service ${TARGET_UNIT} still running after stop"
fi

smoke_log "svc-event post"
"${HELPER_BIN}" svc-event service post \
    --scope rc-base --unit "${TARGET_UNIT}" --verb stop \
    --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Wait for the daemon to journal the SystemdOp event.
smoke_wait_for_event "discriminant = 'SystemdOp'" 1 10

smoke_log "running: shit undo --yes"
export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: target should be running again.
sleep 1
if ! /usr/sbin/service "${TARGET_UNIT}" onestatus >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_UNIT} not running after undo — service rollback didn't fire"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: service-restart-undo-fbsd (${TARGET_UNIT} stopped→undone)"
