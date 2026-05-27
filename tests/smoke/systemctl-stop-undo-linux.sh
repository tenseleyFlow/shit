#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: systemctl-stop-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L03 smoke — `systemctl --user stop <unit>; shit undo` restarts it.
#
# Exercises:
#   1. helper's `svc-event systemctl pre` snapshots ActiveState +
#      EnabledFlag via the real systemctl on the relevant scope.
#   2. The real `systemctl --user stop` runs (no sudo needed for the
#      user scope).
#   3. helper's `svc-event systemctl post` snapshots the post state.
#   4. Daemon diffs pre/post → journals a SystemdOp event with
#      scope=User, verb=Stop, ActiveState before=active after=inactive.
#   5. `shit undo` plans `InverseOp::SystemdRollback` → executes via
#      ServiceExecutor (shells out to `systemctl --user start <unit>`).
#   6. Unit is active again.
#
# Uses the --user scope so we don't need root: dropping a system
# service is dangerous on a real workstation; the user scope is
# hermetic. A transient unit (RemainAfterExit=yes) means start is
# synchronous and the unit appears active until explicitly stopped.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: systemctl-stop-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v systemctl >/dev/null 2>&1; then
    smoke_log "SKIP: systemctl not on PATH"
    exit 0
fi
if ! systemctl --user list-units >/dev/null 2>&1; then
    smoke_log "SKIP: user systemd manager not reachable"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WRAPPER="${SHIT_REPO_ROOT}/packaging/svc-hooks/systemctl-wrapper"
[ -x "${WRAPPER}" ] || smoke_fail "systemctl-wrapper missing at ${WRAPPER}"

smoke_start_shitd

# Unit name unique per run so concurrent / repeat invocations don't
# collide. Drop under XDG_CONFIG_HOME (lib.sh has already set it to
# a per-run tempdir, but the user systemd manager looks at the
# REAL $HOME/.config/systemd/user — so we point USER_UNIT_DIR there
# explicitly and clean up on exit).
UNIT_NAME="shit-l03-stop-$$-$$.service"
USER_UNIT_DIR="${HOME}/.config/systemd/user"
mkdir -p "${USER_UNIT_DIR}"
cleanup_unit() {
    systemctl --user stop "${UNIT_NAME}" >/dev/null 2>&1 || true
    rm -f "${USER_UNIT_DIR}/${UNIT_NAME}"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
}
trap 'cleanup_unit' EXIT

cat >"${USER_UNIT_DIR}/${UNIT_NAME}" <<'EOF'
[Unit]
Description=shit L03 smoke target — stoppable transient unit

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF
systemctl --user daemon-reload

# Start the unit so we have something to stop.
systemctl --user start "${UNIT_NAME}"
if [ "$(systemctl --user is-active "${UNIT_NAME}")" != "active" ]; then
    smoke_fail "could not start transient test unit ${UNIT_NAME}"
fi
smoke_log "started transient unit ${UNIT_NAME} (state=active)"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

export SHIT_HELPER="${HELPER_BIN}"
smoke_log "wrapper stop ${UNIT_NAME}"
"${WRAPPER}" --user stop "${UNIT_NAME}" || smoke_fail "wrapper stop failed"

if [ "$(systemctl --user is-active "${UNIT_NAME}")" = "active" ]; then
    smoke_fail "unit ${UNIT_NAME} still active after stop"
fi
smoke_log "unit stopped (state=inactive)"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'SystemdOp'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Verify restoration: unit should be active again.
sleep 0.3
RESTORED_STATE="$(systemctl --user is-active "${UNIT_NAME}")"
if [ "${RESTORED_STATE}" != "active" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "unit not restored: expected=active got=${RESTORED_STATE}"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: systemctl-stop-undo-linux (${UNIT_NAME}: active → inactive → active)"
