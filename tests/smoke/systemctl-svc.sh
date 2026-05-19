#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# DR-34 smoke — systemctl wrapper bracket-fires the daemon,
# SystemdOp event lands in the journal.
#
# Uses --user scope so we don't need sudo. The user-scope systemd
# manager has to be reachable; not all CI runners have it active.
# Precondition-skip when unavailable so the smoke can be invoked
# anywhere.
#
# Test shape:
#   1. Start shitd.
#   2. PreExec keyed on $$.
#   3. Drop a trivial oneshot .service under
#      $XDG_CONFIG_HOME/systemd/user/, daemon-reload.
#   4. PATH-prepend the systemctl-wrapper from packaging/svc-hooks/.
#   5. Run `systemctl --user start shit-smoke.service` — wrapper
#      fires svc-event pre/post for the mutating verb.
#   6. Assert SystemdOp event lands in the journal.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

UNIT_NAME="shit-smoke.service"

# Pre-flight: skip on hosts without systemctl or with no user manager.
if ! command -v systemctl >/dev/null 2>&1; then
    smoke_log "systemctl not present; skipping systemctl smoke"
    exit 0
fi
if ! systemctl --user list-units >/dev/null 2>&1; then
    smoke_log "user systemd manager not reachable; skipping systemctl smoke"
    exit 0
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/svc-hooks/systemctl-wrapper"
if [ ! -x "${WRAPPER}" ]; then
    smoke_fail "systemctl-wrapper missing at ${WRAPPER}"
fi

# Drop the test unit. Oneshot + /bin/true so start completes
# synchronously without leaving a long-running child.
USER_UNIT_DIR="${XDG_CONFIG_HOME}/systemd/user"
mkdir -p "${USER_UNIT_DIR}"
cat >"${USER_UNIT_DIR}/${UNIT_NAME}" <<'EOF'
[Unit]
Description=shit DR-34 smoke target
[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF
systemctl --user daemon-reload

# Register a command window — same pattern as apt smoke.
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

# Trigger the wrapper. Point SHIT_HELPER at our release binary so
# the wrapper finds it without depending on /usr/local/bin install.
export SHIT_HELPER="${HELPER}"
smoke_log "running wrapper start ${UNIT_NAME}"
"${WRAPPER}" --user start "${UNIT_NAME}" || smoke_fail "wrapper start failed"

# Drain.
sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Cleanup the unit before asserting so a fail-and-bail doesn't leave
# state behind. The assertion still runs after.
systemctl --user stop "${UNIT_NAME}" >/dev/null 2>&1 || true
rm -f "${USER_UNIT_DIR}/${UNIT_NAME}"
systemctl --user daemon-reload >/dev/null 2>&1 || true

n="$(smoke_journal_count "discriminant = 'SystemdOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_log "SystemdOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected SystemdOp event; saw ${n}"
fi
smoke_log "SystemdOp events: ${n}"
smoke_log "PASS: systemctl-svc"
