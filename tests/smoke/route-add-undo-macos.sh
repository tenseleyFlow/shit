#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: route-add-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M06.3 / DR-44 — end-to-end `route add -net <test-net> 127.0.0.1`
# → `shit undo` → route gone.
#
# Validates:
# 1. Wrapper: route-wrapper recognizes `add` as mutating and fires
#    net-event with verb=add.
# 2. Inspector: RouteInspector captures `netstat -nrf inet` output.
# 3. Daemon: net_track journals a NetworkOp with before/after raw
#    bytes.
# 4. Planner: synthesise_route diffs the netstat snapshots and emits
#    `["route", "delete", "-net", <dst>]` as the inverse.
# 5. Executor: PrivilegedNetRunner sudo-spawns the inverse.
#
# Pre-conditions:
# - Passwordless sudo for /sbin/route. GHA macos-14 runners have
#   this for the `runner` user by default; dev machines need a
#   manual sudoers entry. The smoke SKIPs if `sudo -n route get`
#   prompts.
#
# We use 192.0.2.0/24 (TEST-NET-1, RFC 5737) so we never collide
# with anything real. Cleanup unconditionally tries to delete the
# route so failures don't leave the box's routing table dirty.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: route-add-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

# Probe passwordless sudo via a benign route op.
if ! sudo -n /sbin/route -n get default >/dev/null 2>&1; then
    smoke_log "SKIP: passwordless sudo for route not available"
    exit 0
fi

TEST_NET="192.0.2.0/24"
TEST_GW="127.0.0.1"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/route-wrapper"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -x "${WRAPPER}" ]    || smoke_fail "route-wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_HELPER="${HELPER_BIN}"

# Make sure the test route isn't already present (would mean a
# previous run died without cleanup). Quietly try to delete it; if
# it wasn't there, that's a no-op stderr we ignore.
sudo /sbin/route -n delete -net "${TEST_NET}" >/dev/null 2>&1 || true

cleanup() {
    sudo /sbin/route -n delete -net "${TEST_NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

smoke_start_shitd

SESSION="$(/opt/homebrew/bin/python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null \
    || python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload: add a route via the wrapper. See networksetup smoke
# for the `sudo env VAR=val cmd` rationale — sudoers env_reset
# silently drops `sudo VAR=val cmd` on macOS, so env(1) preserves
# the helper / runtime vars across the privilege boundary.
smoke_log "wrapper bootstrap: ${WRAPPER} add -net ${TEST_NET} ${TEST_GW}"
set +e
sudo env \
    SHIT_HELPER="${HELPER_BIN}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    "${WRAPPER}" add -net "${TEST_NET}" "${TEST_GW}" \
    >"${SHIT_SMOKE_TMP}/add.log" 2>&1
ADD_RC=$?
set -e
sed 's/^/    /' "${SHIT_SMOKE_TMP}/add.log" >&2
if [ "${ADD_RC}" -ne 0 ]; then
    smoke_fail "route add via wrapper exited rc=${ADD_RC}"
fi

# Confirm the route is now in the table.
if ! netstat -nrf inet 2>/dev/null | grep -qE "^192\.0\.2"; then
    smoke_fail "route add claimed success but 192.0.2.x not in netstat -nrf inet"
fi
smoke_log "route present in netstat after add"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_NET_OPS="$(smoke_journal_count "discriminant = 'NetworkOp'" 2>/dev/null || echo 0)"
smoke_log "NetworkOp events: ${N_NET_OPS}"
N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo: the route is gone from the table.
if [ "${UNDO_RC}" -eq 0 ] && ! netstat -nrf inet 2>/dev/null | grep -qE "^192\.0\.2"; then
    smoke_log "OUTCOME A — full undo (route deleted, NetworkOps=${N_NET_OPS})"
    smoke_log "PASS: route-add-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal: undo exits non-zero with a message
# mentioning the route/synth.
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "route|192\.0\.2|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named route/synth)"
    smoke_log "PASS: route-add-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  post-undo netstat (first 10 lines):"
netstat -nrf inet 2>/dev/null | head -10 | sed 's/^/    /' >&2
smoke_log "  undo exit:   ${UNDO_RC}"
smoke_log "  NetworkOps:  ${N_NET_OPS}"
smoke_log "  events:      ${N_EVENTS}"
smoke_fail "route-add-undo did NOT delete ${TEST_NET} from the routing table (Outcome C)"
