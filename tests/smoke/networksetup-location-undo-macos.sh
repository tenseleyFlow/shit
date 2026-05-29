#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: networksetup-location-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M06.5 — end-to-end `networksetup -switchtolocation <name>` →
# `shit undo` → location restored.
#
# Validates:
# 1. Wrapper: networksetup-wrapper recognizes -switchtolocation as
#    a global mutating verb (no service positional arg).
# 2. Inspector: NetworksetupInspector dispatches verb=switchtolocation
#    to `networksetup -getcurrentlocation`, emits the location name
#    with the new `# verb=` header.
# 3. Planner: synthesise_networksetup_location parses the header,
#    emits `["networksetup", "-switchtolocation", <prior>]`.
# 4. Executor: PrivilegedNetRunner spawns the inverse.
#
# Pre-conditions:
# - Passwordless sudo for /usr/sbin/networksetup.
# - At least TWO configured locations (one is the current; one
#   to switch TO). Default macOS systems have only "Automatic" —
#   SKIP when there's no second location to switch to. This is the
#   common state on GHA macos-14 runners; the smoke will skip
#   cleanly there.
#
# We deliberately don't create a synthetic second location: that
# would itself require a mutating networksetup call (`-createlocation`)
# whose own undo path isn't covered by M06.5. Keep the smoke pure:
# it validates the path WHEN preconditions are met.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: networksetup-location-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

if ! sudo -n /usr/sbin/networksetup -getcurrentlocation >/dev/null 2>&1; then
    smoke_log "SKIP: passwordless sudo for networksetup not available"
    exit 0
fi

# Enumerate locations. macOS networksetup ships `-listlocations`
# returning one location name per line (no header).
LOCATIONS_RAW="$(sudo /usr/sbin/networksetup -listlocations 2>/dev/null \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | grep -v '^$')"
N_LOCATIONS="$(printf '%s\n' "${LOCATIONS_RAW}" | wc -l | tr -d ' ')"
smoke_log "configured locations (${N_LOCATIONS}):"
printf '%s\n' "${LOCATIONS_RAW}" | sed 's/^/    /' >&2
if [ "${N_LOCATIONS}" -lt 2 ]; then
    smoke_log "SKIP: need >=2 configured locations to exercise switchtolocation undo"
    exit 0
fi

PRE_LOCATION="$(sudo /usr/sbin/networksetup -getcurrentlocation 2>/dev/null | tr -d '\n')"
smoke_log "pre-state location: '${PRE_LOCATION}'"

# Pick a location different from the current.
TARGET_LOCATION="$(printf '%s\n' "${LOCATIONS_RAW}" | grep -v -F -x "${PRE_LOCATION}" | head -1)"
if [ -z "${TARGET_LOCATION}" ]; then
    smoke_log "SKIP: couldn't find a location different from current ('${PRE_LOCATION}')"
    exit 0
fi
smoke_log "target location: '${TARGET_LOCATION}'"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/networksetup-wrapper"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -x "${WRAPPER}" ]    || smoke_fail "networksetup-wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_HELPER="${HELPER_BIN}"

cleanup() {
    # Unconditional restore — pass or fail, return the box to its
    # original location.
    sudo /usr/sbin/networksetup -switchtolocation "${PRE_LOCATION}" >/dev/null 2>&1 || true
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

# Switch to the target location via the wrapper. The wrapper
# dispatches verb=switchtolocation (no scope), inspector captures
# the prior location, daemon journals NetworkOp.
#
# NB: networksetup -switchtolocation triggers a brief network
# reconfigure on macOS — DHCP renewals, route table refresh. On
# CI runners with one network interface this is a 1-2s blip;
# GitHub Actions tolerates that without dropping the runner.
smoke_log "wrapper bootstrap: ${WRAPPER} -switchtolocation '${TARGET_LOCATION}'"
set +e
sudo env \
    SHIT_HELPER="${HELPER_BIN}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    "${WRAPPER}" -switchtolocation "${TARGET_LOCATION}" \
    >"${SHIT_SMOKE_TMP}/switch.log" 2>&1
SWITCH_RC=$?
set -e
sed 's/^/    /' "${SHIT_SMOKE_TMP}/switch.log" >&2
if [ "${SWITCH_RC}" -ne 0 ]; then
    smoke_fail "switchtolocation via wrapper exited rc=${SWITCH_RC}"
fi

# Allow the location switch to settle before we read it back.
sleep 1.5

POST_CMD_LOCATION="$(sudo /usr/sbin/networksetup -getcurrentlocation 2>/dev/null | tr -d '\n')"
smoke_log "post-cmd location: '${POST_CMD_LOCATION}'"
if [ "${POST_CMD_LOCATION}" != "${TARGET_LOCATION}" ]; then
    smoke_fail "switchtolocation claimed success but current location is '${POST_CMD_LOCATION}', not '${TARGET_LOCATION}'"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_NET_OPS="$(smoke_journal_count "discriminant = 'NetworkOp'" 2>/dev/null || echo 0)"
smoke_log "NetworkOp events: ${N_NET_OPS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

# Give the post-undo location switch a moment to settle too.
sleep 1.5

POST_UNDO_LOCATION="$(sudo /usr/sbin/networksetup -getcurrentlocation 2>/dev/null | tr -d '\n')"
smoke_log "post-undo location: '${POST_UNDO_LOCATION}'"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${UNDO_RC}" -eq 0 ] && [ "${POST_UNDO_LOCATION}" = "${PRE_LOCATION}" ]; then
    smoke_log "OUTCOME A — full undo (location restored, NetworkOps=${N_NET_OPS})"
    smoke_log "PASS: networksetup-location-undo-macos (Outcome A)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "networksetup|location|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal"
    smoke_log "PASS: networksetup-location-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  pre:       '${PRE_LOCATION}'"
smoke_log "  post-cmd:  '${POST_CMD_LOCATION}'"
smoke_log "  post-undo: '${POST_UNDO_LOCATION}'"
smoke_log "  undo exit: ${UNDO_RC}"
smoke_log "  NetworkOps: ${N_NET_OPS}"
smoke_fail "switchtolocation undo did NOT restore '${PRE_LOCATION}' (Outcome C)"
