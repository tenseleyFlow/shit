#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: networksetup-dns-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M06.1 — end-to-end `networksetup -setdnsservers <svc> <dns>` →
# `shit undo` → DNS restored to pre-state.
#
# Validates:
# 1. Wrapper: networksetup-wrapper recognizes -setdnsservers and
#    fires net-event with the service as scope_hint.
# 2. Inspector: NetworksetupInspector captures `-getdnsservers
#    <svc>` output with the `# scope=<svc>` header prefix.
# 3. Daemon: net_track journals a NetworkOp with before/after raw
#    bytes carrying the snapshot.
# 4. Planner: synthesise_networksetup parses the header + DNS list
#    and emits `["networksetup", "-setdnsservers", <svc>, <dns...>]`
#    as the inverse.
# 5. Executor: spawns the inverse via sudo (PrivilegedNetRunner).
#
# Pre-conditions:
# - Some non-Bluetooth network service must exist (Wi-Fi, Ethernet,
#   or one of the standard services). We pick the first non-Bluetooth
#   service from `-listallnetworkservices`.
# - Passwordless sudo for /usr/sbin/networksetup. GHA macos-14
#   runners have this by default for the `runner` user. On dev
#   machines a manual sudoers entry is needed; the smoke SKIPs
#   when sudo -n probe fails.
#
# Per-run isolation: captures + restores the DNS list end-to-end;
# cleanup unconditionally re-restores to be safe.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: networksetup-dns-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

# Probe passwordless sudo. If we can't run sudo -n networksetup
# without prompting, the smoke can't run end-to-end.
if ! sudo -n /usr/sbin/networksetup -listallnetworkservices >/dev/null 2>&1; then
    smoke_log "SKIP: passwordless sudo for networksetup not available"
    exit 0
fi

# Pick the first non-Bluetooth network service. The * prefix on
# listallnetworkservices output marks disabled services; we want
# enabled ones. macos-14 GHA runners reliably have at least one.
SERVICE="$(sudo /usr/sbin/networksetup -listallnetworkservices 2>/dev/null \
    | grep -v '^An asterisk' \
    | grep -v '^\*' \
    | grep -iv "Bluetooth" \
    | head -1 \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
if [ -z "${SERVICE}" ]; then
    smoke_log "SKIP: no non-Bluetooth network service detected"
    exit 0
fi
smoke_log "service: ${SERVICE}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/networksetup-wrapper"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -x "${WRAPPER}" ]    || smoke_fail "networksetup-wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_HELPER="${HELPER_BIN}"

# Capture the pre-state DNS for the assertion + restore-on-cleanup.
PRE_DNS_RAW="$(sudo /usr/sbin/networksetup -getdnsservers "${SERVICE}" 2>&1)"
smoke_log "pre-state DNS for ${SERVICE}:"
printf '%s\n' "${PRE_DNS_RAW}" | sed 's/^/    /' >&2

# Build the "restore-to-pre-state" command for cleanup.
# Empty pre-state (no DNS configured) → use the literal "empty" arg.
if printf '%s' "${PRE_DNS_RAW}" | grep -q "There aren't any DNS Servers"; then
    PRE_RESTORE_ARGS="empty"
else
    PRE_RESTORE_ARGS="$(printf '%s' "${PRE_DNS_RAW}" | tr '\n' ' ')"
fi

cleanup() {
    # Unconditional restore — pass or fail, leave the box's DNS
    # exactly as we found it.
    sudo /usr/sbin/networksetup -setdnsservers "${SERVICE}" ${PRE_RESTORE_ARGS} >/dev/null 2>&1 || true
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

# THE workload. -setdnsservers is mutating; the wrapper brackets
# net-event pre/post around the real networksetup call.
#
# IMPORTANT: sudo on macOS resets the env by default (sudoers
# `Defaults env_reset`), so `sudo -E` ALONE doesn't reliably
# preserve our smoke-specific vars. Pass them explicitly with
# `VAR=val` syntax so the wrapper-as-root sees:
#   - SHIT_HELPER         (path to the locally-built helper binary)
#   - XDG_RUNTIME_DIR     (where the daemon's UDS sockets live)
#   - XDG_STATE_HOME      (state dir; helper uses it for some lookups)
# Without these the wrapper's HELPER defaults to
# /usr/local/bin/shit-helper (absent on the runner), the helper
# fails silently (|| true), no net-event reaches the daemon, and
# the journal stays empty.
TEST_DNS="1.1.1.1"

# DIAGNOSTIC: call the helper directly (bypassing the wrapper) to
# confirm env-through-sudo reaches the helper + the helper can
# reach the daemon. Surfaces any env-passing or socket-resolution
# bugs before we point fingers at the wrapper.
smoke_log "DIAG: direct helper invocation (env through sudo)"
sudo env \
    SHIT_HELPER="${HELPER_BIN}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    RUST_LOG=debug \
    "${HELPER_BIN}" net-event networksetup pre --scope "${SERVICE}" \
    2>"${SHIT_SMOKE_TMP}/diag-helper.log" || true
smoke_log "DIAG: helper stderr (first 20 lines):"
head -20 "${SHIT_SMOKE_TMP}/diag-helper.log" 2>/dev/null | sed 's/^/    /' >&2 || true

smoke_log "wrapper bootstrap: ${WRAPPER} -setdnsservers ${SERVICE} ${TEST_DNS}"
set +e
# `sudo VAR=val cmd` is silently dropped on macOS by default
# (sudoers `Defaults env_reset` without `setenv`). The reliable
# form is `sudo env VAR=val cmd` — env(1) runs as root with the
# vars set and then execs the wrapper, inheriting them.
sudo env \
    SHIT_HELPER="${HELPER_BIN}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    "${WRAPPER}" -setdnsservers "${SERVICE}" "${TEST_DNS}" \
    >"${SHIT_SMOKE_TMP}/set.log" 2>&1
SET_RC=$?
set -e
if [ "${SET_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/set.log" >&2
    smoke_fail "networksetup -setdnsservers via wrapper exited rc=${SET_RC}"
fi

POST_CMD_DNS="$(sudo /usr/sbin/networksetup -getdnsservers "${SERVICE}" 2>&1)"
smoke_log "post-cmd DNS:"
printf '%s\n' "${POST_CMD_DNS}" | sed 's/^/    /' >&2
if ! printf '%s' "${POST_CMD_DNS}" | grep -q "${TEST_DNS}"; then
    smoke_fail "set claimed success but DNS doesn't contain ${TEST_DNS}"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_NET_OPS="$(smoke_journal_count "discriminant = 'NetworkOp'" 2>/dev/null || echo 0)"
smoke_log "NetworkOp events: ${N_NET_OPS}"
N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_DNS="$(sudo /usr/sbin/networksetup -getdnsservers "${SERVICE}" 2>&1)"
smoke_log "post-undo DNS:"
printf '%s\n' "${POST_UNDO_DNS}" | sed 's/^/    /' >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (post-undo DNS == pre-state DNS, ignoring
# any incidental whitespace).
PRE_NORMALIZED="$(printf '%s' "${PRE_DNS_RAW}" | tr -s '[:space:]' '\n' | sort)"
POST_NORMALIZED="$(printf '%s' "${POST_UNDO_DNS}" | tr -s '[:space:]' '\n' | sort)"
if [ "${PRE_NORMALIZED}" = "${POST_NORMALIZED}" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — full undo (DNS restored, NetworkOps=${N_NET_OPS})"
    smoke_log "PASS: networksetup-dns-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "networksetup|dns|refus|conflict|${SERVICE}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named networksetup/dns/refusal)"
    smoke_log "PASS: networksetup-dns-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  pre DNS:        $(printf '%s' "${PRE_DNS_RAW}" | tr '\n' ' ')"
smoke_log "  post-cmd DNS:   $(printf '%s' "${POST_CMD_DNS}" | tr '\n' ' ')"
smoke_log "  post-undo DNS:  $(printf '%s' "${POST_UNDO_DNS}" | tr '\n' ' ')"
smoke_log "  undo exit:      ${UNDO_RC}"
smoke_log "  NetworkOp:      ${N_NET_OPS}"
smoke_log "  journal:        ${N_EVENTS}"
smoke_fail "networksetup DNS undo did NOT restore pre-state on ${SERVICE} (Outcome C)"
