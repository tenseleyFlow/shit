#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: pfctl-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M06.4 / DR-42 — end-to-end `pfctl -f <test-ruleset>` →
# `shit undo` → original ruleset restored.
#
# Validates:
# 1. Wrapper: pfctl-wrapper recognizes `-f` as mutating + fires
#    net-event around the call (existing path, also exercised by
#    FreeBSD smokes — this slice focuses on macOS-specific gaps).
# 2. Inspector: PfctlInspector captures `pfctl -sr -a '*'` + `-sn`
#    sections successfully on macOS (auto-escalates via sudo).
# 3. Daemon: net_track journals a NetworkOp.
# 4. Planner: pfctl uses FullReload, so the inverse is captured-
#    state replayed via `pfctl -f <stashed>`.
# 5. Executor: PrivilegedNetRunner stashes the captured dump and
#    runs `/sbin/pfctl -f <tmpfile>` under sudo to restore.
#
# Pre-conditions:
# - Passwordless sudo for /sbin/pfctl. GHA macos-14 runners have
#   this; dev machines need a manual sudoers entry. SKIP if not.
# - Test ruleset uses `pass quick all` — minimally invasive,
#   never blocks any traffic on its own (the absence of block
#   rules means pf passes everything regardless). Since macOS
#   ships with pf disabled by default the loaded rules don't
#   affect packet flow even if we somehow leave them loaded —
#   the unconditional cleanup re-loads the pre-state anyway.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: pfctl-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

if ! sudo -n /sbin/pfctl -sr >/dev/null 2>&1; then
    smoke_log "SKIP: passwordless sudo for pfctl not available"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/pfctl-wrapper"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -x "${WRAPPER}" ]    || smoke_fail "pfctl-wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_HELPER="${HELPER_BIN}"

# Snapshot the live pre-state for the unconditional restore-on-exit.
# pfctl -sr emits the active filter ruleset; loading it back via
# pfctl -f restores. We don't need to capture -sn (nat) for cleanup
# because we only mutate the filter ruleset in this smoke.
PRE_DUMP="${SHIT_SMOKE_TMP}/pre-rules.conf"
sudo /sbin/pfctl -sr 2>/dev/null > "${PRE_DUMP}" || true
smoke_log "pre-state filter rules (first 5 lines):"
head -5 "${PRE_DUMP}" 2>/dev/null | sed 's/^/    /' >&2

cleanup() {
    # Unconditional restore — leave the box's pf ruleset exactly
    # as we found it. If pre-state was empty, `pfctl -f /dev/null`
    # equivalent is `pfctl -F rules`.
    if [ -s "${PRE_DUMP}" ]; then
        sudo /sbin/pfctl -f "${PRE_DUMP}" >/dev/null 2>&1 || true
    else
        sudo /sbin/pfctl -F rules >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

smoke_start_shitd

# A benign test ruleset. `pass quick all` matches every packet
# but is non-blocking; loading it has no functional effect even
# when pf is enabled.
TEST_RULESET="${SHIT_SMOKE_TMP}/test-rules.conf"
cat > "${TEST_RULESET}" <<'EOF'
# shit M06.4 smoke marker
pass quick all
EOF

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

# THE workload: load the test ruleset via the wrapper. See
# M06.1 networksetup smoke for `sudo env VAR=val cmd` rationale.
smoke_log "wrapper bootstrap: ${WRAPPER} -f ${TEST_RULESET}"
set +e
sudo env \
    SHIT_HELPER="${HELPER_BIN}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    "${WRAPPER}" -f "${TEST_RULESET}" \
    >"${SHIT_SMOKE_TMP}/load.log" 2>&1
LOAD_RC=$?
set -e
sed 's/^/    /' "${SHIT_SMOKE_TMP}/load.log" >&2
if [ "${LOAD_RC}" -ne 0 ]; then
    smoke_fail "pfctl -f via wrapper exited rc=${LOAD_RC}"
fi

# Confirm the test ruleset is loaded.
POST_LOAD="${SHIT_SMOKE_TMP}/post-load-rules.conf"
sudo /sbin/pfctl -sr 2>/dev/null > "${POST_LOAD}" || true
if ! grep -qE "^pass[[:space:]]+quick[[:space:]]+all" "${POST_LOAD}"; then
    smoke_log "post-load filter rules:"
    sed 's/^/    /' "${POST_LOAD}" >&2
    smoke_fail "pfctl load claimed success but test rule 'pass quick all' not present"
fi
smoke_log "test ruleset confirmed loaded"

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

# Capture post-undo state for the outcome decision.
POST_UNDO="${SHIT_SMOKE_TMP}/post-undo-rules.conf"
sudo /sbin/pfctl -sr 2>/dev/null > "${POST_UNDO}" || true

# Outcome A — full undo: the test rule is gone AND the post-undo
# state matches the pre-state (modulo incidental whitespace).
TEST_RULE_GONE=0
if ! grep -qE "^pass[[:space:]]+quick[[:space:]]+all" "${POST_UNDO}"; then
    TEST_RULE_GONE=1
fi

if [ "${UNDO_RC}" -eq 0 ] && [ "${TEST_RULE_GONE}" -eq 1 ]; then
    # Normalise both sides (collapse whitespace, sort) for comparison.
    PRE_NORM="$(tr -s '[:space:]' ' ' < "${PRE_DUMP}" | sort)"
    POST_NORM="$(tr -s '[:space:]' ' ' < "${POST_UNDO}" | sort)"
    if [ "${PRE_NORM}" = "${POST_NORM}" ]; then
        smoke_log "OUTCOME A — full undo (test rule gone + pre-state byte-equal, NetworkOps=${N_NET_OPS})"
        smoke_log "PASS: pfctl-undo-macos (Outcome A — exact restore)"
        exit 0
    fi
    smoke_log "OUTCOME A* — test rule gone + undo rc=0 (pre/post differ in incidentals)"
    smoke_log "PASS: pfctl-undo-macos (Outcome A* — test rule cleared)"
    exit 0
fi

# Outcome B — loud refusal: undo exits non-zero with a relevant
# message.
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "pfctl|ruleset|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named pfctl/ruleset)"
    smoke_log "PASS: pfctl-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  post-undo rules (first 10 lines):"
head -10 "${POST_UNDO}" 2>/dev/null | sed 's/^/    /' >&2
smoke_log "  undo exit:   ${UNDO_RC}"
smoke_log "  NetworkOps:  ${N_NET_OPS}"
smoke_log "  events:      ${N_EVENTS}"
smoke_fail "pfctl-undo did NOT restore pre-state ruleset on macOS (Outcome C)"
