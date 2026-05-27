#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: pfctl-add-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# B01 smoke — `pfctl -f <new ruleset>; shit undo` restores the prior
# ruleset.
#
# Exercises:
#   1. helper's `net-event pfctl pre` snapshots the live pf state via
#      `pfctl -s rules` / -s nat / -s tables / -sa (concatenated).
#   2. The real `pfctl -f <test ruleset>` loads a new ruleset.
#   3. helper's `net-event pfctl post` snapshots the new state.
#   4. Daemon diffs pre/post (network_diff) → journals a
#      NetworkOp event with the captured before-state blob.
#   5. `shit undo` plans `InverseOp::NetworkRollback { ... }` and
#      executes via NetworkExecutor → PrivilegedNetRunner →
#      `doas /sbin/pfctl -f <before-state.dump>`.
#
# Prereqs on the FreeBSD VM:
#   - `doas` (or `sudo`) configured for the test user.
#   - pf kernel module loaded with a permissive baseline (else this
#     smoke SKIPs with a one-time setup hint). One-time setup:
#       doas kldload pf
#       echo 'pass all' | doas tee /etc/pf.conf
#       doas service pf onestart
#   - `python3`, `sqlite3`.
#
# Safety: this smoke deliberately loads `pass all` ruleset(s) so SSH
# is never filtered. We never `pfctl -F all` here — that's B01.6.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: pfctl-add-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

PRIV=""
if command -v doas >/dev/null 2>&1; then
    PRIV="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: neither doas nor sudo on PATH; pfctl smoke needs root"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

# Pre-flight: pf must be loaded. /dev/pf existence is the quickest
# probe; pfctl -si is the authoritative check but needs root.
if [ ! -e /dev/pf ]; then
    smoke_log "SKIP: pf kernel module not loaded (/dev/pf absent)"
    smoke_log "      one-time VM setup:"
    smoke_log "        ${PRIV} kldload pf"
    smoke_log "        echo 'pass all' | ${PRIV} tee /etc/pf.conf"
    smoke_log "        ${PRIV} service pf onestart"
    exit 0
fi

# Sanity-check pf is actually filtering nothing (or 'pass all') —
# the smoke MUST NOT proceed if there's a real filter that might
# drop SSH when we replace the ruleset.
SAFE_BASELINE=0
if ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -qE '^pass +all'; then
    SAFE_BASELINE=1
elif [ -z "$(${PRIV} /sbin/pfctl -sr 2>/dev/null)" ]; then
    SAFE_BASELINE=1  # empty ruleset; default is pass-on-no-match
fi
if [ "${SAFE_BASELINE}" -ne 1 ]; then
    smoke_log "SKIP: pf has a non-trivial ruleset; refusing to mutate (may break SSH)"
    smoke_log "      current ruleset:"
    ${PRIV} /sbin/pfctl -sr 2>&1 | head -5 | sed 's/^/        /'
    smoke_log "      to run this smoke safely, reset to a 'pass all' baseline first"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Capture baseline so the EXIT trap can restore even on a smoke
# crash. We snapshot 'pfctl -sr' before doing anything.
BASELINE_RULES="$(${PRIV} /sbin/pfctl -sr 2>/dev/null || true)"
cleanup() {
    # MUST call smoke_stop_shitd because we're overriding lib.sh's
    # EXIT trap. Without it, shitd is orphaned and the CI action's
    # SSH session waits for its inherited fds to close → 5-min hang.
    smoke_stop_shitd 2>/dev/null || true
    # Best-effort restore: rewrite a 'pass all' ruleset.
    # The captured BASELINE_RULES may be empty (default); 'pass all'
    # is the equivalent of empty for our purposes.
    echo 'pass all' | ${PRIV} tee /etc/pf-shit-smoke-restore.conf >/dev/null
    ${PRIV} /sbin/pfctl -f /etc/pf-shit-smoke-restore.conf >/dev/null 2>&1 || true
    ${PRIV} rm -f /etc/pf-shit-smoke-restore.conf 2>/dev/null || true
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

# Author a test ruleset that's still safe (passes all) but distinct
# from baseline. We use a labelled rule so the diff is detectable.
TEST_RULESET="${SHIT_SMOKE_TMP}/test-rules.conf"
cat >"${TEST_RULESET}" <<'EOF'
# B01 smoke test ruleset — labelled pass-all
pass all label "shit-b01-smoke"
EOF
smoke_log "test ruleset: ${TEST_RULESET}"

smoke_log "net-event pre"
"${HELPER_BIN}" net-event pfctl pre --verb=-f --scope-hint="" \
    --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} pfctl -f ${TEST_RULESET}"
${PRIV} /sbin/pfctl -f "${TEST_RULESET}" \
    || smoke_fail "pfctl -f failed (baseline may be filtering — should have SKIPped above)"

# Verify the new ruleset is active.
if ! ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -q 'shit-b01-smoke'; then
    smoke_fail "test ruleset not active after pfctl -f"
fi

smoke_log "net-event post"
"${HELPER_BIN}" net-event pfctl post --verb=-f --scope-hint="" \
    --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Wait for the daemon to journal the NetworkOp event.
smoke_wait_for_event "discriminant = 'NetworkOp'" 1 10

smoke_log "running: shit undo --yes"
export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: the 'shit-b01-smoke' label should be gone.
sleep 0.5
if ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -q 'shit-b01-smoke'; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "test ruleset still active after undo — pf rollback didn't fire"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: pfctl-add-undo-fbsd (test ruleset loaded→undone)"
