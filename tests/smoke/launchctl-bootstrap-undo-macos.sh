#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: launchctl-bootstrap-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M05.2 — end-to-end `launchctl bootstrap` → `shit undo` →
# `launchctl bootout` round-trip on macOS.
#
# Validates three layers in concert:
# 1. Wrapper: `launchctl-wrapper` extracts the Label key from the
#    plist when bootstrap is invoked with a bare `gui/<uid>` target
#    (M05.2 wrapper fix). Without this the unit name is empty and
#    the daemon journals nothing identifiable.
# 2. Daemon: `svc_track` ingests the launchctl bootstrap event,
#    journals a ServiceOp with the captured `before` (service not
#    loaded) and `after` (loaded) state.
# 3. Executor: planner's `launchctl_argv` synthesizes
#    `launchctl bootout gui/<uid>/<label>` as the reverse and the
#    SvcRunner spawns it.
#
# Per-run isolation: unique label tagged with $$ so concurrent
# runs don't collide on the same launchd target.
#
# Outcomes:
#   A. Full undo: service gone from launchctl print post-undo.
#   B. Loud refusal: undo non-zero AND log mentions launchctl /
#      bootout / the service label. Accepted as graceful failure.
#   C. Silent partial undo (FAIL): service still loaded + undo exit 0.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: launchctl-bootstrap-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/svc-hooks/launchctl-wrapper"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -x "${WRAPPER}" ]    || smoke_fail "launchctl-wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_HELPER="${HELPER_BIN}"

# Per-run unique label so concurrent smokes don't collide.
LABEL="com.tenseleyflow.shit-smoke.m05.$$"
DOMAIN="gui/$(id -u)"
TARGET_FULL="${DOMAIN}/${LABEL}"
PLIST="${SHIT_SMOKE_TMP}/${LABEL}.plist"

# Tiny LaunchAgent: prints "ok" to /dev/null. KeepAlive=false so
# launchd doesn't keep restarting it after one shot.
cat > "${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>echo ok</string>
    </array>
    <key>KeepAlive</key>
    <false/>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
EOF
smoke_log "plist: ${PLIST}"
smoke_log "label: ${LABEL}"

# Pre-flight: ensure no stale entry from a prior failed run.
/bin/launchctl bootout "${TARGET_FULL}" 2>/dev/null || true
if /bin/launchctl print "${TARGET_FULL}" >/dev/null 2>&1; then
    smoke_fail "${TARGET_FULL} still loaded after pre-flight bootout"
fi

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

smoke_log "launchctl wrapper bootstrap ${DOMAIN} ${PLIST}"
set +e
"${WRAPPER}" bootstrap "${DOMAIN}" "${PLIST}" \
    >"${SHIT_SMOKE_TMP}/bootstrap.log" 2>&1
BOOTSTRAP_RC=$?
set -e
if [ "${BOOTSTRAP_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/bootstrap.log" >&2
    smoke_fail "launchctl bootstrap via wrapper exited rc=${BOOTSTRAP_RC}"
fi
if ! /bin/launchctl print "${TARGET_FULL}" >/dev/null 2>&1; then
    smoke_fail "bootstrap claimed success but ${TARGET_FULL} not loaded"
fi
smoke_log "post-cmd: launchctl print ${TARGET_FULL} OK (service loaded)"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_SVC_OPS="$(smoke_journal_count "discriminant = 'ServiceOp'" 2>/dev/null || echo 0)"
smoke_log "ServiceOp events: ${N_SVC_OPS}"
N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_LOADED="no"
if /bin/launchctl print "${TARGET_FULL}" >/dev/null 2>&1; then
    POST_UNDO_LOADED="yes"
fi
smoke_log "post-undo: launchctl print ${TARGET_FULL} loaded=${POST_UNDO_LOADED}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Cleanup whether we pass or fail.
/bin/launchctl bootout "${TARGET_FULL}" 2>/dev/null || true

# Outcome A — full undo
if [ "${POST_UNDO_LOADED}" = "no" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — full undo (service bootout'd, ServiceOps=${N_SVC_OPS})"
    smoke_log "PASS: launchctl-bootstrap-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "launchctl|bootout|service|refus|conflict|${LABEL}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named launchctl/service/refusal)"
    smoke_log "PASS: launchctl-bootstrap-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  pre:             not loaded"
smoke_log "  post-cmd:        loaded"
smoke_log "  post-undo:       loaded=${POST_UNDO_LOADED}"
smoke_log "  undo exit:       ${UNDO_RC}"
smoke_log "  ServiceOp:       ${N_SVC_OPS}"
smoke_log "  journal events:  ${N_EVENTS}"
smoke_fail "launchctl bootstrap undo did NOT bootout ${LABEL} (Outcome C)"
