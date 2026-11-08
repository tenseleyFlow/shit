#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-redirect-unresolvable-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice D — a redirect target the hook cannot resolve (`$NOPE/out`)
# cannot be pre-stashed. The command still runs.
#
#   Phase 1, SHIT_STRICT_CAPTURE=1: the daemon journals a CaptureRefused
#   row naming the target, and `shit undo` refuses with capture-incomplete.
#
#   Phase 2, flag unset: the same command journals no CaptureRefused row
#   and undo prints no capture-incomplete refusal (trunk behavior).
#
# Validate-the-gap: trunk has no strict mode, so the row cannot appear.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-redirect-unresolvable-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

run_phase() {
    local label="$1"
    local dir="${SHIT_SMOKE_TMP}/${label}-dir"
    mkdir -p "${dir}"
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    cd "${dir}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "$$" \
        --cwd "${dir}" --shell bash --sock "${SHIT_HOOK_SOCK}"
    sleep 0.5
    # shellcheck disable=SC2016
    "${SHIT_BIN}" hook-send pre-exec-redirects \
        --session "${session}" --seq 1 \
        --cmdline 'echo x > $NOPE/out' \
        --sock "${SHIT_HOOK_SOCK}" 2> "${SHIT_SMOKE_TMP}/${label}.hook.log"
    sleep 0.3
    NOPE="${dir}" bash -c 'echo x > "$NOPE/out"'
    [ -f "${dir}/out" ] || smoke_fail "[${label}] command did not run"
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    cd "${SHIT_SMOKE_TMP}"
    sleep 1.0
    set +e
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/${label}.undo.log" 2>&1
    local rc=$?
    set -e
    smoke_log "[${label}] shit undo --yes exit=${rc}"
    sed 's/^/    undo: /' "${SHIT_SMOKE_TMP}/${label}.undo.log" >&2 || true
    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"
}

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
run_phase strict
smoke_wait_for_event "discriminant = 'CaptureRefused'" 1 10
STRICT_ROWS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
# Hosts without a kernel tier add their own tier-less refusal, so the
# redirect row is identified by its detail text, not by a row count.
REDIRECT_LINES="$(grep -c "redirect pre-stash failed for" "${SHIT_SMOKE_TMP}/strict.undo.log" || true)"
[ "${REDIRECT_LINES}" -eq 1 ] \
    || smoke_fail "strict: expected 1 redirect refusal line, got ${REDIRECT_LINES}"
grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/strict.undo.log" \
    || smoke_fail "strict: undo did not refuse with capture-incomplete"
# shellcheck disable=SC2016
grep -qF '$NOPE/out' "${SHIT_SMOKE_TMP}/strict.undo.log" \
    || smoke_fail "strict: refusal does not name the unresolved target"
smoke_stop_shitd

unset SHIT_STRICT_CAPTURE
smoke_start_shitd
run_phase default
DEFAULT_ROWS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
[ "${DEFAULT_ROWS}" -eq "${STRICT_ROWS}" ] \
    || smoke_fail "default: CaptureRefused rows grew from ${STRICT_ROWS} to ${DEFAULT_ROWS} with the flag unset"
if grep -q "capture-incomplete\|redirect pre-stash failed" "${SHIT_SMOKE_TMP}/default.undo.log"; then
    smoke_fail "default: undo refused although strict mode is off"
fi

smoke_log "PASS: strict-redirect-unresolvable-linux (strict refused, default proceeded)"
