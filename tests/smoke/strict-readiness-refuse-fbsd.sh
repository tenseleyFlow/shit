#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-readiness-refuse-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice A — strict capture refuses when the helper reports
# WatchTreeFailed; default mode proceeds best-effort.
#
# The PreExec names a watch cwd that does not exist. The BSD capture
# pump cannot register a kqueue subtree there and answers
# WatchTreeFailed instead of WatchTreeReady. The shell hook
# prints one not-ready line with the reason and the command still runs.
#
#   Phase 1, SHIT_STRICT_CAPTURE=1: the daemon journals a command-scoped
#   CaptureRefused row (class capture-incomplete). `shit undo` prints a
#   refusal carrying the attach failure reason.
#
#   Phase 2, flag unset: same command shape, no CaptureRefused row, and
#   undo prints no capture-incomplete refusal (trunk behavior).
#
# Validate-the-gap: trunk already sends WatchTreeFailed on BSD (R1), but
# has no strict mode, so the refusal row cannot appear there.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: strict-readiness-refuse-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
MISSING_CWD="${SHIT_SMOKE_TMP}/no-such-watch-dir"
cd "${SCRATCH}"

# run_phase <label> <seq-tag>: one session, one command whose WatchTree
# fails, then `shit undo --yes`. Leaves hook stderr and undo output in
# ${SHIT_SMOKE_TMP}/<label>.{hook,undo}.log.
run_phase() {
    local label="$1"
    local victim="${SCRATCH}/${label}-victim"
    printf '%s\n' "${label} payload" > "${victim}"
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    smoke_log "[${label}] PreExec with missing watch cwd ${MISSING_CWD}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "$$" \
        --cwd "${MISSING_CWD}" --shell bash \
        --cmdline "rm ${victim}" \
        --sock "${SHIT_HOOK_SOCK}" 2> "${SHIT_SMOKE_TMP}/${label}.hook.log"
    sed 's/^/    hook: /' "${SHIT_SMOKE_TMP}/${label}.hook.log" >&2 || true
    rm "${victim}"
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    [ ! -e "${victim}" ] || smoke_fail "[${label}] command did not run (victim still present)"
    if ! grep -q "not-ready (reason: capture attach failed" "${SHIT_SMOKE_TMP}/${label}.hook.log"; then
        smoke_fail "[${label}] hook did not report WatchTreeFailed as not-ready"
    fi
    set +e
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/${label}.undo.log" 2>&1
    local rc=$?
    set -e
    smoke_log "[${label}] shit undo --yes exit=${rc}"
    sed 's/^/    undo: /' "${SHIT_SMOKE_TMP}/${label}.undo.log" >&2 || true
    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"
}

# Phase 1: strict.
SHIT_STRICT_CAPTURE=1 smoke_start_shitd
run_phase strict
smoke_wait_for_event "discriminant = 'CaptureRefused'" 1 10
STRICT_ROWS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
if ! grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/strict.undo.log"; then
    smoke_fail "strict: undo did not refuse with capture-incomplete"
fi
REASON_LINES="$(grep -c "capture attach failed" "${SHIT_SMOKE_TMP}/strict.undo.log" || true)"
if [ "${REASON_LINES}" -ne 1 ]; then
    smoke_fail "strict: expected exactly one refusal line with the attach reason, got ${REASON_LINES}"
fi
smoke_stop_shitd

# Phase 2: flag unset, same shape.
unset SHIT_STRICT_CAPTURE
smoke_start_shitd
run_phase default
DEFAULT_ROWS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
if [ "${DEFAULT_ROWS}" -ne "${STRICT_ROWS}" ]; then
    smoke_fail "default: CaptureRefused rows grew from ${STRICT_ROWS} to ${DEFAULT_ROWS} with the flag unset"
fi
if grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/default.undo.log"; then
    smoke_fail "default: undo refused with capture-incomplete although strict mode is off"
fi

smoke_log "PASS: strict-readiness-refuse-fbsd (strict refused once, default proceeded)"
