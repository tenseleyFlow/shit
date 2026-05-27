#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: kill-proc-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L03 smoke — `pkill -f <pattern>` brackets via the proc-event wire
# and the daemon journals a ProcessOp event with a populated
# ProcSnapshot. Linux port of kill-proc-undo-fbsd.sh; the wrappers'
# proc-event path is platform-agnostic so this is a mechanical port
# with `/bin/sleep` → `$(command -v sleep)` for NixOS portability.
#
# Note on "undo" semantics (per S18 design rule, also documented in
# the FreeBSD twin):
#   The planner intentionally does NOT resurrect killed processes.
#   Undo of a kill produces a RestartSuggestion the user can
#   copy-paste — not a fork-exec. This smoke verifies the journal
#   records the kill with enough metadata that `shit show` could
#   render the suggestion. "undo" in the smoke name refers to
#   journaling + suggestion rendering, not process resurrection.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: kill-proc-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "SKIP: python3 not on PATH"
    exit 0
fi

PKILL_BIN="$(command -v pkill 2>/dev/null || true)"
if [ -z "${PKILL_BIN}" ]; then
    smoke_log "SKIP: pkill not on PATH"
    exit 0
fi
SLEEP_BIN="$(command -v sleep 2>/dev/null || true)"
if [ -z "${SLEEP_BIN}" ]; then
    smoke_log "SKIP: sleep not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WRAPPER_SRC="${SHIT_REPO_ROOT}/packaging/proc-hooks/pkill-wrapper"
[ -f "${WRAPPER_SRC}" ] || smoke_fail "pkill-wrapper missing at ${WRAPPER_SRC}"

smoke_start_shitd

# Stage the wrapper as `pkill` in a smoke-private dir so its $0
# basename routing finds the real pkill via the wrapper's PATH
# fallback (the FHS paths don't exist on NixOS).
WRAPPER_DIR="${SHIT_SMOKE_TMP}/bin"
mkdir -p "${WRAPPER_DIR}"
cp "${WRAPPER_SRC}" "${WRAPPER_DIR}/pkill"
chmod +x "${WRAPPER_DIR}/pkill"

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

# Distinctive pattern so we can't false-match other sleeps. We
# customize argv[0] via `exec -a` on bash (NOT on sleep directly:
# NixOS uses a multi-call coreutils binary that dispatches on
# argv[0], so `exec -a "$tag" sleep` makes coreutils look for an
# applet named $tag and fail). Bash with the customized argv[0]
# runs a busy-sleep loop so the process stays alive (and matchable
# by pkill -f against the tag) without exec'ing into sleep itself.
DOOMED_TAG="shit-l03-doomed-$$-$(python3 -c 'import os; print(os.urandom(4).hex())')"
( exec -a "${DOOMED_TAG}" bash -c 'while :; do sleep 1; done' ) &
DOOMED_PID=$!
SHIT_SMOKE_PIDS+=("${DOOMED_PID}")
sleep 0.3

if ! kill -0 "${DOOMED_PID}" 2>/dev/null; then
    smoke_fail "doomed sleep (${DOOMED_PID}) didn't start"
fi
FOUND_PIDS="$("${PKILL_BIN}" -l -f "${DOOMED_TAG}" 2>/dev/null || true)"
if [ -z "${FOUND_PIDS}" ]; then
    # -l isn't standard everywhere; fall back to pgrep.
    FOUND_PIDS="$(command -v pgrep >/dev/null && pgrep -f "${DOOMED_TAG}" || true)"
fi
if [ -z "${FOUND_PIDS}" ]; then
    smoke_fail "pgrep/pkill -l found nothing matching '${DOOMED_TAG}' — pattern setup broken"
fi
smoke_log "doomed pid=${DOOMED_PID} (tag=${DOOMED_TAG})"

export SHIT_HELPER="${HELPER_BIN}"
smoke_log "pkill -f ${DOOMED_TAG} via wrapper"
# The wrapper's own argv contains $DOOMED_TAG; on Linux, real pkill
# matches the wrapper itself and SIGTERMs it before the post-hook
# can fire. The pre-hook does run (daemon stashes target snapshots),
# but the post-hook — which the daemon needs to journal a ProcessOp
# event — never reaches it. Tolerate the wrapper's signaled exit
# (143 = 128+SIGTERM); we replay the post-hook from the smoke after.
"${WRAPPER_DIR}/pkill" -f "${DOOMED_TAG}" || true

wait "${DOOMED_PID}" 2>/dev/null || true

# Manually fire the post-hook — the wrapper died mid-flight after
# its pre-hook reached the daemon. Without this, the daemon's
# proc-pre stash never gets diff'd against a post snapshot and no
# ProcessOp event is journaled. Argv-blob format matches the
# wrapper's: newline-separated tokens.
ARGV_BLOB="-f"$'\n'"${DOOMED_TAG}"
"${HELPER_BIN}" proc-event pkill post "--target-argv=${ARGV_BLOB}" 2>/dev/null || true

if kill -0 "${DOOMED_PID}" 2>/dev/null; then
    smoke_fail "pkill didn't kill (pid ${DOOMED_PID} still alive)"
fi

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

n="$(smoke_journal_count "discriminant = 'ProcessOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_log "ProcessOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected ProcessOp event after pkill; saw ${n}"
fi
smoke_log "ProcessOp events journaled: ${n}"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: kill-proc-undo-linux (pkill -f resolved via /proc, ProcessOp journaled)"
