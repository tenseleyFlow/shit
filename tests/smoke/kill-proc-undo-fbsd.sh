#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# B02 smoke — `pkill -f <pattern>` brackets via the proc-event wire
# and the daemon journals a ProcessOp event with a populated
# ProcSnapshot. Mirrors tests/smoke/kill-proc.sh shape but exercises
# the FreeBSD sysctl(KERN_PROC_*) enumeration path that B02 lands.
#
# Note on "undo" semantics:
#   The planner intentionally does NOT resurrect killed processes
#   (S18 design rule). Undo of a kill produces a `RestartSuggestion`
#   the user can copy-paste — NOT a fork-exec. This smoke verifies
#   the journal records the kill with enough metadata that
#   `shit show` could render the suggestion. The "undo" in the
#   smoke name refers to journaling + suggestion rendering, not
#   process resurrection.
#
# Prereqs on the FreeBSD VM:
#   - `doas` (or `sudo`) on PATH (for the standard smoke harness).
#   - `python3`, `sqlite3`.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: kill-proc-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "SKIP: python3 not on PATH"
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
# basename routing finds /usr/bin/pkill (the real one).
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

# Use a distinctive sleep duration so the pattern can't false-match
# other sleeps on the system.
DOOMED_TAG="shit-b02-doomed-$$-$(python3 -c 'import os; print(os.urandom(4).hex())')"
( exec -a "${DOOMED_TAG}" /bin/sleep 3600 ) &
DOOMED_PID=$!
SHIT_SMOKE_PIDS+=("${DOOMED_PID}")
sleep 0.3

# Verify the doomed process is alive and findable.
if ! kill -0 "${DOOMED_PID}" 2>/dev/null; then
    smoke_fail "doomed sleep (${DOOMED_PID}) didn't start"
fi
# pgrep by full-arg pattern should find it.
FOUND_PIDS="$(/bin/pgrep -f "${DOOMED_TAG}" || true)"
if [ -z "${FOUND_PIDS}" ]; then
    smoke_fail "pgrep -f '${DOOMED_TAG}' returned nothing — pattern setup broken"
fi
smoke_log "doomed pid=${DOOMED_PID} (tag=${DOOMED_TAG})"

export SHIT_HELPER="${HELPER_BIN}"
smoke_log "pkill -f ${DOOMED_TAG} via wrapper"
"${WRAPPER_DIR}/pkill" -f "${DOOMED_TAG}"

# Reap.
wait "${DOOMED_PID}" 2>/dev/null || true

# Verify the process is gone.
if kill -0 "${DOOMED_PID}" 2>/dev/null; then
    smoke_fail "pkill didn't kill (pid ${DOOMED_PID} still alive)"
fi

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Verify the ProcessOp event landed in the journal.
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

smoke_log "PASS: kill-proc-undo-fbsd (pkill -f resolved via sysctl, ProcessOp journaled)"
