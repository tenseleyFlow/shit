#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: hook-ipc
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# DR smoke #2 — full hook-IPC roundtrip.
#
# Exercises:
#   1. SessionOpen registers a session.
#   2. PreExec opens a command window keyed on $$.
#   3. PostExec closes it cleanly.
#
# Doesn't assert journal-events (capture-side wiring is per-tier and
# covered by the apt/dnf/etc smokes). What this asserts is the
# daemon's hook-socket roundtrip: no decode errors, no drops, the
# active-command tracker took the PreExec and released on PostExec.
#
# Run after daemon-boot smoke — same lib, same shape.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

smoke_start_shitd

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

# Generate a session UUID. Python's uuid is on every GH runner.
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" \
    --pid "${PID}" \
    --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" \
    --seq 1 \
    --pid "${PID}" \
    --cwd "$(pwd)" \
    --shell bash \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq 1 \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "SessionClose"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" \
    --sock "${SHIT_HOOK_SOCK}"

# Drain a moment so async writes settle through the group-commit
# boundary (5ms default, 1000-row max).
sleep 0.5

# Validate the session row landed. The daemon writes one row to
# `sessions` on SessionOpen and one to `commands` on PreExec.
sessions="$(smoke_journal_query 'SELECT COUNT(*) FROM sessions;' 2>/dev/null || echo 0)"
commands="$(smoke_journal_query 'SELECT COUNT(*) FROM commands;' 2>/dev/null || echo 0)"
smoke_log "after roundtrip: sessions=${sessions} commands=${commands}"

if [ "${sessions}" -ne 1 ]; then
    smoke_log "sessions table dump:"
    smoke_journal_query 'SELECT * FROM sessions;' 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "expected 1 session, got ${sessions}"
fi
if [ "${commands}" -ne 1 ]; then
    smoke_log "commands table dump:"
    smoke_journal_query 'SELECT * FROM commands;' 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "expected 1 command, got ${commands}"
fi

# Validate no panic / no error landed in the daemon log.
if grep -E 'ERROR|panicked|panic at' "${SHIT_SMOKE_TMP}/shitd.log" >/dev/null; then
    smoke_log "shitd log has errors:"
    grep -E 'ERROR|panicked|panic at' "${SHIT_SMOKE_TMP}/shitd.log" \
        | sed 's/^/    /' >&2
    smoke_fail "daemon logged errors during the hook roundtrip"
fi

smoke_log "PASS: hook-ipc"
