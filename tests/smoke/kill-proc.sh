#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: kill-proc
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# DR-53 smoke — kill-wrapper bracket-fires the daemon, ProcessOp
# event lands in the journal.
#
# Spawns a doomed `sleep` child, then routes `kill <pid>` through
# the kill-wrapper. The wrapper picks `real kill` by basename so we
# stage a copy named `kill` in our tempdir.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if ! command -v sleep >/dev/null 2>&1 || ! command -v kill >/dev/null 2>&1; then
    smoke_log "sleep/kill not present; skipping"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "python3 not present; skipping"
    exit 0
fi
# The helper's proc enumerator is Linux-only today (DR-48/49 cover
# macOS/BSD). Without /proc, target snapshots come back empty and
# no ProcessOp event is journaled. Skip on non-Linux.
if [ ! -r /proc/self/stat ]; then
    smoke_log "/proc not available (macOS/BSD); skipping (DR-48/49 needed)"
    exit 0
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER_SRC="${SHIT_REPO_ROOT}/packaging/proc-hooks/kill-wrapper"

# Stage the wrapper as `kill` so $0 basename resolves correctly and
# `real kill` is found at /bin/kill or /usr/bin/kill (skipping our
# copy via the readlink check in the wrapper).
WRAPPER_DIR="${SHIT_SMOKE_TMP}/bin"
mkdir -p "${WRAPPER_DIR}"
cp "${WRAPPER_SRC}" "${WRAPPER_DIR}/kill"
chmod +x "${WRAPPER_DIR}/kill"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Spawn a doomed child. Detach via setsid so the kill doesn't race
# with bash's own job notifications.
sleep 600 &
DOOMED=$!
SHIT_SMOKE_PIDS+=("${DOOMED}")
sleep 0.2

# Verify the process is alive before we kill it.
if ! kill -0 "${DOOMED}" 2>/dev/null; then
    smoke_fail "doomed sleep child (${DOOMED}) not running"
fi
smoke_log "doomed sleep pid=${DOOMED} alive; about to kill via wrapper"

export SHIT_HELPER="${HELPER}"
"${WRAPPER_DIR}/kill" "${DOOMED}"

# Reap if not already gone.
wait "${DOOMED}" 2>/dev/null || true

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
    smoke_fail "expected ProcessOp event after kill; saw ${n}"
fi
smoke_log "ProcessOp events: ${n}"
smoke_log "PASS: kill-proc"
