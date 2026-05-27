#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: sqlite3-db
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# DR-58 smoke — sqlite3 wrapper bracket-fires the daemon, DbOp
# event lands in the journal.
#
# sqlite3 is unprivileged and ships ubiquitously. We stage the
# wrapper as `sqlite3` so its basename resolution finds the real
# binary, then run `sqlite3 <tmpdb> "INSERT ..."`.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if ! command -v sqlite3 >/dev/null 2>&1; then
    smoke_log "sqlite3 not present; skipping"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "python3 not present; skipping"
    exit 0
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER_SRC="${SHIT_REPO_ROOT}/packaging/db-hooks/sqlite3-wrapper"

# Stage as `sqlite3` so the wrapper's basename resolution finds the
# real sqlite3 (skipping our copy via readlink).
WRAPPER_DIR="${SHIT_SMOKE_TMP}/bin"
mkdir -p "${WRAPPER_DIR}"
cp "${WRAPPER_SRC}" "${WRAPPER_DIR}/sqlite3"
chmod +x "${WRAPPER_DIR}/sqlite3"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

DB_FILE="${SHIT_SMOKE_TMP}/smoke.db"

export SHIT_HELPER="${HELPER}"
smoke_log "wrapper sqlite3 ${DB_FILE} CREATE+INSERT"
"${WRAPPER_DIR}/sqlite3" "${DB_FILE}" \
    "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);" \
    "INSERT INTO t (name) VALUES ('alice');"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

n="$(smoke_journal_count "discriminant = 'DbOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_log "DbOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected DbOp event after sqlite3 INSERT; saw ${n}"
fi
smoke_log "DbOp events: ${n}"
smoke_log "PASS: sqlite3-db"
