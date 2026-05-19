# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared helpers for the DR smoke matrix.
#
# Sources from a per-tool script (e.g. tests/smoke/apt.sh). Stays
# POSIX-ish but uses bash for arrays. Designed to run on a fresh
# GitHub Actions runner with sudo available.
#
# Conventions:
# - SHIT_SMOKE_TMP — root tempdir for this run; one per smoke job.
# - shitd runs in the foreground in the background (yes, bash) with
#   XDG_* overrides pointing into SHIT_SMOKE_TMP.
# - State dir: $XDG_STATE_HOME/shit (per config.rs::default_state_dir).
# - Ctl socket: $XDG_RUNTIME_DIR/shit-ctl.sock (per the helper's default).
# - Hook socket: $XDG_RUNTIME_DIR/shit-hook.sock.

set -euo pipefail

: "${SHIT_REPO_ROOT:?must be set to the repo root}"
: "${SHIT_SMOKE_BIN_DIR:=${SHIT_REPO_ROOT}/target/release}"

# Per-run tempdir. Cleaned by smoke_cleanup on exit.
SHIT_SMOKE_TMP="$(mktemp -d -t shit-smoke.XXXXXX)"
export XDG_STATE_HOME="${SHIT_SMOKE_TMP}/state"
export XDG_RUNTIME_DIR="${SHIT_SMOKE_TMP}/runtime"
export XDG_CONFIG_HOME="${SHIT_SMOKE_TMP}/config"
mkdir -p "${XDG_STATE_HOME}" "${XDG_RUNTIME_DIR}" "${XDG_CONFIG_HOME}"
chmod 0700 "${XDG_RUNTIME_DIR}"

SHIT_INDEX_DB="${XDG_STATE_HOME}/shit/index.sqlite"
SHIT_CTL_SOCK="${XDG_RUNTIME_DIR}/shit-ctl.sock"
# Matches shitd::config::default_hook_socket_path when XDG_RUNTIME_DIR
# is set: `${XDG_RUNTIME_DIR}/shit.sock` (no `-hook` infix).
SHIT_HOOK_SOCK="${XDG_RUNTIME_DIR}/shit.sock"
SHITD_PID=""

# Append every started bg process into here; smoke_cleanup kills them.
SHIT_SMOKE_PIDS=()

smoke_log() {
    printf '[smoke %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

smoke_fail() {
    smoke_log "FAIL: $*"
    exit 1
}

# Start shitd in the background. Blocks until the ctl socket appears
# (or 10s have passed, at which point we bail).
smoke_start_shitd() {
    local shitd="${SHIT_SMOKE_BIN_DIR}/shitd"
    if [ ! -x "${shitd}" ]; then
        smoke_fail "shitd binary missing at ${shitd}"
    fi
    smoke_log "starting shitd (state=${XDG_STATE_HOME}/shit)"
    "${shitd}" --foreground >"${SHIT_SMOKE_TMP}/shitd.log" 2>&1 &
    SHITD_PID=$!
    SHIT_SMOKE_PIDS+=("${SHITD_PID}")
    for _ in $(seq 1 100); do
        if [ -S "${SHIT_CTL_SOCK}" ]; then
            smoke_log "shitd ctl socket up (pid=${SHITD_PID})"
            return 0
        fi
        sleep 0.1
    done
    smoke_log "shitd log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/shitd.log" >&2 || true
    smoke_fail "shitd ctl socket never appeared at ${SHIT_CTL_SOCK}"
}

smoke_stop_shitd() {
    if [ -n "${SHITD_PID}" ] && kill -0 "${SHITD_PID}" 2>/dev/null; then
        smoke_log "stopping shitd (pid=${SHITD_PID})"
        kill -TERM "${SHITD_PID}" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "${SHITD_PID}" 2>/dev/null || return 0
            sleep 0.1
        done
        kill -KILL "${SHITD_PID}" 2>/dev/null || true
    fi
}

smoke_cleanup() {
    local rc=$?
    smoke_stop_shitd
    for pid in "${SHIT_SMOKE_PIDS[@]}"; do
        kill -KILL "${pid}" 2>/dev/null || true
    done
    if [ "${SMOKE_KEEP_TMP:-0}" != "1" ]; then
        rm -rf "${SHIT_SMOKE_TMP}"
    else
        smoke_log "SMOKE_KEEP_TMP=1; tmpdir preserved at ${SHIT_SMOKE_TMP}"
    fi
    exit "${rc}"
}
trap smoke_cleanup EXIT

# Run a sqlite query against the index db. Returns stdout; non-zero
# exit means the file doesn't exist yet (the daemon hasn't initialized
# its db) or the query failed.
smoke_journal_query() {
    if [ ! -f "${SHIT_INDEX_DB}" ]; then
        return 1
    fi
    sqlite3 -readonly "${SHIT_INDEX_DB}" "$@"
}

# Count rows in the events table matching `WHERE <predicate>`. Returns
# the count via stdout; on error prints 0.
smoke_journal_count() {
    local predicate="${1:-1=1}"
    local count
    if ! count="$(smoke_journal_query "SELECT COUNT(*) FROM events WHERE ${predicate};")"; then
        printf '0'
        return
    fi
    printf '%s' "${count}"
}

# Poll the journal for up to `timeout_secs` seconds, waiting for the
# event count under `predicate` to reach at least `min`. Exits with
# success when satisfied, failure when the timeout expires.
smoke_wait_for_event() {
    local predicate="$1"
    local min="${2:-1}"
    local timeout="${3:-10}"
    local elapsed=0
    while [ "${elapsed}" -lt $((timeout * 10)) ]; do
        local n
        n="$(smoke_journal_count "${predicate}")"
        if [ "${n}" -ge "${min}" ]; then
            smoke_log "journal: ${n} events matching '${predicate}' (>= ${min})"
            return 0
        fi
        sleep 0.1
        elapsed=$((elapsed + 1))
    done
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_log "shitd log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/shitd.log" >&2 || true
    smoke_fail "timed out waiting for ${min}+ events matching '${predicate}'"
}
