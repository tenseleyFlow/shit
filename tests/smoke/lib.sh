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
    # Stop the daemon so its tracing-appender's WorkerGuard drops
    # and the JSON log is fully flushed to disk. Then dump it so the
    # failure surfaces the daemon-side breadcrumbs.
    smoke_stop_shitd
    smoke_dump_daemon_logs
    exit 1
}

# Dump the daemon's rolling JSON log on failure. The `info`-level
# breadcrumbs the daemon emits (`pkg-event Pre stashed by command`,
# `net-pre stashed`, etc.) land only here, not in shitd.log.
smoke_dump_daemon_logs() {
    local log_dir="${XDG_STATE_HOME}/shit/log"
    if [ -d "${log_dir}" ]; then
        smoke_log "daemon JSON log:"
        find "${log_dir}" -name 'daemon.jsonl*' -type f -print 2>/dev/null \
            | while read -r f; do
                echo "    --- ${f} ---" >&2
                tail -100 "${f}" 2>/dev/null | sed 's/^/    /' >&2 || true
            done
    fi
}

# Start shitd in the background. Blocks until the ctl socket appears
# (or 10s have passed, at which point we bail).
smoke_start_shitd() {
    local shitd="${SHIT_SMOKE_BIN_DIR}/shitd"
    if [ ! -x "${shitd}" ]; then
        smoke_fail "shitd binary missing at ${shitd}"
    fi
    smoke_log "starting shitd (state=${XDG_STATE_HOME}/shit)"
    # Pin RUST_LOG=debug for the daemon so per-tier handlers' debug
    # breadcrumbs (`net-pre stashed`, `svc-pre stashed`, etc.) land
    # in the JSON log — they're the most reliable signal that a
    # helper-side send_event reached the daemon at all.
    # `</dev/null` is load-bearing under cross-platform-actions
    # FreeBSD VMs: without it, shitd inherits the smoke shell's
    # stdin, shit-helper inherits it from shitd, and the SSH session
    # the CI action runs over waits for every fd-holder to close
    # before terminating — surfacing as a 5-minute hang at smoke
    # exit. Local interactive ssh hides this because the terminal
    # fd is implicitly closed when the user closes the session.
    RUST_LOG="${SHIT_SMOKE_RUST_LOG:-debug}" \
        "${shitd}" --foreground \
        </dev/null \
        >"${SHIT_SMOKE_TMP}/shitd.log" 2>&1 &
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
    # === B04.6c INSTRUMENTATION ===
    # Earlier evidence showed bash hangs forever past "stopping shitd"
    # for service-restart, while every other smoke completes here in
    # ~5 sec (SIGTERM ignored, SIGKILL after 5-sec backoff works).
    # Service-restart appears to be the only smoke where SIGKILL is
    # also deferred. Log every step so we see exactly which line
    # blocks.
    printf '[stop-shitd %s] enter (SHITD_PID=%s)\n' "$(date -u +%H:%M:%S)" "${SHITD_PID:-unset}" >&2
    if [ -n "${SHITD_PID}" ] && kill -0 "${SHITD_PID}" 2>/dev/null; then
        printf '[stop-shitd %s] alive — SIGTERM %s\n' "$(date -u +%H:%M:%S)" "${SHITD_PID}" >&2
        kill -TERM "${SHITD_PID}" 2>/dev/null || true
        local i
        for i in $(seq 1 50); do
            kill -0 "${SHITD_PID}" 2>/dev/null || { printf '[stop-shitd %s] gone after SIGTERM (i=%d)\n' "$(date -u +%H:%M:%S)" "${i}" >&2; break; }
            sleep 0.1
        done
        if kill -0 "${SHITD_PID}" 2>/dev/null; then
            printf '[stop-shitd %s] still alive after 5 sec — SIGKILL %s\n' "$(date -u +%H:%M:%S)" "${SHITD_PID}" >&2
            kill -KILL "${SHITD_PID}" 2>/dev/null || true
            # Wait briefly for SIGKILL to take effect; sample state.
            for i in $(seq 1 50); do
                kill -0 "${SHITD_PID}" 2>/dev/null || { printf '[stop-shitd %s] gone after SIGKILL (i=%d)\n' "$(date -u +%H:%M:%S)" "${i}" >&2; break; }
                sleep 0.1
            done
            if kill -0 "${SHITD_PID}" 2>/dev/null; then
                printf '[stop-shitd %s] DEFERRED-SIGKILL — process %s alive 5 sec after SIGKILL\n' "$(date -u +%H:%M:%S)" "${SHITD_PID}" >&2
                printf '[stop-shitd %s] procstat -k:\n' "$(date -u +%H:%M:%S)" >&2
                procstat -k "${SHITD_PID}" 2>&1 | sed 's/^/  /' >&2 || true
                printf '[stop-shitd %s] ps state:\n' "$(date -u +%H:%M:%S)" >&2
                ps -o pid,stat,wchan,command -p "${SHITD_PID}" 2>&1 | sed 's/^/  /' >&2 || true
            fi
        fi
    else
        printf '[stop-shitd %s] not alive (kill -0 failed)\n' "$(date -u +%H:%M:%S)" >&2
    fi
    # Reap any orphaned shit-helper subprocesses. shitd spawns
    # shit-helper as a child on handshake; if shitd dies via SIGKILL
    # before completing graceful teardown, the helper may briefly
    # outlive its parent. On the cross-platform-actions FreeBSD VM,
    # an orphaned helper keeps bash's exit blocked (the SSH session
    # waits for tty-fd-sharing processes). Wait for `wait` to reap
    # the shitd job, then nuke any leftover helpers by name.
    printf '[stop-shitd %s] before wait\n' "$(date -u +%H:%M:%S)" >&2
    wait "${SHITD_PID}" 2>/dev/null || true
    printf '[stop-shitd %s] after wait; pkill shit-helper\n' "$(date -u +%H:%M:%S)" >&2
    pkill -f 'target/release/shit-helper' 2>/dev/null || true
    printf '[stop-shitd %s] return\n' "$(date -u +%H:%M:%S)" >&2
}

smoke_cleanup() {
    local rc=$?
    printf '[cleanup %s] enter (rc=%d)\n' "$(date -u +%H:%M:%S)" "${rc}" >&2
    smoke_stop_shitd
    printf '[cleanup %s] smoke_stop_shitd returned; iterating SHIT_SMOKE_PIDS\n' "$(date -u +%H:%M:%S)" >&2
    # Iterate guarded: precondition-skip paths exit before populating
    # the array, and `set -u` would explode on `"${arr[@]}"` then.
    if [ "${#SHIT_SMOKE_PIDS[@]}" -gt 0 ]; then
        for pid in "${SHIT_SMOKE_PIDS[@]}"; do
            kill -KILL "${pid}" 2>/dev/null || true
        done
    fi
    printf '[cleanup %s] SHIT_SMOKE_PIDS killed; about to rm -rf tmpdir\n' "$(date -u +%H:%M:%S)" >&2
    if [ "${SMOKE_KEEP_TMP:-0}" != "1" ]; then
        # Time-bound the rm so a stuck filesystem (open helper fd, an
        # active kqueue watch still being torn down) can't block bash
        # from exiting. If rm doesn't finish in 5 sec, give up — the
        # CI runner reclaims the FS anyway.
        if command -v timeout >/dev/null 2>&1; then
            timeout 5 rm -rf "${SHIT_SMOKE_TMP}" 2>&1 \
                || printf '[cleanup %s] rm timed-out or errored on %s — leaking tmpdir\n' "$(date -u +%H:%M:%S)" "${SHIT_SMOKE_TMP}" >&2
        else
            rm -rf "${SHIT_SMOKE_TMP}"
        fi
    else
        smoke_log "SMOKE_KEEP_TMP=1; tmpdir preserved at ${SHIT_SMOKE_TMP}"
    fi
    printf '[cleanup %s] rm done; sampling exit-time state (rc=%d)\n' "$(date -u +%H:%M:%S)" "${rc}" >&2
    # === B04.6c FINAL-EXIT INSTRUMENTATION ===
    # All other smokes hit `exit $rc` here and bash terminates within
    # ms. service-restart on cross-platform-actions FBSD hangs at the
    # exit call itself. Dump open fds + any shit-* process state +
    # any process referencing the tmpdir.
    printf '[cleanup %s] open fds for $$=%s (procstat -f):\n' "$(date -u +%H:%M:%S)" "$$" >&2
    procstat -f $$ 2>&1 | sed 's/^/  /' >&2 || true
    printf '[cleanup %s] any shit-* processes anywhere:\n' "$(date -u +%H:%M:%S)" >&2
    pgrep -lf 'shit' 2>&1 | sed 's/^/  /' >&2 || echo "  (none)" >&2
    printf '[cleanup %s] doas processes anywhere:\n' "$(date -u +%H:%M:%S)" >&2
    pgrep -lf 'doas' 2>&1 | sed 's/^/  /' >&2 || echo "  (none)" >&2
    printf '[cleanup %s] cron processes anywhere:\n' "$(date -u +%H:%M:%S)" >&2
    pgrep -lf 'cron' 2>&1 | sed 's/^/  /' >&2 || echo "  (none)" >&2
    # If cron is alive, dump ITS open fds — confirms whether it's
    # the one holding bash's stdout/stderr pipe. `|| true` matters:
    # macOS bash 3.2 + `set -e` + `set -o pipefail` aborts the
    # script on command-substitution-failure-in-assignment when
    # pgrep finds no match (it pipes to head whose exit-0 normally
    # papers over the failure, but pipefail surfaces pgrep's exit-1).
    cron_pid=$(pgrep -x cron 2>/dev/null | head -1 || true)
    if [ -n "${cron_pid}" ]; then
        printf '[cleanup %s] cron(%s) open fds:\n' "$(date -u +%H:%M:%S)" "${cron_pid}" >&2
        procstat -f "${cron_pid}" 2>&1 | sed 's/^/  /' >&2 || true
    fi
    # Safety-net: if `exit $rc` hangs (FBSD CI fd-inheritance quirk
    # we couldn't isolate), force-kill bash in 10 sec. Plain
    # backgrounded subshell — `setsid` isn't in FreeBSD base; using
    # it silently fails on the CI VM. The other smokes exit cleanly
    # with this exact arm pattern, proving the subshell doesn't pin
    # bash at exit. PID-reuse-safe: re-check PID's comm+ppid before
    # killing — otherwise the PID was freed by clean exit and reused.
    target_pid=$$
    target_ppid=$PPID
    safety_net_log="/tmp/safety-net.${target_pid}.log"
    (
        sleep 10
        cur_comm=$(ps -p "${target_pid}" -o comm= 2>/dev/null || true)
        cur_ppid=$(ps -p "${target_pid}" -o ppid= 2>/dev/null | tr -d ' ' || true)
        {
            echo "[safety-net $(date -u +%H:%M:%S)] woke up: comm='${cur_comm}' ppid='${cur_ppid}' (want bash/${target_ppid})"
            if [ "${cur_comm##*/}" = "bash" ] && [ "${cur_ppid}" = "${target_ppid}" ]; then
                echo "[safety-net $(date -u +%H:%M:%S)] FIRING SIGKILL on pid=${target_pid}"
                kill -KILL "${target_pid}" 2>&1
            else
                echo "[safety-net $(date -u +%H:%M:%S)] skip — PID's identity changed"
            fi
        } >>"${safety_net_log}" 2>&1
    ) </dev/null >/dev/null 2>&1 &
    disown 2>/dev/null || true
    printf '[cleanup %s] safety-net armed (pid=%d ppid=%d, 10 sec); about to exit %d\n' \
        "$(date -u +%H:%M:%S)" "${target_pid}" "${target_ppid}" "${rc}" >&2
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
