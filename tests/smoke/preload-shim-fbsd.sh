#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: preload-shim-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# S24.D smoke — LD_PRELOAD shim notify path on FreeBSD.
#
# Exercises:
#   1. shitd's shim_listener binds the per-process UDS at
#      $XDG_RUNTIME_DIR/shit-shim.sock.
#   2. A process started with LD_PRELOAD=libshit_preload_shim.so issues
#      `open(O_CREAT|O_WRONLY)` (via `touch`) and `unlink` (via `rm`).
#   3. The shim's notify_pre_mutation hits the daemon's shim_listener.
#   4. The daemon journals one ShimNotification per interposed call
#      (visible as "shim pre-mutation" debug lines in the JSON log).
#
# Assertion: at least one `open` notification and one `unlink`
# notification reach the daemon within 2s of the user-space syscalls.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: preload-shim-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
if [ ! -f "${SHIM_LIB}" ]; then
    smoke_fail "shim library missing at ${SHIM_LIB}"
fi

smoke_start_shitd

# The daemon writes JSON logs under $XDG_STATE_HOME/shit/log/.
LOG_DIR="${XDG_STATE_HOME}/shit/log"

# Wait for the listener to be up — it binds shit-shim.sock under
# XDG_RUNTIME_DIR. Quick timeout: the daemon-boot smoke already proves
# the daemon itself starts in <10s; the shim listener spawn is part of
# the same task graph.
SHIM_SOCK="${XDG_RUNTIME_DIR}/shit-shim.sock"
for _ in $(seq 1 50); do
    if [ -S "${SHIM_SOCK}" ]; then
        break
    fi
    sleep 0.1
done
if [ ! -S "${SHIM_SOCK}" ]; then
    smoke_fail "shim socket never appeared at ${SHIM_SOCK}"
fi
smoke_log "shim listener socket ready: ${SHIM_SOCK}"

PROBE="${SHIT_SMOKE_TMP}/probe.txt"
LD_PRELOAD="${SHIM_LIB}" /bin/sh -c "touch ${PROBE}; rm ${PROBE}"

# Give the daemon a moment to flush the JSON appender.
sleep 0.5

count_in_log() {
    local syscall="$1"
    if [ ! -d "${LOG_DIR}" ]; then
        echo 0
        return
    fi
    find "${LOG_DIR}" -name 'daemon.jsonl*' -exec \
        grep -c -E "\"syscall\":\"${syscall}\"" {} \; 2>/dev/null \
        | awk '{s+=$1} END {print s+0}'
}

opens="$(count_in_log open)"
unlinks="$(count_in_log unlink)"
smoke_log "shim notifications: open=${opens} unlink=${unlinks}"

if [ "${opens}" -lt 1 ]; then
    smoke_log "daemon log contents (jsonl):"
    find "${LOG_DIR}" -name 'daemon.jsonl*' -exec cat {} \; \
        | grep -i shim | sed 's/^/    /' >&2 || true
    smoke_fail "expected ≥1 open notification, got ${opens}"
fi
if [ "${unlinks}" -lt 1 ]; then
    smoke_log "daemon log contents (jsonl):"
    find "${LOG_DIR}" -name 'daemon.jsonl*' -exec cat {} \; \
        | grep -i shim | sed 's/^/    /' >&2 || true
    smoke_fail "expected ≥1 unlink notification, got ${unlinks}"
fi

smoke_log "PASS: preload-shim-fbsd"
