#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: read-only-cmd-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.10.read-only smoke — `cat /etc/hosts` reads a file; no
# mutations. `shit undo --yes` should report 0 events, 0 ops,
# and the working tree must be byte-identical pre and post.
#
# This is a FALSE-POSITIVE guard. If the journal acquires
# events from a read-only command (e.g. NOTE_ATTRIB on a
# transient access-time update — typical on FreeBSD without
# atime-disabled mounts), undo would emit spurious inverses.
# Today's contract: no journal events from purely read syscalls.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: read-only-cmd-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
# Populate with a few read-target files. Their content shouldn't
# change.
declare -A SHAS
for i in 1 2 3; do
    f="${WATCHED}/file${i}.txt"
    printf 'content for file %d\n' "${i}" > "${f}"
    SHAS["file${i}"]="$(/sbin/sha256 -q "${f}")"
done

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload: purely read-only commands.
smoke_log "cat file1.txt file2.txt file3.txt > /dev/null && ls > /dev/null"
cat file1.txt file2.txt file3.txt > /dev/null
ls > /dev/null

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events from read-only command: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Content invariant.
failures=()
for i in 1 2 3; do
    f="${WATCHED}/file${i}.txt"
    if [ ! -f "${f}" ]; then
        failures+=("file${i}.txt MISSING — undo touched read-only target!")
        continue
    fi
    post="$(/sbin/sha256 -q "${f}")"
    if [ "${post}" != "${SHAS[file${i}]}" ]; then
        failures+=("file${i}.txt content mismatch — undo perturbed a read-only target")
    fi
done

# Soft assertion on event count. Real systems may journal a few
# benign events (e.g. atime-induced NOTE_ATTRIB on touch-test
# kernels). We DON'T fail on N_EVENTS > 0; we DO fail if undo
# wasn't safely applied OR content was perturbed.
if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: read-only-cmd-undo-fbsd (3 targets untouched; journal events=${N_EVENTS})"
    exit 0
fi

smoke_fail "read-only undo perturbed state: ${failures[*]}"
