#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AU10 smoke — when the LD_PRELOAD shim's canonicalize_path trips
# its load-bearing fallback (both the path AND its parent are
# inaccessible), the daemon now journals a CaptureRefused event
# AND `shit undo` surfaces a refusal in the user-visible report
# instead of silently producing applied=0.
#
# Pre-AU10 behavior: the shim's `canonical_path` silently returned
# the raw user-passed string when both canonicalize attempts
# failed. The daemon's path matcher (which keys on canonicalized
# absolute paths) missed, the planner emitted no inverse for the
# affected path, and the user saw a confusing applied=0 conflict
# with no log trail.
#
# Post-AU10: ShimNotification.failure carries a structured
# CanonicalizeFailed payload. The daemon journals a
# CaptureRefused event. The planner emits an InverseOp::Refuse
# node with class="capture-incomplete". The undo report shows:
#   Refused (capture incomplete): /nonexistent-au10/from: ...
#
# Reproducer: call libc rename(2) on a path whose parent doesn't
# exist. Python's `os.rename` passes the path through to the libc
# call without pre-checking, so the shim's interposer fires
# (canonicalize fails on both `from` and parent), even though the
# real syscall ultimately returns ENOENT.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: canonicalize-fail-surface-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "SKIP: python3 required to issue raw libc rename(2) without pre-stat"
    exit 0
fi

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
cd "${WATCHED}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# THE workload — Python issues libc rename(2) directly. Neither
# the path NOR its parent exists, so canonicalize_path's two
# fallbacks both trip and the shim's notify_rename_with_dst_preimage
# path emits a notification with `failure: Some(CanonicalizeFailed)`.
#
# We expect the call itself to fail with ENOENT — that's fine.
# The shim fires BEFORE the libc rename syscall reaches the kernel,
# so the notification ships regardless.
BOGUS_FROM="${WATCHED}/au10-nonexistent-dir/from.txt"
BOGUS_TO="${WATCHED}/au10-nonexistent-dir/to.txt"
smoke_log "issuing libc rename of ${BOGUS_FROM} → ${BOGUS_TO} (expected to fail ENOENT)"
LD_PRELOAD="${SHIM_LIB}" python3 -c "
import os, sys
try:
    os.rename('${BOGUS_FROM}', '${BOGUS_TO}')
    print('UNEXPECTED: rename succeeded', file=sys.stderr)
    sys.exit(2)
except FileNotFoundError:
    sys.exit(0)
" || true

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Verify the journal has the CaptureRefused event keyed to the
# bogus-from path. The discriminant column carries the new
# AU10 value; the path column carries the raw user-passed path
# (canonicalize couldn't resolve it).
N_REFUSED="$(smoke_journal_count "discriminant = 'CaptureRefused'" 2>/dev/null || echo 0)"
smoke_log "CaptureRefused events: ${N_REFUSED}"
if [ "${N_REFUSED}" -lt 1 ]; then
    smoke_log "daemon log tail:"
    tail -80 "${SHIT_SMOKE_TMP}/state/shit/log/daemon.jsonl."* 2>/dev/null | sed 's/^/    /' >&2 || true
    smoke_log "journal contents (all events for this command):"
    smoke_journal_query "SELECT discriminant, path FROM events ORDER BY id" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "expected >= 1 CaptureRefused event, got ${N_REFUSED}"
fi

# The refusal path should carry the raw user-passed argv.
N_AT_PATH="$(smoke_journal_count "discriminant = 'CaptureRefused' AND path LIKE '%au10-nonexistent-dir%'" 2>/dev/null || echo 0)"
if [ "${N_AT_PATH}" -lt 1 ]; then
    smoke_fail "expected CaptureRefused keyed to the bogus path; got ${N_AT_PATH}"
fi

# Run shit undo --yes; the planner emits an InverseOp::Refuse
# node which the CLI renders in the "Refused" block. The undo
# command itself exits non-zero per AR07.2 when the plan
# contains only refusals (or applied=0 + refused>=1).
UNDO_LOG="${SHIT_SMOKE_TMP}/undo.log"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${UNDO_LOG}" || true

# The user-visible signal: "Refused" block exists with our class.
if ! grep -q "capture-incomplete\|Refused" "${UNDO_LOG}"; then
    smoke_log "undo log:"
    sed 's/^/    /' "${UNDO_LOG}" >&2
    smoke_fail "expected undo report to render a Refused block (class capture-incomplete)"
fi
smoke_log "undo surfaced the refusal:"
grep -E "Refused|capture-incomplete" "${UNDO_LOG}" | sed 's/^/    /' || true

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: canonicalize-fail-surface-linux (CaptureRefused journaled + surfaced at undo)"
