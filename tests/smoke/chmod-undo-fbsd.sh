#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chmod-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# S29.3 smoke — `chmod 755 foo.txt; shit undo` restores the mode.
#
# Exercises:
#   1. register_subtree snapshots metadata for foo.txt at attach time
#      (mode=0o644 by default).
#   2. `chmod 755 foo.txt` fires NOTE_ATTRIB on the file's fd.
#   3. handle_attrib diffs the fstat against the baseline; modes
#      differ → emits CapturedMetadataChange with before=0o644,
#      after=0o755.
#   4. Daemon journals as CaptureEventKind::MetadataChange.
#   5. shit undo plans InverseOp::RestoreMetadata { target: before } →
#      chmod back to 0o644.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: chmod-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
if [ ! -x "${HELPER_BIN}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
fi
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
FOO="${SCRATCH}/foo.txt"
echo "metadata-target" > "${FOO}"
chmod 0644 "${FOO}"
# FreeBSD's stat -f outputs the mode bits in octal-ish; use `%Mp` for the
# permission bits or `%p` for the full mode. We want the perm bits only.
PRE_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
smoke_log "wrote ${FOO} with pre-mode=${PRE_MODE}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Mutation: change mode 644 → 755.
chmod 0755 "${FOO}"
POST_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
smoke_log "chmod 0755; mode is now ${POST_MODE}"
sleep 0.5

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'MetadataChange'" 1 10

# Sanity: mode is still 755 pre-undo.
if [ "${POST_MODE}" != "0o755" ]; then
    smoke_fail "expected mode=0755 pre-undo, got ${POST_MODE}"
fi

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

RESTORED_MODE="$(python3 -c "import os; print(oct(os.stat('${FOO}').st_mode & 0o777))")"
if [ "${RESTORED_MODE}" != "${PRE_MODE}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "mode not restored: pre=${PRE_MODE} restored=${RESTORED_MODE}"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: chmod-undo-fbsd (mode ${POST_MODE} → ${RESTORED_MODE})"
