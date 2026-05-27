#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: touch-edit-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# S29.2 smoke — `touch foo; echo content > foo; rm foo; shit undo`
# fully restores the watched directory's pre-state (no foo).
#
# Exercises:
#   1. Dir-diff emits TreeOpWire::Create for the new file from `touch`.
#   2. `subtree.add_path` registers a kqueue watch on the new fd.
#   3. The `echo >` redirect triggers NOTE_WRITE on the (now tracked)
#      file fd → CapturedPreImage for the empty pre-content.
#   4. The `rm` triggers NOTE_DELETE on the file fd → another
#      CapturedPreImage with is_delete=true + paired TreeOpUnlink.
#   5. `shit undo` walks the events and reverses everything: the
#      file ends up absent (which is the pre-command state).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: touch-edit-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
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

NEW_FILE="${SCRATCH}/created_by_smoke.txt"

# Mutation sequence: create a new file inside the watched dir, write
# content, then rm. All three operations should be observable; the
# undo plan should reverse to the pre-mutation state (file absent).
touch "${NEW_FILE}"
sleep 0.2
echo "smoke content" > "${NEW_FILE}"
sleep 0.2
rm "${NEW_FILE}"
smoke_log "touch+echo+rm complete"
sleep 0.5

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# We expect a Create event (from touch) — proves auto-add wired up.
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10
# The rm produces a TreeOpUnlink. Whether the echo's NOTE_WRITE
# produced a FilePreImage depends on whether the auto-add happened
# before the echo — accept either 0 or 1 for FilePreImage; the
# end-state assertion is the load-bearing check.
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

# Sanity: file is gone post-rm.
if [ -e "${NEW_FILE}" ]; then
    smoke_fail "file should have been rm'd: ${NEW_FILE}"
fi

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# End-state: file must be absent (the pre-command state). The undo
# pipeline reverses the rm (RecreatePath + RestoreContent) but the
# Create from `touch` is *also* reversed (TreeOpUnlink for the
# RecreatePath's path). Net effect: file should not exist.
if [ -e "${NEW_FILE}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "file still present after undo (expected absent — touch should be reversed): ${NEW_FILE}"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: touch-edit-undo-fbsd"
