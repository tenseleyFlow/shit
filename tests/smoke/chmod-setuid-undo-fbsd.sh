#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.13 — setuid bit round-trip through undo.
#
# Reproduces: chmod 4755 → 0755 → undo expects 4755 but gets 0755.
# Symptom is silent (exit=0, conflicts=0) so a setuid-marked binary
# accidentally `chmod 0755`'d cannot be restored — a real privilege
# regression.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: chmod-setuid-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
TARGET="${SCRATCH}/binary"
printf '#!/bin/sh\necho ok\n' > "${TARGET}"
chmod 4755 "${TARGET}"
mode_of() { python3 -c "import os; print('%04o' % (os.stat('$1').st_mode & 0o7777))"; }
PRE_MODE="$(mode_of "${TARGET}")"
[ "${PRE_MODE}" = "4755" ] || smoke_fail "pre-chmod mode is ${PRE_MODE}, want 4755"
smoke_log "pre-cmd mode: ${PRE_MODE}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

smoke_log "chmod 0755 ${TARGET} (drop setuid)"
chmod 0755 "${TARGET}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_wait_for_event "discriminant = 'MetadataChange'" 1 10

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

FINAL_MODE="$(mode_of "${TARGET}")"
smoke_log "post-undo mode: ${FINAL_MODE}"

[ "${UNDO_RC}" -eq 0 ] || smoke_fail "shit undo exited ${UNDO_RC}"
if [ "${FINAL_MODE}" = "4755" ]; then
    smoke_log "PASS: chmod-setuid-undo-fbsd (setuid bit round-trip preserved)"
    exit 0
fi
smoke_fail "undo dropped setuid bit — got ${FINAL_MODE}, want 4755"
