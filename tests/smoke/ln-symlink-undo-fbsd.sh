#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: ln-symlink-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.1 smoke — `ln -s target link; shit undo` removes the symlink
# without touching the target.
#
# Validates TreeOp::Symlink capture + inverse. The kqueue dir-diff
# should emit Create for the symlink path (symlinks ARE directory
# entries); the planner's inverse is Unlink for the link, NOT the
# target. A buggy implementation might follow the symlink and
# unlink the target — this smoke catches that.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: ln-symlink-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

# Pre-existing target the symlink will point at. This file must NOT
# be touched by undo — a buggy symlink-follow would delete it.
TARGET="${SCRATCH}/target.txt"
printf 'i am the target\n' > "${TARGET}"
TARGET_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "pre-cmd target sha: ${TARGET_SHA}"

LINK="${SCRATCH}/link"
[ ! -e "${LINK}" ] || smoke_fail "smoke env not clean: ${LINK} pre-exists"

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

# The mutation: create a symlink inside the watched subtree.
ln -s "${TARGET}" "${LINK}"
smoke_log "ln -s ${TARGET} ${LINK}"
[ -L "${LINK}" ] || smoke_fail "ln did not create a symlink at ${LINK}"
sleep 0.5

smoke_log "PostExec seq=1 exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Wait for a Create-or-Symlink event for the link path. Different
# capture layers may surface it as TreeOpCreate (kqueue dir-diff
# sees the new directory entry) or TreeOpSymlink (if S29.1's
# symlink pairing fires). Either is acceptable.
smoke_wait_for_event "discriminant IN ('TreeOpCreate','TreeOpSymlink')" 1 10

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

# Post-undo: link must be GONE, target must be UNTOUCHED.
if [ -L "${LINK}" ] || [ -e "${LINK}" ]; then
    smoke_fail "symlink ${LINK} still exists post-undo"
fi
if [ ! -f "${TARGET}" ]; then
    smoke_fail "target file ${TARGET} was deleted by undo (symlink follow bug!)"
fi
POST_SHA="$(/sbin/sha256 -q "${TARGET}")"
if [ "${POST_SHA}" != "${TARGET_SHA}" ]; then
    smoke_fail "target content perturbed: ${TARGET_SHA} → ${POST_SHA}"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: ln-symlink-undo-fbsd (link removed; target sha=${TARGET_SHA} intact)"
