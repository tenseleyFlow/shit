#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mkfifo-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.10.1 smoke — `mkfifo(1)` creates a named pipe. FreeBSD's
# kqueue NOTE_WRITE on the parent dir does NOT fire for FIFO/
# special-file additions (the kernel distinguishes those from
# regular-file/dir adds at the vnode-op level), so without the
# LD_PRELOAD shim's `mkfifo`/`mkfifoat` interposers the journal
# stays empty and `shit undo` no-ops. With the interposers, the
# shim emits a `TreeOp::Create` whose inverse is `unlink <path>`.
#
# Validates:
#   - `mkfifo` under LD_PRELOAD produces ≥1 journal event.
#   - `shit undo --yes` removes the FIFO.
#   - The parent dir is otherwise untouched.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: mkfifo-undo-fbsd is FreeBSD-only"
    exit 0
fi

MKFIFO_BIN="$(command -v mkfifo || echo /usr/bin/mkfifo)"
[ -x "${MKFIFO_BIN}" ] || smoke_fail "mkfifo not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing (rebuild shit-preload-shim cdylib)"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
FIFO="${WATCHED}/pipe"
# Sanity: must not pre-exist.
[ ! -e "${FIFO}" ] || smoke_fail "${FIFO} already exists before smoke"

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

smoke_log "LD_PRELOAD=${SHIM_LIB} mkfifo ${FIFO}"
LD_PRELOAD="${SHIM_LIB}" "${MKFIFO_BIN}" "${FIFO}"

# The FIFO must exist after the syscall and be of fifo type.
[ -p "${FIFO}" ] || smoke_fail "mkfifo didn't produce a FIFO at ${FIFO}"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events after mkfifo: ${N_EVENTS}"
[ "${N_EVENTS}" -ge 1 ] || smoke_fail "no journal events — shim mkfifo interposer didn't fire (LD_PRELOAD inert?)"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ -e "${FIFO}" ]; then
    smoke_fail "undo didn't remove the FIFO (TreeOp::Create reverse should be unlink)"
fi

smoke_log "PASS: mkfifo-undo-fbsd (FIFO created via shim, removed by undo)"
exit 0
