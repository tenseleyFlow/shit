#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chmod-undo-dyld-shim-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M07.B.5 — `chmod` (via brew's `gchmod`, which is non-SIP so DYLD
# survives) followed by `shit undo` should restore the prior mode
# bits.
#
# Exercises three layers fixed in M07.B.5:
# 1. Shim: `fchmodat` interposer (M07.B missed it — GNU coreutils
#    calls fchmodat, not chmod). Without the interposer the shim
#    is silently inert against `gchmod`.
# 2. Daemon: shim_listener routes chmod-family syscalls to the
#    FilePreImage ingest path (was previously dropped as
#    "syscall not classifiable").
# 3. Planner: existing FilePreImage handling restores the metadata
#    fields (mode/uid/gid/mtime) alongside content.
#
# Outcomes:
#   A. Full undo: mode bits restored to the pre-state value.
#   B. Loud refusal: undo non-zero AND log named the chmod path.
#   C. Silent partial undo (FAIL): mode unchanged + undo exit 0.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: chmod-undo-dyld-shim-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

CHMOD_BIN="$(command -v gchmod 2>/dev/null || true)"
if [ -z "${CHMOD_BIN}" ]; then
    smoke_log "SKIP: gchmod (non-SIP) required; brew install coreutils"
    exit 0
fi
smoke_log "chmod: ${CHMOD_BIN} (non-SIP, DYLD survives)"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.dylib"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim dylib missing (cargo build --release -p shit-preload-shim)"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
TARGET="${WATCHED}/file.txt"
mkdir -p "${WATCHED}"
printf 'unchanged contents\n' > "${TARGET}"
chmod 0600 "${TARGET}"
PRE_MODE="$(stat -f %p "${TARGET}" | tail -c 4)"
smoke_log "pre-state: ${TARGET} mode=${PRE_MODE}"
[ "${PRE_MODE}" = "600" ] || smoke_fail "pre-state mode set failed (got ${PRE_MODE}, want 600)"

smoke_start_shitd

SESSION="$(/opt/homebrew/bin/python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null \
    || python3 -c 'import uuid; print(uuid.uuid4())')"
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

smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} gchmod 0644 ${TARGET}"
set +e
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${CHMOD_BIN}" 0644 "${TARGET}" \
    >"${SHIT_SMOKE_TMP}/chmod.log" 2>&1
CHMOD_RC=$?
set -e
if [ "${CHMOD_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/chmod.log" >&2
    smoke_fail "gchmod under shim failed rc=${CHMOD_RC}"
fi
POST_MODE="$(stat -f %p "${TARGET}" | tail -c 4)"
[ "${POST_MODE}" = "644" ] || smoke_fail "chmod didn't actually change mode (got ${POST_MODE})"
smoke_log "post-cmd: ${TARGET} mode=${POST_MODE}"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

SHIM_HITS="$(grep -hc 'metadata-mutation pre-image journaled' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim metadata events journaled by daemon: ${SHIM_HITS}"

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

FINAL_MODE="$(stat -f %p "${TARGET}" 2>/dev/null | tail -c 4 || echo MISSING)"
smoke_log "post-undo: ${TARGET} mode=${FINAL_MODE}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (mode restored)
if [ "${FINAL_MODE}" = "${PRE_MODE}" ]; then
    smoke_log "OUTCOME A — full undo (mode restored to ${PRE_MODE}, shim hits=${SHIM_HITS})"
    smoke_log "PASS: chmod-undo-dyld-shim-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal acceptable
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "chmod|metadata|refus|conflict|${TARGET}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named chmod/conflict)"
    smoke_log "PASS: chmod-undo-dyld-shim-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  pre mode:   ${PRE_MODE}"
smoke_log "  post-cmd:   ${POST_MODE}"
smoke_log "  post-undo:  ${FINAL_MODE} (expected ${PRE_MODE})"
smoke_log "  undo exit:  ${UNDO_RC}"
smoke_log "  shim hits:  ${SHIM_HITS}"
smoke_log "  journal:    ${N_EVENTS}"
smoke_fail "chmod undo did NOT restore mode (Outcome C)"
