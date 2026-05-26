#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.17 smoke — log rotation pattern: `mv log log.1 && touch log`.
# Two ops compose in one command window:
#   - mv: rename(log, log.1). Captured as TreeOp::Rename.
#   - touch: open(log, O_WRONLY|O_CREAT|O_TRUNC). Creates a new
#     empty file at the original name. Captured by kqueue dir-diff
#     as TreeOp::Create.
#
# Undo composes the inverses:
#   - Unlink the freshly-touched log (new empty file).
#   - Rename log.1 -> log (restore original).
#
# Real-world: every log rotator script does this. Failing to
# compose would silently break logrotate-style workflows.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: rotate-and-touch-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
LOG="${WATCHED}/app.log"
LOG_BAK="${WATCHED}/app.log.1"
printf 'line1\nline2\nline3\n' > "${LOG}"
PRE_LOG_SHA="$(/sbin/sha256 -q "${LOG}")"
[ ! -e "${LOG_BAK}" ] || smoke_fail "${LOG_BAK} pre-exists"
smoke_log "pre-cmd: log sha=${PRE_LOG_SHA}; log.1 absent"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload.
smoke_log "bash -c 'mv app.log app.log.1 && touch app.log'"
LD_PRELOAD="${SHIM_LIB}" bash -c \
    "cd '${WATCHED}' && mv app.log app.log.1 && touch app.log"

# Sanity: both effects visible.
[ -f "${LOG}" ] || smoke_fail "touch didn't produce ${LOG}"
[ -f "${LOG_BAK}" ] || smoke_fail "mv didn't produce ${LOG_BAK}"
[ "$(/sbin/sha256 -q "${LOG_BAK}")" = "${PRE_LOG_SHA}" ] || smoke_fail "log.1 content drift after mv"
[ "$(/usr/bin/stat -f '%z' "${LOG}")" = "0" ] || smoke_fail "post-touch log is not empty"
smoke_log "post-cmd: log empty; log.1 has original ${PRE_LOG_SHA}"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

failures=()
[ "${UNDO_RC}" -eq 0 ] || failures+=("undo exited ${UNDO_RC}")
[ ! -e "${LOG_BAK}" ] || failures+=("log.1 still present after undo (ReverseRename should have moved it back)")
if [ -f "${LOG}" ]; then
    FINAL_SHA="$(/sbin/sha256 -q "${LOG}")"
    [ "${FINAL_SHA}" = "${PRE_LOG_SHA}" ] \
        || failures+=("log content mismatch: got ${FINAL_SHA}, want ${PRE_LOG_SHA}")
else
    failures+=("log missing after undo")
fi

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: rotate-and-touch-undo-fbsd (mv + touch composed correctly)"
    exit 0
fi
smoke_fail "rotate-and-touch undo incomplete: ${failures[*]}"
