#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: shell-append-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# AU19 smoke — bash `cmd >> file` append undo, Linux side.
# Mirror of W09.18's shell-append-undo-fbsd.sh.
#
# Wire path (unblocked by AU27, which closed DR-CR-55):
#   1. C06 redirect parser classifies `>>` as
#      `RedirectOp::Append` in the DEBUG-trap pre-exec-redirects
#      call.
#   2. Daemon's `redirect_track::stash_append` (AU27) stats
#      the target at PreExec time and journals a
#      `CaptureEventKind::FileAppendPreStash { pre_size }`.
#   3. Planner emits `InverseOp::FileExtend { truncate_to:
#      pre_size }` on undo.
#   4. `FileExecutor::apply_file_extend` (C06) ftruncate(2)s
#      the file back. Grow-refusal guard catches malformed
#      pre_size > current_size at execute time.
#
# Without this smoke a regression in any of those four layers
# would silently break Linux `>>` undo while BSD stays green.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: shell-append-undo-linux is Linux-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

LOG="${SHIT_SMOKE_TMP}/app.log"
printf 'line1\nline2\n' > "${LOG}"
PRE_SHA="$(sha256sum "${LOG}" | awk '{print $1}')"
PRE_SIZE="$(stat -c %s "${LOG}")"
smoke_log "pre-state: ${LOG} sha=${PRE_SHA:0:12} size=${PRE_SIZE}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SHIT_SMOKE_TMP}" --shell bash --depth 1 \
    --cmdline "echo appended-line >> ${LOG}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# C06 redirect parser detects `>>` → ships RedirectOp::Append
# → AU27's stash_append journals FileAppendPreStash{pre_size}.
smoke_log "pre-exec-redirects: shipping Append pre-stash for ${LOG}"
"${SHIT_BIN}" hook-send pre-exec-redirects \
    --session "${SESSION}" --seq 1 \
    --cmdline "echo appended-line >> ${LOG}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# The workload — bash opens O_WRONLY|O_CREAT|O_APPEND,
# writes new bytes, closes. File grows.
smoke_log "workload: echo appended-line >> ${LOG}"
echo "appended-line" >> "${LOG}"

POST_SIZE="$(stat -c %s "${LOG}")"
[ "${POST_SIZE}" -gt "${PRE_SIZE}" ] \
    || smoke_fail "append didn't grow file (${POST_SIZE} <= ${PRE_SIZE})"
grep -q 'appended-line' "${LOG}" || smoke_fail "appended content missing"
smoke_log "post-cmd: size=${POST_SIZE}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${UNDO_RC}" -ne 0 ]; then
    smoke_fail "shit undo exited ${UNDO_RC}"
fi
if [ ! -f "${LOG}" ]; then
    smoke_fail "${LOG} missing post-undo — undo unlinked instead of truncating"
fi

POST_UNDO_SIZE="$(stat -c %s "${LOG}")"
POST_UNDO_SHA="$(sha256sum "${LOG}" | awk '{print $1}')"
smoke_log "post-undo: sha=${POST_UNDO_SHA:0:12} size=${POST_UNDO_SIZE}"

if [ "${POST_UNDO_SIZE}" != "${PRE_SIZE}" ]; then
    smoke_log "expected size=${PRE_SIZE}"
    smoke_log "got      size=${POST_UNDO_SIZE}"
    smoke_fail "FileExtend didn't truncate back to pre-size"
fi
if [ "${POST_UNDO_SHA}" != "${PRE_SHA}" ]; then
    smoke_log "expected sha=${PRE_SHA}"
    smoke_log "got      sha=${POST_UNDO_SHA}"
    smoke_fail "FileExtend truncated to right size but content differs"
fi

smoke_log "PASS: shell-append-undo-linux (>> append undone to byte-identical pre-state)"
