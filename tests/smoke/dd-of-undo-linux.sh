#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR08.2.dd-of smoke — `dd if=/dev/zero of=existing` truncates and
# overwrites an existing file. Same race shape as `cmd > existing`
# (the AR06.5 target): the shell never opens(O_TRUNC) for dd —
# dd does it itself — but the shell-side C06 redirect parser
# recognizes `of=path` as a DdOf op and ships a pre-stash. This
# smoke pins that contract end-to-end.
#
# Closes the AR08.1 'covered, smoke-gap' entry for dd. Simpler
# than dd-notrunc-undo-fbsd.sh (which tests partial-write-at-
# offset, a different code path).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: dd-of-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

DD_BIN="$(command -v dd)"
[ -x "${DD_BIN}" ] || smoke_fail "dd not on PATH"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

PROBE="${SHIT_SMOKE_TMP}/probe.bin"
printf 'original content from before dd\n' > "${PROBE}"
PRE_SHA="$(sha256sum "${PROBE}" | awk '{print $1}')"
smoke_log "pre-state: probe sha=${PRE_SHA:0:16}..."

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SHIT_SMOKE_TMP}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# THE pre-stash. shit_shell::redirect parses `of=PATH` as DdOf
# and ships it. Without this synchronous pre-stash the dd's
# truncate would race the kernel tier and the original bytes
# would be lost.
smoke_log "PreExecRedirects: shipping pre-stash for dd of=${PROBE}"
"${SHIT_BIN}" hook-send pre-exec-redirects \
    --session "${SESSION}" --seq 1 \
    --cmdline "dd if=/dev/zero of=${PROBE} bs=1 count=8" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# THE workload — dd truncates + writes zeroes.
smoke_log "${DD_BIN} if=/dev/zero of=${PROBE} bs=1 count=8"
"${DD_BIN}" if=/dev/zero of="${PROBE}" bs=1 count=8 2>/dev/null

POST_CMD_SHA="$(sha256sum "${PROBE}" | awk '{print $1}')"
smoke_log "post-cmd sha=${POST_CMD_SHA:0:16}..."
if [ "${POST_CMD_SHA}" = "${PRE_SHA}" ]; then
    smoke_fail "workload was a no-op — dd didn't actually change the file"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ ! -f "${PROBE}" ]; then
    smoke_fail "${PROBE} missing post-undo — undo unlinked instead of restoring"
fi

POST_SHA="$(sha256sum "${PROBE}" | awk '{print $1}')"
if [ "${POST_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "OUTCOME A — full undo (probe restored byte-identical)"
    smoke_log "PASS: dd-of-undo-linux (Outcome A)"
    exit 0
fi

# Loud refusal is acceptable second-best.
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "out-of-scope|refus|conflict|${PROBE}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the path)"
    smoke_log "PASS: dd-of-undo-linux (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial / wrong restore"
smoke_log "  undo exit:   ${UNDO_RC}"
smoke_log "  sha now:     ${POST_SHA:0:16}..."
smoke_log "  sha pre-cmd: ${PRE_SHA:0:16}..."
smoke_fail "dd of= undo did NOT restore original bytes (outcome C)"
