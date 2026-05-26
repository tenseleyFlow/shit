#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR06.5 smoke — the C06 load-bearing target.
#
# `bash` opens the file in `cmd > existing-file` with O_TRUNC
# BEFORE invoking `cmd`. The kernel-tier capture sees the truncate
# as part of the open syscall, which the planner attributes to
# bash's PID, not to the user-typed command. The pre-image of the
# original content is lost to the kernel tier.
#
# AR06.5 closes that race by parsing the user's command line at
# the DEBUG-trap layer (BEFORE bash performs the open) and
# synchronously asking the daemon to hash + stash the destination
# file's bytes. The daemon journals a FilePreImage event keyed to
# the open command window; on undo, the planner emits
# RestoreContent and the bytes the truncation discarded come back.
#
# Outcomes:
#   A. Full undo: /tmp/probe.txt content restored to the pre-cmd
#      bytes byte-identically.
#   B. Loud refusal: undo exits non-zero AND log explains why.
#      Acceptable but second-best — we want Outcome A here.
#   C. Silent partial / wrong restore: FAIL.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: redirect-race-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

PROBE="${SHIT_SMOKE_TMP}/probe.txt"
printf 'original content from before the redirect\n' > "${PROBE}"
PRE_SHA="$(sha256sum "${PROBE}" | awk '{print $1}')"
PRE_SIZE="$(stat -c %s "${PROBE}" 2>/dev/null || stat -f %z "${PROBE}")"
smoke_log "pre-state: probe at ${PROBE}, sha=${PRE_SHA:0:16}..., size=${PRE_SIZE}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${SHIT_SMOKE_TMP}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SHIT_SMOKE_TMP}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# THE pre-stash. Simulates the DEBUG-trap call the bash hook will
# make for the about-to-run command. Runs BEFORE the truncating
# echo so the daemon captures the original bytes.
smoke_log "PreExecRedirects: shipping pre-stash for ${PROBE}"
"${SHIT_BIN}" hook-send pre-exec-redirects \
    --session "${SESSION}" --seq 1 \
    --cmdline "echo overwritten > ${PROBE}" \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# THE workload. bash performs open(O_TRUNC) on PROBE then writes
# new content. The original bytes are now gone from disk — only
# the daemon's pre-stash blob holds them.
smoke_log "workload: echo overwritten > ${PROBE}"
echo "overwritten by the redirect" > "${PROBE}"

POST_CMD_SHA="$(sha256sum "${PROBE}" | awk '{print $1}')"
smoke_log "post-cmd: probe sha=${POST_CMD_SHA:0:16}... (truncated + rewritten)"
if [ "${POST_CMD_SHA}" = "${PRE_SHA}" ]; then
    smoke_fail "workload was a no-op — probe content didn't actually change"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

if [ ! -f "${PROBE}" ]; then
    smoke_fail "${PROBE} missing post-undo — undo unlinked instead of restoring"
fi

POST_SHA="$(sha256sum "${PROBE}" | awk '{print $1}')"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (original bytes restored byte-identical)
if [ "${POST_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "OUTCOME A — full undo (probe restored byte-identical, events=${N_EVENTS})"
    smoke_log "PASS: redirect-race-undo-linux (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "out-of-scope|refus|conflict|${PROBE}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the path)"
    smoke_log "PASS: redirect-race-undo-linux (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial / wrong restore"
smoke_log "  undo exit:        ${UNDO_RC}"
smoke_log "  sha now:          ${POST_SHA:0:16}..."
smoke_log "  sha pre-cmd:      ${PRE_SHA:0:16}..."
smoke_log "  journal events:   ${N_EVENTS}"
smoke_fail "redirect-race undo did NOT restore original bytes (outcome C)"
