#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-chflags-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-es
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: issue-269
# EXCLUDED_REASON: FSEvents reports the file's earlier create in the chflags batch, so undo deletes the file before RestoreFlags (#269); ES capture itself works
#
# Lane M2: undo of the SIP-protected /usr/bin/chflags under
# EndpointSecurity (AUTH_SETFLAGS).
#
# /usr/bin/chflags is an Apple platform binary, so the DYLD shim's
# chflags interposer never loads into it. The ES producer's
# AUTH_SETFLAGS handler reads the pre-change st_flags from the event's
# target stat and emits a MetadataChange; the planner turns a
# flags-only change into RestoreFlags. The smoke sets UF_NODUMP and
# UF_HIDDEN and checks that `shit undo` clears them again.
#
# Needs root and an ES-capable helper (tools/macos-tart-vm/
# run-es-smoke.sh on the macos-es host). Elsewhere it logs SKIP and
# exits 0; run-es-smoke.sh turns a SKIP into a failure.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-chflags-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"

probe_out="$("${HELPER_BIN}" es-probe 2>/dev/null || true)"
smoke_log "es-probe: ${probe_out}"
if ! grep -q '"result":"Success"' <<<"${probe_out}"; then
    smoke_log "SKIP: ES not available here (need SIP off + AMFI boot-arg + signed helper)"
    exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
    smoke_log "SKIP: ES capture requires root"
    exit 0
fi

sig="$(codesign -dv /usr/bin/chflags 2>&1 || true)"
if ! grep -q "Platform identifier" <<<"${sig}"; then
    smoke_fail "/usr/bin/chflags is not an Apple platform binary on this host"
fi

export SHIT_HELPER_BIN="${HELPER_BIN}"
smoke_start_shitd
sleep 0.5

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
F="${SCRATCH}/flagged.txt"
printf 'flags canary\n' >"${F}"
BEFORE="$(stat -f %f "${F}")"
smoke_log "st_flags before: ${BEFORE}"
# If the file's create lands in the command's FSEvents batch, the
# planner treats the file as created by the command and undo deletes
# it (#269). A pause here makes that less likely but does not stop it.
sleep 3

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open --session "${SESSION}" --pid "${PID}" \
    --shell bash --tty /dev/null --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION}" --seq "${SEQ}" \
    --pid "${PID}" --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

smoke_log "/usr/bin/chflags nodump,hidden ${F}"
/usr/bin/chflags nodump,hidden "${F}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec --session "${SESSION}" --seq "${SEQ}" \
    --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

AFTER="$(stat -f %f "${F}")"
smoke_log "st_flags after chflags: ${AFTER}"
[ "${AFTER}" != "${BEFORE}" ] || smoke_fail "chflags did not change st_flags"

smoke_wait_for_event "discriminant = 'MetadataChange'" 1 10

smoke_log "running: shit undo --yes"
if ! "${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo.log" 2>&1; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
fi
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log"

GOT="$(stat -f %f "${F}")"
[ "${GOT}" = "${BEFORE}" ] || smoke_fail "st_flags not restored: want ${BEFORE} got ${GOT}"
smoke_log "st_flags restored to ${GOT} ✓"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-chflags-undo-macos"
