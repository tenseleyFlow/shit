#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-truncate-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: M03-vm-runner
# EXCLUDED_REASON: macOS smokes need a signed binary on a Tart VM; GH-hosted macos-14 runner cannot satisfy the EndpointSecurity entitlement 
#
# M03.1.I.C end-to-end smoke — macOS ES AUTH_TRUNCATE.
#
# Truncate paths that fire this event:
#   - truncate(2) directly via `truncate -s 0 file`
#   - ftruncate(2) after open (e.g. editors that rewrite-in-place)
#
# Both produce ES_EVENT_TYPE_AUTH_TRUNCATE. NOTE: open(O_TRUNC) /
# shell redirect-truncation (`: > file`) does NOT fire AUTH_TRUNCATE —
# it fires AUTH_OPEN with O_TRUNC flag. That path lives behind
# M03.1.I.B (AUTH_OPEN flags-response).
#
# This smoke uses `truncate -s 0 file` which executes /usr/bin/truncate
# (a separate process calling truncate(2)). The producer clonefiles
# the pre-truncate bytes; undo restores them. sha256 match is the
# acceptance gate.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-truncate-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
if [ ! -x "${HELPER_BIN}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
fi

probe_out="$("${HELPER_BIN}" es-probe 2>/dev/null || true)"
if [ -z "${probe_out}" ]; then
    smoke_log "SKIP: shit-helper es-probe produced no output"
    exit 0
fi
smoke_log "es-probe: ${probe_out}"
if ! grep -q '"result":"Success"' <<<"${probe_out}"; then
    smoke_log "SKIP: ES not entitled (need SIP+AuthRoot+AMFI VM)"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    smoke_log "SKIP: ES capture requires sudo; rerun as root"
    exit 0
fi

export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

sleep 0.5

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
smoke_log "watch root: ${SCRATCH}"

KNOWN_CONTENT="es-truncate canary $(date -u +%Y-%m-%dT%H:%M:%SZ)"
FILE="${SCRATCH}/data.txt"
printf '%s\n' "${KNOWN_CONTENT}" >"${FILE}"
EXPECTED_SHA="$(shasum -a 256 "${FILE}" | awk '{print $1}')"
ORIG_BYTES="$(wc -c <"${FILE}" | awk '{print $1}')"
smoke_log "wrote ${FILE} sha256=${EXPECTED_SHA} bytes=${ORIG_BYTES}"

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" \
    --pid "${PID}" \
    --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" \
    --seq 1 \
    --pid "${PID}" \
    --cwd "${SCRATCH}" \
    --shell bash \
    --sock "${SHIT_HOOK_SOCK}"

sleep 0.5

smoke_log "truncate -s 0 ${FILE}  # truncate(2) syscall"
truncate -s 0 "${FILE}"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq 1 \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
smoke_log "FilePreImage journaled ✓"

# Sanity: post-truncate the file exists but is empty.
if [ ! -f "${FILE}" ]; then
    smoke_fail "${FILE} should still exist after truncate"
fi
POST_BYTES="$(wc -c <"${FILE}" | awk '{print $1}')"
if [ "${POST_BYTES}" -ne 0 ]; then
    smoke_fail "post-truncate file should be 0 bytes; got ${POST_BYTES}"
fi
smoke_log "post-truncate file is empty ✓"

smoke_log "shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"; sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}
if [ ! -f "${FILE}" ]; then
    smoke_fail "${FILE} missing after undo"
fi
RESTORED_SHA="$(shasum -a 256 "${FILE}" | awk '{print $1}')"
if [ "${RESTORED_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${RESTORED_SHA}"
    smoke_fail "restored content sha256 mismatch"
fi
smoke_log "restored bytes sha256 matches original ✓"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-truncate-undo-macos (M03.1.I.C)"
