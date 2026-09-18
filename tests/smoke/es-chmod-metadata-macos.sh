#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-chmod-metadata-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: M03-vm-runner
# EXCLUDED_REASON: macOS smokes need a signed binary on a Tart VM; GH-hosted macos-14 runner cannot satisfy the EndpointSecurity entitlement 
#
# M03.1.I.D end-to-end smoke — macOS ES metadata-mutation refusal.
#
# Validates that AUTH_SETMODE (chmod) fires and the producer emits a durable
# CaptureRefused event. The broad metadata inverse cannot yet represent every
# mode/ACL side effect, so it must never be presented as actionable.
#
# AUTH_SETOWNER shares this fail-closed path. AUTH_UTIMES is also refused until
# atime is captured and restored.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-chmod-metadata-macos is macOS-only (uname=$(uname -s))"
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

FILE="${SCRATCH}/data.txt"
printf 'chmod-canary\n' >"${FILE}"
chmod 644 "${FILE}"
ORIG_MODE="$(stat -f '%p' "${FILE}" | tail -c 4)"
smoke_log "wrote ${FILE} mode=${ORIG_MODE}"

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" \
    --pid "${PID}" \
    --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" \
    --seq 1 \
    --pid "${PID}" \
    --cwd "${SCRATCH}" \
    --shell bash \
    --sock "${SHIT_HOOK_SOCK}"

sleep 0.5

smoke_log "chmod 755 ${FILE}"
chmod 755 "${FILE}"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq 1 \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'CaptureRefused' AND path LIKE '%/data.txt'" 1 10
smoke_log "CaptureRefused journaled ✓"

N_ACTIONABLE="$(smoke_journal_count "discriminant = 'MetadataChange' AND path LIKE '%/data.txt'")"
if [ "${N_ACTIONABLE}" -ne 0 ]; then
    smoke_fail "AUTH_SETMODE produced ${N_ACTIONABLE} actionable MetadataChange event(s)"
fi

# Sanity: post-chmod mode reflects the change.
NEW_MODE="$(stat -f '%Lp' "${FILE}")"
if [ "${NEW_MODE}" != "755" ]; then
    smoke_fail "post-chmod mode mismatch: expected 755, got ${NEW_MODE}"
fi
smoke_log "post-chmod mode = ${NEW_MODE} ✓"

# This smoke isolates entitled-ES observation and does not exercise `shit
# undo`. The acceptance criterion is that successful AUTH_SETMODE is recorded
# as a command-atomic refusal and never as a lossy inverse.

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-chmod-metadata-macos (M03.1.I.D — chmod refusal is explicit)"
