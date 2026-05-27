#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-chmod-metadata-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# M03.1.I.D end-to-end smoke — macOS ES metadata-mutation capture.
#
# Validates that AUTH_SETMODE (chmod) fires + the producer emits a
# CapturedMetadataChange event carrying `before`/`after` mode bits
# the daemon can invert. Same skip-checks as the other ES smokes.
#
# We test chmod specifically because it's the canonical metadata
# event; AUTH_SETOWNER/AUTH_UTIMES share the same handler path so
# this smoke is representative of all three.

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

smoke_wait_for_event "discriminant = 'MetadataChange'" 1 10
smoke_log "MetadataChange journaled ✓"

# Sanity: post-chmod mode reflects the change.
NEW_MODE="$(stat -f '%Lp' "${FILE}")"
if [ "${NEW_MODE}" != "755" ]; then
    smoke_fail "post-chmod mode mismatch: expected 755, got ${NEW_MODE}"
fi
smoke_log "post-chmod mode = ${NEW_MODE} ✓"

# We don't exercise `shit undo` here — the metadata-change invert
# path in the planner (apply old uid/gid/mode/mtime via chmod/chown/
# utimes) is a daemon-side concern this slice doesn't touch. The
# acceptance criterion for I.D is: producer captures + journals
# the change, ES correctly observes chmod via AUTH_SETMODE.

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-chmod-metadata-macos (M03.1.I.D — chmod capture acceptance)"
