#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-xattr-roundtrip-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# M03.x.XATTR end-to-end smoke — macOS ES xattr capture.
#
# Validates that a file's xattrs are captured by the ES producer's
# worker (flistxattr + fgetxattr off the staging fd) and round-trip
# through `shit undo`. macOS uses xattrs HEAVILY (Gatekeeper
# quarantine, codesign signatures, Spotlight metadata, ACLs,
# FinderInfo) — restoring a file without its xattrs leaves it
# user-visibly broken (signed binaries unsigned, etc).
#
# Test shape: create a file with a user-set xattr → rm → undo →
# verify the file exists AND its xattr is back with the original
# value.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-xattr-roundtrip-macos is macOS-only (uname=$(uname -s))"
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

FILE="${SCRATCH}/xattr-test.txt"
KNOWN_CONTENT="xattr-canary $(date -u +%Y-%m-%dT%H:%M:%SZ)"
XATTR_KEY="com.example.shit-test"
XATTR_VALUE="the-original-xattr-value"
printf '%s\n' "${KNOWN_CONTENT}" >"${FILE}"
xattr -w "${XATTR_KEY}" "${XATTR_VALUE}" "${FILE}"
EXPECTED_SHA="$(shasum -a 256 "${FILE}" | awk '{print $1}')"
smoke_log "wrote ${FILE} sha256=${EXPECTED_SHA} with xattr ${XATTR_KEY}=${XATTR_VALUE}"

# Sanity: confirm xattr is on the file.
PRE_XATTR_VAL="$(xattr -p "${XATTR_KEY}" "${FILE}" 2>/dev/null)"
if [ "${PRE_XATTR_VAL}" != "${XATTR_VALUE}" ]; then
    smoke_fail "pre-mutation xattr value mismatch: expected ${XATTR_VALUE}, got ${PRE_XATTR_VAL}"
fi

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

smoke_log "rm ${FILE}"
rm "${FILE}"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq 1 \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
smoke_log "FilePreImage journaled ✓"

# Verify the captured event recorded our xattr. xattrs live inside
# the FilePreImage's `payload` column (postcard-serialized
# CaptureEvent). We hex-dump the payload and look for the xattr's
# value bytes verbatim — sufficient since postcard encodes strings
# + byte vecs inline.
XATTR_HEX="$(printf '%s' "${XATTR_VALUE}" | od -An -tx1 | tr -d ' \n')"
HEX_DUMP="$(smoke_journal_query "SELECT hex(payload) FROM events WHERE discriminant = 'FilePreImage' AND path LIKE '%xattr-test.txt';" 2>/dev/null | tr 'A-Z' 'a-z' || true)"
if [ -z "${HEX_DUMP}" ]; then
    smoke_fail "no FilePreImage row found"
fi
if ! grep -q "${XATTR_HEX}" <<<"${HEX_DUMP}"; then
    smoke_log "expected to find xattr value hex ${XATTR_HEX} in serialized payload"
    smoke_log "payload (first 200 hex chars): ${HEX_DUMP:0:200}"
    smoke_fail "captured event payload missing the user-set xattr value bytes"
fi
smoke_log "captured event payload contains user-set xattr value ✓"

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
smoke_log "restored content sha256 matches original ✓"

# Verify the xattr was restored. If the daemon's restore path
# doesn't apply xattrs yet, this is the failure mode we surface
# (the producer captured them correctly — the gap is daemon-side).
POST_XATTR_VAL="$(xattr -p "${XATTR_KEY}" "${FILE}" 2>/dev/null || true)"
if [ "${POST_XATTR_VAL}" != "${XATTR_VALUE}" ]; then
    smoke_log "expected xattr=${XATTR_VALUE}"
    smoke_log "got      xattr=${POST_XATTR_VAL}"
    smoke_log "all current xattrs on file:"
    xattr -l "${FILE}" | sed 's/^/    /'
    smoke_fail "restored file is missing the user xattr (producer captured it; daemon restore gap)"
fi
smoke_log "restored xattr ${XATTR_KEY}=${POST_XATTR_VAL} ✓"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-xattr-roundtrip-macos (M03.x.XATTR)"
