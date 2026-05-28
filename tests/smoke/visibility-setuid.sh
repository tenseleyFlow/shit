#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: visibility-setuid
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU12 smoke — `shit doctor --visibility <PATH>` correctly surfaces
# setuid binaries in a watched tree, both in JSON and text mode.
#
# The smoke creates a scratch dir with:
#   - one regular executable      (should NOT count)
#   - one setuid executable       (should count; details[0])
#   - one setuid non-executable   (should NOT count — exec(2) ignores)
# Then asserts the JSON report's counts and the text-mode WARN line.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

SCRATCH="${SHIT_SMOKE_TMP}/visibility-scratch"
mkdir -p "${SCRATCH}"

echo '#!/bin/sh' >"${SCRATCH}/regular"
chmod 0755 "${SCRATCH}/regular"

echo '#!/bin/sh' >"${SCRATCH}/setuid-exec"
chmod 4755 "${SCRATCH}/setuid-exec"

echo 'data, not a binary' >"${SCRATCH}/setuid-data"
chmod 4644 "${SCRATCH}/setuid-data"

smoke_log "scratch:"
ls -la "${SCRATCH}" | sed 's/^/    /' >&2

# JSON mode.
JSON_OUT="${SHIT_SMOKE_TMP}/visibility.json"
"${SHIT_BIN}" doctor --visibility "${SCRATCH}" --json >"${JSON_OUT}" 2>&1 \
    || smoke_fail "doctor --visibility --json non-zero"

scanned="$(python3 -c "import json; print(json.load(open('${JSON_OUT}'))['executables_scanned'])")"
suid_count="$(python3 -c "import json; print(json.load(open('${JSON_OUT}'))['setuid_bypassing_shim'])")"
detail_kinds="$(python3 -c "import json; print(','.join(d['kind'] for d in json.load(open('${JSON_OUT}'))['details']))")"

# 2 executables visited (regular + setuid-exec). setuid-data is mode
# 0o4644 — not executable by anyone — so the walker should skip it
# entirely.
if [ "${scanned}" != "2" ]; then
    smoke_log "expected executables_scanned=2 got=${scanned}"
    sed 's/^/    /' "${JSON_OUT}" >&2 || true
    smoke_fail "JSON scanned count wrong"
fi
if [ "${suid_count}" != "1" ]; then
    smoke_log "expected setuid_bypassing_shim=1 got=${suid_count}"
    sed 's/^/    /' "${JSON_OUT}" >&2 || true
    smoke_fail "JSON setuid count wrong"
fi
if [ "${detail_kinds}" != "setuid" ]; then
    smoke_log "expected details=[setuid] got=[${detail_kinds}]"
    smoke_fail "JSON details kinds wrong"
fi
smoke_log "  JSON: scanned=${scanned} setuid=${suid_count} kinds=[${detail_kinds}] (ok)"

# Text mode.
TXT_OUT="${SHIT_SMOKE_TMP}/visibility.txt"
"${SHIT_BIN}" doctor --visibility "${SCRATCH}" >"${TXT_OUT}" 2>&1 \
    || smoke_fail "doctor --visibility text non-zero"

if ! grep -q "setuid bypass count:  1" "${TXT_OUT}"; then
    smoke_log "text mode missing 'setuid bypass count:  1':"
    sed 's/^/    /' "${TXT_OUT}" >&2 || true
    smoke_fail "text count line wrong"
fi
if ! grep -q "WARN: at least 1 setuid" "${TXT_OUT}"; then
    smoke_log "text mode missing WARN line"
    sed 's/^/    /' "${TXT_OUT}" >&2 || true
    smoke_fail "text WARN line missing"
fi
if ! grep -q "Setuid.*setuid-exec" "${TXT_OUT}"; then
    smoke_log "text mode missing the setuid-exec path in details"
    smoke_fail "text details missing"
fi
smoke_log "  text-mode WARN block present (ok)"

# Empty-tree case: zero bypass count, no WARN line.
EMPTY="${SHIT_SMOKE_TMP}/visibility-empty"
mkdir -p "${EMPTY}"
echo '#!/bin/sh' >"${EMPTY}/plain"
chmod 0755 "${EMPTY}/plain"

EMPTY_OUT="${SHIT_SMOKE_TMP}/visibility-empty.txt"
"${SHIT_BIN}" doctor --visibility "${EMPTY}" >"${EMPTY_OUT}" 2>&1 \
    || smoke_fail "doctor --visibility on empty-of-setuid non-zero"
if ! grep -q "setuid bypass count:  0" "${EMPTY_OUT}"; then
    smoke_log "empty-tree mode missing 'setuid bypass count:  0':"
    sed 's/^/    /' "${EMPTY_OUT}" >&2 || true
    smoke_fail "empty-tree count line wrong"
fi
if grep -q "^WARN:" "${EMPTY_OUT}"; then
    smoke_log "empty-tree unexpectedly emits WARN:"
    sed 's/^/    /' "${EMPTY_OUT}" >&2 || true
    smoke_fail "empty-tree should not WARN"
fi
smoke_log "  empty-tree: 0 bypass, no WARN (ok)"

smoke_log "PASS: visibility-setuid"
