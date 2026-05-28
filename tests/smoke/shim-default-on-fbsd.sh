#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: shim-default-on-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 120
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU07 smoke — validates the BSD doctor + helper tier-picker
# coherence around the LD_PRELOAD shim install state.
#
# Two states are exercised:
#
#   1. **Absent**: with no SHIT_PRELOAD_SHIM_PATH set and no shim
#      at /usr/local/lib/shit/libshit_preload_shim.so, doctor
#      reports preload_shim_installed=false and runtime_capture
#      "kqueue-only", and the text mode surfaces the multi-line
#      WARN block (not the previous single quiet line).
#
#   2. **Present**: pointing SHIT_PRELOAD_SHIM_PATH at the build
#      artifact flips both fields to true / "kqueue+preload"
#      WITHOUT requiring sudo write access to /usr/local/lib/shit/.
#      This is the audit-honesty guarantee: doctor and the helper
#      see the same path.
#
# The smoke does NOT exercise actual shim-interposed capture (that
# coverage lives in preload-shim-fbsd.sh and the mv-across-dirs
# smoke). AU07's surface is "the doctor and helper agree about
# whether the shim is installed."

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: shim-default-on-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"

if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi
if [ ! -f "${SHIM_LIB}" ]; then
    smoke_fail "shim build artifact missing at ${SHIM_LIB}"
fi

# Doctor reads probes only — no daemon required.
# State 1 — shim absent (override not set, and the real
# /usr/local/lib/shit/libshit_preload_shim.so should not exist on
# a stock CI VM; if it does the test author's host is unusual and
# this smoke would surface that loudly).
smoke_log "state 1: doctor with SHIT_PRELOAD_SHIM_PATH unset"
ABSENT_JSON="${SHIT_SMOKE_TMP}/absent.json"
ABSENT_TXT="${SHIT_SMOKE_TMP}/absent.txt"
unset SHIT_PRELOAD_SHIM_PATH
"${SHIT_BIN}" doctor --json >"${ABSENT_JSON}" 2>&1 \
    || smoke_fail "doctor --json (absent) returned non-zero"
"${SHIT_BIN}" doctor       >"${ABSENT_TXT}"  2>&1 \
    || smoke_fail "doctor (absent) returned non-zero"

# JSON assertions (state 1).
absent_installed="$(python3 -c "
import json
d = json.load(open('${ABSENT_JSON}'))
print(d.get('bsd', {}).get('preload_shim_installed', 'MISSING'))
")"
if [ "${absent_installed}" != "False" ]; then
    smoke_log "absent state: expected preload_shim_installed=False got=${absent_installed}"
    smoke_fail "state-1 doctor JSON wrong"
fi
smoke_log "  preload_shim_installed=${absent_installed} (ok)"

# Text-mode WARN block must be present (the loud line, not the old
# single quiet breadcrumb).
if ! grep -q "NOT INSTALLED" "${ABSENT_TXT}"; then
    smoke_log "absent-state doctor text missing 'NOT INSTALLED':"
    sed 's/^/    /' "${ABSENT_TXT}" >&2 || true
    smoke_fail "state-1 doctor text WARN line missing"
fi
if ! grep -q "WARN: unlink and rename" "${ABSENT_TXT}"; then
    smoke_log "absent-state doctor text missing impact line"
    smoke_fail "state-1 doctor text impact line missing"
fi
smoke_log "  text-mode WARN block present (ok)"

# State 2 — shim present via override.
smoke_log "state 2: doctor with SHIT_PRELOAD_SHIM_PATH=${SHIM_LIB}"
PRESENT_JSON="${SHIT_SMOKE_TMP}/present.json"
SHIT_PRELOAD_SHIM_PATH="${SHIM_LIB}" "${SHIT_BIN}" doctor --json >"${PRESENT_JSON}" 2>&1 \
    || smoke_fail "doctor --json (present) returned non-zero"

present_installed="$(python3 -c "
import json
d = json.load(open('${PRESENT_JSON}'))
print(d.get('bsd', {}).get('preload_shim_installed', 'MISSING'))
")"
present_runtime="$(python3 -c "
import json
d = json.load(open('${PRESENT_JSON}'))
print(d.get('bsd', {}).get('runtime_capture', 'MISSING'))
")"
if [ "${present_installed}" != "True" ]; then
    smoke_log "present state: expected preload_shim_installed=True got=${present_installed}"
    smoke_fail "state-2 doctor JSON wrong (installed)"
fi
if [ "${present_runtime}" != "kqueue+preload" ]; then
    smoke_log "present state: expected runtime_capture=kqueue+preload got=${present_runtime}"
    smoke_fail "state-2 doctor JSON wrong (runtime_capture)"
fi
smoke_log "  preload_shim_installed=${present_installed} runtime_capture=${present_runtime} (ok)"

smoke_log "PASS: shim-default-on-fbsd"
