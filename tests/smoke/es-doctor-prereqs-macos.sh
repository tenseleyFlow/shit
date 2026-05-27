#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-doctor-prereqs-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 120
# EXCLUDED_BY: M03-vm-runner
# EXCLUDED_REASON: macOS smokes need a signed binary on a Tart VM; GH-hosted macos-14 runner cannot satisfy the EndpointSecurity entitlement
#
# M03.x.POWER-USER.6 smoke — doctor surface + setup-es-mode CLI.
#
# Validates the prereq probe + CLI surface end-to-end on the Tart
# VM (which IS the SIP+AuthRoot+AMFI-bypassed power-user
# environment our M03.x.POWER-USER install is targeting):
#
#   1. `shit doctor --json` reports `es_capable: true`
#   2. Each individual prereq probe is green
#      (`sip.state="disabled"|"custom"`, `sip.authenticated_root="disabled"`,
#      `sip.amfi_bypass=true`, `endpoint_security.helper_has_es_entitlement=true`)
#   3. `es_blockers` array is empty
#   4. `shit setup-es-mode --check` exits 0 and prints all-pass
#   5. `shit setup-es-mode --print` short-circuits to "nothing to do"
#
# Skips cleanly on stock macOS (any prereq missing) — the smoke is
# specifically for the power-user-mode VM target.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-doctor-prereqs-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"

# Same env discrimination as the other ES smokes — only run when the
# host is in the power-user state. SHIT_HELPER_BIN points the doctor
# at the same binary `shitd` would spawn.
export SHIT_HELPER_BIN="${HELPER_BIN}"
probe_out="$("${HELPER_BIN}" es-probe 2>/dev/null || true)"
if [ -z "${probe_out}" ] || ! grep -q '"result":"Success"' <<<"${probe_out}"; then
    smoke_log "SKIP: ES not entitled in this env (need SIP+AuthRoot+AMFI VM with signed helper); probe=${probe_out}"
    exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
    smoke_log "SKIP: ES probe requires sudo to return Success; rerun as root"
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────
# Part 1 — doctor JSON envelope checks
# ─────────────────────────────────────────────────────────────────────

DOCTOR_JSON="${SHIT_SMOKE_TMP}/doctor.json"
"${SHIT_BIN}" doctor --json >"${DOCTOR_JSON}" 2>&1 \
    || { sed 's/^/    /' "${DOCTOR_JSON}" >&2; smoke_fail "shit doctor --json exited non-zero"; }

# Use python3 (always present on macOS) to assert on each field. One
# call so failures surface together.
/usr/bin/python3 - "${DOCTOR_JSON}" <<'PY' || smoke_fail "doctor JSON assertions failed"
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
m = d.get("macos") or {}
fails = []
def expect(cond, msg):
    if not cond:
        fails.append(msg)

expect(m.get("es_capable") is True, f"macos.es_capable should be true; got {m.get('es_capable')!r}")
expect(m.get("es_blockers") == [], f"macos.es_blockers should be []; got {m.get('es_blockers')!r}")

sip = m.get("sip") or {}
expect(sip.get("state") in ("disabled", "custom"),
       f"macos.sip.state should be disabled|custom; got {sip.get('state')!r}")
expect(sip.get("authenticated_root") == "disabled",
       f"macos.sip.authenticated_root should be disabled; got {sip.get('authenticated_root')!r}")
expect(sip.get("amfi_bypass") is True,
       f"macos.sip.amfi_bypass should be true; got {sip.get('amfi_bypass')!r}")

es = m.get("endpoint_security") or {}
expect(es.get("helper_has_es_entitlement") is True,
       f"macos.endpoint_security.helper_has_es_entitlement should be true; got {es.get('helper_has_es_entitlement')!r}")

if fails:
    for m in fails:
        print("  FAIL:", m, file=sys.stderr)
    sys.exit(1)
print("all doctor JSON assertions green")
PY

smoke_log "doctor JSON: es_capable=true + all 4 prereq fields green ✓"

# ─────────────────────────────────────────────────────────────────────
# Part 2 — `shit setup-es-mode --check` exits 0 with all-pass output
# ─────────────────────────────────────────────────────────────────────

SETUP_CHECK_OUT="${SHIT_SMOKE_TMP}/setup-check.out"
"${SHIT_BIN}" setup-es-mode --check >"${SETUP_CHECK_OUT}" 2>&1
SETUP_CHECK_RC=$?
if [ "${SETUP_CHECK_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SETUP_CHECK_OUT}" >&2
    smoke_fail "setup-es-mode --check exited ${SETUP_CHECK_RC} (expected 0)"
fi
# All four prereq lines should show ✓ pass.
PASS_COUNT="$(grep -cE '\[✓ pass\]' "${SETUP_CHECK_OUT}" || true)"
if [ "${PASS_COUNT}" -ne 4 ]; then
    sed 's/^/    /' "${SETUP_CHECK_OUT}" >&2
    smoke_fail "setup-es-mode --check should show 4 ✓ pass lines; got ${PASS_COUNT}"
fi
if ! grep -q "es_capable = TRUE" "${SETUP_CHECK_OUT}"; then
    sed 's/^/    /' "${SETUP_CHECK_OUT}" >&2
    smoke_fail "setup-es-mode --check missing 'es_capable = TRUE' summary"
fi
smoke_log "setup-es-mode --check: exit 0, 4/4 prereqs pass, es_capable=TRUE ✓"

# ─────────────────────────────────────────────────────────────────────
# Part 3 — `shit setup-es-mode --print` short-circuits when capable
# ─────────────────────────────────────────────────────────────────────

SETUP_PRINT_OUT="${SHIT_SMOKE_TMP}/setup-print.out"
"${SHIT_BIN}" setup-es-mode --print >"${SETUP_PRINT_OUT}" 2>&1 \
    || { sed 's/^/    /' "${SETUP_PRINT_OUT}" >&2; smoke_fail "setup-es-mode --print exited non-zero"; }
if ! grep -q "nothing to do" "${SETUP_PRINT_OUT}"; then
    sed 's/^/    /' "${SETUP_PRINT_OUT}" >&2
    smoke_fail "setup-es-mode --print should report 'nothing to do' when es_capable; got different output"
fi
smoke_log "setup-es-mode --print: short-circuited (nothing to do) ✓"

smoke_log "PASS: es-doctor-prereqs-macos (M03.x.POWER-USER.1/.2 surface verified)"
