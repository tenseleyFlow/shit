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

# AU12.A — synthesize a minimal static ELF64 (no PT_INTERP, ET_EXEC).
# Python-only construction so the smoke doesn't depend on a system
# compiler or a busybox-style binary. Same byte layout the unit tests
# in visibility.rs validate.
python3 - "${SCRATCH}/static-bin" <<'PY'
import struct, sys, os
path = sys.argv[1]
# ELF64 header (64 bytes) + one PT_LOAD program header (56 bytes).
hdr = bytearray(120)
hdr[0:4] = b'\x7fELF'
hdr[4] = 2          # ELFCLASS64
hdr[5] = 1          # ELFDATA2LSB
hdr[6] = 1          # EI_VERSION
struct.pack_into('<H', hdr, 16, 2)        # e_type = ET_EXEC
struct.pack_into('<H', hdr, 18, 0x3e)     # e_machine = EM_X86_64
struct.pack_into('<I', hdr, 20, 1)        # e_version
struct.pack_into('<Q', hdr, 24, 0x400000) # e_entry
struct.pack_into('<Q', hdr, 32, 64)       # e_phoff
struct.pack_into('<H', hdr, 52, 64)       # e_ehsize
struct.pack_into('<H', hdr, 54, 56)       # e_phentsize
struct.pack_into('<H', hdr, 56, 1)        # e_phnum
# Program header at offset 64: PT_LOAD (= 1) so there's structure but
# no PT_INTERP. The classifier sees no interp + e_type=ET_EXEC → static.
struct.pack_into('<I', hdr, 64, 1)        # p_type = PT_LOAD
with open(path, 'wb') as f:
    f.write(hdr)
os.chmod(path, 0o755)
PY

smoke_log "scratch:"
ls -la "${SCRATCH}" | sed 's/^/    /' >&2

# JSON mode.
JSON_OUT="${SHIT_SMOKE_TMP}/visibility.json"
"${SHIT_BIN}" doctor --visibility "${SCRATCH}" --json >"${JSON_OUT}" 2>&1 \
    || smoke_fail "doctor --visibility --json non-zero"

scanned="$(python3 -c "import json; print(json.load(open('${JSON_OUT}'))['executables_scanned'])")"
suid_count="$(python3 -c "import json; print(json.load(open('${JSON_OUT}'))['setuid_bypassing_shim'])")"
static_count="$(python3 -c "import json; print(json.load(open('${JSON_OUT}'))['static_bypassing_shim'])")"
detail_kinds="$(python3 -c "import json; print(','.join(sorted(d['kind'] for d in json.load(open('${JSON_OUT}'))['details'])))")"

# 3 executables visited: regular (script, not ELF) + setuid-exec
# (script, not ELF) + static-bin (synthetic ELF). setuid-data is
# mode 0o4644 — not executable — and is skipped.
if [ "${scanned}" != "3" ]; then
    smoke_log "expected executables_scanned=3 got=${scanned}"
    sed 's/^/    /' "${JSON_OUT}" >&2 || true
    smoke_fail "JSON scanned count wrong"
fi
if [ "${suid_count}" != "1" ]; then
    smoke_log "expected setuid_bypassing_shim=1 got=${suid_count}"
    sed 's/^/    /' "${JSON_OUT}" >&2 || true
    smoke_fail "JSON setuid count wrong"
fi
if [ "${static_count}" != "1" ]; then
    smoke_log "expected static_bypassing_shim=1 got=${static_count}"
    sed 's/^/    /' "${JSON_OUT}" >&2 || true
    smoke_fail "JSON static count wrong"
fi
if [ "${detail_kinds}" != "setuid,static" ]; then
    smoke_log "expected details kinds=[setuid,static] got=[${detail_kinds}]"
    smoke_fail "JSON details kinds wrong"
fi
smoke_log "  JSON: scanned=${scanned} setuid=${suid_count} static=${static_count} kinds=[${detail_kinds}] (ok)"

# Text mode.
TXT_OUT="${SHIT_SMOKE_TMP}/visibility.txt"
"${SHIT_BIN}" doctor --visibility "${SCRATCH}" >"${TXT_OUT}" 2>&1 \
    || smoke_fail "doctor --visibility text non-zero"

if ! grep -q "setuid bypass count:  1" "${TXT_OUT}"; then
    smoke_log "text mode missing 'setuid bypass count:  1':"
    sed 's/^/    /' "${TXT_OUT}" >&2 || true
    smoke_fail "text setuid count line wrong"
fi
if ! grep -q "static bypass count:  1" "${TXT_OUT}"; then
    smoke_log "text mode missing 'static bypass count:  1':"
    sed 's/^/    /' "${TXT_OUT}" >&2 || true
    smoke_fail "text static count line wrong"
fi
if ! grep -q "WARN: 2 bypass" "${TXT_OUT}"; then
    smoke_log "text mode missing 'WARN: 2 bypass' line"
    sed 's/^/    /' "${TXT_OUT}" >&2 || true
    smoke_fail "text WARN line missing"
fi
if ! grep -q "Setuid.*setuid-exec" "${TXT_OUT}"; then
    smoke_log "text mode missing setuid-exec detail line"
    smoke_fail "text setuid detail missing"
fi
if ! grep -q "Static.*static-bin" "${TXT_OUT}"; then
    smoke_log "text mode missing static-bin detail line"
    smoke_fail "text static detail missing"
fi
smoke_log "  text-mode WARN block present (ok)"

# Empty-tree case: zero bypass count, no WARN line.
EMPTY="${SHIT_SMOKE_TMP}/visibility-empty"
mkdir -p "${EMPTY}"
echo '#!/bin/sh' >"${EMPTY}/plain"
chmod 0755 "${EMPTY}/plain"

EMPTY_OUT="${SHIT_SMOKE_TMP}/visibility-empty.txt"
"${SHIT_BIN}" doctor --visibility "${EMPTY}" >"${EMPTY_OUT}" 2>&1 \
    || smoke_fail "doctor --visibility on empty-of-bypass non-zero"
if ! grep -q "setuid bypass count:  0" "${EMPTY_OUT}"; then
    smoke_log "empty-tree mode missing 'setuid bypass count:  0':"
    sed 's/^/    /' "${EMPTY_OUT}" >&2 || true
    smoke_fail "empty-tree setuid count line wrong"
fi
if ! grep -q "static bypass count:  0" "${EMPTY_OUT}"; then
    smoke_log "empty-tree mode missing 'static bypass count:  0':"
    sed 's/^/    /' "${EMPTY_OUT}" >&2 || true
    smoke_fail "empty-tree static count line wrong"
fi
if grep -q "^WARN:" "${EMPTY_OUT}"; then
    smoke_log "empty-tree unexpectedly emits WARN:"
    sed 's/^/    /' "${EMPTY_OUT}" >&2 || true
    smoke_fail "empty-tree should not WARN"
fi
smoke_log "  empty-tree: 0 bypass, no WARN (ok)"

smoke_log "PASS: visibility-setuid"
