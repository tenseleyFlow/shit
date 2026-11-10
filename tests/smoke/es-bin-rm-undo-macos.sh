#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-bin-rm-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-es
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Lane M2: undo of the SIP-protected /bin/rm under EndpointSecurity.
#
# /bin/rm is an Apple platform binary. SIP strips DYLD_INSERT_LIBRARIES
# from it, so the DYLD shim never sees its unlinks. ES AUTH_UNLINK is
# the only capture path. The smoke removes two files with one
# `/bin/rm` and checks that `shit undo` brings both back byte for
# byte. `/bin/rm -r` of a tree is #280.
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
    smoke_log "SKIP: es-bin-rm-undo-macos is macOS-only (uname=$(uname -s))"
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

# /bin/rm must be a platform binary, or this smoke proves nothing
# about SIP binaries.
rm_sig="$(codesign -dv /bin/rm 2>&1 || true)"
if ! grep -q "Platform identifier" <<<"${rm_sig}"; then
    smoke_fail "/bin/rm is not an Apple platform binary on this host"
fi

export SHIT_HELPER_BIN="${HELPER_BIN}"
smoke_start_shitd
sleep 0.5

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
printf 'first %s\n' "$(date -u +%s)" >"${SCRATCH}/a.txt"
printf 'second %s\n' "$(date -u +%s)" >"${SCRATCH}/b.txt"
SHA_A="$(shasum -a 256 "${SCRATCH}/a.txt" | awk '{print $1}')"
SHA_B="$(shasum -a 256 "${SCRATCH}/b.txt" | awk '{print $1}')"

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open --session "${SESSION}" --pid "${PID}" \
    --shell bash --tty /dev/null --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION}" --seq "${SEQ}" \
    --pid "${PID}" --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

smoke_log "/bin/rm a.txt b.txt"
/bin/rm "${SCRATCH}/a.txt" "${SCRATCH}/b.txt"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec --session "${SESSION}" --seq "${SEQ}" \
    --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 2 10
[ ! -e "${SCRATCH}/a.txt" ] && [ ! -e "${SCRATCH}/b.txt" ] \
    || smoke_fail "a.txt and b.txt should be gone after /bin/rm"

smoke_log "running: shit undo --yes"
if ! "${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo.log" 2>&1; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
fi
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log"

for pair in "a.txt:${SHA_A}" "b.txt:${SHA_B}"; do
    rel="${pair%%:*}"
    want="${pair#*:}"
    [ -f "${SCRATCH}/${rel}" ] || smoke_fail "${rel} was not restored"
    got="$(shasum -a 256 "${SCRATCH}/${rel}" | awk '{print $1}')"
    [ "${got}" = "${want}" ] || smoke_fail "${rel} sha256 mismatch: want ${want} got ${got}"
    smoke_log "${rel} restored byte for byte ✓"
done

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-bin-rm-undo-macos"
