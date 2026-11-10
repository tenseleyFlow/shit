#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-bin-mv-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-es
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Lane M2: undo of the SIP-protected /bin/mv under EndpointSecurity.
#
# /bin/mv is an Apple platform binary, so the DYLD shim never loads
# into it. ES AUTH_RENAME is the only capture path. The smoke moves a
# file into a subdirectory under a new name and checks that
# `shit undo` puts it back at its old path with the same bytes.
# Moving over an existing file is es-rename-undo-macos (#279).
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
    smoke_log "SKIP: es-bin-mv-undo-macos is macOS-only (uname=$(uname -s))"
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

mv_sig="$(codesign -dv /bin/mv 2>&1 || true)"
if ! grep -q "Platform identifier" <<<"${mv_sig}"; then
    smoke_fail "/bin/mv is not an Apple platform binary on this host"
fi

export SHIT_HELPER_BIN="${HELPER_BIN}"
smoke_start_shitd
sleep 0.5

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}/dest"
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
SRC="${SCRATCH}/src.txt"
DST="${SCRATCH}/dest/moved.txt"
printf 'mv canary %s\n' "$(date -u +%s)" >"${SRC}"
WANT="$(shasum -a 256 "${SRC}" | awk '{print $1}')"

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open --session "${SESSION}" --pid "${PID}" \
    --shell bash --tty /dev/null --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION}" --seq "${SEQ}" \
    --pid "${PID}" --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

smoke_log "/bin/mv ${SRC} ${DST}"
/bin/mv "${SRC}" "${DST}"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec --session "${SESSION}" --seq "${SEQ}" \
    --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'TreeOpRename'" 1 10
[ ! -e "${SRC}" ] || smoke_fail "src.txt should be gone after /bin/mv"
[ -f "${DST}" ] || smoke_fail "dest/moved.txt should exist after /bin/mv"

smoke_log "running: shit undo --yes"
if ! "${SHIT_BIN}" undo --yes >"${SHIT_SMOKE_TMP}/undo.log" 2>&1; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
fi
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log"

[ -f "${SRC}" ] || smoke_fail "src.txt was not moved back"
[ ! -e "${DST}" ] || smoke_fail "dest/moved.txt still exists after undo"
GOT="$(shasum -a 256 "${SRC}" | awk '{print $1}')"
[ "${GOT}" = "${WANT}" ] || smoke_fail "src.txt sha256 mismatch: want ${WANT} got ${GOT}"
smoke_log "src.txt back at its old path, byte for byte ✓"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-bin-mv-undo-macos"
