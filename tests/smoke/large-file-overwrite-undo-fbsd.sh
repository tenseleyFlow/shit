#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: large-file-overwrite-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W06.A.4.1 smoke — overwrite a 2 MiB file at an unwatched
# destination via `install`. The pre-W06.A.4.1 inline pre-image cap
# was 256 KiB, so this would have silently skipped pre-image
# capture and undo would no-op. With the cap raised to 32 MiB and
# the daemon's recv buffer dynamic-allocated, the entire pre-image
# rides inline through the shim notification.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: large-file-overwrite-undo-fbsd is FreeBSD-only"
    exit 0
fi

INSTALL_BIN="$(command -v install || echo /usr/bin/install)"
[ -x "${INSTALL_BIN}" ] || smoke_fail "install not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
DST_DIR="${SHIT_SMOKE_TMP}/install-target/bin"
mkdir -p "${WATCHED}" "${DST_DIR}"

# Pre-populate the dst with a 2 MiB file of ORIGINAL bytes.
# 2 MiB = 8x the old cap; comfortably above 256 KiB without being
# a CI burden.
DST="${DST_DIR}/big.bin"
dd if=/dev/urandom of="${DST}" bs=1024 count=2048 2>/dev/null
PRE_DST_SHA="$(/sbin/sha256 -q "${DST}")"
PRE_DST_SIZE="$(/usr/bin/stat -f '%z' "${DST}")"
smoke_log "pre-cmd dst: sha=${PRE_DST_SHA} size=${PRE_DST_SIZE}"

# Source: a different 2 MiB file (also random — different content).
SRC="${WATCHED}/replacement.bin"
dd if=/dev/urandom of="${SRC}" bs=1024 count=2048 2>/dev/null
PRE_SRC_SHA="$(/sbin/sha256 -q "${SRC}")"
[ "${PRE_SRC_SHA}" != "${PRE_DST_SHA}" ] || smoke_fail "src and dst collide (bad RNG?)"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

smoke_log "LD_PRELOAD=${SHIM_LIB} install -m 0644 ${SRC} ${DST}"
LD_PRELOAD="${SHIM_LIB}" "${INSTALL_BIN}" -m 0644 "${SRC}" "${DST}"

POST_INSTALL_SHA="$(/sbin/sha256 -q "${DST}")"
[ "${POST_INSTALL_SHA}" = "${PRE_SRC_SHA}" ] || smoke_fail "install didn't overwrite (got ${POST_INSTALL_SHA})"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

[ -f "${DST}" ] || smoke_fail "dst removed by undo (should have been restored)"
POST_UNDO_SHA="$(/sbin/sha256 -q "${DST}")"
POST_UNDO_SIZE="$(/usr/bin/stat -f '%z' "${DST}")"
smoke_log "post-undo dst: sha=${POST_UNDO_SHA} size=${POST_UNDO_SIZE}"

if [ "${POST_UNDO_SHA}" = "${PRE_DST_SHA}" ]; then
    smoke_log "PASS: large-file-overwrite-undo-fbsd (2 MiB restored byte-identical via raised cap)"
    exit 0
fi

smoke_fail "byte mismatch: got ${POST_UNDO_SHA}, expected ${PRE_DST_SHA} (size ${POST_UNDO_SIZE} vs ${PRE_DST_SIZE})"
