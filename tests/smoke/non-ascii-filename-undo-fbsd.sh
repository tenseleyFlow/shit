#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: non-ascii-filename-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.19 smoke — non-ASCII filename. POSIX paths are opaque byte
# strings; nothing about the kernel or filesystems assumes UTF-8.
# But if anywhere in the shit stack (wire serialization, sqlite
# storage, log formatting, Rust String vs OsString handling)
# treats paths as UTF-8 / drops high-bit bytes / panics on
# non-Unicode bytes, this smoke surfaces it.
#
# Test data: `café.txt` (UTF-8 c3 a9 for é). Common workflow:
# create file, modify in-place via sed, undo. Verifies undo
# round-trips the name through every layer.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: non-ascii-filename-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
# UTF-8 byte string for `café` is 63 61 66 c3 a9. Use $'...' so
# bash decodes the escape into bytes; relies on the source being
# valid UTF-8 (this script is).
NAME=$'caf\xc3\xa9.txt'
TARGET="${WATCHED}/${NAME}"
printf 'unmodified content\n' > "${TARGET}"
PRE_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "pre-cmd: ${NAME} sha=${PRE_SHA}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload: sed -i in-place on a non-ASCII-named file.
smoke_log "sed -i s/unmodified/modified/ ${NAME}"
LD_PRELOAD="${SHIM_LIB}" /usr/bin/sed -i '' s/unmodified/modified/ "${TARGET}"

grep -q '^modified content$' "${TARGET}" || smoke_fail "sed didn't modify content"
POST_SHA="$(/sbin/sha256 -q "${TARGET}")"
[ "${POST_SHA}" != "${PRE_SHA}" ] || smoke_fail "post-sed content unchanged"
smoke_log "post-cmd: sha=${POST_SHA}"

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

[ "${UNDO_RC}" -eq 0 ] || smoke_fail "undo exited ${UNDO_RC}"
[ -f "${TARGET}" ] || smoke_fail "non-ASCII path lost in undo round-trip"
FINAL_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "post-undo: sha=${FINAL_SHA}"

if [ "${FINAL_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: non-ascii-filename-undo-fbsd (UTF-8 name round-trips through journal)"
    exit 0
fi
smoke_fail "undo didn't restore pre-bytes for ${NAME}: got ${FINAL_SHA}, want ${PRE_SHA}"
