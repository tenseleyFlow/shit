#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: shell-append-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.18 smoke — bash builtin append redirect: `echo X >> file`.
# Distinct from:
#   - shell-redirect-undo-fbsd ( `>` truncate via bash builtin)
#   - tee-undo-fbsd ( `tee -a` separate-binary append)
#
# bash itself calls `open(file, O_WRONLY|O_CREAT|O_APPEND)` for
# `>>`. The shim's open interposer's `writes` predicate fires on
# O_WRONLY, captures pre-image. After write, the file is longer.
# Undo: RestoreContent → tmpfile-rename to put back pre-bytes,
# implicitly truncating back to the original size.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: shell-append-undo-fbsd is FreeBSD-only"
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
DST_DIR="${SHIT_SMOKE_TMP}/unwatched"
mkdir -p "${WATCHED}" "${DST_DIR}"
DST="${DST_DIR}/app.log"
printf 'line1\nline2\n' > "${DST}"
PRE_SHA="$(/sbin/sha256 -q "${DST}")"
PRE_SIZE="$(/usr/bin/stat -f '%z' "${DST}")"
smoke_log "pre-cmd: sha=${PRE_SHA} size=${PRE_SIZE}"

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

# Bash builtin append. LD_PRELOAD scoped to bash so its open(>>)
# is interposed.
smoke_log "bash -c 'echo appended-line >> ${DST}'"
LD_PRELOAD="${SHIM_LIB}" bash -c "echo 'appended-line' >> '${DST}'"

POST_SIZE="$(/usr/bin/stat -f '%z' "${DST}")"
[ "${POST_SIZE}" -gt "${PRE_SIZE}" ] || smoke_fail "append didn't grow file (size ${POST_SIZE} ≤ ${PRE_SIZE})"
grep -q 'appended-line' "${DST}" || smoke_fail "appended content missing"
smoke_log "post-cmd: size=${POST_SIZE}"

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
[ -f "${DST}" ] || smoke_fail "undo removed the file (should have restored content)"
POST_UNDO_SHA="$(/sbin/sha256 -q "${DST}")"
POST_UNDO_SIZE="$(/usr/bin/stat -f '%z' "${DST}")"
smoke_log "post-undo: sha=${POST_UNDO_SHA} size=${POST_UNDO_SIZE}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: shell-append-undo-fbsd (>> append byte-identical restored)"
    exit 0
fi
smoke_fail "undo didn't restore pre-bytes: got ${POST_UNDO_SHA}, want ${PRE_SHA}"
