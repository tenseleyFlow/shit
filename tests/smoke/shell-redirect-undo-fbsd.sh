#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: shell-redirect-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.2 smoke — shell redirect `echo new > /unwatched/file` undo
# restores the file's pre-content. Exercises the W06.A.4 shim
# `open(O_TRUNC|O_WRONLY)` interposer (with pre-image capture) for
# files OUTSIDE the watched cwd. Inside the watched cwd, kqueue +
# live-baseline already handle this; outside, only the shim does.
#
# Without W06.A.4's open pre-image path, the destination's bytes
# would not land in the journal at all (kqueue can't see outside
# the watched subtree) and undo would no-op silently.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: shell-redirect-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
UNWATCHED_DIR="${SHIT_SMOKE_TMP}/unwatched"
mkdir -p "${WATCHED}" "${UNWATCHED_DIR}"

# Pre-populate the unwatched destination with content.
DST="${UNWATCHED_DIR}/data.txt"
printf 'ORIGINAL content predating the redirect\n' > "${DST}"
PRE_SHA="$(/sbin/sha256 -q "${DST}")"
smoke_log "pre-cmd dst sha: ${PRE_SHA}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 cwd=${WATCHED}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload — shell redirect overwrites the unwatched file via
# open(O_TRUNC|O_WRONLY|O_CREAT). LD_PRELOAD the shim into the bash
# subshell so its `open` interposer fires.
smoke_log "LD_PRELOAD=${SHIM_LIB} bash -c 'echo NEW > ${DST}'"
LD_PRELOAD="${SHIM_LIB}" bash -c "echo 'NEW content from shell redirect' > '${DST}'"

POST_REDIRECT_SHA="$(/sbin/sha256 -q "${DST}")"
smoke_log "post-redirect dst sha: ${POST_REDIRECT_SHA}"
[ "${POST_REDIRECT_SHA}" != "${PRE_SHA}" ] || smoke_fail "redirect didn't actually change dst"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed: ${SHIM_HITS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

if [ ! -f "${DST}" ]; then
    smoke_fail "dst file was removed by undo (open interposer should produce RestoreContent, not Unlink)"
fi
POST_UNDO_SHA="$(/sbin/sha256 -q "${DST}")"
smoke_log "post-undo dst sha: ${POST_UNDO_SHA}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: shell-redirect-undo-fbsd (dst restored to pre-redirect bytes; shim hits=${SHIM_HITS})"
    exit 0
fi

smoke_fail "dst bytes not restored: got ${POST_UNDO_SHA}, expected ${PRE_SHA}"
