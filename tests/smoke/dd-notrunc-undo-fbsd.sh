#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: dd-notrunc-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.8.dd smoke — `dd of=existing conv=notrunc bs=4k count=1
# seek=2` overwrites a 4k chunk in the middle of an existing
# file via pwrite/write at a non-zero offset. This is the
# canonical fd-based partial write the W06.A.4 shim doesn't
# cover (open without O_TRUNC + pwrite via fd; the open
# interposer doesn't fire because no write flags imply
# truncation, and the pwrite interposer ships a fd:N arg
# that the daemon doesn't yet resolve to a path).
#
# For files INSIDE the watched cwd: the kqueue tier's
# live-baseline pre-image capture (W02.B) should cover this
# — baseline holds a content snapshot from pre-exec, and
# NOTE_WRITE on the file promotes the baseline to a real
# FilePreImage. So intra-watch dd should work via the same
# path vim/sed use.
#
# Cross-watch dd is broken (deferred — see followups).
# This smoke tests intra-watch only.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: dd-notrunc-undo-fbsd is FreeBSD-only"
    exit 0
fi

DD_BIN="$(command -v dd)"
[ -x "${DD_BIN}" ] || smoke_fail "dd not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/data.bin"
# Build a 16k file with predictable content (4 distinct chunks).
( for c in A B C D; do dd if=/dev/zero bs=4k count=1 2>/dev/null | tr '\0' "${c}"; done ) > "${SUBJECT}"
PRE_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
PRE_SIZE="$(/usr/bin/stat -f '%z' "${SUBJECT}")"
smoke_log "pre-cmd sha=${PRE_SHA} size=${PRE_SIZE}"

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
sleep 1.0  # extra time for baseline capture

# THE workload: overwrite chunk 3 (offset 8k–12k) in-place with X's.
# conv=notrunc means dd uses open(O_WRONLY) without O_TRUNC.
smoke_log "${DD_BIN} if=/dev/zero of=${SUBJECT} bs=4k count=1 seek=2 conv=notrunc | tr→X"
dd if=/dev/zero bs=4k count=1 2>/dev/null | tr '\0' 'X' | \
    "${DD_BIN}" of="${SUBJECT}" bs=4k count=1 seek=2 conv=notrunc 2>/dev/null

POST_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
POST_SIZE="$(/usr/bin/stat -f '%z' "${SUBJECT}")"
smoke_log "post-dd sha=${POST_SHA} size=${POST_SIZE}"
[ "${POST_SHA}" != "${PRE_SHA}" ] || smoke_fail "dd didn't change content"
[ "${POST_SIZE}" = "${PRE_SIZE}" ] || smoke_fail "dd changed size (notrunc?): ${PRE_SIZE} → ${POST_SIZE}"

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

POST_UNDO_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-undo sha: ${POST_UNDO_SHA}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: dd-notrunc-undo-fbsd (data.bin restored byte-identical via baseline pre-image)"
    exit 0
fi

smoke_fail "dd notrunc undo failed: got ${POST_UNDO_SHA}, expected ${PRE_SHA} (intra-watch fd-write coverage hole)"
