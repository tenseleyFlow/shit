#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chflags-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY: M03.x.SETATTR-impl-pending
# EXCLUDED_REASON: chflags(2) is a REAL capture gap on the M07 shim. Closing it needs FileMetadataWire.flags field (wire-shape change), chflags/fchflags interposers, daemon shim_listener routing, planner MetadataChange inverse, and chflags executor. Tracked under M03.x.SETATTR-FAMILY; this smoke documents the gap pending a dedicated implementation sprint. Re-enable by clearing this EXCLUDED_BY when the fix lands.
#
# M03.x.SETATTR-FAMILY gap-validation smoke (chflags variant).
#
# Per `feedback-validate-gap-before-building`: before building
# AUTH_SETFLAGS handler in macos_es.rs, write a smoke that should
# FAIL pre-fix and verify it actually fails.
#
# Workload: `chflags uchg <file>` sets UF_IMMUTABLE — a pure
# metadata mutation that locks the file from modification/
# deletion. Unlike chmod/chown (covered by M07.B.5 in the shim
# and M03.1.I.D in ES), chflags goes through a DIFFERENT syscall
# (`chflags(2)` not `chmod(2)`) and the M07 shim does NOT
# interpose it.
#
# Outcomes:
#   A. Full undo: post-undo file has same flags as pre-mutation
#      (i.e. no UF_IMMUTABLE). Surprising — would mean some
#      other tier caught the change.
#   B. Loud refusal: undo non-zero with explicit "chflags not
#      captured" or similar.
#   C. Silent stomp (EXPECTED): post-undo file STILL has
#      UF_IMMUTABLE. Gap confirmed — needs AUTH_SETFLAGS
#      handler OR a chflags shim interposer.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: chflags-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

CHFLAGS_BIN="$(command -v chflags 2>/dev/null || echo /usr/bin/chflags)"
[ -x "${CHFLAGS_BIN}" ] || smoke_fail "chflags not found at ${CHFLAGS_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.dylib"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Capture file flags via `ls -lO` (BSD ls; macOS ships it).
# Returns a string like "-rw-r--r--  1 user staff - 12 May 31 12:34 file"
# where "-" is the flags column when no flags are set, or "uchg" etc.
flags_of() {
    /bin/ls -lO "$1" 2>/dev/null | awk '{print $5}'
}

WATCHED="${SHIT_SMOKE_TMP}/watched"
TARGET="${SHIT_SMOKE_TMP}/data/locked.txt"
mkdir -p "${WATCHED}" "$(dirname "${TARGET}")"

printf 'pre-chflags content\n' > "${TARGET}"
PRE_FLAGS="$(flags_of "${TARGET}")"
smoke_log "pre-state flags: '${PRE_FLAGS}'"
if [ "${PRE_FLAGS}" != "-" ]; then
    smoke_fail "pre-state invariant: target file has unexpected flags '${PRE_FLAGS}' (want '-')"
fi

# Belt-and-suspenders cleanup. UF_IMMUTABLE prevents deletion;
# always clear it before any rm so the tmpdir tear-down works.
cleanup() {
    /usr/bin/chflags nouchg "${TARGET}" 2>/dev/null || true
}
trap cleanup EXIT

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

# THE workload: chflags uchg sets UF_IMMUTABLE. Pure metadata
# mutation via the chflags(2) syscall — no content path. The
# M07 shim doesn't interpose chflags, so no pre-state capture
# unless some other tier (ES with AUTH_SETFLAGS, FSEvents
# metadata-modified) lands a usable event.
#
# /usr/bin/chflags is SIP-stripped → DYLD_INSERT is dropped,
# shim doesn't load. But it doesn't matter: shim has no
# chflags interposer anyway.
smoke_log "${CHFLAGS_BIN} uchg ${TARGET}"
"${CHFLAGS_BIN}" uchg "${TARGET}" > "${SHIT_SMOKE_TMP}/chflags.log" 2>&1
CHFLAGS_RC=$?
if [ "${CHFLAGS_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/chflags.log" >&2 || true
    smoke_fail "chflags uchg failed (rc=${CHFLAGS_RC})"
fi

POST_MUTATE_FLAGS="$(flags_of "${TARGET}")"
smoke_log "post-mutate flags: '${POST_MUTATE_FLAGS}'"
if [ "${POST_MUTATE_FLAGS}" != "uchg" ]; then
    smoke_fail "expected uchg flag after chflags, got '${POST_MUTATE_FLAGS}'"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events for command: ${N_EVENTS}"
N_META="$(smoke_journal_count "discriminant LIKE '%Metadata%'" 2>/dev/null || echo 0)"
smoke_log "metadata-discriminant events: ${N_META}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_FLAGS="$(flags_of "${TARGET}")"
smoke_log "post-undo flags: '${POST_UNDO_FLAGS}'"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${POST_UNDO_FLAGS}" = "${PRE_FLAGS}" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — flags restored to pre-state (surprising; some tier captured it)"
    smoke_log "PASS: chflags-undo-macos (Outcome A — gap closed by unknown path)"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "chflags|uchg|setflags|refus|conflict|metadata" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log names the gap)"
    smoke_log "PASS: chflags-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (M03.x.SETATTR-FAMILY gap CONFIRMED for chflags)"
smoke_log "  pre flags:        '${PRE_FLAGS}'"
smoke_log "  post-mutate:      '${POST_MUTATE_FLAGS}'"
smoke_log "  post-undo:        '${POST_UNDO_FLAGS}'"
smoke_log "  undo exit:        ${UNDO_RC}"
smoke_log "  journal events:   ${N_EVENTS}"
smoke_log "  metadata events:  ${N_META}"
smoke_fail "chflags undo did NOT restore pre-state flags (gap confirmed)"
