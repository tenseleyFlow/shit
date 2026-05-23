#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W07 smoke — `dd` overwriting a >PRE_IMAGE_INLINE_CAP file. Surfaces
# the architectural gap in shit's user-facing refusal path when a file
# is too large to pre-image-capture inline.
#
# The inline cap is 64 MiB on BSD (PRE_IMAGE_INLINE_CAP in
# crates/shit-helper/src/kqueue/capture.rs:65). Pre-W07.B.fix-loud-
# refusal, both the live-baseline walker and the S24.4 NOTE_WRITE
# path silently warn + skip when read_pre_image errors with
# TooLargeForBuffer. The journal then lacks a FilePreImage event,
# the planner doesn't emit a RestoreContent, and `shit undo --yes`
# happily exits 0 while the file is still in its modified state.
#
# This smoke catches that silent partial undo by checking sha256(file)
# post-undo against the pre-modify sha. PASS conditions:
#   (a) sha256 matches pre-modify (a streaming pre-image path landed
#       between this smoke being written and run — best case)
#   OR
#   (b) `shit undo --yes` exits non-zero AND its log mentions the
#       large file (loud-refusal path implemented)
#
# FAIL condition (the bug to catch):
#   undo exit 0, no mention of the large file, but sha256 still
#   matches the post-modify state. Silent partial undo.
#
# Expected outcome on shit-fbsd today: FAIL. The smoke surfaces the
# gap; W07.B.fix-loud-refusal is the follow-up to fix it.
#
# See .docs/sprints/W/W07-dd-large-file.md for the spec and
# .docs/sprints/W/W07.B-bsd.md for execution notes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: dd-large-file-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

DD_BIN="$(command -v dd || echo /bin/dd)"
[ -x "${DD_BIN}" ] || smoke_fail "dd not found at /bin/dd"
smoke_log "dd: ${DD_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
TARGET="${SCRATCH}/large.bin"

# 70 MiB — just enough to cross the 64 MiB inline cap. urandom keeps
# entropy high so blob-store dedupe doesn't trivialize the test.
# `status=none` keeps dd quiet in CI logs.
smoke_log "creating large.bin (70 MiB)"
"${DD_BIN}" if=/dev/urandom of="${TARGET}" bs=1m count=70 status=none

PRIOR_SHA="$(/sbin/sha256 -q "${TARGET}")"
PRIOR_SIZE="$(stat -f %z "${TARGET}")"
smoke_log "pre-edit large.bin sha256=${PRIOR_SHA} size=${PRIOR_SIZE}"

# Confirm we crossed the cap (sanity).
if [ "${PRIOR_SIZE}" -le 67108864 ]; then
    smoke_fail "large.bin is only ${PRIOR_SIZE} bytes; need > 64 MiB to cross PRE_IMAGE_INLINE_CAP"
fi

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Give the live-baseline walker time to attempt large.bin and skip
# it with TooLargeForBuffer. Walker runs async; this is generous.
sleep 1.0

# THE workload: overwrite first 1 MiB of large.bin in place.
# `conv=notrunc` keeps the file at 70 MiB; only the first 1 MiB
# is modified. This is the classic "edit a big binary" pattern
# (e.g. patching the header of a large data file).
smoke_log "dd if=/dev/urandom of=large.bin bs=1m count=1 conv=notrunc"
"${DD_BIN}" if=/dev/urandom of="${TARGET}" bs=1m count=1 conv=notrunc status=none
DD_RC=$?
if [ "${DD_RC}" -ne 0 ]; then
    smoke_fail "dd overwrite failed pre-undo (rc=${DD_RC}) — workload setup broken"
fi
POST_EDIT_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "post-edit large.bin sha256=${POST_EDIT_SHA}"
if [ "${POST_EDIT_SHA}" = "${PRIOR_SHA}" ]; then
    smoke_fail "dd didn't actually edit the file — workload setup broken"
fi

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Don't smoke_wait_for_event a specific FilePreImage — the entire
# point of this test is that NO FilePreImage may be emitted for
# large.bin. Wait a beat for any other events (MetadataChange) to
# settle.
sleep 1.0

NUM_PREIMAGES="$(smoke_journal_count "discriminant = 'FilePreImage'")"
NUM_META="$(smoke_journal_count "discriminant = 'MetadataChange'")"
smoke_log "journal: FilePreImage events=${NUM_PREIMAGES}, MetadataChange events=${NUM_META}"

# Run undo. Capture both stdout and exit code.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
smoke_log "shit undo --yes exit=${UNDO_RC}"
smoke_log "undo log:"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "post-undo large.bin sha256=${POST_UNDO_SHA}"

# Evaluate which outcome we got:
#
# Outcome A: streaming pre-image landed; undo restored bytes.
if [ "${POST_UNDO_SHA}" = "${PRIOR_SHA}" ]; then
    smoke_log "OUTCOME A — undo restored byte-identical (streaming path active)"
    smoke_log "session close"
    "${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
    smoke_log "PASS: dd-large-file-undo-fbsd (Outcome A — streaming restore)"
    exit 0
fi

# Outcome B: refusal-with-reason; undo exits non-zero AND mentions
# the file. The check for "mentions the file" is permissive on
# format — any of: large.bin path, "too large", "exceeded", "cap"
# in the undo log counts as a user-visible signal.
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "large\.bin|too large|exceeded|cap|PRE_IMAGE_INLINE_CAP" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — undo refused loudly with user-readable reason"
    smoke_log "session close"
    "${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
    smoke_log "PASS: dd-large-file-undo-fbsd (Outcome B — loud refusal)"
    exit 0
fi

# Outcome C: silent partial undo. The bug we want to catch.
smoke_log "OUTCOME C — silent partial undo detected (this is the gap W07 surfaces)"
smoke_log "  pre-modify sha256:  ${PRIOR_SHA}"
smoke_log "  post-edit  sha256:  ${POST_EDIT_SHA}"
smoke_log "  post-undo  sha256:  ${POST_UNDO_SHA}"
smoke_log "  undo exit code:     ${UNDO_RC}"
smoke_log "  FilePreImage events in journal: ${NUM_PREIMAGES}"
smoke_log "  the file is still in its modified state, yet shit undo"
smoke_log "  reported success. follow-up: W07.B.fix-loud-refusal."
smoke_fail "silent partial undo — file too large to pre-image, but undo claimed success"
