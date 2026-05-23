#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W04 smoke — `sed -i '' s/x/y/g foo.txt` then `shit undo` restores
# foo.txt to its pre-edit byte-identical state.
#
# Exercises (atomic-rename undo + live-baseline interaction):
#   1. sed-i's canonical write-via-tmpfile-then-rename pattern.
#      Structurally identical to git commit's .git/index.lock →
#      .git/index dance (W01) but on a user-space file.
#   2. Planner's classify_replace_paths (W01.B follow-up) bins
#      foo.txt's Create+PreImage+Unlink triple as atomic-replace
#      and emits exactly one RestoreContent inverse; the sed
#      tmpfile's Create+Unlink (no pre-image) is classified
#      transient and produces zero inverses.
#   3. Live-baseline (W02.B) supplies the pre-edit content for
#      foo.txt — without it, the FilePreImage would carry
#      post-rename content (kqueue NOTE_WRITE race) and undo
#      would be a no-op.
#
# FreeBSD-only — kqueue producer + BSD smoke convention. Linux
# equivalent: sed-inline-undo-linux.sh (per W04.L-linux.md,
# user-owned).
#
# See .docs/sprints/W/W04-sed-inline-undo.md for the cross-platform
# spec and .docs/sprints/W/W04.B-bsd.md for execution notes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: sed-inline-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

SED_BIN="$(command -v sed || echo /usr/bin/sed)"
[ -x "${SED_BIN}" ] || smoke_fail "sed not found at /usr/bin/sed"
smoke_log "sed: ${SED_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
TARGET="${SCRATCH}/foo.txt"

# Pre-edit content with a deterministic substring that sed will
# replace. Three short lines keep the file well under the inline
# pre-image cap (256KB).
printf 'apple\nbanana\ncherry\n' > "${TARGET}"
PRIOR_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "pre-edit foo.txt sha256=${PRIOR_SHA}"

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

# Let live-baseline populate foo.txt's pre-edit content into the
# LiveBaseline cache before sed runs.
sleep 0.5

# THE workload under test.
#   -i ''  in-place edit, no backup. BSD sed REQUIRES the
#          extension argument; '' = no backup file. GNU sed
#          (Linux) takes bare `-i` — this is the platform-specific
#          divergence W04 anticipates.
#   's/banana/PINEAPPLE/g'  the substitution; banana → PINEAPPLE.
smoke_log "sed -i '' 's/banana/PINEAPPLE/g' foo.txt"
"${SED_BIN}" -i '' 's/banana/PINEAPPLE/g' "${TARGET}"
SED_RC=$?
smoke_log "sed exit=${SED_RC}"
if [ "${SED_RC}" -ne 0 ]; then
    smoke_fail "sed -i failed pre-undo (rc=${SED_RC}) — workload setup broken"
fi
POST_EDIT_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "post-edit foo.txt sha256=${POST_EDIT_SHA}"
if [ "${POST_EDIT_SHA}" = "${PRIOR_SHA}" ]; then
    smoke_fail "sed didn't actually edit the file (sha unchanged) — workload setup broken"
fi

# Let kqueue NOTE_DELETE / WRITE / RENAME events propagate.
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. sed-i's burst is atomic-rename
# shape; expect at least one FilePreImage for foo.txt.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

NUM_PREIMAGES="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events in journal: ${NUM_PREIMAGES}"

# Run undo.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: foo.txt content restored byte-identical.
POST_UNDO_SHA="$(/sbin/sha256 -q "${TARGET}")"
if [ "${POST_UNDO_SHA}" != "${PRIOR_SHA}" ]; then
    smoke_log "foo.txt sha256 mismatch: expected=${PRIOR_SHA} got=${POST_UNDO_SHA}"
    smoke_log "foo.txt content (current):"
    /usr/bin/sed 's/^/    /' "${TARGET}" >&2 || true
    smoke_log "undo log:"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal events:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | /usr/bin/sed 's/^/    /' >&2 || true
    smoke_fail "foo.txt content not restored — atomic-replace undo failed"
fi
smoke_log "foo.txt restored: sha256=${POST_UNDO_SHA} matches pre-edit"

# Assertion 2: no leftover sed tmpfiles. BSD sed's tmpfile pattern
# is mktemp-style (`sed.XXXXXX` or similar). Catch any name that
# matches sed* OR ends in .tmp, plus the .bak suffix that would
# appear if someone passed a non-empty -i extension.
ORPHANS=()
for f in "${SCRATCH}"/sed.* "${SCRATCH}"/*.tmp "${SCRATCH}"/foo.txt.bak; do
    [ -e "${f}" ] && ORPHANS+=("$(basename "${f}")")
done
if [ "${#ORPHANS[@]}" -gt 0 ]; then
    smoke_log "leftover artifacts in ${SCRATCH}:"
    ls -la "${SCRATCH}" | /usr/bin/sed 's/^/    /' >&2
    smoke_fail "scratch dir has leftover sed artifacts: ${ORPHANS[*]}"
fi
smoke_log "scratch dir clean: no sed tmpfiles, no backup"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: sed-inline-undo-fbsd (foo.txt restored byte-identical, ${NUM_PREIMAGES} pre-images captured)"
