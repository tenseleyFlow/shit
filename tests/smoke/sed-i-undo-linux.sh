#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: sed-i-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR01.4 smoke — `sed -i 's/x/y/g' foo.txt` then `shit undo` restores
# foo.txt to its pre-edit byte-identical state. Linux mirror of
# `sed-inline-undo-fbsd.sh` (W04).
#
# Exercises (LSM tier — `SHIT_FORCE_TIER=ebpf-lsm`):
#   1. GNU sed's write-via-tmpfile-then-rename pattern. Structurally
#      identical to git commit's `.git/index.lock → .git/index` swap
#      (AR01.1) but on a user-space file in the watch root.
#   2. `inode_create` fires for the `sed*` tmpfile. `inode_rename`
#      fires for `sed.tmp → foo.txt`. AR01.1's fix-rename-target-
#      preimage captures `foo.txt`'s OLD content via `ws.path_to_inode`
#      reverse lookup → `pre_snapshots` → CapturedPreImage. The
#      planner's atomic-rename classifier (W01.B.fix-rename-coalescing,
#      commit 77a1768) bins the resulting Create+PreImage+Unlink as
#      atomic-replace and emits one RestoreContent inverse.
#   3. The `sed*` tmpfile's Create-then-rename-away leaves no orphan
#      after undo. The W01.B transient-lock classifier handles the
#      pure-Create-path-absent shape with zero inverses.
#
# Tier compatibility note: AR01.1's fix-rename-target-preimage is the
# load-bearing fix here. Under fanotify-perm the rename hook isn't
# visible, so the OLD foo.txt content isn't captured. Wired under
# LSM_SMOKES for the same reason as `git-commit-undo-linux.sh`.
#
# Inheritance from AR00 / AR01.1:
#   - `shit hook-send pre-exec` blocks on WaitWatchReady; no pre-
#     command settle sleep needed.
#   - `pre_open_tree` recursion (irrelevant here — flat dir) and
#     path-via-parent-inode (irrelevant — top-level file).
#   - drop-empty-path guard catches any unresolved-path event.
#
# Linux-only.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: sed-i-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

SED_BIN="$(command -v sed || true)"
if [ -z "${SED_BIN}" ]; then
    smoke_log "SKIP: sed not on PATH"
    exit 0
fi
smoke_log "sed: ${SED_BIN} ($("${SED_BIN}" --version 2>/dev/null | head -1))"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight: helper caps. Without cap_sys_admin (+ cap_bpf,cap_perfmon
# under LSM tier) the helper degrades, no FilePreImage events fire,
# and the smoke times out at smoke_wait_for_event below instead of
# failing here with an actionable message.
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing on this system; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
if ! printf '%s' "${HELPER_CAPS}" | grep -q cap_sys_admin; then
    smoke_log "FAIL: helper lacks cap_sys_admin (getcap output: '${HELPER_CAPS}')"
    smoke_log ""
    smoke_log "  Run this on the box first, then re-run the smoke:"
    smoke_log "    sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${HELPER_BIN}"
    exit 1
fi
smoke_log "helper has caps: ${HELPER_CAPS}"

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
TARGET="${SCRATCH}/foo.txt"

# Pre-edit content with a deterministic substring that sed will
# replace. Three short lines stay well under the inline pre-image
# cap (256 KiB) and produce a stable sha256.
printf 'apple\nbanana\ncherry\n' > "${TARGET}"
PRIOR_SHA="$(sha256sum "${TARGET}" | cut -d' ' -f1)"
smoke_log "pre-edit foo.txt sha256=${PRIOR_SHA}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

# cd into the watch root so the helper's WatchTree resolves
# /proc/${PID}/cwd to SCRATCH. The L01/L04 mark routines descend up
# to DEFAULT_DEPTH_LIMIT (8); foo.txt is depth 0 so the flat scratch
# layout is trivially covered.
cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# PreExec — `shit hook-send pre-exec` blocks on `WaitWatchReady`
# (AR00.5) until the helper signals capture-is-live. No settle
# sleep needed before running the workload.
smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# THE workload under test.
#   GNU sed -i (no extension arg required, unlike BSD sed which
#   needs `-i ''`). sed writes a `sed*` tmpfile in the same dir,
#   chmod()s it to match foo.txt's mode (may fire setattr — should
#   be deduped against the create), atomically renames over
#   foo.txt, and exits.
smoke_log "sed -i 's/banana/PINEAPPLE/g' foo.txt"
"${SED_BIN}" -i 's/banana/PINEAPPLE/g' "${TARGET}"
SED_RC=$?
smoke_log "sed exit=${SED_RC}"
if [ "${SED_RC}" -ne 0 ]; then
    smoke_fail "sed -i failed pre-undo (rc=${SED_RC}) — workload setup broken"
fi
POST_EDIT_SHA="$(sha256sum "${TARGET}" | cut -d' ' -f1)"
smoke_log "post-edit foo.txt sha256=${POST_EDIT_SHA}"
if [ "${POST_EDIT_SHA}" = "${PRIOR_SHA}" ]; then
    smoke_fail "sed didn't actually edit the file (sha unchanged) — workload setup broken"
fi

# Let LSM events propagate end-to-end: kernel ringbuf → helper
# reader → CapturedPreImage send → daemon ingest → journal.
# Matches the AR01.1 git-commit smoke's drain budget.
sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. sed-i's burst is atomic-rename
# shape; expect at least one FilePreImage for foo.txt (sourced
# from AR01.1's fix-rename-target-preimage path).
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
POST_UNDO_SHA="$(sha256sum "${TARGET}" | cut -d' ' -f1)"
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

# Assertion 2: no leftover sed tmpfiles. GNU sed uses
# `sed<random>` named tmpfiles via mkstemp in the target's
# directory. Also catch *.tmp (defensive) and foo.txt.bak (which
# would only appear if someone passed -i.bak — sanity check).
ORPHANS=()
for f in "${SCRATCH}"/sed* "${SCRATCH}"/*.tmp "${SCRATCH}"/foo.txt.bak; do
    if [ -e "${f}" ] && [ "${f}" != "${TARGET}" ]; then
        ORPHANS+=("$(basename "${f}")")
    fi
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

smoke_log "PASS: sed-i-undo-linux (foo.txt restored byte-identical, ${NUM_PREIMAGES} pre-images captured)"
