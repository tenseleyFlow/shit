#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR01.1 smoke — `git commit` then `shit undo` reverts the repo to the
# pre-commit state. Linux mirror of `git-commit-undo-fbsd.sh` (W01.B).
#
# Exercises (LSM tier — `SHIT_FORCE_TIER=ebpf-lsm` post-L04.1):
#   1. `inode_create` fires for `.git/index.lock`, `.git/COMMIT_EDITMSG`,
#      and each new `.git/objects/XX/YY...` blob/tree object.
#   2. `inode_setattr` fires for ATTR_SIZE during O_TRUNC of
#      `.git/index.lock` and HEAD updates (`refs/heads/main`,
#      `logs/HEAD`); userspace handler reads pre-image from
#      `ws.pre_snapshots` (AR00.5b race-free path), NOT the live fd.
#   3. `inode_rename` fires for git's atomic `.git/index.lock` →
#      `.git/index` swap; planner's atomic-replace classifier in
#      plan.rs handles the Create+PreImage+Unlink shape and rewrites
#      the inverse as a file-content restore over the surviving inode.
#   4. `inode_unlink` fires when `.git/index.lock` is removed if the
#      rename path isn't taken (older gits, or when the lock is
#      abandoned). Planner's transient-lock classifier handles the
#      pure-Create+Unlink-no-PreImage shape by emitting no inverse.
#   5. `file_open` fires when git reads the staged working-tree file
#      to hash it into the object store; pre-image of staged content
#      is captured for the read.
#
# Exercises (fanotify-perm tier — degraded mode):
#   - `FAN_OPEN_PERM` fires on every open under the watched directory,
#     including the O_TRUNC opens of `.git/index.lock`, `HEAD`, and
#     `refs/heads/main`. Pure renames/unlinks aren't visible; the
#     planner falls back to whatever FilePreImage events fanotify
#     did capture. Working-tree-only assertions still pass; the
#     `M  README.md` porcelain assertion is the load-bearing check
#     because it validates the index was restored end-to-end.
#
# Assertions post-undo (per W01.B-bsd.md correctness lesson —
# `git commit` doesn't touch the working tree, so undo must leave
# the staged content in place; the status should be back to
# "staged but uncommitted"):
#   1. `git rev-parse HEAD` == PRIOR_HEAD (anchor commit)
#   2. sha256(README.md) == STAGED_SHA (working-tree intact)
#   3. `git status --porcelain` == "M  README.md"
#
# Inheritance from AR00:
#   - `shit hook-send pre-exec` blocks on `WaitWatchReady` until the
#     helper signals capture-is-live. No `smoke_wait_lsm_ready` call;
#     no pre-command settle sleep needed.
#   - BPF-time `parent_pid` capture covers direct children of the
#     smoke shell (i.e. `git` itself). Git's internal sub-execs
#     (git-write-tree, git-hash-object — these are static-linked
#     in modern git but historically were forked sub-binaries) are
#     2-level descendants of the smoke shell. If git ever shells
#     out (e.g. pre-commit hook, which we disable), the deeper-than-
#     1-level ancestry walk falls through to /proc per the AR00
#     carry-forward; surface here if events go missing.
#
# Linux-only. The producer wire (LSM/fanotify) differs; the
# CapturedPreImage SCM_RIGHTS payload, blob ingest, journal, and
# undo planner are identical to BSD.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: git-commit-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

GIT_BIN="$(command -v git || true)"
if [ -z "${GIT_BIN}" ]; then
    smoke_log "SKIP: git not on PATH"
    exit 0
fi
smoke_log "git: ${GIT_BIN} ($("${GIT_BIN}" --version))"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight: helper caps. Without cap_sys_admin (+ cap_bpf,cap_perfmon
# under LSM tier) the helper degrades, no FilePreImage events fire,
# and the smoke times out at the wait-for-event below instead of
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

# Hermetic git identity + hooks-off via in-process -c overrides so we
# don't depend on the smoke user's ~/.gitconfig and don't accidentally
# fire pre-commit hooks (out-of-scope per AR01 spec). HOME pointed
# at SHIT_SMOKE_TMP and config files redirected to /dev/null block
# any global-config bleed.
GIT_HERMETIC=(
    -c "user.email=ar01@shit-smoke"
    -c "user.name=shit-smoke"
    -c "core.hooksPath=/dev/null"
    -c "init.defaultBranch=main"
    -c "commit.gpgsign=false"
    -c "tag.gpgsign=false"
)
git_invoke() {
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null HOME="${SHIT_SMOKE_TMP}" \
        "${GIT_BIN}" "${GIT_HERMETIC[@]}" "$@"
}

# Build the repo under a watched scratch dir.
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
REPO="${SCRATCH}/repo"
mkdir -p "${REPO}"

# `git init` (creates .git/) BEFORE smoke_start_shitd so the helper's
# watch (registered at PreExec) sees a fully-formed .git/ tree to
# baseline. If we init INSIDE the watch window, the initial creation
# storm would mask the commit's events.
git_invoke -C "${REPO}" init -q
echo "initial content" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m "anchor commit"
PRIOR_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
smoke_log "anchor commit: ${PRIOR_HEAD}"

# Stage a modification — this is what the test commit will commit.
# Per W01.B: post-undo working-tree should equal STAGED_SHA (NOT the
# pre-modify "initial content" SHA). `git commit` never writes to
# README.md, so undoing the commit must leave the staged content
# in place.
echo "modified line one" >> "${REPO}/README.md"
echo "modified line two" >> "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
STAGED_SHA="$(sha256sum "${REPO}/README.md" | cut -d' ' -f1)"
smoke_log "staged README.md sha256=${STAGED_SHA}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

# cd into the repo so the helper's WatchTree resolves /proc/${PID}/cwd
# to ${REPO}. The L01/L04 mark routines descend up to DEFAULT_DEPTH_LIMIT
# (8) so .git/objects/XX/ subdirs are covered.
cd "${REPO}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# PreExec — `shit hook-send pre-exec` blocks on `WaitWatchReady`
# (AR00.5) until the helper signals capture-is-live. No additional
# settle sleep is needed before running the workload.
smoke_log "PreExec seq=1 pid=${PID} cwd=${REPO}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${REPO}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# THE workload under test.
smoke_log "git commit -m 'edit README'"
git_invoke -C "${REPO}" commit -q -m "edit README"
NEW_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
smoke_log "new HEAD: ${NEW_HEAD}"

# Let LSM/fanotify events propagate end-to-end: kernel ringbuf →
# helper reader → CapturedPreImage send → daemon ingest → journal.
# Empirically tight on the AR00 runner; bumped over the BSD smoke's
# 0.5s because a cold-start LSM tier has more events to drain
# (.git/objects/XX/YY... explosion) than kqueue's coalesced output.
sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. git commit writes many files; we
# accept at least one FilePreImage as evidence the capture pipeline
# saw the workload. The undo planner will use whatever pre-images
# the journal has — fewer means a partial restore which we'll catch
# at the assertion stage.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

# Diagnostic: count the pre-images captured. Useful when debugging
# because a successful undo needs ALL pre-images, not just "at
# least one". On the LSM tier we expect roughly: index, HEAD,
# refs/heads/main, logs/HEAD, COMMIT_EDITMSG, the new objects' parent
# dirs — so >= ~5 in steady state.
NUM_PREIMAGES="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events in journal: ${NUM_PREIMAGES}"

# Run undo. Refusal-to-undo on missing pre-images is acceptable
# behavior; we'll detect it via the assertions below.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: HEAD reverted to the anchor commit.
POST_UNDO_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
if [ "${POST_UNDO_HEAD}" != "${PRIOR_HEAD}" ]; then
    smoke_log "HEAD mismatch: expected=${PRIOR_HEAD} got=${POST_UNDO_HEAD}"
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal events:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "git HEAD not restored — undo did not reach .git/refs/heads/main"
fi
smoke_log "HEAD restored: ${POST_UNDO_HEAD} == ${PRIOR_HEAD}"

# Assertion 2: README.md working tree byte-equal to its STAGED form.
# `git commit` doesn't write to README.md — it only reads it and
# writes objects/refs under .git/. So undoing the commit must leave
# README.md unchanged from its pre-commit (already-staged) state.
POST_UNDO_README_SHA="$(sha256sum "${REPO}/README.md" | cut -d' ' -f1)"
if [ "${POST_UNDO_README_SHA}" != "${STAGED_SHA}" ]; then
    smoke_log "README.md sha256 mismatch: expected=${STAGED_SHA} got=${POST_UNDO_README_SHA}"
    smoke_log "README.md content (current):"
    sed 's/^/    /' "${REPO}/README.md" >&2 || true
    smoke_fail "working tree perturbed — README.md content changed by undo (it shouldn't have)"
fi
smoke_log "working tree intact: README.md sha256 == staged content"

# Assertion 3: `git status --porcelain` shows the staged change is
# back (README.md staged but not yet committed). Pre-commit state
# was: README.md modified+staged, HEAD at anchor. Post-undo should
# match that exactly.
STATUS="$(git_invoke -C "${REPO}" status --porcelain || true)"
EXPECTED_STATUS="M  README.md"
if [ "${STATUS}" != "${EXPECTED_STATUS}" ]; then
    smoke_log "git status mismatch: expected='${EXPECTED_STATUS}' got='${STATUS}'"
    smoke_log "journal events:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "post-undo git status doesn't match pre-commit staged state"
fi
smoke_log "git status: ${STATUS} (matches pre-commit staged state)"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-commit-undo-linux (HEAD ${PRIOR_HEAD} restored + working tree byte-identical, ${NUM_PREIMAGES} pre-images captured)"
