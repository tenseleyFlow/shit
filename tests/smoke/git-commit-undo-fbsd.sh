#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W01 smoke — `git commit` then `shit undo` reverts the repo to the
# pre-commit state.
#
# Exercises (cross-tier integration):
#   1. kqueue NOTE_WRITE / NOTE_DELETE / NOTE_RENAME on every file
#      git touches: .git/index, .git/HEAD, .git/refs/heads/*, .git/
#      logs/HEAD, .git/objects/XX/YY..., .git/COMMIT_EDITMSG, plus the
#      working-tree files that were staged.
#   2. The pump's dir-baseline diff sees the new .git/objects/XX
#      subdir, adds it via add_path, then captures subsequent writes.
#   3. read_pre_image stages bytes for each modified file before the
#      write completes.
#   4. The undo planner sequences FileRestore inverses in the correct
#      order (objects first, then refs, then index, then working tree).
#   5. After `shit undo --yes`: git rev-parse HEAD matches PRIOR_HEAD,
#      every working-tree file matches its pre-commit sha256.
#
# FreeBSD-only — kqueue producer + BSD smoke convention. The Linux
# equivalent is `git-commit-undo-linux.sh` (per W01.L-linux.md).
#
# See .docs/sprints/W/W01-git-commit-undo.md for the cross-platform
# spec and .docs/sprints/W/W01.B-bsd.md for execution notes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: git-commit-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

# git lives at /usr/local/bin/git after `pkg install git`. SKIP if
# absent so we don't false-fail on a minimal install.
export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
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

# Hermetic git identity + hooks-off via in-process -c overrides so we
# don't depend on the smoke user's ~/.gitconfig and don't accidentally
# fire pre-commit hooks. Disable HOME entirely too to keep git
# from reading global config.
GIT_HERMETIC=(
    -c "user.email=w01@shit-smoke"
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

# Snapshot working-tree state we'll verify gets restored.
# (README.md will be modified+committed; we restore to "initial content".)
PRIOR_README_SHA="$(/sbin/sha256 -q "${REPO}/README.md")"
smoke_log "pre-commit README.md sha256=${PRIOR_README_SHA}"

# Stage a modification — this is what the test commit will commit.
echo "modified line one" >> "${REPO}/README.md"
echo "modified line two" >> "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
STAGED_SHA="$(/sbin/sha256 -q "${REPO}/README.md")"
smoke_log "staged README.md sha256=${STAGED_SHA}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

# cd into the repo so the helper's watch root resolves to ${REPO}.
cd "${REPO}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${REPO}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${REPO}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Give the pump a moment to register watches + baseline-read the
# .git/ subtree (DEFAULT_DEPTH_LIMIT=8 should cover .git/objects/XX).
sleep 0.5

# THE workload under test.
smoke_log "git commit -m 'edit README'"
git_invoke -C "${REPO}" commit -q -m "edit README"
NEW_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
smoke_log "new HEAD: ${NEW_HEAD}"

# Let kqueue NOTE_DELETE / WRITE / RENAME events propagate.
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. git commit writes many files; we
# accept at least one FilePreImage as evidence the capture pipeline
# saw the workload. The undo planner will use whatever pre-images
# the journal has — fewer means a partial restore which we'll catch
# at the assertion stage.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

# Diagnostic: print the count of pre-images captured. Useful when
# debugging because a successful undo needs ALL pre-images, not just
# "at least one".
NUM_PREIMAGES="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events in journal: ${NUM_PREIMAGES}"

# Run undo. Refusal-to-undo on missing pre-images is acceptable
# behavior; we'll detect that via the assertions.
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

# Assertion 2: README.md content restored byte-identical.
POST_UNDO_README_SHA="$(/sbin/sha256 -q "${REPO}/README.md")"
if [ "${POST_UNDO_README_SHA}" != "${PRIOR_README_SHA}" ]; then
    smoke_log "README.md sha256 mismatch: expected=${PRIOR_README_SHA} got=${POST_UNDO_README_SHA}"
    smoke_log "README.md content (current):"
    sed 's/^/    /' "${REPO}/README.md" >&2 || true
    smoke_fail "working tree not restored — README.md content differs from pre-commit"
fi
smoke_log "working tree restored: README.md sha256 matches"

# Assertion 3: `git status --porcelain` shows the working tree
# matches the index AND the index matches HEAD. After undo, we
# expect: README.md is "modified but not staged" (pre-commit had
# staged changes, but the FILE on disk == staged content was
# part of the workload — restore reverts the file too). So the
# tree is clean, no staged or unstaged changes.
#
# Actually subtle: the smoke staged the modification BEFORE
# PreExec. So the pre-commit working tree had a STAGED change.
# After commit, .git/index points to the new tree. After undo,
# .git/index should point to the old tree (no staged changes),
# AND the working tree should show README.md modified.
#
# Wait — the smoke restores README.md byte-identical to its
# "initial content" form. That's the anchor-commit form, NOT the
# staged-pre-commit form. So post-undo, README.md == HEAD content
# → clean tree.
STATUS="$(git_invoke -C "${REPO}" status --porcelain || true)"
if [ -n "${STATUS}" ]; then
    smoke_log "git status not clean:"
    echo "${STATUS}" | sed 's/^/    /' >&2
    smoke_fail "post-undo git status is not clean (working tree + index out of sync with HEAD)"
fi
smoke_log "git status: clean"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-commit-undo-fbsd (HEAD ${PRIOR_HEAD} restored + working tree byte-identical, ${NUM_PREIMAGES} pre-images captured)"
