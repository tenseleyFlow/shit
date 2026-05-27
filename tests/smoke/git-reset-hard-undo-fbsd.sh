#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: git-reset-hard-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# G01.B.1 smoke — `git reset --hard <prior>` then `shit undo` returns
# the repo to its pre-reset state. FreeBSD mirror of G01.1.
#
# `git reset --hard A` mutates:
#   - `.git/HEAD` or `.git/refs/heads/main`  (ref moved to A's sha)
#   - `.git/index`  (matches A's tree)
#   - working-tree files  (overwritten to A's content)
#   - `.git/logs/HEAD`  (reflog entry appended)
#
# Captured cross-tier on BSD via kqueue NOTE_RENAME/DELETE/WRITE
# (S29 tree-op pairing) and the LD_PRELOAD shim's pre-image
# capture for content syscalls (W06.A.4). Existing W01.B git-commit
# plumbing already covers the same surface, so this is a port-job
# from the Linux smoke (G01.1).
#
# Setup creates a 3-commit linear history (A, B, C) modifying the
# same file across commits, then resets back to A. Undo should
# return HEAD to C with the file at C's content.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: git-reset-hard-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
if [ -z "${GIT_BIN}" ]; then
    smoke_log "SKIP: git not on PATH"
    exit 0
fi
smoke_log "git: ${GIT_BIN} ($("${GIT_BIN}" --version))"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
[ "${caps_rc}" = "0" ] || exit "${caps_rc}"

# Build a 3-commit linear history under a watched scratch dir.
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
REPO="${SCRATCH}/repo"
mkdir -p "${REPO}"

git_invoke -C "${REPO}" init -q
echo "content at A" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m "commit A"
HEAD_A="$(git_invoke -C "${REPO}" rev-parse HEAD)"

echo "content at B" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m "commit B"
HEAD_B="$(git_invoke -C "${REPO}" rev-parse HEAD)"

echo "content at C" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m "commit C"
HEAD_C="$(git_invoke -C "${REPO}" rev-parse HEAD)"
FILE_C_SHA="$(/sbin/sha256 -q "${REPO}/README.md")"
smoke_log "history built: A=${HEAD_A:0:8} B=${HEAD_B:0:8} C=${HEAD_C:0:8}"
smoke_log "C state: README.md sha=${FILE_C_SHA}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
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

# BSD-specific: the kqueue capture pipeline runs the baseline walk
# asynchronously after PreExec. Wait for it to complete before the
# workload runs, otherwise the workload races baseline and its
# modifications happen before LiveBaseline can record them. The
# Linux equivalent doesn't need this because LSM is synchronous.
sleep 0.5

# BSD-specific: the kqueue capture pipeline does the baseline walk
# asynchronously after PreExec. Wait for it to complete before
# running the workload, otherwise the workload races baseline and
# its modifications happen before the LiveBaseline can record
# them (= no FilePreImage events captured). The Linux equivalent
# doesn't need this because LSM is synchronous.
sleep 0.5

# THE workload: hard-reset 2 commits back. Working tree, index,
# and refs all snap to A.
smoke_log "git reset --hard ${HEAD_A:0:8}"
git_invoke -C "${REPO}" reset --hard "${HEAD_A}" 2>&1 | sed 's/^/    /' >&2

# Sanity-check the reset actually landed.
POST_RESET_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
if [ "${POST_RESET_HEAD}" != "${HEAD_A}" ]; then
    smoke_fail "git reset --hard didn't land: HEAD=${POST_RESET_HEAD} expected=${HEAD_A}"
fi
POST_RESET_README="$(cat "${REPO}/README.md")"
[ "${POST_RESET_README}" = "content at A" ] \
    || smoke_fail "post-reset README content wrong: '${POST_RESET_README}'"
smoke_log "reset landed: HEAD=${HEAD_A:0:8}, README='content at A'"

sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
NUM_PREIMAGES="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events: ${NUM_PREIMAGES}"

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: HEAD back at C.
POST_UNDO_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
if [ "${POST_UNDO_HEAD}" != "${HEAD_C}" ]; then
    smoke_log "HEAD mismatch: expected=${HEAD_C} got=${POST_UNDO_HEAD}"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "HEAD not restored to C — undo missed .git/refs/heads/main or .git/HEAD"
fi
smoke_log "HEAD restored: ${POST_UNDO_HEAD:0:8} == C"

# Assertion 2: README.md content matches C byte-identical.
POST_UNDO_FILE_SHA="$(/sbin/sha256 -q "${REPO}/README.md")"
if [ "${POST_UNDO_FILE_SHA}" != "${FILE_C_SHA}" ]; then
    smoke_log "README sha mismatch: expected=${FILE_C_SHA} got=${POST_UNDO_FILE_SHA}"
    smoke_log "README current content:"
    sed 's/^/    /' "${REPO}/README.md" >&2
    smoke_fail "working tree not restored — README content doesn't match C"
fi
smoke_log "working tree restored: README.md sha == C"

# Assertion 3: porcelain clean (no staged/unstaged drift).
STATUS="$(git_invoke -C "${REPO}" status --porcelain)"
if [ -n "${STATUS}" ]; then
    smoke_log "porcelain output (expected empty):"
    printf '%s\n' "${STATUS}" | sed 's/^/    /' >&2
    smoke_fail "post-undo git status not clean — index out of sync with HEAD"
fi
smoke_log "git status: clean (index matches HEAD=C)"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-reset-hard-undo-fbsd (HEAD A->C restored, working tree intact, ${NUM_PREIMAGES} pre-images captured)"
