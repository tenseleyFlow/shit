#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: git-checkout-branch-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# G01.6 smoke — `git checkout <branch>` (or `git switch <branch>`)
# moves HEAD and rewrites the working tree. `shit undo` returns
# to the prior branch with the prior working-tree content.
#
# Retires the unverified "covered (AR01 family)" claim in
# `.docs/sprints/AR/AR08-long-tail-descriptor-pack.md` — there was
# no dedicated smoke until now.
#
# Captured surface:
#   - `.git/HEAD`               — symref rewritten via rename
#   - Working-tree files        — overwritten via open(O_TRUNC) or
#                                 unlink+open(O_CREAT). Both flow
#                                 through W06.A.4 / W09.5 atomic-
#                                 replace classifiers.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: git-checkout-branch-undo-linux is Linux-only"
    exit 0
fi
if [ -z "${GIT_BIN}" ]; then
    smoke_log "SKIP: git not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"
smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
[ "${caps_rc}" = "0" ] || exit "${caps_rc}"

REPO="${SHIT_SMOKE_TMP}/scratch/repo"
mkdir -p "${REPO}"

git_invoke -C "${REPO}" init -q
# main commit with one content
echo "main content" > "${REPO}/file.txt"
git_invoke -C "${REPO}" add file.txt
git_invoke -C "${REPO}" commit -q -m "main commit"
MAIN_SHA="$(git_invoke -C "${REPO}" rev-parse HEAD)"
MAIN_FILE_SHA="$(sha256sum "${REPO}/file.txt" | cut -d' ' -f1)"

# Branch off and divergent content.
git_invoke -C "${REPO}" checkout -q -b feat
echo "feat content" > "${REPO}/file.txt"
git_invoke -C "${REPO}" add file.txt
git_invoke -C "${REPO}" commit -q -m "feat commit"
FEAT_SHA="$(git_invoke -C "${REPO}" rev-parse HEAD)"
git_invoke -C "${REPO}" checkout -q main
smoke_log "main=${MAIN_SHA:0:8} feat=${FEAT_SHA:0:8}"

# Sanity: working tree is at main content.
[ "$(cat "${REPO}/file.txt")" = "main content" ] \
    || smoke_fail "pre-state: file.txt not at main content"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${REPO}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${REPO}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# THE workload.
smoke_log "git checkout feat"
git_invoke -C "${REPO}" checkout -q feat
[ "$(git_invoke -C "${REPO}" rev-parse HEAD)" = "${FEAT_SHA}" ] \
    || smoke_fail "checkout didn't land at feat"
[ "$(cat "${REPO}/file.txt")" = "feat content" ] \
    || smoke_fail "post-checkout file.txt not at feat content"
smoke_log "checkout landed: HEAD=${FEAT_SHA:0:8} file='feat content'"

sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
NUM_PRE="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events: ${NUM_PRE}"

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo exited non-zero"
}

# Assertion 1: HEAD back on main.
POST_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
if [ "${POST_HEAD}" != "${MAIN_SHA}" ]; then
    smoke_log "HEAD mismatch: expected=${MAIN_SHA} got=${POST_HEAD}"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "HEAD not restored to main"
fi
POST_BRANCH="$(git_invoke -C "${REPO}" symbolic-ref HEAD 2>/dev/null || echo "?")"
[ "${POST_BRANCH}" = "refs/heads/main" ] \
    || smoke_fail "HEAD not on refs/heads/main post-undo (got: ${POST_BRANCH})"
smoke_log "HEAD restored: on refs/heads/main at ${POST_HEAD:0:8}"

# Assertion 2: working tree restored.
POST_FILE_SHA="$(sha256sum "${REPO}/file.txt" | cut -d' ' -f1)"
if [ "${POST_FILE_SHA}" != "${MAIN_FILE_SHA}" ]; then
    smoke_log "file.txt sha mismatch: expected=${MAIN_FILE_SHA} got=${POST_FILE_SHA}"
    smoke_log "current content:"
    sed 's/^/    /' "${REPO}/file.txt" >&2
    smoke_fail "working tree not restored — file.txt content not at main"
fi
smoke_log "working tree restored: file.txt sha == main"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-checkout-branch-undo-linux (HEAD feat->main restored, working tree intact, ${NUM_PRE} pre-images)"
