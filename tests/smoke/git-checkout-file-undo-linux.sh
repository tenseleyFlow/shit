#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: git-checkout-file-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# G01.2 smoke — `git checkout -- <file>` (or `git restore <file>`)
# discards a working-tree edit; `shit undo` restores the edit.
#
# git reads the file's blob from the index and rewrites the
# working-tree path. Captured by the LSM tier's inode_setattr
# (O_TRUNC) → FilePreImage with the user's modified content
# pre-image. Plain RestoreContent inverse via W06.A.4's atomic-
# replace classifier when path exists at undo. No code changes
# expected.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: git-checkout-file-undo-linux is Linux-only"
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
echo "committed content" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m "anchor"

# Modify the working tree but DON'T stage. This is the state we want
# back after undo.
echo "uncommitted edit" >> "${REPO}/README.md"
DIRTY_SHA="$(sha256sum "${REPO}/README.md" | cut -d' ' -f1)"
smoke_log "dirty state: README.md sha=${DIRTY_SHA}"

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

# THE workload — discard the edit.
smoke_log "git checkout -- README.md"
git_invoke -C "${REPO}" checkout -- README.md
POST_CHECKOUT_CONTENT="$(cat "${REPO}/README.md")"
[ "${POST_CHECKOUT_CONTENT}" = "committed content" ] \
    || smoke_fail "checkout didn't land: '${POST_CHECKOUT_CONTENT}'"
smoke_log "checkout landed: edit discarded"

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

POST_UNDO_SHA="$(sha256sum "${REPO}/README.md" | cut -d' ' -f1)"
if [ "${POST_UNDO_SHA}" != "${DIRTY_SHA}" ]; then
    smoke_log "sha mismatch: expected=${DIRTY_SHA} got=${POST_UNDO_SHA}"
    smoke_log "README current content:"
    sed 's/^/    /' "${REPO}/README.md" >&2
    smoke_fail "uncommitted edit not restored"
fi
smoke_log "edit restored: README.md sha == dirty"

STATUS="$(git_invoke -C "${REPO}" status --porcelain)"
if [ "${STATUS}" != " M README.md" ]; then
    smoke_log "porcelain mismatch: expected=' M README.md' got='${STATUS}'"
    smoke_fail "post-undo git status doesn't show unstaged edit"
fi
smoke_log "git status: '${STATUS}' (unstaged edit back)"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-checkout-file-undo-linux (uncommitted edit restored, ${NUM_PRE} pre-images)"
