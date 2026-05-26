#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# G01.3 smoke — `git stash drop` removes the most recent stash
# entry; `shit undo` restores `.git/refs/stash` (and its reflog)
# so the dropped entry is reachable again.
#
# The stash commit object itself stays in `.git/objects/` (git
# doesn't gc until later), so restoring the ref alone is enough
# for `git stash list` + `git stash apply` to work.
#
# Captured surface:
#   - `.git/refs/stash`           — overwritten or unlinked
#   - `.git/logs/refs/stash`      — overwritten (reflog tail)
# Both flow through W06.A.4 / W09.5 atomic-replace via inode_rename
# + FilePreImage capture from the pre-snapshotted .git/ tree.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: git-stash-drop-undo-linux is Linux-only"
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
echo "anchor" > "${REPO}/file.txt"
git_invoke -C "${REPO}" add file.txt
git_invoke -C "${REPO}" commit -q -m "anchor"

# Modify + stash. This creates `.git/refs/stash` pointing at a
# stash-merge commit.
echo "uncommitted edit" >> "${REPO}/file.txt"
git_invoke -C "${REPO}" stash push -q -m "the work I care about"

# Record the pre-drop stash ref sha — undo must restore this byte-
# identical so `git stash list` re-exposes the entry.
STASH_REF_SHA="$(cat "${REPO}/.git/refs/stash")"
smoke_log "pre-drop stash ref: ${STASH_REF_SHA:0:12}..."

# Also record the stash-list output so we can compare post-undo.
STASH_LIST_BEFORE="$(git_invoke -C "${REPO}" stash list)"
[ -n "${STASH_LIST_BEFORE}" ] || smoke_fail "stash push didn't land — list empty"
smoke_log "pre-drop stash list:"
printf '%s\n' "${STASH_LIST_BEFORE}" | sed 's/^/    /' >&2

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
smoke_log "git stash drop"
git_invoke -C "${REPO}" stash drop 2>&1 | sed 's/^/    /' >&2

# Sanity: stash gone.
STASH_LIST_DURING="$(git_invoke -C "${REPO}" stash list || true)"
[ -z "${STASH_LIST_DURING}" ] \
    || smoke_fail "stash drop didn't land — list still: ${STASH_LIST_DURING}"
smoke_log "stash drop landed: list empty"

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

# Assertion 1: .git/refs/stash restored byte-identical.
if [ ! -f "${REPO}/.git/refs/stash" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail ".git/refs/stash missing post-undo"
fi
POST_UNDO_REF="$(cat "${REPO}/.git/refs/stash")"
if [ "${POST_UNDO_REF}" != "${STASH_REF_SHA}" ]; then
    smoke_log "stash ref mismatch: expected=${STASH_REF_SHA} got=${POST_UNDO_REF}"
    smoke_fail "stash ref not restored byte-identical"
fi
smoke_log "stash ref restored: ${POST_UNDO_REF:0:12}..."

# Assertion 2: `git stash list` recovers the original entry.
STASH_LIST_AFTER="$(git_invoke -C "${REPO}" stash list)"
if [ -z "${STASH_LIST_AFTER}" ]; then
    smoke_log "post-undo stash list still empty:"
    smoke_fail "stash list didn't recover — reflog (.git/logs/refs/stash) may not have been restored"
fi
smoke_log "stash list recovered:"
printf '%s\n' "${STASH_LIST_AFTER}" | sed 's/^/    /' >&2

# Assertion 3: applying the recovered stash re-introduces the edit.
git_invoke -C "${REPO}" stash apply -q
POST_APPLY="$(cat "${REPO}/file.txt")"
if ! printf '%s\n' "${POST_APPLY}" | grep -q "uncommitted edit"; then
    smoke_log "file.txt content after re-apply:"
    sed 's/^/    /' "${REPO}/file.txt" >&2
    smoke_fail "recovered stash applied but didn't re-introduce the edit"
fi
smoke_log "stash apply works: edit re-introduced"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-stash-drop-undo-linux (stash recovered + applies cleanly, ${NUM_PRE} pre-images)"
