#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: git-branch-D-packed-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# G01.4-packed smoke — `git branch -D <name>` against a PACKED
# branch (`git pack-refs --all` previously collapsed
# `.git/refs/heads/<name>` into `.git/packed-refs`).
#
# Branch-delete on a packed ref is a different destructive shape
# from the unpacked case (G01.4): the loose `.git/refs/heads/feat`
# file doesn't exist, so the deletion is a tmpfile-rename rewrite
# of `.git/packed-refs` that removes the line referencing `feat`
# (and leaves all other refs intact). The classifier path is
# W06.A.4 atomic-replace on rename destination — the same shape
# that already covers `git reset --hard`'s `.git/HEAD` rewrite —
# so this smoke validates that path works for a multi-entry text
# file rewrite, not just a small fixed-content file.
#
# Sibling smoke `git-branch-D-undo-linux.sh` covers the unpacked
# shape.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: git-branch-D-packed-undo-linux is Linux-only"
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
git_invoke -C "${REPO}" commit -q -m "anchor on main"

# Create the branch + force the packed shape.
git_invoke -C "${REPO}" branch feat
FEAT_SHA="$(git_invoke -C "${REPO}" rev-parse feat)"
smoke_log "branch feat at ${FEAT_SHA:0:12}... (before pack)"

# `pack-refs --all` collapses loose refs into `.git/packed-refs`;
# without --no-prune (the default) it also unlinks the loose
# files. For a freshly-created branch with a single reflog entry
# (creation) git considers the loose ref redundant and removes it.
git_invoke -C "${REPO}" pack-refs --all

# Confirm the packed shape took: loose ref gone, packed-refs has
# the line.
if [ -f "${REPO}/.git/refs/heads/feat" ]; then
    smoke_fail "expected pack-refs to remove .git/refs/heads/feat (loose ref still there)"
fi
[ -f "${REPO}/.git/packed-refs" ] \
    || smoke_fail "pack-refs didn't create .git/packed-refs"
grep -qE "[[:space:]]refs/heads/feat\$" "${REPO}/.git/packed-refs" \
    || smoke_fail "packed-refs missing the feat line"
smoke_log "packed shape confirmed: loose ref absent, packed-refs lists feat"

PACKED_BEFORE_SHA="$(sha256sum "${REPO}/.git/packed-refs" | cut -d' ' -f1)"
smoke_log "packed-refs pre-delete sha: ${PACKED_BEFORE_SHA:0:12}"

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
smoke_log "git branch -D feat (against packed ref)"
git_invoke -C "${REPO}" branch -D feat 2>&1 | sed 's/^/    /' >&2

if git_invoke -C "${REPO}" rev-parse feat >/dev/null 2>&1; then
    smoke_fail "branch -D didn't land — feat still resolves"
fi
if grep -qE "[[:space:]]refs/heads/feat\$" "${REPO}/.git/packed-refs" 2>/dev/null; then
    smoke_fail "branch -D didn't rewrite packed-refs — feat line still there"
fi
smoke_log "branch -D landed: feat gone from packed-refs"

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

POST_SHA="$(git_invoke -C "${REPO}" rev-parse feat 2>/dev/null || echo MISSING)"
if [ "${POST_SHA}" != "${FEAT_SHA}" ]; then
    smoke_log "feat sha mismatch: expected=${FEAT_SHA} got=${POST_SHA}"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "feat branch ref not restored after packed-refs rewrite undo"
fi
# Also verify the packed-refs file itself round-tripped byte-identical
# — anything less means we restored "the ref" but left noise behind.
PACKED_AFTER_SHA="$(sha256sum "${REPO}/.git/packed-refs" | cut -d' ' -f1)"
if [ "${PACKED_AFTER_SHA}" != "${PACKED_BEFORE_SHA}" ]; then
    smoke_log "packed-refs sha drift: expected=${PACKED_BEFORE_SHA} got=${PACKED_AFTER_SHA}"
    smoke_fail ".git/packed-refs not restored byte-identical"
fi
smoke_log "feat restored: ${POST_SHA:0:12}... + packed-refs byte-identical"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-branch-D-packed-undo-linux (packed ref restored, ${NUM_PRE} pre-images)"
