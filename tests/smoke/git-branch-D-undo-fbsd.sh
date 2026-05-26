#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# G01.4 smoke — `git branch -D <name>` force-deletes a branch.
# `shit undo` restores the ref so `git rev-parse <name>` resolves
# again and the (otherwise unreachable) commits become reachable.
#
# Covers the **unpacked** branch shape: `.git/refs/heads/<name>` is
# an individual file that git's branch-D operation unlinks. Captured
# by LSM inode_unlink + FilePreImage; the G01.3 atomic-replace
# extension (path gone + parent exists) routes RestoreContent over
# the now-vanished path.
#
# The **packed** branch shape (`git pack-refs --all` collapses refs
# into `.git/packed-refs`, then branch -D rewrites packed-refs via
# tmpfile + rename) is deferred to a follow-up smoke
# (G01.4-packed) because the smoke harness's start/stop cycle
# doesn't cleanly compose two subtests in one script.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: git-branch-D-undo-fbsd is FreeBSD-only"
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

git_invoke -C "${REPO}" branch feat
FEAT_SHA="$(git_invoke -C "${REPO}" rev-parse feat)"
smoke_log "branch feat at ${FEAT_SHA:0:12}..."

# Confirm the unpacked shape — the smoke is only meaningful when
# `.git/refs/heads/feat` is a real file (packed shape is deferred).
[ -f "${REPO}/.git/refs/heads/feat" ] \
    || smoke_fail "expected unpacked feat at .git/refs/heads/feat (env didn't auto-pack?)"

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

# THE workload.
smoke_log "git branch -D feat"
git_invoke -C "${REPO}" branch -D feat 2>&1 | sed 's/^/    /' >&2

if git_invoke -C "${REPO}" rev-parse feat >/dev/null 2>&1; then
    smoke_fail "branch -D didn't land — feat still resolves"
fi
smoke_log "branch -D landed: feat gone"

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
    smoke_fail "feat branch ref not restored"
fi
smoke_log "feat restored: ${POST_SHA:0:12}... == original"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-branch-D-undo-fbsd (unpacked branch restored, ${NUM_PRE} pre-images)"
