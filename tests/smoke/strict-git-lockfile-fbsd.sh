#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-git-lockfile-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice B — git's lock-file dance is not loss under strict capture,
# kqueue tier. FreeBSD mirror of strict-git-lockfile-linux.
#
# kqueue reports writes after they happen, so a pre-existing file's
# pre-write content comes from the live-baseline walk at attach. A
# tracked file missing from the attach listing was added by a
# directory diff and was born in the command; it needs no pre-image.
#
# `git config`, `git commit` and `git branch -D` each create a
# `*.lock` (and object temp files), write, chmod, then rename the lock
# over the real file or unlink it. Every one of those files is born
# inside the command, so its pre-state is "absent" and it needs no
# pre-image. The per-hook ring readers deliver these events in any
# order on Linux; on FreeBSD the lock files show up in directory diffs
# after the fact.
#
# One session, SHIT_STRICT_CAPTURE=1, three commands, each undone right
# after it runs:
#   1. git config core.shitprobe yes   -> undo leaves .git/config as before
#   2. git commit                      -> undo restores HEAD and the index
#   3. git branch -D feat              -> undo restores refs/heads/feat
# Then: zero CaptureRefused rows in the journal.
#
# Validate-the-gap: before slice B the kqueue producer reported no loss
# at all, so strict mode could not tell this dance from a real loss.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: strict-git-lockfile-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
if [ -z "${GIT_BIN:-}" ]; then
    smoke_log "SKIP: git not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

sha256_of() {
    sha256 -q "$1"
}

smoke_strict_git_lockfile strict-git-lockfile-fbsd sha256_of
