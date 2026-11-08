#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-git-lockfile-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice B — git's lock-file dance is not loss under strict capture.
#
# `git config`, `git commit` and `git branch -D` each create a
# `*.lock` (and object temp files), write, chmod, then rename the lock
# over the real file or unlink it. Every one of those files is born
# inside the command, so its pre-state is "absent" and it needs no
# pre-image. The per-hook ring readers deliver these events in any
# order, and the create handler's stat often loses the race with the
# rename. The born set (FMODE_CREATED on the creating open, a create
# stat, or absence from a fully walked baseline directory) must
# classify them without depending on order.
#
# One session, SHIT_STRICT_CAPTURE=1, three commands, each undone right
# after it runs:
#   1. git config core.shitprobe yes   -> undo leaves .git/config as before
#   2. git commit                      -> undo restores HEAD and the index
#   3. git branch -D feat              -> undo restores refs/heads/feat
# Then: zero CaptureRefused rows in the journal.
#
# Validate-the-gap: the R3 design memo traces PR 185's strict LSM failures
# to this dance (lock files reported as "created entry disappeared
# before its kernel identity could be captured", plus unmatched
# open/setattr observations).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-git-lockfile-linux is Linux-only (uname=$(uname -s))"
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

if ! grep -q "\bbpf\b" /sys/kernel/security/lsm 2>/dev/null; then
    smoke_log "FAIL: kernel lacks the bpf LSM (active=$(cat /sys/kernel/security/lsm 2>/dev/null))"
    exit 1
fi
set +e
smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
set -e
[ "${caps_rc}" -eq 2 ] && exit 0
[ "${caps_rc}" -eq 0 ] || exit 1
export SHIT_FORCE_TIER=ebpf-lsm

sha256_of() {
    sha256sum "$1" | cut -d' ' -f1
}

smoke_strict_git_lockfile strict-git-lockfile-linux sha256_of
