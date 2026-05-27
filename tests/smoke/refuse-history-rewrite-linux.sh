#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: refuse-history-rewrite-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# AU15 smoke — pins the `history-rewrite` refuse class:
# `git rebase -i HEAD~2` (and filter-branch, filter-repo)
# must short-circuit shit undo with a Refused plan + non-zero
# exit + named class. Reflog is the documented recovery.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-history-rewrite-linux is Linux-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

mkdir -p "${SHIT_SMOKE_TMP}/scratch"
cd "${SHIT_SMOKE_TMP}/scratch"

smoke_refuse_assert "history-rewrite" "git rebase -i HEAD~2"

smoke_log "PASS: refuse-history-rewrite-linux (history-rewrite class pinned)"
