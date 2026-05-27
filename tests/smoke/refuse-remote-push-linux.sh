#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: refuse-remote-push-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# AU15 smoke — pins the `remote-push` refuse class:
# `git push origin main` (and the other catalog patterns
# under remote-push: docker push, npm publish, etc.) must
# short-circuit `shit undo --yes` to a Refused plan with
# non-zero exit and the class name in the output.
#
# Builds on AU26 (the cmd_string wire). Pre-AU26 this smoke
# could not have fired refusal because the refuse-list match
# never saw the command. Pre-AU15 there was no per-class gate
# to catch a planner regression that silently demoted a class.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-remote-push-linux is Linux-only"
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

smoke_refuse_assert "remote-push" "git push origin main"

smoke_log "PASS: refuse-remote-push-linux (remote-push class pinned)"
