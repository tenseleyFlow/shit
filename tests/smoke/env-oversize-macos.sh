#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: env-oversize-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Issue #6: 6 KB PreExecEnv/PostExecEnv frames (SHIT_TRACK_ENV=1
# carriers) reach the daemon although macOS caps AF_UNIX datagrams at
# net.local.dgram.maxdgram=2048. Body lives in lib-env-oversize.sh.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-env-oversize.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-env-oversize.sh"

smoke_env_oversize_run

smoke_log "PASS: env-oversize-macos"
