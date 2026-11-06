#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: env-oversize-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Issue #6: 6 KB PreExecEnv/PostExecEnv frames (SHIT_TRACK_ENV=1
# carriers) reach the daemon even when the hook socket's datagram cap
# is 2048 bytes. Body lives in lib-env-oversize.sh.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-env-oversize.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-env-oversize.sh"

smoke_env_oversize_run

smoke_log "PASS: env-oversize-linux"
