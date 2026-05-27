#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: refuse-system-identity-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# AU15 smoke — pins the `system-identity` refuse class:
# `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`,
# `passwd` must short-circuit shit undo. PAM / shadow-file
# mutations touch system identity state we don't trust
# ourselves to roll back.
#
# Note: the underlying `useradd` would need root to actually
# run, but the refuse short-circuit fires at PLAN TIME from
# the cmdline alone — no useradd subprocess is ever invoked.
# So this smoke runs cleanly without root.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-system-identity-linux is Linux-only"
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

smoke_refuse_assert "system-identity" "useradd au15testuser"

smoke_log "PASS: refuse-system-identity-linux (system-identity class pinned)"
