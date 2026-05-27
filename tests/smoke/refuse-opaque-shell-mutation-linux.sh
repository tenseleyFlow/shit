#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: refuse-opaque-shell-mutation-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# AU15 smoke — pins the `opaque-shell-mutation` refuse
# class: `source <script>` (and the `.` synonym) must
# short-circuit shit undo. Sourcing mutates the parent
# shell in arbitrary ways the capture tier doesn't
# introspect.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-opaque-shell-mutation-linux is Linux-only"
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

smoke_refuse_assert "opaque-shell-mutation" "source /tmp/au15_some_script.sh"

smoke_log "PASS: refuse-opaque-shell-mutation-linux (opaque-shell-mutation class pinned)"
