#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: refuse-helm-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# L8 smoke: pins the `cluster-release` refuse class. shit captures no
# helm release state, so `helm install`, `upgrade`, `uninstall`,
# `delete` and `rollback` must refuse at plan time instead of exiting 0
# with nothing applied (the behavior before this class existed).
#
# The refusal fires from the command line alone, so the smoke needs
# neither helm nor a cluster. Running helm install against kind would
# only show that the release is still there after undo.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-helm-linux is Linux-only"
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

smoke_refuse_assert "cluster-release" "helm install au-l8 ./chart"
smoke_refuse_assert "cluster-release" "helm upgrade --install au-l8 ./chart"
smoke_refuse_assert "cluster-release" "helm uninstall au-l8"
smoke_refuse_assert "cluster-release" "sudo helm install au-l8 ./chart"
smoke_refuse_assert "cluster-release" "helm -n prod upgrade au-l8 ./chart"

smoke_log "PASS: refuse-helm-linux (cluster-release class pinned)"
