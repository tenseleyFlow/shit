#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-rmi-multi-target-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Initial safe container policy deliberately admits exactly one Docker image
# tag per `rmi --no-prune` invocation. A multi-target command must fail closed
# before Docker removes either image. This smoke pins that negative contract
# and proves no batch was confirmed as a side effect of the refusal.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-rmi-multi-target-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
    smoke_log "SKIP: docker not on PATH"
    exit 0
fi
if ! docker version >/dev/null 2>&1; then
    smoke_log "SKIP: 'docker version' failed (daemon unreachable or permission denied)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

IMAGES=("alpine:3.20" "busybox:1.36")
for img in "${IMAGES[@]}"; do
    if ! docker image inspect "${img}" >/dev/null 2>&1; then
        smoke_log "pulling baseline image ${img}"
        docker pull "${img}" >/dev/null 2>&1 || smoke_fail "docker pull ${img} failed"
    fi
done

smoke_start_shitd

"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper not installed at ${HOOKS_BIN}/docker"
export PATH="${HOOKS_BIN}:${SHIT_SMOKE_BIN_DIR}:${PATH}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "expecting fail-closed refusal for multi-target docker rmi"
set +e
SHIT_HELPER_LOG=debug docker rmi --no-prune "${IMAGES[@]}" \
    >"${SHIT_SMOKE_TMP}/rmi.log" 2>&1
rmi_rc=$?
set -e
if [ "${rmi_rc}" -ne 125 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/rmi.log" >&2
    smoke_fail "multi-target rmi returned ${rmi_rc}; expected fail-closed status 125"
fi

for img in "${IMAGES[@]}"; do
    docker image inspect "${img}" >/dev/null 2>&1 \
        || smoke_fail "${img} was removed despite multi-target refusal"
done

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code "${rmi_rc}" --sock "${SHIT_HOOK_SOCK}"

SESSION_HEX="${SESSION//-/}"
actionable="$(smoke_journal_query "SELECT COUNT(*) FROM container_capture_batches WHERE session = X'${SESSION_HEX}' AND seq = 1 AND state IN ('CONFIRMED', 'FINALIZED');" 2>/dev/null || echo 0)"
if [ "${actionable:-0}" -ne 0 ]; then
    smoke_fail "multi-target refusal unexpectedly created ${actionable} actionable batch(es)"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Leave the CI daemon clean. SHIT_DURING_UNDO bypasses capture while retaining
# the wrapper's serialization and exact runtime status.
for img in "${IMAGES[@]}"; do
    SHIT_DURING_UNDO=1 docker rmi --no-prune "${img}" >/dev/null 2>&1 || true
done

smoke_log "PASS: multi-target docker rmi refused before either image was removed"
