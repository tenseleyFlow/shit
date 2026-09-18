#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-network-rm-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR03.4 fail-closed smoke. Network removal is outside the current
# atomic capture policy, so the wrapper must exit 125 before invoking
# the real runtime. The network/subnet must remain intact, and the
# command must not own a CONFIRMED container capture batch.
#
# Skips cleanly when docker isn't available. ubuntu-24.04 hosted
# runners have docker.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-network-rm-undo-linux is Linux-only (uname=$(uname -s))"
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

NET_NAME="shit-test-net-$$"
# Pick a /24 in the 172.31.X.0 range. Real risk of collision with an
# existing docker network is low (default bridge uses 172.17.0.0/16)
# but pick something off the well-trodden path. The PID-suffix lets
# parallel CI legs not collide.
SUBNET="172.31.$(( (RANDOM % 200) + 50 )).0/24"
smoke_log "chose subnet=${SUBNET} for ${NET_NAME}"

cleanup_net() {
    SHIT_DURING_UNDO=1 docker network rm "${NET_NAME}" >/dev/null 2>&1 || true
}

cleanup_on_exit() {
    local rc=$?
    trap - EXIT
    cleanup_net
    smoke_cleanup "${rc}"
}
trap cleanup_on_exit EXIT

# Pre-state: create network with non-default driver + subnet.
smoke_log "creating network ${NET_NAME} subnet=${SUBNET}"
docker network create --driver bridge --subnet "${SUBNET}" "${NET_NAME}" >/dev/null \
    || smoke_fail "docker network create ${NET_NAME} failed"

# Confirm baseline state.
pre_subnet="$(docker network inspect "${NET_NAME}" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)"
if [ "${pre_subnet}" != "${SUBNET}" ]; then
    cleanup_net
    smoke_fail "pre-state subnet mismatch: got '${pre_subnet}' want '${SUBNET}'"
fi

smoke_start_shitd

smoke_log "installing container-hooks (XDG_CONFIG_HOME=${XDG_CONFIG_HOME})"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        cleanup_net
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || { cleanup_net; smoke_fail "docker wrapper missing"; }
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

resolved_docker="$(command -v docker)"
case "${resolved_docker}" in
    "${HOOKS_BIN}/docker") smoke_log "docker resolves to wrapper: ${resolved_docker}" ;;
    *) cleanup_net; smoke_fail "expected docker to resolve to ${HOOKS_BIN}/docker, got ${resolved_docker}" ;;
esac

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "docker network rm ${NET_NAME} (expected fail-closed refusal)"
export SHIT_HOOK_DEBUG=1
set +e
docker network rm "${NET_NAME}" >"${SHIT_SMOKE_TMP}/netrm.log" 2>&1
network_rm_rc=$?
set -e
smoke_log "netrm.log (expected refusal):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/netrm.log" >&2
if [ "${network_rm_rc}" -ne 125 ]; then
    smoke_fail "expected docker network rm wrapper to exit 125, got ${network_rm_rc}"
fi

# The real runtime must never have removed or recreated the network.
if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
    smoke_fail "${NET_NAME} was removed despite fail-closed policy"
fi

intact_subnet="$(SHIT_DURING_UNDO=1 docker network inspect "${NET_NAME}" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)"
if [ "${intact_subnet}" != "${SUBNET}" ]; then
    smoke_fail "network subnet changed despite refusal: pre=${SUBNET} post=${intact_subnet}"
fi
smoke_log "${NET_NAME} remained intact with subnet=${intact_subnet}"

smoke_log "PostExec seq=1 exit=${network_rm_rc}"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code "${network_rm_rc}" --sock "${SHIT_HOOK_SOCK}"

SESSION_HEX="${SESSION//-/}"
if ! actionable_batches="$(smoke_journal_query "SELECT COUNT(*) FROM container_capture_batches WHERE session = X'${SESSION_HEX}' AND seq = 1 AND state IN ('CONFIRMED', 'FINALIZED');" 2>/dev/null)"; then
    smoke_fail "could not query container_capture_batches"
fi
if [ "${actionable_batches:-0}" -ne 0 ]; then
    smoke_fail "unsupported docker network rm produced ${actionable_batches} actionable batch(es)"
fi
smoke_log "actionable container batches: 0"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: docker-network-rm-undo-linux (exit 125; ${NET_NAME} intact; no actionable batch)"
