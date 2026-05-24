#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR03.4 smoke — `docker network rm <net>; shit undo` restores the
# network with its driver + subnet preserved.
#
# Exercises (DR-CR-26 network-rm path):
#   1. Create a docker network with a non-default subnet (so the
#      restore must honor the captured IPAM config, not just recreate
#      a vanilla bridge).
#   2. Through the shit-installed docker-wrapper, `docker network rm
#      shit-test-net` invokes `shit-helper container-event docker
#      pre` before exec'ing the real docker.
#   3. The helper classifies as NetworkRm, runs `docker network
#      inspect shit-test-net`, ships the JSON bytes as
#      captured_config (small payload — no tarball, no inline-bytes
#      path).
#   4. Daemon journals the ContainerOp event with captured_config.
#      No container_stashes row for NetworkRm (config-only verb).
#   5. The real docker proceeds to remove the network.
#   6. `shit undo --yes` plans InverseOp::ContainerRestore { NetworkRm,
#      name=shit-test-net }, which parses the captured JSON via
#      synthesize_network_create and runs `docker network create
#      --driver bridge --subnet <captured> shit-test-net`.
#   7. Post-undo: the network exists with the same driver + subnet.
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

smoke_log "docker network rm ${NET_NAME} (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! docker network rm "${NET_NAME}" >"${SHIT_SMOKE_TMP}/netrm.log" 2>&1; then
    smoke_log "netrm.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/netrm.log" >&2
    cleanup_net
    smoke_fail "docker network rm ${NET_NAME} exited non-zero"
fi
smoke_log "netrm.log (informational; rm succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/netrm.log" >&2

# Confirm gone.
if docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
    cleanup_net
    smoke_fail "${NET_NAME} still present after rm (wrapper or docker bug)"
fi

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'ContainerOp'" 1 10
# NetworkRm doesn't stash a tarball (no container_stashes row to
# probe like AR03.2/AR03.3). The ContainerOp journal entry is the
# only persisted artifact pre-undo; the daemon log shows verb=NetworkRm
# in tracing. The real assertion is the post-undo subnet check below
# — if the daemon journaled the wrong verb shape, undo wouldn't
# recreate the network at all.

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    cleanup_net
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: network must exist + subnet must match.
if ! docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    cleanup_net
    smoke_fail "${NET_NAME} still missing after undo — ContainerRestore (NetworkRm) didn't recreate"
fi

post_subnet="$(SHIT_DURING_UNDO=1 docker network inspect "${NET_NAME}" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)"
if [ "${post_subnet}" != "${SUBNET}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "subnet mismatch: pre=${SUBNET} post=${post_subnet}"
    cleanup_net
    smoke_fail "network restored but subnet not preserved"
fi
smoke_log "${NET_NAME} restored with subnet=${post_subnet} (matches pre-state)"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

cleanup_net

smoke_log "PASS: docker-network-rm-undo-linux (${NET_NAME} rm'd → restored with subnet)"
