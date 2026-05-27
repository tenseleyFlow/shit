#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-rm-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR10.9 / AR03.1 smoke — `docker rm -f <container>; shit undo`
# restores the container with its image + name + env + ports + mounts
# + restart policy preserved.
#
# This is the marquee test for the full Rm reverse-synthesis path
# (DR-CR-22). Validates:
#   1. Helper's prepare_rm: `docker inspect` → captured_config JSON,
#      detects .State.Running, `docker commit` to a `shit-stash-*`
#      tag so in-place rootfs writes round-trip.
#   2. Daemon ingests via container_track::handle (no tarball stash;
#      captured_config carries the JSON, stash_image carries the
#      commit tag).
#   3. Executor's apply_rm: parses inspect JSON, verifies stash
#      image exists, walks ~15 options through synthesize_container_run,
#      and runs `docker run -d --name ... -p ... -e ... -v ... <stash>`.
#   4. The restored container has the same effective config (name,
#      image-source = stash, env vars, port bindings, mounts, restart
#      policy) AND any in-place rootfs writes the user made before
#      the rm.
#
# Skips cleanly when docker isn't available. ubuntu-24.04 hosted
# runners have docker.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-rm-undo-linux is Linux-only (uname=$(uname -s))"
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

CONTAINER_NAME="shit-test-rm-$$"
VOL_NAME="shit-test-rm-vol-$$"
HOST_PORT=$(( (RANDOM % 10000) + 30000 ))
ENV_PROBE="AR10_9_PROBE=hello-$(date +%s)"
ROOTFS_PROBE="rootfs-probe-content-$(date +%s)"

cleanup_container() {
    SHIT_DURING_UNDO=1 docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    SHIT_DURING_UNDO=1 docker volume rm "${VOL_NAME}" >/dev/null 2>&1 || true
    # Clean up any shit-stash-* images this run created.
    SHIT_DURING_UNDO=1 docker images --filter "reference=shit-stash-*" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
        | xargs -r docker rmi -f 2>/dev/null || true
}
trap 'cleanup_container' EXIT

# Pre-state: launch a realistic container — busybox (small) with a
# port binding, an env var, a named volume mount, and a restart policy.
# Then write a probe file to the rootfs so we can validate the stash-
# commit preserves in-place writes.
smoke_log "creating volume ${VOL_NAME}"
docker volume create "${VOL_NAME}" >/dev/null \
    || smoke_fail "docker volume create failed"

smoke_log "pulling busybox:1.36 (small image, fits inline tarball if Rmi were involved)"
docker pull busybox:1.36 >/dev/null 2>&1 || smoke_fail "docker pull busybox failed"

smoke_log "launching container ${CONTAINER_NAME} with port=${HOST_PORT} env=${ENV_PROBE}"
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:9999/tcp" \
    -e "${ENV_PROBE}" \
    -v "${VOL_NAME}:/data" \
    --restart unless-stopped \
    -w /tmp \
    busybox:1.36 \
    sh -c 'while sleep 60; do :; done' \
    >/dev/null \
    || smoke_fail "docker run failed"

# In-place rootfs write so we can prove the stash-commit captures it
# (the original busybox image doesn't have this file).
docker exec "${CONTAINER_NAME}" sh -c "echo '${ROOTFS_PROBE}' > /tmp/rootfs-probe.txt" \
    || smoke_fail "docker exec write failed"

# Read it back as a sanity check.
pre_rootfs="$(docker exec "${CONTAINER_NAME}" cat /tmp/rootfs-probe.txt 2>/dev/null)"
if [ "${pre_rootfs}" != "${ROOTFS_PROBE}" ]; then
    smoke_fail "pre-rm rootfs probe read-back mismatch: got '${pre_rootfs}'"
fi

smoke_start_shitd

smoke_log "installing container-hooks"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper missing"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

resolved_docker="$(command -v docker)"
case "${resolved_docker}" in
    "${HOOKS_BIN}/docker") smoke_log "docker resolves to wrapper: ${resolved_docker}" ;;
    *) smoke_fail "expected docker to resolve to wrapper, got ${resolved_docker}" ;;
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

smoke_log "docker rm -f ${CONTAINER_NAME} (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! docker rm -f "${CONTAINER_NAME}" >"${SHIT_SMOKE_TMP}/rm.log" 2>&1; then
    smoke_log "rm.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/rm.log" >&2
    smoke_fail "docker rm -f ${CONTAINER_NAME} exited non-zero"
fi
smoke_log "rm.log (informational; rm succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/rm.log" >&2

# Confirm gone.
if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    smoke_fail "${CONTAINER_NAME} still present after rm"
fi

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'ContainerOp'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo assertions: container exists, env preserved, port bound,
# volume mounted, restart policy honored, rootfs probe survived via
# the stash-commit.
if ! docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${CONTAINER_NAME} still missing after undo — Rm reverse didn't recreate"
fi

post_image="$(SHIT_DURING_UNDO=1 docker inspect "${CONTAINER_NAME}" --format '{{.Config.Image}}' 2>/dev/null)"
case "${post_image}" in
    shit-stash-*)
        smoke_log "container image is the stash-commit: ${post_image} (preserves in-place writes)"
        ;;
    *)
        smoke_fail "expected stash-commit image; got '${post_image}' (rootfs writes would be lost)"
        ;;
esac

post_env="$(SHIT_DURING_UNDO=1 docker inspect "${CONTAINER_NAME}" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)"
if ! printf '%s' "${post_env}" | grep -qF "${ENV_PROBE}"; then
    smoke_log "post-undo env list:"
    printf '%s' "${post_env}" | sed 's/^/    /' >&2
    smoke_fail "env var ${ENV_PROBE} not preserved across rm/undo"
fi
smoke_log "env var preserved: ${ENV_PROBE}"

post_port="$(SHIT_DURING_UNDO=1 docker inspect "${CONTAINER_NAME}" --format '{{(index (index .HostConfig.PortBindings "9999/tcp") 0).HostPort}}' 2>/dev/null)"
if [ "${post_port}" != "${HOST_PORT}" ]; then
    smoke_fail "port binding lost: pre=${HOST_PORT} post=${post_port}"
fi
smoke_log "port binding preserved: ${HOST_PORT}:9999/tcp"

post_mount="$(SHIT_DURING_UNDO=1 docker inspect "${CONTAINER_NAME}" --format '{{range .Mounts}}{{.Name}}->{{.Destination}}{{end}}' 2>/dev/null)"
if [ "${post_mount}" != "${VOL_NAME}->/data" ]; then
    smoke_fail "volume mount lost: expected '${VOL_NAME}->/data' got '${post_mount}'"
fi
smoke_log "volume mount preserved: ${post_mount}"

post_restart="$(SHIT_DURING_UNDO=1 docker inspect "${CONTAINER_NAME}" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)"
if [ "${post_restart}" != "unless-stopped" ]; then
    smoke_fail "restart policy lost: expected 'unless-stopped' got '${post_restart}'"
fi
smoke_log "restart policy preserved: ${post_restart}"

# The marquee assertion: in-place rootfs writes survived via the
# stash-commit. Without the commit, the restored container would
# be a fresh busybox without our probe file.
post_rootfs="$(SHIT_DURING_UNDO=1 docker exec "${CONTAINER_NAME}" cat /tmp/rootfs-probe.txt 2>/dev/null)"
if [ "${post_rootfs}" != "${ROOTFS_PROBE}" ]; then
    smoke_log "post-undo rootfs probe read:"
    printf '  %s\n' "${post_rootfs}" >&2
    smoke_fail "rootfs probe lost across rm/undo — stash-commit didn't preserve in-place writes"
fi
smoke_log "rootfs probe preserved across stash-commit: '${post_rootfs}'"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: docker-rm-undo-linux (${CONTAINER_NAME}: image+env+port+mount+restart+rootfs all round-trip)"
