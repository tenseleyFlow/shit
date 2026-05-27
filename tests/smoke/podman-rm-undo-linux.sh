#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: podman-rm-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR03.5 smoke — rootless `podman rm -f <container>; shit undo`
# round-trips name + image-source (stash) + env + ports + mounts +
# restart policy + in-place rootfs writes.
#
# Mirrors `docker-rm-undo-linux.sh` (AR10.9 / AR03.1) but uses
# **podman** as the runtime. Validates the cross-runtime delegation
# path: the helper's `prepare_rm` shells out via `Command::new(tool)`
# where `tool == "podman"`, classifier returns PodmanVerb::Rm which
# normalises to DockerVerb::Rm via From<DockerVerb> in
# container/event.rs::prepare. From there the capture (`podman
# inspect` + `podman commit`) and the daemon-side synthesis (which
# spells `bin = "podman"` from the wire-level ContainerRuntime) are
# identical to the docker path — this smoke is the proof.
#
# Rootless: no `sudo`. ubuntu-24.04 hosted runners install podman
# via apt as the runner user; the smoke runs entirely in user
# namespace. Reserve a host port > 30000 so slirp4netns doesn't
# need CAP_NET_BIND_SERVICE.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: podman-rm-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v podman >/dev/null 2>&1; then
    smoke_log "SKIP: podman not on PATH"
    exit 0
fi
if ! podman version >/dev/null 2>&1; then
    smoke_log "SKIP: 'podman version' failed (rootless backend not configured)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

CONTAINER_NAME="shit-test-pod-rm-$$"
VOL_NAME="shit-test-pod-rm-vol-$$"
HOST_PORT=$(( (RANDOM % 10000) + 30000 ))
ENV_PROBE="AR03_5_PROBE=hello-$(date +%s)"
ROOTFS_PROBE="rootfs-probe-content-$(date +%s)"

cleanup_container() {
    SHIT_DURING_UNDO=1 podman rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    SHIT_DURING_UNDO=1 podman volume rm "${VOL_NAME}" >/dev/null 2>&1 || true
    # Clean up any shit-stash-* images this run created.
    SHIT_DURING_UNDO=1 podman images --filter "reference=shit-stash-*" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
        | xargs -r podman rmi -f 2>/dev/null || true
}
trap 'cleanup_container' EXIT

# Pre-state: launch a realistic container with port + env + volume +
# restart policy, then write a probe file to the rootfs.
smoke_log "creating volume ${VOL_NAME}"
podman volume create "${VOL_NAME}" >/dev/null \
    || smoke_fail "podman volume create failed"

smoke_log "pulling busybox:1.36"
podman pull busybox:1.36 >/dev/null 2>&1 || smoke_fail "podman pull busybox failed"

smoke_log "launching container ${CONTAINER_NAME} with port=${HOST_PORT} env=${ENV_PROBE}"
podman run -d \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:9999/tcp" \
    -e "${ENV_PROBE}" \
    -v "${VOL_NAME}:/data" \
    --restart unless-stopped \
    -w /tmp \
    busybox:1.36 \
    sh -c 'while sleep 60; do :; done' \
    >/dev/null \
    || smoke_fail "podman run failed"

podman exec "${CONTAINER_NAME}" sh -c "echo '${ROOTFS_PROBE}' > /tmp/rootfs-probe.txt" \
    || smoke_fail "podman exec write failed"

pre_rootfs="$(podman exec "${CONTAINER_NAME}" cat /tmp/rootfs-probe.txt 2>/dev/null)"
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
[ -x "${HOOKS_BIN}/podman" ] || smoke_fail "podman wrapper missing"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

resolved_podman="$(command -v podman)"
case "${resolved_podman}" in
    "${HOOKS_BIN}/podman") smoke_log "podman resolves to wrapper: ${resolved_podman}" ;;
    *) smoke_fail "expected podman to resolve to ${HOOKS_BIN}/podman, got ${resolved_podman}" ;;
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

smoke_log "podman rm -f ${CONTAINER_NAME} (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! podman rm -f "${CONTAINER_NAME}" >"${SHIT_SMOKE_TMP}/rm.log" 2>&1; then
    smoke_log "rm.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/rm.log" >&2
    smoke_fail "podman rm -f ${CONTAINER_NAME} exited non-zero"
fi
smoke_log "rm.log (informational; rm succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/rm.log" >&2

if podman inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
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

# Post-undo assertions — same set as the docker AR10.9 smoke.
if ! podman inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${CONTAINER_NAME} still missing after undo — podman Rm reverse didn't recreate"
fi

post_image="$(SHIT_DURING_UNDO=1 podman inspect "${CONTAINER_NAME}" --format '{{.Config.Image}}' 2>/dev/null)"
# podman inspect's .Config.Image may include "localhost/" or "docker.io/" prefix
# on a freshly-committed local image; tolerate either form.
case "${post_image}" in
    *shit-stash-*)
        smoke_log "container image is the stash-commit: ${post_image} (preserves in-place writes)"
        ;;
    *)
        smoke_fail "expected stash-commit image; got '${post_image}' (rootfs writes would be lost)"
        ;;
esac

post_env="$(SHIT_DURING_UNDO=1 podman inspect "${CONTAINER_NAME}" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)"
if ! printf '%s' "${post_env}" | grep -qF "${ENV_PROBE}"; then
    smoke_log "post-undo env list:"
    printf '%s' "${post_env}" | sed 's/^/    /' >&2
    smoke_fail "env var ${ENV_PROBE} not preserved across rm/undo"
fi
smoke_log "env var preserved: ${ENV_PROBE}"

# Podman's inspect HostConfig.PortBindings shape matches docker's.
post_port="$(SHIT_DURING_UNDO=1 podman inspect "${CONTAINER_NAME}" --format '{{(index (index .HostConfig.PortBindings "9999/tcp") 0).HostPort}}' 2>/dev/null)"
if [ "${post_port}" != "${HOST_PORT}" ]; then
    smoke_fail "port binding lost: pre=${HOST_PORT} post=${post_port}"
fi
smoke_log "port binding preserved: ${HOST_PORT}:9999/tcp"

post_mount="$(SHIT_DURING_UNDO=1 podman inspect "${CONTAINER_NAME}" --format '{{range .Mounts}}{{.Name}}->{{.Destination}}{{end}}' 2>/dev/null)"
if [ "${post_mount}" != "${VOL_NAME}->/data" ]; then
    smoke_fail "volume mount lost: expected '${VOL_NAME}->/data' got '${post_mount}'"
fi
smoke_log "volume mount preserved: ${post_mount}"

post_restart="$(SHIT_DURING_UNDO=1 podman inspect "${CONTAINER_NAME}" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)"
if [ "${post_restart}" != "unless-stopped" ]; then
    smoke_fail "restart policy lost: expected 'unless-stopped' got '${post_restart}'"
fi
smoke_log "restart policy preserved: ${post_restart}"

# Rootfs probe — proves cross-runtime stash-commit works.
post_rootfs="$(SHIT_DURING_UNDO=1 podman exec "${CONTAINER_NAME}" cat /tmp/rootfs-probe.txt 2>/dev/null)"
if [ "${post_rootfs}" != "${ROOTFS_PROBE}" ]; then
    smoke_log "post-undo rootfs probe read:"
    printf '  %s\n' "${post_rootfs}" >&2
    smoke_fail "rootfs probe lost across rm/undo — podman commit didn't preserve in-place writes"
fi
smoke_log "rootfs probe preserved across podman commit: '${post_rootfs}'"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: podman-rm-undo-linux (cross-runtime delegation confirmed end-to-end)"
