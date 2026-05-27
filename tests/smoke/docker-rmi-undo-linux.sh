#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-rmi-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR03.2 smoke — `docker rmi <image>; shit undo` restores the image.
#
# Exercises (DR-CR-26 inline-bytes path, AR03 PR-B):
#   1. The docker-wrapper script (installed by `shit container-hooks
#      install`) PATH-shadows the real docker.
#   2. On `docker rmi alpine`, the wrapper invokes
#      `shit-helper container-event docker pre` BEFORE exec'ing the
#      real docker.
#   3. The helper runs `docker save alpine` to capture the tarball
#      bytes in-memory, computes blake3, and ships them inline in the
#      ContainerEventReq to the daemon's ctl socket.
#   4. The daemon writes the tarball to its BlobStore (content-
#      verified — claimed hash must equal computed), registers a
#      container_stashes row, and journals a CaptureEventKind::
#      ContainerOp event attributed to the active command window.
#   5. The real docker proceeds to remove the image.
#   6. `shit undo` plans InverseOp::ContainerRestore { Rmi, image=alpine,
#      stash_tarball=<hash> }, MultiTierExecutor dispatches to
#      ContainerExecutor::apply_rmi which loads the tarball back via
#      `docker load`.
#   7. Post-undo: `docker image inspect alpine` succeeds (image present).
#
# Skips cleanly when docker isn't available or the user can't reach
# the docker socket (CI sets things up; dev boxes vary).
#
# Prereqs (when not skipping):
#   - docker on PATH and the calling user can reach the socket
#     (member of docker group, or running as root).
#   - Network access to pull alpine (~5 MB compressed).
#   - python3, sqlite3.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-rmi-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
    smoke_log "SKIP: docker not on PATH"
    exit 0
fi
# Sanity-check that we can actually reach the docker daemon. CI may
# provision docker but a user-namespace issue (rootless) or socket
# permission gap should skip rather than fail.
if ! docker version >/dev/null 2>&1; then
    smoke_log "SKIP: 'docker version' failed (daemon unreachable or permission denied)"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

TARGET_IMAGE="alpine:3.20"

smoke_log "ensuring ${TARGET_IMAGE} is pulled (baseline)"
if ! docker image inspect "${TARGET_IMAGE}" >/dev/null 2>&1; then
    docker pull "${TARGET_IMAGE}" >/dev/null 2>&1 || smoke_fail "docker pull ${TARGET_IMAGE} failed"
fi

smoke_start_shitd

# Install container hooks into XDG_CONFIG_HOME and prepend that bin
# dir to PATH so `docker` resolves to the wrapper.
smoke_log "installing container-hooks (XDG_CONFIG_HOME=${XDG_CONFIG_HOME})"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper not installed at ${HOOKS_BIN}/docker"
export PATH="${HOOKS_BIN}:${PATH}"
# Make `shit-helper` resolvable from the wrapper.
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

# Sanity: PATH-resolved docker is now our wrapper, not /usr/bin/docker.
resolved_docker="$(command -v docker)"
case "${resolved_docker}" in
    "${HOOKS_BIN}/docker") smoke_log "docker resolves to wrapper: ${resolved_docker}" ;;
    *) smoke_fail "expected docker to resolve to ${HOOKS_BIN}/docker, got ${resolved_docker}" ;;
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

smoke_log "docker rmi ${TARGET_IMAGE} (via wrapper)"
# Wrapper + helper diagnostics: always dump wrapper stderr so we can see
# whether the helper was invoked, whether it reached the daemon, and
# whether `docker save` succeeded. Cheap insurance for a path with
# subtle env-var dependencies.
export SHIT_HOOK_DEBUG=1
if ! SHIT_HELPER_LOG=debug docker rmi "${TARGET_IMAGE}" \
    >"${SHIT_SMOKE_TMP}/rmi.log" 2>&1; then
    smoke_log "rmi.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/rmi.log" >&2
    smoke_fail "docker rmi ${TARGET_IMAGE} exited non-zero"
fi
smoke_log "rmi.log (informational; rmi succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/rmi.log" >&2

# Confirm the image is actually gone.
if docker image inspect "${TARGET_IMAGE}" >/dev/null 2>&1; then
    smoke_fail "${TARGET_IMAGE} still present after rmi (wrapper or docker bug)"
fi

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Wait for the daemon to journal the ContainerOp event.
smoke_wait_for_event "discriminant = 'ContainerOp'" 1 10

# Confirm a container_stashes row landed for the tarball.
stash_count="$(smoke_journal_query "SELECT COUNT(*) FROM container_stashes WHERE name = '${TARGET_IMAGE}';" 2>/dev/null || echo 0)"
if [ "${stash_count:-0}" -lt 1 ]; then
    smoke_log "container_stashes contents:"
    smoke_journal_query "SELECT blob_hash, kind, runtime, name, size_bytes FROM container_stashes;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "no container_stashes row for ${TARGET_IMAGE}"
fi
smoke_log "container_stashes: ${stash_count} row(s) for ${TARGET_IMAGE}"

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: image should be back.
if ! docker image inspect "${TARGET_IMAGE}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_IMAGE} still missing after undo — ContainerRestore (Rmi) didn't restore"
fi
smoke_log "${TARGET_IMAGE} restored by undo"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Cleanup: leave the local docker state clean — remove the image so a
# rerun starts from a clean baseline. (Use the wrapper's underlying
# real docker via SHIT_DURING_UNDO to avoid re-triggering capture.)
SHIT_DURING_UNDO=1 docker rmi "${TARGET_IMAGE}" >/dev/null 2>&1 || true

smoke_log "PASS: docker-rmi-undo-linux (${TARGET_IMAGE} rmi'd → restored)"
