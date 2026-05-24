#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR03.3 smoke — `docker volume rm <vol>; shit undo` restores volume
# contents byte-identically.
#
# Exercises (DR-CR-26 inline-bytes volume path):
#   1. Create a docker volume + write a probe file via a transient
#      busybox container.
#   2. Through the shit-installed docker-wrapper, `docker volume rm
#      shit-test-vol` invokes `shit-helper container-event docker pre`
#      before exec'ing the real docker.
#   3. The helper classifies the argv as VolumeRm, runs `docker run
#      --rm -v vol:/src:ro busybox tar -C /src -czf - .` to capture
#      the volume contents as a gzipped tarball, blake3-hashes it,
#      and ships the bytes inline via encode_frame_large.
#   4. Daemon writes the tarball to the BlobStore (content-verified),
#      registers a container_stashes row (kind=VolumeTar), and
#      journals the ContainerOp event.
#   5. The real docker proceeds to remove the volume.
#   6. `shit undo --yes` plans InverseOp::ContainerRestore { VolumeRm,
#      name=shit-test-vol, stash_tarball=<hash> }, which goes through
#      ContainerExecutor::apply_volume_rm:
#        a. `docker volume create shit-test-vol`
#        b. `docker run --rm -i -v shit-test-vol:/data busybox tar -C
#           /data -xzf -` with the captured bytes on stdin
#   7. Post-undo: the volume is back and the probe file's content is
#      byte-identical to what we wrote pre-rm.
#
# Skips cleanly when docker isn't available or the user can't reach
# the docker socket. ubuntu-24.04 hosted runners have docker.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-volume-rm-undo-linux is Linux-only (uname=$(uname -s))"
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

VOL_NAME="shit-test-vol-$$"
PROBE_CONTENT="hello-from-ar03.3-$(date +%s)"

# Ensure busybox is present for the tar transient container.
smoke_log "pulling busybox for tar steps"
docker pull busybox:1.36 >/dev/null 2>&1 || smoke_fail "docker pull busybox failed"

cleanup_volume() {
    SHIT_DURING_UNDO=1 docker volume rm "${VOL_NAME}" >/dev/null 2>&1 || true
}

# Pre-state: create volume + write probe file.
smoke_log "creating volume ${VOL_NAME} with probe file"
docker volume create "${VOL_NAME}" >/dev/null \
    || smoke_fail "docker volume create ${VOL_NAME} failed"
docker run --rm -v "${VOL_NAME}:/data" busybox:1.36 \
    sh -c "printf '%s' '${PROBE_CONTENT}' > /data/probe.txt" \
    >/dev/null 2>&1 \
    || { cleanup_volume; smoke_fail "writing probe file to volume failed"; }

# Sanity: confirm we can read the probe back.
read_back="$(docker run --rm -v "${VOL_NAME}:/data" busybox:1.36 cat /data/probe.txt 2>/dev/null)"
if [ "${read_back}" != "${PROBE_CONTENT}" ]; then
    cleanup_volume
    smoke_fail "pre-rm probe read-back mismatch: got '${read_back}' want '${PROBE_CONTENT}'"
fi

smoke_start_shitd

smoke_log "installing container-hooks (XDG_CONFIG_HOME=${XDG_CONFIG_HOME})"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        cleanup_volume
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || { cleanup_volume; smoke_fail "docker wrapper missing"; }
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

resolved_docker="$(command -v docker)"
case "${resolved_docker}" in
    "${HOOKS_BIN}/docker") smoke_log "docker resolves to wrapper: ${resolved_docker}" ;;
    *) cleanup_volume; smoke_fail "expected docker to resolve to ${HOOKS_BIN}/docker, got ${resolved_docker}" ;;
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

smoke_log "docker volume rm ${VOL_NAME} (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! docker volume rm "${VOL_NAME}" >"${SHIT_SMOKE_TMP}/volrm.log" 2>&1; then
    smoke_log "volrm.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/volrm.log" >&2
    cleanup_volume
    smoke_fail "docker volume rm ${VOL_NAME} exited non-zero"
fi
smoke_log "volrm.log (informational; rm succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/volrm.log" >&2

# Confirm the volume is gone before undo.
if docker volume inspect "${VOL_NAME}" >/dev/null 2>&1; then
    cleanup_volume
    smoke_fail "${VOL_NAME} still present after rm (wrapper or docker bug)"
fi

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'ContainerOp'" 1 10

stash_count="$(smoke_journal_query "SELECT COUNT(*) FROM container_stashes WHERE name = '${VOL_NAME}';" 2>/dev/null || echo 0)"
if [ "${stash_count:-0}" -lt 1 ]; then
    smoke_log "container_stashes contents:"
    smoke_journal_query "SELECT blob_hash, kind, runtime, name, size_bytes FROM container_stashes;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    cleanup_volume
    smoke_fail "no container_stashes row for ${VOL_NAME}"
fi
smoke_log "container_stashes: ${stash_count} row(s) for ${VOL_NAME}"

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    cleanup_volume
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: volume must exist + probe file content must match.
if ! docker volume inspect "${VOL_NAME}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    cleanup_volume
    smoke_fail "${VOL_NAME} still missing after undo — ContainerRestore (VolumeRm) didn't recreate"
fi

restored_content="$(SHIT_DURING_UNDO=1 docker run --rm -v "${VOL_NAME}:/data" busybox:1.36 cat /data/probe.txt 2>/dev/null)"
if [ "${restored_content}" != "${PROBE_CONTENT}" ]; then
    smoke_log "post-undo probe.txt content mismatch:"
    smoke_log "  expected: '${PROBE_CONTENT}'"
    smoke_log "  got:      '${restored_content}'"
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    cleanup_volume
    smoke_fail "volume content not byte-identical after undo"
fi
smoke_log "${VOL_NAME} restored, probe.txt content matches (${#restored_content} bytes)"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

cleanup_volume

smoke_log "PASS: docker-volume-rm-undo-linux (${VOL_NAME} rm'd → contents restored)"
