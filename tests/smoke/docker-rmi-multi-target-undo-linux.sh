#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-rmi-multi-target-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 420
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU24 / DR-CR-52 — `docker rmi <a> <b> <c>; shit undo` restores
# all three images. Multi-target sibling of docker-rmi-undo-linux.sh.
#
# Validate-the-gap pattern: pre-AU24, `prepare_rmi` took only the
# first positional and silently dropped the rest. After undo only
# `alpine:3.20` would come back; `busybox:1.36` and `hello-world:latest`
# stayed missing. This smoke pins the post-AU24 contract: N images
# rmi'd → N events journaled → undo restores all N.
#
# Exercises:
#   1. Wrapper invokes `shit-helper container-event docker pre` once.
#   2. Helper `prepare_rmi` iterates over the three images, calling
#      `docker save` on each and shipping THREE ContainerEventReq
#      frames over the same command_seq.
#   3. Daemon writes three container_stashes rows + three
#      CaptureEventKind::ContainerOp events attributed to the active
#      window.
#   4. Real docker proceeds with `docker rmi alpine:3.20 busybox:1.36
#      hello-world:latest`.
#   5. `shit undo --yes` plans three InverseOp::ContainerRestore { Rmi }
#      nodes; ContainerExecutor::apply_rmi loads each tarball back.
#   6. Post-undo: all three images present.

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

IMAGES=("alpine:3.20" "busybox:1.36" "hello-world:latest")

for img in "${IMAGES[@]}"; do
    if ! docker image inspect "${img}" >/dev/null 2>&1; then
        smoke_log "pulling baseline image ${img}"
        docker pull "${img}" >/dev/null 2>&1 || smoke_fail "docker pull ${img} failed"
    fi
done

smoke_start_shitd

smoke_log "installing container-hooks (XDG_CONFIG_HOME=${XDG_CONFIG_HOME})"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper not installed at ${HOOKS_BIN}/docker"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

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

smoke_log "docker rmi ${IMAGES[*]} (via wrapper, multi-target)"
export SHIT_HOOK_DEBUG=1
if ! SHIT_HELPER_LOG=debug docker rmi "${IMAGES[@]}" \
    >"${SHIT_SMOKE_TMP}/rmi.log" 2>&1; then
    smoke_log "rmi.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/rmi.log" >&2
    smoke_fail "docker rmi ${IMAGES[*]} exited non-zero"
fi
smoke_log "rmi.log (informational):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/rmi.log" >&2

for img in "${IMAGES[@]}"; do
    if docker image inspect "${img}" >/dev/null 2>&1; then
        smoke_fail "${img} still present after rmi"
    fi
done
smoke_log "all ${#IMAGES[@]} images confirmed removed"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# AU24 contract: three ContainerOp events, not one.
smoke_wait_for_event "discriminant = 'ContainerOp'" 3 15

# One container_stashes row per image.
for img in "${IMAGES[@]}"; do
    n="$(smoke_journal_query "SELECT COUNT(*) FROM container_stashes WHERE name = '${img}';" 2>/dev/null || echo 0)"
    if [ "${n:-0}" -lt 1 ]; then
        smoke_log "container_stashes contents:"
        smoke_journal_query "SELECT blob_hash, kind, runtime, name, size_bytes FROM container_stashes;" 2>/dev/null \
            | sed 's/^/    /' >&2 || true
        smoke_fail "no container_stashes row for ${img} — AU24 multi-target capture regressed"
    fi
    smoke_log "container_stashes: ${n} row(s) for ${img}"
done

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

for img in "${IMAGES[@]}"; do
    if ! docker image inspect "${img}" >/dev/null 2>&1; then
        smoke_log "undo log:"
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
        smoke_fail "${img} still missing after undo — AU24 batch restore regressed"
    fi
done
smoke_log "all ${#IMAGES[@]} images restored by undo"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Cleanup: remove the test images via the real docker (SHIT_DURING_UNDO
# avoids re-triggering capture).
for img in "${IMAGES[@]}"; do
    SHIT_DURING_UNDO=1 docker rmi "${img}" >/dev/null 2>&1 || true
done

smoke_log "PASS: docker-rmi-multi-target-undo-linux (${#IMAGES[@]} images rmi'd → all restored)"
