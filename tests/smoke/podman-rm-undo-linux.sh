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
# AR03.5 fail-closed smoke. Podman container removal is outside the
# current atomic capture policy, so the wrapper must exit 125 before
# invoking the real runtime. The container/rootfs must remain intact,
# and the command must not own a CONFIRMED container capture batch.
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
}

cleanup_on_exit() {
    local rc=$?
    trap - EXIT
    cleanup_container
    smoke_cleanup "${rc}"
}
trap cleanup_on_exit EXIT

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

smoke_log "podman rm -f ${CONTAINER_NAME} (expected fail-closed refusal)"
export SHIT_HOOK_DEBUG=1
set +e
podman rm -f "${CONTAINER_NAME}" >"${SHIT_SMOKE_TMP}/rm.log" 2>&1
rm_rc=$?
set -e
smoke_log "rm.log (expected refusal):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/rm.log" >&2
if [ "${rm_rc}" -ne 125 ]; then
    smoke_fail "expected podman rm wrapper to exit 125, got ${rm_rc}"
fi

# The real runtime must never have seen the destructive command.
if ! podman inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    smoke_fail "${CONTAINER_NAME} was removed despite fail-closed policy"
fi

post_rootfs="$(SHIT_DURING_UNDO=1 podman exec "${CONTAINER_NAME}" cat /tmp/rootfs-probe.txt 2>/dev/null)"
if [ "${post_rootfs}" != "${ROOTFS_PROBE}" ]; then
    smoke_fail "rootfs changed despite refusal: got '${post_rootfs}'"
fi
smoke_log "container and rootfs remained intact after refusal"

smoke_log "PostExec seq=1 exit=${rm_rc}"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code "${rm_rc}" --sock "${SHIT_HOOK_SOCK}"

SESSION_HEX="${SESSION//-/}"
if ! actionable_batches="$(smoke_journal_query "SELECT COUNT(*) FROM container_capture_batches WHERE session = X'${SESSION_HEX}' AND seq = 1 AND state IN ('CONFIRMED', 'FINALIZED');" 2>/dev/null)"; then
    smoke_fail "could not query container_capture_batches"
fi
if [ "${actionable_batches:-0}" -ne 0 ]; then
    smoke_fail "unsupported podman rm produced ${actionable_batches} actionable batch(es)"
fi
smoke_log "actionable container batches: 0"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: podman-rm-undo-linux (exit 125; ${CONTAINER_NAME} intact; no actionable batch)"
