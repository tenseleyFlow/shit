#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-volume-rm-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR03.3 fail-closed smoke. Volume removal is outside the current
# atomic capture policy, so the wrapper must exit 125 without invoking
# the real runtime. The volume and probe bytes must remain intact, and
# the command must not own a CONFIRMED container capture batch.
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

# Ensure busybox is present for the probe container.
smoke_log "pulling busybox for volume probe"
docker pull busybox:1.36 >/dev/null 2>&1 || smoke_fail "docker pull busybox failed"

cleanup_volume() {
    SHIT_DURING_UNDO=1 docker volume rm "${VOL_NAME}" >/dev/null 2>&1 || true
}

cleanup_on_exit() {
    local rc=$?
    trap - EXIT
    cleanup_volume
    smoke_cleanup "${rc}"
}
trap cleanup_on_exit EXIT

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

smoke_log "docker volume rm ${VOL_NAME} (expected fail-closed refusal)"
export SHIT_HOOK_DEBUG=1
set +e
docker volume rm "${VOL_NAME}" >"${SHIT_SMOKE_TMP}/volrm.log" 2>&1
volume_rm_rc=$?
set -e
smoke_log "volrm.log (expected refusal):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/volrm.log" >&2
if [ "${volume_rm_rc}" -ne 125 ]; then
    smoke_fail "expected docker volume rm wrapper to exit 125, got ${volume_rm_rc}"
fi

# The real runtime must never have removed the volume.
if ! docker volume inspect "${VOL_NAME}" >/dev/null 2>&1; then
    smoke_fail "${VOL_NAME} was removed despite fail-closed policy"
fi

intact_content="$(SHIT_DURING_UNDO=1 docker run --rm -v "${VOL_NAME}:/data" busybox:1.36 cat /data/probe.txt 2>/dev/null)"
if [ "${intact_content}" != "${PROBE_CONTENT}" ]; then
    smoke_fail "volume probe changed despite refusal: got '${intact_content}'"
fi
smoke_log "${VOL_NAME} and probe.txt remained intact"

smoke_log "PostExec seq=1 exit=${volume_rm_rc}"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code "${volume_rm_rc}" --sock "${SHIT_HOOK_SOCK}"

SESSION_HEX="${SESSION//-/}"
if ! actionable_batches="$(smoke_journal_query "SELECT COUNT(*) FROM container_capture_batches WHERE session = X'${SESSION_HEX}' AND seq = 1 AND state IN ('CONFIRMED', 'FINALIZED');" 2>/dev/null)"; then
    smoke_fail "could not query container_capture_batches"
fi
if [ "${actionable_batches:-0}" -ne 0 ]; then
    smoke_fail "unsupported docker volume rm produced ${actionable_batches} actionable batch(es)"
fi
smoke_log "actionable container batches: 0"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: docker-volume-rm-undo-linux (exit 125; ${VOL_NAME} intact; no actionable batch)"
