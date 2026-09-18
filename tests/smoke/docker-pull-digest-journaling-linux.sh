#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-pull-digest-journaling-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Historical filename, current release-boundary smoke: `docker pull` is an
# engine mutation with no lossless inverse. The wrapper must reject it with
# status 125 before invoking either helper or real Docker, leave the image
# absent, and create no container capture batch/event.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-pull-digest-journaling-linux is Linux-only"
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
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

TARGET_IMAGE="alpine:3.20"

# Clean slate: remove alpine if present so the hooked pull is what
# fetches it. (SHIT_DURING_UNDO=1 prevents the wrapper's pre-handler
# from journaling this rmi if hooks happen to already be installed
# from a prior smoke run.)
SHIT_DURING_UNDO=1 docker rmi "${TARGET_IMAGE}" >/dev/null 2>&1 || true

smoke_start_shitd

smoke_log "installing container-hooks"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "container-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper not installed at ${HOOKS_BIN}/docker"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

# Sanity — PATH-resolved docker is the wrapper.
resolved_docker="$(command -v docker)"
[ "${resolved_docker}" = "${HOOKS_BIN}/docker" ] \
    || smoke_fail "expected docker to resolve to wrapper; got ${resolved_docker}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash \
    --cmdline "docker pull ${TARGET_IMAGE}" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "docker pull ${TARGET_IMAGE} (expected fail-closed refusal)"
export SHIT_HOOK_DEBUG=1
set +e
SHIT_HELPER_LOG=debug docker pull "${TARGET_IMAGE}" \
    >"${SHIT_SMOKE_TMP}/pull.log" 2>&1
pull_rc=$?
set -e
if [ "${pull_rc}" -ne 125 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/pull.log" >&2
    smoke_fail "docker pull returned ${pull_rc}; expected fail-closed status 125"
fi

if SHIT_DURING_UNDO=1 docker image inspect "${TARGET_IMAGE}" >/dev/null 2>&1; then
    smoke_fail "${TARGET_IMAGE} exists despite refused docker pull"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code "${pull_rc}" --sock "${SHIT_HOOK_SOCK}"

SESSION_HEX="${SESSION//-/}"
batch_count="$(smoke_journal_query "SELECT COUNT(*) FROM container_capture_batches WHERE session = X'${SESSION_HEX}' AND seq = 1;" 2>/dev/null || echo 0)"
event_count="$(smoke_journal_query "SELECT COUNT(*) FROM events WHERE session = X'${SESSION_HEX}' AND seq = 1 AND discriminant = 'ContainerOp';" 2>/dev/null || echo 0)"
if [ "${batch_count:-0}" -ne 0 ] || [ "${event_count:-0}" -ne 0 ]; then
    smoke_fail "refused pull left container state: batches=${batch_count:-0} events=${event_count:-0}"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Cleanup: leave the runner's docker state clean.
SHIT_DURING_UNDO=1 docker rmi "${TARGET_IMAGE}" >/dev/null 2>&1 || true

smoke_log "PASS: docker pull refused before helper/runtime; image remains absent"
