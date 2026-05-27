#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: docker-compose-down-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR03.6 / DR-CR-53 smoke — `docker compose down; shit undo` brings
# the project back up via `docker compose up -d`.
#
# Exercises:
#   1. Helper's prepare_compose_down: from a `docker compose down`
#      invocation through the docker-wrapper (v2 plugin form), packs
#      project + compose_file into extras. The classifier handles
#      both `docker compose ...` (via the docker wrapper's fall-
#      through to classify_compose_argv) and `docker-compose ...`
#      (v1 standalone via docker-compose-wrapper).
#   2. Daemon container_track handler builds ContainerOp::ComposeDown
#      from the extras.
#   3. Executor's apply_compose_down runs `docker compose -f <file>
#      -p <project> up -d`.
#   4. Both services come back up post-undo.
#
# Uses the v2 plugin form via docker-wrapper (which is what ships on
# ubuntu-24.04). Tests the docker-compose-wrapper path separately
# is deferred (would require installing the standalone v1 binary).
#
# Skips cleanly when docker / docker compose isn't available.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: docker-compose-down-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
    smoke_log "SKIP: docker not on PATH"
    exit 0
fi
if ! docker version >/dev/null 2>&1; then
    smoke_log "SKIP: 'docker version' failed (daemon unreachable)"
    exit 0
fi
if ! docker compose version >/dev/null 2>&1; then
    smoke_log "SKIP: 'docker compose' plugin not available"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Stage a 2-service compose project in an isolated dir so the
# project-name defaults to something predictable.
PROJECT_DIR="${SHIT_SMOKE_TMP}/compose-project"
mkdir -p "${PROJECT_DIR}"
PROJECT_NAME="$(basename "${PROJECT_DIR}" | tr '[:upper:]' '[:lower:]')"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"

cat > "${COMPOSE_FILE}" <<EOF
services:
  web:
    image: busybox:1.36
    command: sh -c "while sleep 60; do :; done"
  db:
    image: busybox:1.36
    command: sh -c "while sleep 60; do :; done"
EOF

smoke_log "pulling busybox:1.36"
docker pull busybox:1.36 >/dev/null 2>&1 || smoke_fail "docker pull busybox failed"

cleanup_compose() {
    SHIT_DURING_UNDO=1 docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" down >/dev/null 2>&1 || true
}
trap 'cleanup_compose' EXIT

smoke_log "starting compose project=${PROJECT_NAME} file=${COMPOSE_FILE}"
( cd "${PROJECT_DIR}" && docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" up -d ) \
    >/dev/null 2>&1 \
    || smoke_fail "docker compose up failed"

# Sanity: both services running.
running_count_pre="$(docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps --status running --format json 2>/dev/null | grep -c '"State"' || true)"
if [ "${running_count_pre}" -lt 2 ]; then
    smoke_fail "expected 2 running services pre-down, got ${running_count_pre}"
fi
smoke_log "pre-down: ${running_count_pre} services running"

smoke_start_shitd

smoke_log "installing container-hooks"
"${SHIT_BIN}" container-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || smoke_fail "container-hooks install failed"
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper missing"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

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
    --cwd "${PROJECT_DIR}" --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "docker compose -f ${COMPOSE_FILE} -p ${PROJECT_NAME} down (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! ( cd "${PROJECT_DIR}" && docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" down ) \
    >"${SHIT_SMOKE_TMP}/down.log" 2>&1; then
    smoke_log "down.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/down.log" >&2
    smoke_fail "docker compose down exited non-zero"
fi
smoke_log "down.log (informational; down succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/down.log" >&2

# Confirm services are gone.
running_count_post_down="$(docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps --status running --format json 2>/dev/null | grep -c '"State"' || true)"
if [ "${running_count_post_down}" -ne 0 ]; then
    smoke_fail "expected 0 running services post-down, got ${running_count_post_down}"
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

# Post-undo: both services back up.
running_count_post_undo="$(docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps --status running --format json 2>/dev/null | grep -c '"State"' || true)"
if [ "${running_count_post_undo}" -lt 2 ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "ps output:"
    docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps 2>&1 | sed 's/^/    /' >&2
    smoke_fail "expected 2 running services post-undo, got ${running_count_post_undo}"
fi
smoke_log "post-undo: ${running_count_post_undo} services running (compose project restored)"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: docker-compose-down-undo-linux (${PROJECT_NAME} restored via shit undo)"
