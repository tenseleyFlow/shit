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
# AR03.6 / DR-CR-53 fail-closed smoke. Compose-down is outside the
# current atomic capture policy, so the wrapper must exit 125 before
# invoking the real runtime. Both services must remain running, and
# the command must not own a CONFIRMED container capture batch.
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

cleanup_on_exit() {
    local rc=$?
    trap - EXIT
    cleanup_compose
    smoke_cleanup "${rc}"
}
trap cleanup_on_exit EXIT

smoke_log "starting compose project=${PROJECT_NAME} file=${COMPOSE_FILE}"
( cd "${PROJECT_DIR}" && docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" up -d ) \
    >/dev/null 2>&1 \
    || smoke_fail "docker compose up failed"

# Sanity: both services running.
running_count_pre="$(docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps --services --status running 2>/dev/null | wc -l | tr -d '[:space:]')"
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

smoke_log "docker compose -f ${COMPOSE_FILE} -p ${PROJECT_NAME} down (expected fail-closed refusal)"
export SHIT_HOOK_DEBUG=1
set +e
( cd "${PROJECT_DIR}" && docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" down ) \
    >"${SHIT_SMOKE_TMP}/down.log" 2>&1
down_rc=$?
set -e
smoke_log "down.log (expected refusal):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/down.log" >&2
if [ "${down_rc}" -ne 125 ]; then
    smoke_fail "expected docker compose down wrapper to exit 125, got ${down_rc}"
fi

# The real runtime must never have stopped the project.
running_count_after_refusal="$(docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps --services --status running 2>/dev/null | wc -l | tr -d '[:space:]')"
if [ "${running_count_after_refusal}" -lt 2 ]; then
    smoke_log "ps output:"
    docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" ps 2>&1 | sed 's/^/    /' >&2
    smoke_fail "compose project changed despite refusal: ${running_count_after_refusal} service(s) running"
fi
smoke_log "compose project remained intact with ${running_count_after_refusal} services running"

smoke_log "PostExec seq=1 exit=${down_rc}"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code "${down_rc}" --sock "${SHIT_HOOK_SOCK}"

SESSION_HEX="${SESSION//-/}"
if ! actionable_batches="$(smoke_journal_query "SELECT COUNT(*) FROM container_capture_batches WHERE session = X'${SESSION_HEX}' AND seq = 1 AND state IN ('CONFIRMED', 'FINALIZED');" 2>/dev/null)"; then
    smoke_fail "could not query container_capture_batches"
fi
if [ "${actionable_batches:-0}" -ne 0 ]; then
    smoke_fail "unsupported docker compose down produced ${actionable_batches} actionable batch(es)"
fi
smoke_log "actionable container batches: 0"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: docker-compose-down-undo-linux (exit 125; ${PROJECT_NAME} intact; no actionable batch)"
