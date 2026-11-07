#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-docker-capture-fail-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice D — the docker wrapper never blocks the runtime. When the
# helper's pre-capture of `docker rm` fails, the wrapper still runs
# the runtime, and strict mode journals a command-scoped CaptureRefused.
#
# The runtime here is a fake `docker` script: `rm` succeeds and leaves a
# marker file, `inspect` fails, so the helper cannot capture the
# container's configuration. No container engine is needed.
#
#   Phase 1, SHIT_STRICT_CAPTURE=1: the container is removed (marker
#   present, wrapper exit 0), one CaptureRefused row is journaled, and
#   `shit undo` refuses with capture-incomplete.
#
#   Phase 2, flag unset: same command, no new CaptureRefused row, undo
#   prints no capture-incomplete refusal (trunk behavior).
#
# Validate-the-gap: trunk has no strict mode, so the row cannot appear.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-docker-capture-fail-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

FAKE_BIN="${SHIT_SMOKE_TMP}/fake-bin"
MARKER_DIR="${SHIT_SMOKE_TMP}/removed"
mkdir -p "${FAKE_BIN}" "${MARKER_DIR}"
cat > "${FAKE_BIN}/docker" <<EOF
#!/bin/sh
# Fake runtime: rm succeeds, everything else (inspect, commit, save) fails.
case "\$1" in
    rm)
        shift
        for arg in "\$@"; do
            case "\$arg" in -*) ;; *) : > "${MARKER_DIR}/\$arg" ;; esac
        done
        exit 0
        ;;
    *) echo "fake docker: \$1 unavailable" >&2; exit 1 ;;
esac
EOF
chmod +x "${FAKE_BIN}/docker"

install_wrappers() {
    # The installer only wraps tools it finds on PATH.
    export PATH="${FAKE_BIN}:${PATH}"
    "${SHIT_BIN}" container-hooks install > "${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
        || {
            sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
            smoke_fail "container-hooks install failed"
        }
    HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
    [ -x "${HOOKS_BIN}/docker" ] || smoke_fail "docker wrapper missing"
    export PATH="${HOOKS_BIN}:${SHIT_SMOKE_BIN_DIR}:${FAKE_BIN}:${PATH}"
    [ "$(command -v docker)" = "${HOOKS_BIN}/docker" ] \
        || smoke_fail "docker does not resolve to the wrapper: $(command -v docker)"
}

run_phase() {
    local label="$1"
    local victim="victim-${label}"
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "$$" \
        --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"
    sleep 0.5
    set +e
    docker rm -f "${victim}" > "${SHIT_SMOKE_TMP}/${label}.rm.log" 2>&1 < /dev/null
    local rm_rc=$?
    set -e
    [ "${rm_rc}" -eq 0 ] || smoke_fail "[${label}] wrapper exit ${rm_rc}; the runtime must run and its status pass through"
    [ -e "${MARKER_DIR}/${victim}" ] || smoke_fail "[${label}] runtime did not run (no removal marker)"
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    sleep 1.0
    set +e
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/${label}.undo.log" 2>&1
    local rc=$?
    set -e
    smoke_log "[${label}] shit undo --yes exit=${rc}"
    sed 's/^/    undo: /' "${SHIT_SMOKE_TMP}/${label}.undo.log" >&2 || true
    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"
}

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
install_wrappers
run_phase strict
smoke_wait_for_event "discriminant = 'CaptureRefused'" 1 10
STRICT_ROWS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/strict.undo.log" \
    || smoke_fail "strict: undo did not refuse with capture-incomplete"
grep -q "container Rm pre-capture failed" "${SHIT_SMOKE_TMP}/strict.undo.log" \
    || smoke_fail "strict: refusal does not carry the container capture failure"
smoke_stop_shitd

unset SHIT_STRICT_CAPTURE
smoke_start_shitd
run_phase default
DEFAULT_ROWS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
[ "${DEFAULT_ROWS}" -eq "${STRICT_ROWS}" ] \
    || smoke_fail "default: CaptureRefused rows grew from ${STRICT_ROWS} to ${DEFAULT_ROWS} with the flag unset"
if grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/default.undo.log"; then
    smoke_fail "default: undo refused with capture-incomplete although strict mode is off"
fi

smoke_log "PASS: strict-docker-capture-fail-linux (runtime ran; strict refused, default proceeded)"
