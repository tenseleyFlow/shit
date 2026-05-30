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
# AU23 / DR-CR-51 smoke — `docker pull <image>` journals a Pull event
# carrying the resolved manifest digest (not just the floating tag),
# and `shit show <id>` renders both.
#
# Exercises:
#   1. `shit container-hooks install` PATH-shadows real docker with
#      the AU23-extended wrapper (pre + post phases, vs. the AR03
#      pre-only baseline).
#   2. On `docker pull alpine:3.20`:
#      - Wrapper fires pre-phase: helper classifies as Pull, the
#        pre-handler returns None (digest not yet resolvable), so
#        no event ships. (Negative half of AU23 — pre is
#        intentionally silent.)
#      - Real docker pull runs.
#      - Wrapper fires post-phase: helper runs `docker inspect
#        --format '{{.Id}}'`, ships a ContainerEventReq with
#        verb=Pull and extras["image"]+extras["resolved_id"].
#   3. Daemon journals one CaptureEvent::ContainerOp(Pull) event
#      under the active command window.
#   4. `shit show <session>:<seq>` renders:
#        Pull: alpine:3.20
#        resolved: sha256:<digest>
#
# Skips cleanly when docker isn't available or the runner can't
# reach the daemon socket. Pre-pulls alpine before installing the
# hooks so the BASELINE (non-hooked) pull doesn't get tracked
# spuriously, then `docker rmi`s it (under SHIT_DURING_UNDO=1 so
# the wrapper's pre-handler doesn't journal the rmi either) so the
# hooked pull is the only Pull event in the journal.

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

smoke_log "docker pull ${TARGET_IMAGE} (via wrapper, AU23 post-phase active)"
export SHIT_HOOK_DEBUG=1
if ! SHIT_HELPER_LOG=debug docker pull "${TARGET_IMAGE}" \
    >"${SHIT_SMOKE_TMP}/pull.log" 2>&1; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/pull.log" >&2
    smoke_fail "docker pull ${TARGET_IMAGE} exited non-zero"
fi
smoke_log "pull.log (informational):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/pull.log" >&2 | head -20 || true

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# AU23 load-bearing #1: a ContainerOp event must land in the journal.
smoke_wait_for_event "discriminant = 'ContainerOp'" 1 10

# AU23 load-bearing #2: the event must be a Pull variant with a
# resolved_id that starts with sha256:. Query the journal directly
# via sqlite (cheaper than parsing shit show output).
EVENT_JSON="$(smoke_journal_query "SELECT payload FROM events WHERE discriminant = 'ContainerOp' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo)"
if [ -z "${EVENT_JSON}" ]; then
    smoke_fail "no ContainerOp event payload in journal"
fi
smoke_log "event payload (truncated):"
printf '%s\n' "${EVENT_JSON}" | head -c 400 | sed 's/^/    /' >&2
echo "" >&2

# Payload is postcard-encoded (binary); decode via shit show's JSON
# envelope. AU30's CmdDetail wire serializes each event's kind to
# JSON, so we read it from the CLI instead of parsing sqlite's blob.
CMD_ID="${SESSION}:1"
smoke_log "shit show ${CMD_ID} --json"
SHOW_JSON="$("${SHIT_BIN}" show --ctl-sock "${SHIT_CTL_SOCK}" "${CMD_ID}" --json 2>&1)" || {
    printf '%s\n' "${SHOW_JSON}" | sed 's/^/    /' >&2
    smoke_fail "shit show --json exited non-zero"
}

printf '%s\n' "${SHOW_JSON}" | python3 -c "
import json, sys
env = json.loads(sys.stdin.read())
body = env['data']
events = body['events']
pulls = [e for e in events if e['kind_label'] == 'ContainerOp' and 'Pull' in e['kind_json']]
assert pulls, f'no ContainerOp Pull events; got {[e[\"kind_label\"] for e in events]}'
pull = pulls[0]
payload = json.loads(pull['kind_json'])
op = payload['op']
assert 'Pull' in op, f'expected Pull variant; got {list(op.keys())}'
inner = op['Pull']
assert inner['image'] == '${TARGET_IMAGE}', f'image mismatch: {inner[\"image\"]!r}'
resolved = inner.get('resolved_id')
assert resolved is not None, 'resolved_id is null — AU23 post-phase failed to ship digest'
assert resolved.startswith('sha256:'), f'expected sha256: prefix, got {resolved!r}'
print(f'OK: Pull event with image={inner[\"image\"]} resolved={resolved}')
" || smoke_fail "AU23 journal-shape assertion failed"

# AU23 load-bearing #3: shit show (human) renders both lines.
SHOW_HUMAN="$("${SHIT_BIN}" show --ctl-sock "${SHIT_CTL_SOCK}" "${CMD_ID}" 2>&1)" || {
    printf '%s\n' "${SHOW_HUMAN}" | sed 's/^/    /' >&2
    smoke_fail "shit show (human) exited non-zero"
}
echo "${SHOW_HUMAN}" | grep -qE "Pull: ${TARGET_IMAGE}" \
    || { printf '%s\n' "${SHOW_HUMAN}" | sed 's/^/    /' >&2 ; smoke_fail "expected 'Pull: ${TARGET_IMAGE}' line"; }
echo "${SHOW_HUMAN}" | grep -qE "resolved: sha256:" \
    || { printf '%s\n' "${SHOW_HUMAN}" | sed 's/^/    /' >&2 ; smoke_fail "expected 'resolved: sha256:...' line"; }
smoke_log "human render: OK (Pull + resolved digest both present)"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Cleanup: leave the runner's docker state clean.
SHIT_DURING_UNDO=1 docker rmi "${TARGET_IMAGE}" >/dev/null 2>&1 || true

smoke_log "PASS: docker-pull-digest-journaling-linux (Pull event journaled with digest, shit show renders both)"
