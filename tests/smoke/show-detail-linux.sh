#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: show-detail-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 120
#
# AU30 — end-to-end exercise of the `shit show <id>` command-detail
# endpoint. Validates the wire (CtlRequest::CmdDetail →
# CmdDetailBody) and the renderer (`render::cmd_detail::render`).
#
# Flow:
#   1. shitd up; no helper needed (capture-tier-independent — this
#      smoke gates on the command record + plan-summary, not file
#      events).
#   2. Open a session, fire PreExec (which lands a CommandRecord),
#      do a no-op workload, fire PostExec.
#   3. `shit show <session>:1` — assert the rendered header has
#      cmd_string, cwd, shell, plan line.
#   4. `shit show <session>:1 --json` — assert JSON envelope has
#      `cmd_string` and `events_total` keys.
#   5. `shit show <bogus-uuid>:99` — assert exit code non-zero and
#      the error mentions "no captured command".

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: show-detail-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing"

# Disable helper spawn — this smoke doesn't need the capture tier.
# Cuts ~5s off the boot and keeps the failure surface focused on
# the ctl wire + renderer.
export SHIT_HELPER_DISABLED=1

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash \
    --cmdline 'echo au30-show-detail' \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# Give the daemon a moment to persist the CommandRecord.
sleep 0.5

CMD_ID="${SESSION}:1"

smoke_log "shit show ${CMD_ID}"
SHOW_OUT="$("${SHIT_BIN}" show --ctl-sock "${SHIT_CTL_SOCK}" "${CMD_ID}" 2>&1)" || {
    smoke_log "show output:"
    printf '%s\n' "${SHOW_OUT}" | sed 's/^/    /' >&2
    smoke_fail "shit show exited non-zero"
}

printf '%s\n' "${SHOW_OUT}" | sed 's/^/    show: /' >&2

# Header assertions — these are what the AU30 wire delivers from
# the CommandRecord regardless of capture-tier state.
echo "${SHOW_OUT}" | grep -q "shit show ${CMD_ID}" \
    || smoke_fail "header line missing CMD_ID"
echo "${SHOW_OUT}" | grep -q "cmd:.*au30-show-detail" \
    || smoke_fail "cmd_string not rendered"
echo "${SHOW_OUT}" | grep -q "cwd:.*${SCRATCH}" \
    || smoke_fail "cwd not rendered"
echo "${SHOW_OUT}" | grep -q "shell:.*bash" \
    || smoke_fail "shell line not rendered"
echo "${SHOW_OUT}" | grep -qE "^plan: " \
    || smoke_fail "plan section missing"
echo "${SHOW_OUT}" | grep -qE "^events \(" \
    || smoke_fail "events section missing"
smoke_log "human render: OK"

# JSON envelope.
JSON_OUT="$("${SHIT_BIN}" show --ctl-sock "${SHIT_CTL_SOCK}" "${CMD_ID}" --json 2>&1)" || {
    smoke_log "json output:"
    printf '%s\n' "${JSON_OUT}" | sed 's/^/    /' >&2
    smoke_fail "shit show --json exited non-zero"
}
printf '%s\n' "${JSON_OUT}" | python3 -c "
import json, sys
env = json.loads(sys.stdin.read())
# write_json wraps in {schema_version, data: body}; peel one layer.
assert 'schema_version' in env, 'envelope missing schema_version'
body = env['data']
assert body['cmd_string'] == 'echo au30-show-detail', f'cmd_string mismatch: {body.get(\"cmd_string\")!r}'
assert 'events_total' in body, 'events_total field missing'
assert 'plan_summary' in body, 'plan_summary field missing'
assert isinstance(body['plan_summary']['tier_counts'], dict)
print('json shape OK')
" || smoke_fail "JSON envelope shape wrong"
smoke_log "JSON render: OK"

# Negative — bogus id returns CmdNotFound and the CLI exits non-zero.
set +e
NOT_FOUND_OUT="$("${SHIT_BIN}" show --ctl-sock "${SHIT_CTL_SOCK}" "00000000-0000-0000-0000-000000000000:99" 2>&1)"
NOT_FOUND_RC=$?
set -e
if [ "${NOT_FOUND_RC}" = 0 ]; then
    smoke_fail "expected non-zero exit for unknown id; got 0"
fi
if ! echo "${NOT_FOUND_OUT}" | grep -q "no captured command"; then
    smoke_log "not-found output:"
    printf '%s\n' "${NOT_FOUND_OUT}" | sed 's/^/    /' >&2
    smoke_fail "expected 'no captured command' error message"
fi
smoke_log "negative path: OK (rc=${NOT_FOUND_RC})"

smoke_log "PASS: show-detail-linux (header + plan + events + JSON + negative)"
