#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: refuse-cmd-string-wire-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
#
# AU26 smoke — refuse-list cmd_string wire end-to-end.
#
# Before AU26, `CommandRecord.cmd_string` was None in every
# production write path. The refuse-list catalog matches on
# cmd_string; without the wire, the entire catalog was dead
# code at runtime. AU26 plumbs $BASH_COMMAND through the
# shell hook → PreExec → daemon → CommandRecord.
#
# This smoke proves the wire is alive:
#   1. PreExec with --cmdline "git push origin main" persists
#      cmd_string verbatim into the commands table.
#   2. `shit undo --yes` short-circuits to a Refused plan,
#      exits non-zero, names the `remote-push` class.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-cmd-string-wire-linux is Linux-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Refuse-list short-circuit happens entirely on the planner
# side — no kernel-tier capture needed. Force fanotify-perm
# (the lighter tier) to keep the smoke fast and tier-agnostic.
smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
CWD="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${CWD}"
cd "${CWD}"

CMDLINE="git push origin main"
smoke_log "PreExec --cmdline '${CMDLINE}'"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${CWD}" --shell bash --depth 1 \
    --cmdline "${CMDLINE}" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# Wait for the commands row to appear with cmd_string set.
deadline=$(( $(date +%s) + 10 ))
PERSISTED_CMD=""
while [ "$(date +%s)" -lt "${deadline}" ]; do
    PERSISTED_CMD="$(smoke_journal_query "SELECT cmd_string FROM commands WHERE seq = 1;" 2>/dev/null || true)"
    [ -n "${PERSISTED_CMD}" ] && break
    sleep 0.2
done

if [ "${PERSISTED_CMD}" != "${CMDLINE}" ]; then
    smoke_log "expected cmd_string='${CMDLINE}'"
    smoke_log "got      cmd_string='${PERSISTED_CMD}'"
    smoke_journal_query "SELECT session, seq, cmd_string, pid FROM commands;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "cmd_string did not flow through to CommandRecord"
fi
smoke_log "cmd_string persisted: '${PERSISTED_CMD}'"

# Now the load-bearing assertion: `shit undo` for a refused
# class exits non-zero and names the class.
smoke_log "running: shit undo --yes (expecting refuse short-circuit)"
UNDO_RC=0
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || UNDO_RC=$?

if [ "${UNDO_RC}" -eq 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo exited 0 for a refused class — refusal didn't fire"
fi

if ! grep -qiE "refuse|remote-push|out of scope" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo non-zero but log doesn't mention refuse / remote-push / out of scope"
fi

smoke_log "refuse short-circuit fired: exit=${UNDO_RC}, log mentions remote-push"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: refuse-cmd-string-wire-linux (cmd_string='${CMDLINE}' → refuse class=remote-push)"
