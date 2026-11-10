#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: set-e-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# The bash hook installed by `shit hooks install --shell bash` runs in an
# interactive bash on a pty. The shell runs `set -o errexit`, then `shit
# undo --apply-shell-state`. The hook's option snapshot records errexit
# going on, the undo queues `set +o errexit`, and the hook's
# PROMPT_COMMAND sources it, so the option is off again in the same
# shell.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-hooks.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-hooks.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: set-e-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${SHIT_SMOKE_BIN_DIR}/shit-helper" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"

WATCHED="${SHIT_SMOKE_TMP}/watched"
DIFFERENT="${SHIT_SMOKE_TMP}/different"
mkdir -p "${WATCHED}" "${DIFFERENT}"

smoke_install_hook bash
smoke_start_shitd

INPUT="${SHIT_SMOKE_TMP}/bash-input"
cat > "${INPUT}" <<EOF
set -o errexit
'${SHIT_BIN}' undo --yes --apply-shell-state > '${SHIT_SMOKE_TMP}/undo.log' 2>&1 || true
if [[ -o errexit ]]; then echo on; else echo off; fi > '${SHIT_SMOKE_TMP}/after'
exit
EOF

smoke_log "running an interactive bash with the installed hook on a pty"
smoke_run_hooked_shell "${WATCHED}" "${INPUT}" bash -i
smoke_log "shit undo output:"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'")"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
[ "${N_SSD}" -ge 1 ] || smoke_fail "the bash hook journaled no ShellStateDiff for set -o errexit"

smoke_hook_queue_drained

AFTER="$(cat "${SHIT_SMOKE_TMP}/after" 2>/dev/null || true)"
[ "${AFTER}" = off ] \
    || smoke_fail "the bash hook did not apply the undo: errexit is '${AFTER}' after undo, expected off"

smoke_log "PASS: set-e-undo-linux (the installed bash hook journaled set -o errexit and drained the undo)"
