#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cd-undo-fish-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# FreeBSD counterpart of cd-undo-fish-linux, driven through the real
# fish hook. `shit hooks install --shell fish` renders shell/fish.fish
# into the smoke's fish conf.d, and an interactive fish on a pty runs
# `cd` and `shit undo --apply-shell-state`. fish only fires
# fish_preexec/fish_postexec from its interactive reader, hence the
# pty. fish has no precmd queue (DR-30): the undo prints the fish
# snippet instead of queueing it. The smoke checks the hook's frames
# were journaled, the snippet is printed and valid fish, and no queue
# file was written.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-hooks.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-hooks.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: cd-undo-fish-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
command -v fish >/dev/null 2>&1 || smoke_fail "fish not installed (the B04 job installs it)"

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${SHIT_SMOKE_BIN_DIR}/shit-helper" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"

WATCHED="${SHIT_SMOKE_TMP}/watched"
DIFFERENT="${SHIT_SMOKE_TMP}/different"
mkdir -p "${WATCHED}" "${DIFFERENT}"

smoke_install_hook fish
smoke_start_shitd

INPUT="${SHIT_SMOKE_TMP}/fish-input"
cat > "${INPUT}" <<EOF
cd '${DIFFERENT}'
'${SHIT_BIN}' undo --yes --apply-shell-state > '${SHIT_SMOKE_TMP}/undo.log' 2>&1
pwd > '${SHIT_SMOKE_TMP}/result'
exit
EOF

smoke_log "running an interactive fish with the installed hook on a pty"
smoke_run_hooked_shell "${WATCHED}" "${INPUT}" fish -i
smoke_log "shit undo output:"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'")"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
[ "${N_SSD}" -ge 1 ] || smoke_fail "the fish hook journaled no ShellStateDiff for the cd"

grep -q "DR-30" "${SHIT_SMOKE_TMP}/undo.log" \
    || smoke_fail "undo output for the fish session lacks the DR-30 marker"
FISH_SNIPPET="$(grep -F "cd '${WATCHED}'" "${SHIT_SMOKE_TMP}/undo.log" | grep '^cd ' | head -1)"
[ -n "${FISH_SNIPPET}" ] || smoke_fail "undo output lacks the fish snippet (cd '${WATCHED}')"

QUEUE_DIR="${XDG_STATE_HOME}/shit/precmd-queue"
if [ -n "$(find "${QUEUE_DIR}" -type f -size +0 2>/dev/null)" ]; then
    smoke_fail "the fish session wrote a precmd-queue file"
fi

# fish does not drain a queue, so the shell stays where the cd left it.
RESULT_PWD="$(cat "${SHIT_SMOKE_TMP}/result" 2>/dev/null || true)"
[ "${RESULT_PWD}" = "${DIFFERENT}" ] \
    || smoke_fail "pwd after the fish undo is '${RESULT_PWD}', expected ${DIFFERENT} (nothing applies the snippet)"

# The printed snippet is valid fish and does the cd.
RESULT_PWD="$(cd "${DIFFERENT}" && fish --no-config -c "${FISH_SNIPPET}; pwd")"
[ "${RESULT_PWD}" = "${WATCHED}" ] \
    || smoke_fail "fish running the printed snippet landed in '${RESULT_PWD}', expected ${WATCHED}"

smoke_log "PASS: cd-undo-fish-fbsd (the installed fish hook journaled the cd; undo printed a valid fish snippet per DR-30)"
