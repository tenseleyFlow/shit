#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cd-undo-zsh-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# FreeBSD counterpart of cd-undo-zsh-linux, driven through the real
# zsh hook. `shit hooks install --shell zsh` renders shell/zsh.sh into
# the smoke's config dir and sources it from a scratch .zshrc. An
# interactive zsh then runs `cd`, `shit undo --apply-shell-state` and
# `pwd`. The hook's preexec/precmd send every frame, and its precmd
# drains the precmd queue, so the final `pwd` in the same shell must be
# back where the `cd` started.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-hooks.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-hooks.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: cd-undo-zsh-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
command -v zsh >/dev/null 2>&1 || smoke_fail "zsh not installed (the B04 job installs it)"

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${SHIT_SMOKE_BIN_DIR}/shit-helper" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"

WATCHED="${SHIT_SMOKE_TMP}/watched"
DIFFERENT="${SHIT_SMOKE_TMP}/different"
mkdir -p "${WATCHED}" "${DIFFERENT}"

smoke_install_hook zsh
smoke_start_shitd

INPUT="${SHIT_SMOKE_TMP}/zsh-input"
cat > "${INPUT}" <<EOF
cd '${DIFFERENT}'
'${SHIT_BIN}' undo --yes --apply-shell-state > '${SHIT_SMOKE_TMP}/undo.log' 2>&1
pwd > '${SHIT_SMOKE_TMP}/result'
exit
EOF

smoke_log "running an interactive zsh with the installed hook on a pty"
smoke_run_hooked_shell "${WATCHED}" "${INPUT}" zsh -i
smoke_log "shit undo output:"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'")"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
[ "${N_SSD}" -ge 1 ] || smoke_fail "the zsh hook journaled no ShellStateDiff for the cd"

smoke_hook_queue_drained

RESULT_PWD="$(cat "${SHIT_SMOKE_TMP}/result" 2>/dev/null || true)"
if [ "${RESULT_PWD}" != "${WATCHED}" ]; then
    smoke_fail "the zsh hook did not apply the undo: pwd after undo is '${RESULT_PWD}', expected ${WATCHED}"
fi

smoke_log "PASS: cd-undo-zsh-fbsd (the installed zsh hook journaled the cd and drained the undo snippet)"
