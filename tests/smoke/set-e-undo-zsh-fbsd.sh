#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: set-e-undo-zsh-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# FreeBSD counterpart of set-e-undo-zsh-linux, driven through the real
# zsh hook (see cd-undo-zsh-fbsd). An interactive zsh runs `setopt
# errexit`, then `shit undo --apply-shell-state`. The hook's option
# snapshot records errexit going on, the undo queues `unsetopt
# errexit`, and the hook's precmd sources it, so the option is off
# again in the same shell.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-hooks.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-hooks.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: set-e-undo-zsh-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
command -v zsh >/dev/null 2>&1 || smoke_fail "zsh not installed (the B04 job installs it)"

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${SHIT_SMOKE_BIN_DIR}/shit-helper" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"

smoke_install_hook zsh
smoke_start_shitd

# Each line is one command line, so one preexec/precmd pair. The
# errexit probe shares the setopt line so it is not a command of its
# own for the undo to pick. `|| true` keeps errexit from ending the
# shell if the undo fails; the result file then shows it.
INPUT="${SHIT_SMOKE_TMP}/zsh-input"
cat > "${INPUT}" <<EOF
setopt errexit; [[ -o errexit ]] && echo on > '${SHIT_SMOKE_TMP}/before'
'${SHIT_BIN}' undo --yes --apply-shell-state > '${SHIT_SMOKE_TMP}/undo.log' 2>&1 || true
if [[ -o errexit ]]; then echo on; else echo off; fi > '${SHIT_SMOKE_TMP}/after'
exit
EOF

smoke_log "running an interactive zsh with the installed hook on a pty"
smoke_run_hooked_shell "${WATCHED}" "${INPUT}" zsh -i
smoke_log "shit undo output:"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

[ "$(cat "${SHIT_SMOKE_TMP}/before" 2>/dev/null)" = on ] \
    || smoke_fail "setopt errexit did not take effect in the hooked zsh"

N_SSD="$(smoke_journal_count "discriminant = 'ShellStateDiff'")"
smoke_log "ShellStateDiff events journaled: ${N_SSD}"
[ "${N_SSD}" -ge 1 ] || smoke_fail "the zsh hook journaled no ShellStateDiff for setopt errexit"

smoke_hook_queue_drained

AFTER="$(cat "${SHIT_SMOKE_TMP}/after" 2>/dev/null || true)"
[ "${AFTER}" = off ] \
    || smoke_fail "the zsh hook did not apply the undo: errexit is '${AFTER}' after undo, expected off"

smoke_log "PASS: set-e-undo-zsh-fbsd (the installed zsh hook journaled setopt errexit and drained unsetopt errexit)"
