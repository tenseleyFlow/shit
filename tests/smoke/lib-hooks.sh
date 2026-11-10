# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Helpers for smokes that drive the real shell hooks. Each smoke
# sources `lib.sh` first and `lib-hooks.sh` next:
#
#   source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
#   source "${SHIT_REPO_ROOT}/tests/smoke/lib-hooks.sh"
#
# `smoke_install_hook <shell>` installs the hook with `shit hooks
# install` into a scratch HOME (SMOKE_HOOK_HOME) and the smoke's
# XDG_CONFIG_HOME, then checks the installed file is the repo's
# shell/ template with only the two placeholders filled in. The smoke
# then starts the shell with HOME (and ZDOTDIR for zsh) pointing at
# SMOKE_HOOK_HOME, so the shell sources that file the way a user's
# shell would.

# pkg installs zsh and fish under /usr/local/bin, which a minimal CI
# PATH may not hold.
case "$(uname -s)" in
    FreeBSD|NetBSD|OpenBSD|DragonFly)
        export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
        ;;
esac

SMOKE_HOOK_HOME="${SHIT_SMOKE_TMP}/home"

smoke_install_hook() {
    local shell="$1" template hook
    case "${shell}" in
        zsh)
            template="${SHIT_REPO_ROOT}/shell/zsh.sh"
            hook="${XDG_CONFIG_HOME}/shit/hook.zsh"
            ;;
        fish)
            template="${SHIT_REPO_ROOT}/shell/fish.fish"
            hook="${XDG_CONFIG_HOME}/fish/conf.d/shit.fish"
            ;;
        bash)
            template="${SHIT_REPO_ROOT}/shell/bash.sh"
            hook="${XDG_CONFIG_HOME}/shit/hook.bash"
            ;;
        *) smoke_fail "smoke_install_hook: unknown shell ${shell}" ;;
    esac
    mkdir -p "${SMOKE_HOOK_HOME}"
    HOME="${SMOKE_HOOK_HOME}" "${SHIT_SMOKE_BIN_DIR}/shit" hooks install --shell "${shell}" \
        > "${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
        || smoke_fail "shit hooks install --shell ${shell} failed: $(cat "${SHIT_SMOKE_TMP}/hooks-install.log")"
    [ -f "${hook}" ] || smoke_fail "${shell} hook not installed at ${hook}"
    # The installer writes its own resolved path; take it from the file.
    local bin_line bin
    bin_line="$(grep -m1 -E '^(_SHIT_BIN=|set -g _SHIT_BIN )' "${hook}" || true)"
    bin="${bin_line#*\"}"
    bin="${bin%\"}"
    [ -x "${bin}" ] || smoke_fail "installed ${shell} hook names no runnable shit binary (${bin_line})"
    if ! sed -e "s|@@SHIT_BIN@@|${bin}|g" -e "s|@@SHIT_SOCK@@|${SHIT_HOOK_SOCK}|g" "${template}" \
        | cmp -s - "${hook}"; then
        smoke_fail "installed ${shell} hook differs from ${template} with its placeholders filled in"
    fi
    if [ "${shell}" = zsh ]; then
        # Skip /etc/zsh/zshrc: on Ubuntu it runs compinit, which asks a
        # question about insecure directories on the CI runner and eats
        # the typed lines.
        printf 'unsetopt global_rcs\n' > "${SMOKE_HOOK_HOME}/.zshenv"
    fi
    if [ "${shell}" != fish ]; then
        grep -qF "source ${hook}" "${SMOKE_HOOK_HOME}/.${shell}rc" \
            || smoke_fail "~/.${shell}rc does not source ${hook}"
    fi
    smoke_log "installed the ${shell} hook from ${template} at ${hook}"
}

# smoke_run_hooked_shell <cwd> <input-file> <shell> [args...]
# Start the shell in <cwd> on a pty (tests/smoke/pty-drive.py) with
# HOME and ZDOTDIR at SMOKE_HOOK_HOME, and type each line of
# <input-file>. A pty is what fish needs to fire its preexec and
# postexec events, and it gives the hooks a real `tty`. The session's
# output goes to $SHIT_SMOKE_TMP/<shell>.out.
smoke_run_hooked_shell() {
    local cwd="$1" input="$2" shell="$3" rc=0
    shift 2
    local out="${SHIT_SMOKE_TMP}/${shell}.out"
    (cd "${cwd}" && HOME="${SMOKE_HOOK_HOME}" ZDOTDIR="${SMOKE_HOOK_HOME}" TERM=xterm \
        python3 "${SHIT_REPO_ROOT}/tests/smoke/pty-drive.py" "${input}" "$@" > "${out}" 2>&1) \
        || rc=$?
    if [ "${rc}" -ne 0 ]; then
        smoke_log "${shell} session output:"
        tr -d '\033' < "${out}" | tail -20 | sed 's/^/    /' >&2
        smoke_fail "${shell} session exited ${rc}"
    fi
}

# The hook drains its session's precmd-queue file before each prompt.
# After the shell exits, exactly one queue file exists and it is empty.
smoke_hook_queue_drained() {
    local dir="${XDG_STATE_HOME}/shit/precmd-queue" files
    files="$(ls "${dir}" 2>/dev/null | wc -l | tr -d ' ')"
    [ "${files}" = 1 ] || smoke_fail "expected one precmd-queue file in ${dir}, found ${files}"
    local q
    q="${dir}/$(ls "${dir}")"
    [ ! -s "${q}" ] || smoke_fail "the hook did not drain ${q}: $(cat "${q}")"
}
