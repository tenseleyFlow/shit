# shit shell hook — bash
# Sourced from the user's .bashrc. Spec: .docs/sprints/S01-shell-integration.md.
#
# This script wires the bash DEBUG trap and PROMPT_COMMAND so each interactive
# command is bracketed by `shit hook-send pre-exec` / `shit hook-send post-exec`.
# Heredoc-substitutable placeholders:
#   @@SHIT_BIN@@       absolute path to the `shit` binary at install time
#   @@SHIT_SOCK@@      socket path the CLI should send to
#
# Per-command CLI invocation is the v1 transport (~3-5ms). Persistent-fd
# forwarder follow-up is tracked in S01's "Pitfalls encountered".

# Guard against re-source.
[[ -n "${_SHIT_BASH_LOADED:-}" ]] && return 0
export _SHIT_BASH_LOADED=1

# User-level disable.
[[ -n "${SHIT_DISABLE:-}" ]] && return 0

_SHIT_BIN="@@SHIT_BIN@@"
_SHIT_SOCK="@@SHIT_SOCK@@"

# Per-session uuid + monotonic command counter.
if [[ -r /proc/sys/kernel/random/uuid ]]; then
    _SHIT_SESSION="$(< /proc/sys/kernel/random/uuid)"
else
    _SHIT_SESSION="$("$_SHIT_BIN" internal new-uuid 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")"
fi
export _SHIT_SESSION
export _SHIT_SEQ=0

__shit_send_open() {
    "$_SHIT_BIN" hook-send session-open \
        --session "$_SHIT_SESSION" \
        --pid "$$" \
        --shell bash \
        --tty "$(tty 2>/dev/null || echo unknown)" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
}

__shit_pre() {
    # Skip when inside subshells, function calls, or sourced files —
    # the user didn't type those, the parent did.
    [[ -n "${SHIT_DISABLE:-}" ]] && return
    [[ "${BASH_SUBSHELL:-0}" -gt 0 ]] && return
    [[ -n "${COMP_LINE:-}" ]] && return    # tab-completion fires DEBUG too
    [[ "${BASH_COMMAND}" == "__shit_"* ]] && return
    _SHIT_SEQ=$((_SHIT_SEQ + 1))
    "$_SHIT_BIN" hook-send pre-exec \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pid "$$" \
        --cwd "$PWD" \
        --shell bash \
        --depth "${SHLVL:-1}" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
    # AR06.1/.2/.3 — shell-state snapshot: pwd + set-opts +
    # aliases. Functions (AR06.4) land in a follow-up. We pipe
    # opts + aliases over stdin as NUL-separated records since
    # alias expansions can contain newlines / tabs / pipes.
    __shit_collect_shell_state | "$_SHIT_BIN" hook-send pre-exec-shell-state \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pwd "$PWD" \
        --sock "$_SHIT_SOCK" \
        --from-stdin \
        >/dev/null 2>&1 || true
    # AR06.5 — synchronous pre-stash for stream-redirect targets in
    # the about-to-run command. Runs AFTER pre-exec so the daemon
    # has the command record by the time the FilePreImage event
    # arrives, and BEFORE bash's open(O_TRUNC) so the original
    # content gets captured. The shit subcommand parses
    # $BASH_COMMAND, fast-paths no-redirect lines (no socket touch),
    # and degrades quietly on daemon-down. Per-target errors land
    # in our stderr at debug volume but never fail the hook.
    case "${BASH_COMMAND}" in
        *">"*|*"|"*|*"of="*)
            "$_SHIT_BIN" hook-send pre-exec-redirects \
                --session "$_SHIT_SESSION" \
                --seq "$_SHIT_SEQ" \
                --cmdline "$BASH_COMMAND" \
                --sock "$_SHIT_SOCK" \
                >/dev/null 2>&1 || true
            ;;
    esac
    # S15: opt-in env tracking. Off by default until daemon ingestion
    # lands. `env -0` is GNU coreutils + BSD `env` ≥2024; on legacy
    # systems users get a fallback via `printenv` (not -0-safe for
    # values with newlines, but rare enough for v1).
    if [[ -n "${SHIT_TRACK_ENV:-}" ]]; then
        env -0 2>/dev/null | "$_SHIT_BIN" hook-send pre-exec-env \
            --session "$_SHIT_SESSION" \
            --seq "$_SHIT_SEQ" \
            --sock "$_SHIT_SOCK" \
            >/dev/null 2>&1 || true
    fi
}

__shit_post() {
    local rc=$?
    [[ -n "${SHIT_DISABLE:-}" ]] && return $rc
    "$_SHIT_BIN" hook-send post-exec \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --exit-code "$rc" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
    # AR06.1/.2/.3 — post-command shell-state snapshot.
    __shit_collect_shell_state | "$_SHIT_BIN" hook-send post-exec-shell-state \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pwd "$PWD" \
        --sock "$_SHIT_SOCK" \
        --from-stdin \
        >/dev/null 2>&1 || true
    # AR06.1 / DR-CR-50 — drain the precmd-queue. `shit undo
    # --apply-shell-state` writes shell snippets here; we source
    # + truncate so they run before the next prompt. The queue
    # path is keyed by session-uuid so concurrent shells stay
    # isolated.
    __shit_drain_precmd_queue
    if [[ -n "${SHIT_TRACK_ENV:-}" ]]; then
        env -0 2>/dev/null | "$_SHIT_BIN" hook-send post-exec-env \
            --session "$_SHIT_SESSION" \
            --seq "$_SHIT_SEQ" \
            --sock "$_SHIT_SOCK" \
            >/dev/null 2>&1 || true
    fi
    return $rc
}

__shit_close() {
    "$_SHIT_BIN" hook-send session-close \
        --session "$_SHIT_SESSION" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
}

# AR06.2/.3 — emit NUL-separated shell-state records on stdout
# for the `shit hook-send pre/post-exec-shell-state --from-stdin`
# subcommand to read. Format:
#   OPT\t<name>\t<value>\0      (set -o lines: name + on/off)
#   ALIAS\t<name>\t<value>\0    (alias values are the raw
#                                expansion, single-quotes stripped
#                                and '\\''-unescaped back to ')
# Functions (AR06.4) deferred; this helper is forward-compat
# (the daemon ignores unknown record kinds).
__shit_collect_shell_state() {
    # set -o output is line-oriented: "name<spaces>value" — bash's
    # builtin (not /usr/bin/set, which doesn't exist).
    set -o 2>/dev/null | while read -r __shit_name __shit_value; do
        [[ -n "$__shit_name" ]] && printf 'OPT\t%s\t%s\0' "$__shit_name" "$__shit_value"
    done
    # alias output: lines like  alias NAME='VALUE'
    # bash escapes embedded ' as '\'' inside the value's outer
    # quotes; un-escape here so the daemon stores the literal.
    alias 2>/dev/null | while IFS= read -r __shit_line; do
        [[ "$__shit_line" != alias\ * ]] && continue
        __shit_line=${__shit_line#alias }
        local __shit_name=${__shit_line%%=*}
        local __shit_value=${__shit_line#*=}
        # Strip outer single-quotes (always present in bash's
        # default `alias` output).
        if [[ "$__shit_value" == \'*\' ]]; then
            __shit_value=${__shit_value#\'}
            __shit_value=${__shit_value%\'}
            __shit_value=${__shit_value//\'\\\'\'/\'}
        fi
        printf 'ALIAS\t%s\t%s\0' "$__shit_name" "$__shit_value"
    done
}

# AR06.1 / DR-CR-50 — drain the per-session precmd queue. The
# orchestrator's SystemShellStateRunner appends shell snippets to
# `$XDG_STATE_HOME/shit/precmd-queue/<session-uuid>`; on every
# prompt cycle we source then truncate, so each snippet runs
# exactly once.
__shit_drain_precmd_queue() {
    local _q="${XDG_STATE_HOME:-$HOME/.local/state}/shit/precmd-queue/$_SHIT_SESSION"
    if [[ -s "$_q" ]]; then
        # shellcheck disable=SC1090
        source "$_q" 2>/dev/null || true
        : > "$_q"
    fi
}

trap '__shit_pre' DEBUG
PROMPT_COMMAND="__shit_post${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
trap '__shit_close' EXIT

__shit_send_open

# C05: per-command auto-injection of the install-prefix shim.
#
# Each wrapper below asks `shit auto-inject-install-env --shell prefix`
# whether the about-to-run argv matches an install pattern (make
# install, cargo install --path/--force/--root, pip install --user,
# python setup.py install, etc.). If yes, the helper emits a
# single-line POSIX prefix of the form:
#
#   LD_PRELOAD='/path' SHIT_PRELOAD_ACTIVE='1' SHIT_DAEMON_SOCK='/path'
#
# The wrapper `eval`s that prefix directly in front of `command
# <name> "$@"`, so the shim env only scopes to the user's one
# invocation. If the helper exits with empty stdout (no match), the
# command runs unhooked.
#
# Set SHIT_DISABLE=1 to bypass auto-injection.

__shit_install_wrap() {
    local _cmd="$1"
    shift
    if [[ -n "${SHIT_DISABLE:-}" ]] || [[ -n "${SHIT_PRELOAD_ACTIVE:-}" ]]; then
        # Already inside an active shim invocation or user has
        # disabled — fall through.
        command "$_cmd" "$@"
        return $?
    fi
    local _prefix
    _prefix="$("$_SHIT_BIN" auto-inject-install-env --shell prefix -- "$_cmd" "$@" 2>/dev/null)"
    if [[ -n "$_prefix" ]]; then
        eval "$_prefix command \"\$_cmd\" \"\$@\""
    else
        command "$_cmd" "$@"
    fi
}

make()    { __shit_install_wrap make    "$@"; }
gmake()   { __shit_install_wrap gmake   "$@"; }
cmake()   { __shit_install_wrap cmake   "$@"; }
ninja()   { __shit_install_wrap ninja   "$@"; }
meson()   { __shit_install_wrap meson   "$@"; }
cargo()   { __shit_install_wrap cargo   "$@"; }
pip()     { __shit_install_wrap pip     "$@"; }
pip3()    { __shit_install_wrap pip3    "$@"; }
python()  { __shit_install_wrap python  "$@"; }
python3() { __shit_install_wrap python3 "$@"; }
