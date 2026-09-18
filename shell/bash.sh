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

# Wrapper-based capture (container/package/service/etc.) lives here. Keep the
# prepend idempotent when the hook is sourced more than once and export it so
# child commands actually resolve the installed wrappers.
_SHIT_HOOK_BIN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/shit/bin"
case ":${PATH:-}:" in
    *":$_SHIT_HOOK_BIN_DIR:"*) ;;
    *) export PATH="$_SHIT_HOOK_BIN_DIR${PATH:+:$PATH}" ;;
esac

# Per-session uuid + monotonic command counter.
if [[ -r /proc/sys/kernel/random/uuid ]]; then
    _SHIT_SESSION="$(< /proc/sys/kernel/random/uuid)"
else
    _SHIT_SESSION="$("$_SHIT_BIN" internal new-uuid 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")"
fi
export _SHIT_SESSION
export _SHIT_SEQ=0
# The command may be closed only when every pre-command companion capture was
# delivered to the daemon.  A hook transport failure is fail-open for the
# user's command, but fail-closed for undo: leaving the durable command row
# unfinished is safer than publishing an apparently complete partial capture.
_SHIT_PREPARED_SEQ=-1
_SHIT_ENV_TRACK_SEQ=-1
_SHIT_FAILED_SEQ=-1
_SHIT_FAILED_RC=125
_SHIT_FAILED_RC_SET=0
_SHIT_FAILED_DETAIL=""

__shit_send_open() {
    "$_SHIT_BIN" hook-send session-open \
        --session "$_SHIT_SESSION" \
        --pid "$$" \
        --shell bash \
        --tty "$(tty 2>/dev/null || echo unknown)" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
}

# Record a companion-capture failure without suppressing the user's command.
# The matching command row stays open until __shit_refuse_and_close_failed gets
# a synchronous acknowledgement that a command-wide refusal is durable and the
# normal daemon lifecycle owner has closed the row.
__shit_mark_failed() {
    _SHIT_FAILED_SEQ=$_SHIT_SEQ
    _SHIT_FAILED_DETAIL=$1
    _SHIT_FAILED_RC=${2:-125}
    _SHIT_FAILED_RC_SET=${3:-0}
    _SHIT_PREPARED_SEQ=-1
}

__shit_refuse_and_close_failed() {
    [[ "$_SHIT_FAILED_SEQ" -ge 0 ]] || return 0
    if "$_SHIT_BIN" hook-send refuse-and-close \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_FAILED_SEQ" \
        --exit-code "$_SHIT_FAILED_RC" \
        --detail "$_SHIT_FAILED_DETAIL" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1; then
        _SHIT_FAILED_SEQ=-1
        _SHIT_FAILED_RC=125
        _SHIT_FAILED_RC_SET=0
        _SHIT_FAILED_DETAIL=""
        _SHIT_PREPARED_SEQ=-1
        _SHIT_ENV_TRACK_SEQ=-1
        return 0
    fi
    return 1
}

__shit_pre() {
    # Skip when inside subshells, function calls, or sourced files —
    # the user didn't type those, the parent did.
    [[ "${BASH_SUBSHELL:-0}" -gt 0 ]] && return
    [[ -n "${COMP_LINE:-}" ]] && return    # tab-completion fires DEBUG too
    [[ "${BASH_COMMAND}" == "__shit_"* ]] && return
    # Never overlap command identities. If the previous row could not be
    # closed safely, retry it before allocating a new sequence. A failed retry
    # leaves this user command intentionally untracked.
    if [[ "$_SHIT_FAILED_SEQ" -ge 0 ]] && ! __shit_refuse_and_close_failed; then
        return 0
    fi
    [[ -n "${SHIT_DISABLE:-}" ]] && return
    _SHIT_SEQ=$((_SHIT_SEQ + 1))
    _SHIT_PREPARED_SEQ=-1
    _SHIT_ENV_TRACK_SEQ=-1
    if ! "$_SHIT_BIN" hook-send pre-exec \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pid "$$" \
        --cwd "$PWD" \
        --shell bash \
        --depth "${SHLVL:-1}" \
        --sock "$_SHIT_SOCK" \
        --cmdline "$BASH_COMMAND" \
        >/dev/null 2>&1; then
        return 0
    fi
    # AR06.1/.2/.3 — shell-state snapshot: pwd + set-opts +
    # aliases. Functions (AR06.4) land in a follow-up. We pipe
    # opts + aliases over stdin as NUL-separated records since
    # alias expansions can contain newlines / tabs / pipes.
    if ! __shit_collect_shell_state | "$_SHIT_BIN" hook-send pre-exec-shell-state \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pwd "$PWD" \
        --sock "$_SHIT_SOCK" \
        --from-stdin \
        >/dev/null 2>&1; then
        __shit_mark_failed "pre-command shell-state capture was not delivered" 125 0
        return 0
    fi
    # AR06.5 — synchronous pre-stash for stream-redirect targets in
    # the about-to-run command. Runs AFTER pre-exec so the daemon
    # has the command record by the time the FilePreImage event
    # arrives, and BEFORE bash's open(O_TRUNC) so the original
    # content gets captured. The shit subcommand parses
    # $BASH_COMMAND, fast-paths no-redirect lines (no socket touch),
    # Per-target errors are safe only after a durable command refusal;
    # transport/top-level failures leave this sequence unprepared.
    case "${BASH_COMMAND}" in
        *">"*|*"|"*|*"of="*)
            if ! "$_SHIT_BIN" hook-send pre-exec-redirects \
                --session "$_SHIT_SESSION" \
                --seq "$_SHIT_SEQ" \
                --cmdline "$BASH_COMMAND" \
                --sock "$_SHIT_SOCK" \
                >/dev/null 2>&1; then
                __shit_mark_failed "redirect pre-stash was not durably acknowledged" 125 0
                return 0
            fi
            ;;
    esac
    # S15: opt-in env tracking. Off by default until daemon ingestion
    # lands. `env -0` is GNU coreutils + BSD `env` ≥2024; on legacy
    # systems users get a fallback via `printenv` (not -0-safe for
    # values with newlines, but rare enough for v1).
    if [[ -n "${SHIT_TRACK_ENV:-}" ]]; then
        if ! env -0 2>/dev/null | "$_SHIT_BIN" hook-send pre-exec-env \
            --session "$_SHIT_SESSION" \
            --seq "$_SHIT_SEQ" \
            --sock "$_SHIT_SOCK" \
            >/dev/null 2>&1; then
            __shit_mark_failed "pre-command environment capture was not delivered" 125 0
            return 0
        fi
        _SHIT_ENV_TRACK_SEQ=$_SHIT_SEQ
    fi
    _SHIT_PREPARED_SEQ=$_SHIT_SEQ
}

__shit_post() {
    local rc=$?
    if [[ -n "${SHIT_DISABLE:-}" ]] \
        && [[ "$_SHIT_PREPARED_SEQ" -ne "$_SHIT_SEQ" ]] \
        && [[ "$_SHIT_FAILED_SEQ" -ne "$_SHIT_SEQ" ]]; then
        return $rc
    fi
    if [[ "$_SHIT_FAILED_SEQ" -eq "$_SHIT_SEQ" ]]; then
        if [[ "$_SHIT_FAILED_RC_SET" -eq 0 ]]; then
            _SHIT_FAILED_RC=$rc
            _SHIT_FAILED_RC_SET=1
        fi
        __shit_refuse_and_close_failed || true
        __shit_drain_precmd_queue
        return $rc
    fi
    if [[ "$_SHIT_PREPARED_SEQ" -eq "$_SHIT_SEQ" ]]; then
        local failure_detail=""
        # Post-command companion captures MUST precede PostExec. shitd handles
        # hook datagrams synchronously, so PostExec is the close fence for all
        # earlier messages queued by this hook cycle.
        if ! __shit_collect_shell_state | "$_SHIT_BIN" hook-send post-exec-shell-state \
            --session "$_SHIT_SESSION" \
            --seq "$_SHIT_SEQ" \
            --pwd "$PWD" \
            --sock "$_SHIT_SOCK" \
            --from-stdin \
            >/dev/null 2>&1; then
            failure_detail="post-command shell-state capture was not delivered"
        fi
        # Use the pre-command decision, not the current value: the command may
        # itself have unset SHIT_TRACK_ENV and that change still needs capture.
        if [[ "$_SHIT_ENV_TRACK_SEQ" -eq "$_SHIT_SEQ" ]]; then
            if ! env -0 2>/dev/null | "$_SHIT_BIN" hook-send post-exec-env \
                --session "$_SHIT_SESSION" \
                --seq "$_SHIT_SEQ" \
                --sock "$_SHIT_SOCK" \
                >/dev/null 2>&1; then
                [[ -n "$failure_detail" ]] || failure_detail="post-command environment capture was not delivered"
            fi
        fi
        if [[ -n "$failure_detail" ]]; then
            __shit_mark_failed "$failure_detail" "$rc" 1
        elif "$_SHIT_BIN" hook-send post-exec \
                --session "$_SHIT_SESSION" \
                --seq "$_SHIT_SEQ" \
                --exit-code "$rc" \
                --sock "$_SHIT_SOCK" \
                >/dev/null 2>&1; then
            _SHIT_PREPARED_SEQ=-1
            _SHIT_ENV_TRACK_SEQ=-1
        else
            __shit_mark_failed "post-command close message was not delivered" "$rc" 1
        fi
        [[ "$_SHIT_FAILED_SEQ" -lt 0 ]] || __shit_refuse_and_close_failed || true
    fi
    # AR06.1 / DR-CR-50 — drain the precmd-queue. `shit undo
    # --apply-shell-state` writes shell snippets here; we source
    # + truncate so they run before the next prompt. The queue
    # path is keyed by session-uuid so concurrent shells stay
    # isolated.
    __shit_drain_precmd_queue
    return $rc
}

__shit_close() {
    local rc=$?
    if [[ "$_SHIT_FAILED_SEQ" -lt 0 ]] \
        && [[ "$_SHIT_PREPARED_SEQ" -eq "$_SHIT_SEQ" ]]; then
        __shit_mark_failed "shell exited before post-command capture completed" "$rc" 1
    elif [[ "$_SHIT_FAILED_SEQ" -ge 0 ]] \
        && [[ "$_SHIT_FAILED_RC_SET" -eq 0 ]]; then
        _SHIT_FAILED_RC=$rc
        _SHIT_FAILED_RC_SET=1
    fi
    __shit_refuse_and_close_failed || true
    "$_SHIT_BIN" hook-send session-close \
        --session "$_SHIT_SESSION" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
    return $rc
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
