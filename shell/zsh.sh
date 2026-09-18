# shit shell hook — zsh
# Sourced from the user's .zshrc. Spec: .docs/sprints/S01-shell-integration.md.
# Placeholders @@SHIT_BIN@@, @@SHIT_SOCK@@ are substituted at install time.

# Guard against re-source.
[[ -n "${_SHIT_ZSH_LOADED:-}" ]] && return 0
export _SHIT_ZSH_LOADED=1

[[ -n "${SHIT_DISABLE:-}" ]] && return 0

_SHIT_BIN="@@SHIT_BIN@@"
_SHIT_SOCK="@@SHIT_SOCK@@"

typeset -g _SHIT_HOOK_BIN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/shit/bin"
case ":${PATH:-}:" in
    *":$_SHIT_HOOK_BIN_DIR:"*) ;;
    *) export PATH="$_SHIT_HOOK_BIN_DIR${PATH:+:$PATH}" ;;
esac

if [[ -r /proc/sys/kernel/random/uuid ]]; then
    _SHIT_SESSION="$(< /proc/sys/kernel/random/uuid)"
else
    _SHIT_SESSION="$("$_SHIT_BIN" internal new-uuid 2>/dev/null || echo 00000000-0000-0000-0000-000000000000)"
fi
export _SHIT_SESSION
typeset -gi _SHIT_SEQ=0
export _SHIT_SEQ
typeset -gi _SHIT_PREPARED_SEQ=-1
typeset -gi _SHIT_ENV_TRACK_SEQ=-1
typeset -gi _SHIT_FAILED_SEQ=-1
typeset -gi _SHIT_FAILED_RC=125
typeset -gi _SHIT_FAILED_RC_SET=0
typeset -g _SHIT_FAILED_DETAIL=""

__shit_send_open() {
    "$_SHIT_BIN" hook-send session-open \
        --session "$_SHIT_SESSION" \
        --pid "$$" \
        --shell zsh \
        --tty "$(tty 2>/dev/null || echo unknown)" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
}

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
    # ZSH_EVAL_CONTEXT contains "file" for sourced scripts, "loadautofunc" etc.
    case "$ZSH_EVAL_CONTEXT" in
        toplevel*) ;;
        *) return ;;
    esac
    if [[ "$_SHIT_FAILED_SEQ" -ge 0 ]] && ! __shit_refuse_and_close_failed; then
        return 0
    fi
    [[ -n "${SHIT_DISABLE:-}" ]] && return
    _SHIT_SEQ=$(( _SHIT_SEQ + 1 ))
    _SHIT_PREPARED_SEQ=-1
    _SHIT_ENV_TRACK_SEQ=-1
    if ! "$_SHIT_BIN" hook-send pre-exec \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pid "$$" \
        --cwd "$PWD" \
        --shell zsh \
        --depth "${SHLVL:-1}" \
        --sock "$_SHIT_SOCK" \
        --cmdline "${1:-}" \
        >/dev/null 2>&1; then
        return 0
    fi
    # AR06.1/.2/.3 — shell-state snapshot: pwd + set-opts + aliases.
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
    # AR06.5 — pre-stash redirect destinations while zsh is still in
    # preexec, before it performs the command's open(O_TRUNC). The daemon
    # durably refuses command-wide undo if an individual target cannot be
    # captured, so this remains fail-open for command execution.
    case "${1:-}" in
        *">"*|*"|"*|*"of="*)
            if ! "$_SHIT_BIN" hook-send pre-exec-redirects \
                --session "$_SHIT_SESSION" \
                --seq "$_SHIT_SEQ" \
                --cmdline "${1:-}" \
                --sock "$_SHIT_SOCK" \
                >/dev/null 2>&1; then
                __shit_mark_failed "redirect pre-stash was not durably acknowledged" 125 0
                return 0
            fi
            ;;
    esac
    # S15: opt-in env tracking. Off by default; SHIT_TRACK_ENV=1 enables.
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
        # PostExec is the close fence, so every post-command companion must be
        # queued first. A transport failure leaves the command open.
        if ! __shit_collect_shell_state | "$_SHIT_BIN" hook-send post-exec-shell-state \
            --session "$_SHIT_SESSION" \
            --seq "$_SHIT_SEQ" \
            --pwd "$PWD" \
            --sock "$_SHIT_SOCK" \
            --from-stdin \
            >/dev/null 2>&1; then
            failure_detail="post-command shell-state capture was not delivered"
        fi
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
    # + truncate so they run before the next prompt.
    __shit_drain_precmd_queue
    return $rc
}

# AR06.2/.3 — emit NUL-separated shell-state records. Format:
#   OPT\t<name>\t<value>\0
#   ALIAS\t<name>\t<value>\0
# zsh provides `$options` (associative: name -> on/off) and
# `$aliases` (associative: name -> expansion), so we don't have
# to parse `set -o` / `alias` output. This is faster AND more
# robust against zsh's NO_-prefixed "off" rendering quirk.
__shit_collect_shell_state() {
    emulate -L zsh
    local name value
    for name value in ${(kv)options}; do
        printf 'OPT\t%s\t%s\0' "$name" "$value"
    done
    for name value in ${(kv)aliases}; do
        printf 'ALIAS\t%s\t%s\0' "$name" "$value"
    done
}

# AR06.1 / DR-CR-50 — same drain mechanic as bash. The
# orchestrator's SystemShellStateRunner appends snippets to
# `$XDG_STATE_HOME/shit/precmd-queue/<session-uuid>`; we source
# the file in the current shell (so it actually mutates state),
# then truncate.
__shit_drain_precmd_queue() {
    local _q="${XDG_STATE_HOME:-$HOME/.local/state}/shit/precmd-queue/$_SHIT_SESSION"
    if [[ -s "$_q" ]]; then
        source "$_q" 2>/dev/null || true
        : > "$_q"
    fi
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

# zsh's add-zsh-hook is the idiomatic way to compose hooks.
autoload -Uz add-zsh-hook
add-zsh-hook preexec __shit_pre
add-zsh-hook precmd  __shit_post
add-zsh-hook zshexit __shit_close

__shit_send_open

# C05: per-command auto-injection of the install-prefix shim.
# Same shape as bash.sh — see that file for the full rationale.
__shit_install_wrap() {
    local _cmd="$1"
    shift
    if [[ -n "${SHIT_DISABLE:-}" ]] || [[ -n "${SHIT_PRELOAD_ACTIVE:-}" ]]; then
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
