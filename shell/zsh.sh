# shit shell hook — zsh
# Sourced from the user's .zshrc. Spec: .docs/sprints/S01-shell-integration.md.
# Placeholders @@SHIT_BIN@@, @@SHIT_SOCK@@ are substituted at install time.

# Guard against re-source.
[[ -n "${_SHIT_ZSH_LOADED:-}" ]] && return 0
export _SHIT_ZSH_LOADED=1

[[ -n "${SHIT_DISABLE:-}" ]] && return 0

_SHIT_BIN="@@SHIT_BIN@@"
_SHIT_SOCK="@@SHIT_SOCK@@"

if [[ -r /proc/sys/kernel/random/uuid ]]; then
    _SHIT_SESSION="$(< /proc/sys/kernel/random/uuid)"
else
    _SHIT_SESSION="$("$_SHIT_BIN" internal new-uuid 2>/dev/null || echo 00000000-0000-0000-0000-000000000000)"
fi
export _SHIT_SESSION
typeset -gi _SHIT_SEQ=0

__shit_send_open() {
    "$_SHIT_BIN" hook-send session-open \
        --session "$_SHIT_SESSION" \
        --pid "$$" \
        --shell zsh \
        --tty "$(tty 2>/dev/null || echo unknown)" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
}

__shit_pre() {
    [[ -n "${SHIT_DISABLE:-}" ]] && return
    # ZSH_EVAL_CONTEXT contains "file" for sourced scripts, "loadautofunc" etc.
    case "$ZSH_EVAL_CONTEXT" in
        toplevel*) ;;
        *) return ;;
    esac
    _SHIT_SEQ=$(( _SHIT_SEQ + 1 ))
    "$_SHIT_BIN" hook-send pre-exec \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pid "$$" \
        --cwd "$PWD" \
        --shell zsh \
        --depth "${SHLVL:-1}" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
    # AR06.1/.2/.3 — shell-state snapshot: pwd + set-opts + aliases.
    __shit_collect_shell_state | "$_SHIT_BIN" hook-send pre-exec-shell-state \
        --session "$_SHIT_SESSION" \
        --seq "$_SHIT_SEQ" \
        --pwd "$PWD" \
        --sock "$_SHIT_SOCK" \
        --from-stdin \
        >/dev/null 2>&1 || true
    # S15: opt-in env tracking. Off by default; SHIT_TRACK_ENV=1 enables.
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
    # + truncate so they run before the next prompt.
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
    "$_SHIT_BIN" hook-send session-close \
        --session "$_SHIT_SESSION" \
        --sock "$_SHIT_SOCK" \
        >/dev/null 2>&1 || true
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
