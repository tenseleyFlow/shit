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
    return $rc
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
