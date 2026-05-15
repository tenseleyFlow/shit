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

trap '__shit_pre' DEBUG
PROMPT_COMMAND="__shit_post${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
trap '__shit_close' EXIT

__shit_send_open
