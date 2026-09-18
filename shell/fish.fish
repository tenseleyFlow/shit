# shit shell hook — fish
# Sourced from the user's config.fish. Spec: .docs/sprints/S01-shell-integration.md.
# Placeholders @@SHIT_BIN@@, @@SHIT_SOCK@@ are substituted at install time.

if set -q _SHIT_FISH_LOADED
    exit 0
end
set -gx _SHIT_FISH_LOADED 1

if set -q SHIT_DISABLE
    exit 0
end

set -g _SHIT_BIN "@@SHIT_BIN@@"
set -g _SHIT_SOCK "@@SHIT_SOCK@@"

if set -q XDG_CONFIG_HOME; and test -n "$XDG_CONFIG_HOME"
    set -g _SHIT_HOOK_BIN_DIR (string join / (string trim --right --chars=/ "$XDG_CONFIG_HOME") shit bin)
else
    set -g _SHIT_HOOK_BIN_DIR "$HOME/.config/shit/bin"
end
if not contains -- "$_SHIT_HOOK_BIN_DIR" $PATH
    set -gx PATH "$_SHIT_HOOK_BIN_DIR" $PATH
end

if test -r /proc/sys/kernel/random/uuid
    set -gx _SHIT_SESSION (cat /proc/sys/kernel/random/uuid)
else
    set -gx _SHIT_SESSION ($_SHIT_BIN internal new-uuid 2>/dev/null; or echo 00000000-0000-0000-0000-000000000000)
end
set -gx _SHIT_SEQ 0
set -g _SHIT_PREPARED_SEQ -1
set -g _SHIT_ENV_TRACK_SEQ -1
set -g _SHIT_FAILED_SEQ -1
set -g _SHIT_FAILED_RC 125
set -g _SHIT_FAILED_RC_SET 0
set -g _SHIT_FAILED_DETAIL ""

# S15: emit the env block as NUL-separated KEY=VALUE pairs. fish has
# no `env -0` equivalent across platforms; this loop is the portable
# spelling. Only exported vars are sent — fish's universal/local vars
# are out of scope for v1 env tracking.
function __shit_emit_env
    for name in (set --names --export)
        printf '%s=%s\0' $name "$$name"
    end
end

function __shit_mark_failed --argument-names detail rc rc_set
    set _SHIT_FAILED_SEQ $_SHIT_SEQ
    set _SHIT_FAILED_DETAIL "$detail"
    set _SHIT_FAILED_RC "$rc"
    set _SHIT_FAILED_RC_SET "$rc_set"
    set _SHIT_PREPARED_SEQ -1
end

function __shit_refuse_and_close_failed
    test "$_SHIT_FAILED_SEQ" -ge 0; or return 0
    $_SHIT_BIN hook-send refuse-and-close \
        --session $_SHIT_SESSION \
        --seq $_SHIT_FAILED_SEQ \
        --exit-code $_SHIT_FAILED_RC \
        --detail "$_SHIT_FAILED_DETAIL" \
        --sock $_SHIT_SOCK \
        >/dev/null 2>&1
    if test $status -eq 0
        set _SHIT_FAILED_SEQ -1
        set _SHIT_FAILED_RC 125
        set _SHIT_FAILED_RC_SET 0
        set _SHIT_FAILED_DETAIL ""
        set _SHIT_PREPARED_SEQ -1
        set _SHIT_ENV_TRACK_SEQ -1
        return 0
    end
    return 1
end

function __shit_pre --on-event fish_preexec
    if test "$_SHIT_FAILED_SEQ" -ge 0
        __shit_refuse_and_close_failed; or return 0
    end
    set -q SHIT_DISABLE; and return
    # fish_preexec supplies the complete command line as its event argument.
    # Keep it intact: redirects are shell grammar and disappear from child argv.
    set -l _shit_cmdline "$argv"
    set _SHIT_SEQ (math $_SHIT_SEQ + 1)
    set _SHIT_PREPARED_SEQ -1
    set _SHIT_ENV_TRACK_SEQ -1
    $_SHIT_BIN hook-send pre-exec \
        --session $_SHIT_SESSION \
        --seq $_SHIT_SEQ \
        --pid $fish_pid \
        --cwd $PWD \
        --shell fish \
        --depth (count $SHLVL >/dev/null; and echo $SHLVL; or echo 1) \
        --sock $_SHIT_SOCK \
        --cmdline "$_shit_cmdline" \
        >/dev/null 2>&1
    or return 0
    # AR06.1 / AR06.6 — pwd-only shell-state snapshot. fish has
    # no `set -o` (opts always emit as informational comments;
    # see render_fish) and fish aliases live in the function
    # namespace alongside user-defined functions, which we don't
    # yet distinguish — defer to a follow-up. pwd-only is the
    # load-bearing piece for cd-undo on fish.
    $_SHIT_BIN hook-send pre-exec-shell-state \
        --session $_SHIT_SESSION \
        --seq $_SHIT_SEQ \
        --pwd $PWD \
        --sock $_SHIT_SOCK \
        >/dev/null 2>&1
    or begin
        __shit_mark_failed "pre-command shell-state capture was not delivered" 125 0
        return 0
    end
    # AR06.5 — synchronously pre-stash redirect destinations before fish
    # executes the command and opens any truncate-class target. A durable
    # per-command refusal makes target failures safe to fail open here.
    if string match -rq '[>|]|of=' -- "$_shit_cmdline"
        $_SHIT_BIN hook-send pre-exec-redirects \
            --session $_SHIT_SESSION \
            --seq $_SHIT_SEQ \
            --cmdline "$_shit_cmdline" \
            --sock $_SHIT_SOCK \
            >/dev/null 2>&1
        or begin
            __shit_mark_failed "redirect pre-stash was not durably acknowledged" 125 0
            return 0
        end
    end
    if set -q SHIT_TRACK_ENV
        __shit_emit_env | $_SHIT_BIN hook-send pre-exec-env \
            --session $_SHIT_SESSION \
            --seq $_SHIT_SEQ \
            --sock $_SHIT_SOCK \
            >/dev/null 2>&1
        or begin
            __shit_mark_failed "pre-command environment capture was not delivered" 125 0
            return 0
        end
        set _SHIT_ENV_TRACK_SEQ $_SHIT_SEQ
    end
    set _SHIT_PREPARED_SEQ $_SHIT_SEQ
end

function __shit_post --on-event fish_postexec
    set -l rc $status
    if set -q SHIT_DISABLE
        if test "$_SHIT_PREPARED_SEQ" -ne "$_SHIT_SEQ"; and test "$_SHIT_FAILED_SEQ" -ne "$_SHIT_SEQ"
            return $rc
        end
    end
    if test "$_SHIT_FAILED_SEQ" -eq "$_SHIT_SEQ"
        if test "$_SHIT_FAILED_RC_SET" -eq 0
            set _SHIT_FAILED_RC $rc
            set _SHIT_FAILED_RC_SET 1
        end
        __shit_refuse_and_close_failed; or true
        return $rc
    end
    if test "$_SHIT_PREPARED_SEQ" -eq "$_SHIT_SEQ"
        set -l failure_detail ""
        # PostExec is the close fence, so queue every post-command companion
        # first. Any transport failure leaves the command unfinished.
        $_SHIT_BIN hook-send post-exec-shell-state \
            --session $_SHIT_SESSION \
            --seq $_SHIT_SEQ \
            --pwd $PWD \
            --sock $_SHIT_SOCK \
            >/dev/null 2>&1
        or set failure_detail "post-command shell-state capture was not delivered"
        if test "$_SHIT_ENV_TRACK_SEQ" -eq "$_SHIT_SEQ"
            __shit_emit_env | $_SHIT_BIN hook-send post-exec-env \
                --session $_SHIT_SESSION \
                --seq $_SHIT_SEQ \
                --sock $_SHIT_SOCK \
                >/dev/null 2>&1
            or begin
                test -n "$failure_detail"; or set failure_detail "post-command environment capture was not delivered"
            end
        end
        if test -n "$failure_detail"
            __shit_mark_failed "$failure_detail" $rc 1
        else
            $_SHIT_BIN hook-send post-exec \
                --session $_SHIT_SESSION \
                --seq $_SHIT_SEQ \
                --exit-code $rc \
                --sock $_SHIT_SOCK \
                >/dev/null 2>&1
            if test $status -eq 0
                set _SHIT_PREPARED_SEQ -1
                set _SHIT_ENV_TRACK_SEQ -1
            else
                __shit_mark_failed "post-command close message was not delivered" $rc 1
            end
        end
        test "$_SHIT_FAILED_SEQ" -lt 0; or __shit_refuse_and_close_failed; or true
    end
    return $rc
end

function __shit_close --on-event fish_exit
    set -l rc $status
    if test "$_SHIT_FAILED_SEQ" -lt 0; and test "$_SHIT_PREPARED_SEQ" -eq "$_SHIT_SEQ"
        __shit_mark_failed "shell exited before post-command capture completed" $rc 1
    else if test "$_SHIT_FAILED_SEQ" -ge 0; and test "$_SHIT_FAILED_RC_SET" -eq 0
        set _SHIT_FAILED_RC $rc
        set _SHIT_FAILED_RC_SET 1
    end
    __shit_refuse_and_close_failed; or true
    $_SHIT_BIN hook-send session-close \
        --session $_SHIT_SESSION \
        --sock $_SHIT_SOCK \
        >/dev/null 2>&1
end

# macOS BSD `tty` prints "not a tty" on stdout (rather than just
# erroring) when stdin isn't a TTY; without `string collect`, fish
# word-splits on the newline and the trailing `or echo unknown`
# leaks a second positional arg into `--tty`. Collect into one var.
set -l _shit_tty (tty 2>/dev/null | string collect)
test -z "$_shit_tty"; and set _shit_tty unknown
$_SHIT_BIN hook-send session-open \
    --session $_SHIT_SESSION \
    --pid $fish_pid \
    --shell fish \
    --tty "$_shit_tty" \
    --sock $_SHIT_SOCK \
    >/dev/null 2>&1

# C05: per-command auto-injection of the install-prefix shim.
# Same shape as bash/zsh hooks — fish-syntax wrappers around each
# known install command. See `shell/bash.sh` for the full rationale.
function __shit_install_wrap --argument cmd
    set -l args $argv[2..-1]
    if test -n "$SHIT_DISABLE"; or test -n "$SHIT_PRELOAD_ACTIVE"
        command $cmd $args
        return $status
    end
    set -l fish_lines ($_SHIT_BIN auto-inject-install-env --shell fish -- $cmd $args 2>/dev/null)
    if test (count $fish_lines) -gt 0
        # Each line is `set -x KEY 'value'`. Eval line-by-line then
        # invoke the command in the same scope so the exports apply.
        for line in $fish_lines
            eval $line
        end
        command $cmd $args
        # The exports were local to this function scope; fish auto-
        # unexports them when the function returns.
        return $status
    else
        command $cmd $args
        return $status
    end
end

function make    ; __shit_install_wrap make    $argv; end
function gmake   ; __shit_install_wrap gmake   $argv; end
function cmake   ; __shit_install_wrap cmake   $argv; end
function ninja   ; __shit_install_wrap ninja   $argv; end
function meson   ; __shit_install_wrap meson   $argv; end
function cargo   ; __shit_install_wrap cargo   $argv; end
function pip     ; __shit_install_wrap pip     $argv; end
function pip3    ; __shit_install_wrap pip3    $argv; end
function python  ; __shit_install_wrap python  $argv; end
function python3 ; __shit_install_wrap python3 $argv; end
