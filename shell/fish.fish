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

if test -r /proc/sys/kernel/random/uuid
    set -gx _SHIT_SESSION (cat /proc/sys/kernel/random/uuid)
else
    set -gx _SHIT_SESSION ($_SHIT_BIN internal new-uuid 2>/dev/null; or echo 00000000-0000-0000-0000-000000000000)
end
set -g _SHIT_SEQ 0

# S15: emit the env block as NUL-separated KEY=VALUE pairs. fish has
# no `env -0` equivalent across platforms; this loop is the portable
# spelling. Only exported vars are sent — fish's universal/local vars
# are out of scope for v1 env tracking.
function __shit_emit_env
    for name in (set --names --export)
        printf '%s=%s\0' $name "$$name"
    end
end

function __shit_pre --on-event fish_preexec
    set -q SHIT_DISABLE; and return
    set _SHIT_SEQ (math $_SHIT_SEQ + 1)
    $_SHIT_BIN hook-send pre-exec \
        --session $_SHIT_SESSION \
        --seq $_SHIT_SEQ \
        --pid $fish_pid \
        --cwd $PWD \
        --shell fish \
        --depth (count $SHLVL >/dev/null; and echo $SHLVL; or echo 1) \
        --sock $_SHIT_SOCK \
        >/dev/null 2>&1
    if set -q SHIT_TRACK_ENV
        __shit_emit_env | $_SHIT_BIN hook-send pre-exec-env \
            --session $_SHIT_SESSION \
            --seq $_SHIT_SEQ \
            --sock $_SHIT_SOCK \
            >/dev/null 2>&1
    end
end

function __shit_post --on-event fish_postexec
    set -l rc $status
    set -q SHIT_DISABLE; and return $rc
    $_SHIT_BIN hook-send post-exec \
        --session $_SHIT_SESSION \
        --seq $_SHIT_SEQ \
        --exit-code $rc \
        --sock $_SHIT_SOCK \
        >/dev/null 2>&1
    if set -q SHIT_TRACK_ENV
        __shit_emit_env | $_SHIT_BIN hook-send post-exec-env \
            --session $_SHIT_SESSION \
            --seq $_SHIT_SEQ \
            --sock $_SHIT_SOCK \
            >/dev/null 2>&1
    end
    return $rc
end

function __shit_close --on-event fish_exit
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
