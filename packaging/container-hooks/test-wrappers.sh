#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later

# Focused protocol tests for the POSIX container wrappers. These use fake
# runtimes and a fake shit-helper; no container engine or daemon is required.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/shit-wrapper-test.XXXXXX")
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM

wrapper_bin=$test_tmp/wrappers
real_bin=$test_tmp/real
test_log=$test_tmp/calls.log
stdout_log=$test_tmp/stdout.log
stderr_log=$test_tmp/stderr.log
runtime_dir=$test_tmp/runtime
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"

fail() {
    echo "container wrapper test: $*" >&2
    exit 1
}

assert_contains() {
    needle=$1
    file=$2
    grep -F -- "$needle" "$file" >/dev/null 2>&1 \
        || fail "expected '$needle' in $file"
}

assert_not_contains() {
    needle=$1
    file=$2
    if grep -F -- "$needle" "$file" >/dev/null 2>&1; then
        fail "did not expect '$needle' in $file"
    fi
}

assert_count() {
    expected=$1
    needle=$2
    file=$3
    actual=$(grep -F -c -- "$needle" "$file" 2>/dev/null || true)
    [ "$actual" -eq "$expected" ] \
        || fail "expected $expected occurrences of '$needle' in $file, got $actual"
}

assert_path_absent() {
    path=$1
    [ ! -f "$path" ] && [ ! -d "$path" ] && [ ! -L "$path" ] \
        || fail "expected path to be absent: $path"
}

make_fixture() {
    tool=$1
    wrapper_source=$2
    rm -rf "$wrapper_bin" "$real_bin"
    mkdir -p "$wrapper_bin" "$real_bin"
    cp "$wrapper_source" "$wrapper_bin/$tool"
    chmod 755 "$wrapper_bin/$tool"

    cat >"$real_bin/$tool" <<'RUNTIME'
#!/bin/sh
printf 'runtime:%s:%s\n' "$(basename "$0")" "$*" >>"$WRAPPER_TEST_LOG"
printf 'runtime-env:%s:host=%s:context=%s:tls=%s:cert=%s:config=%s\n' \
    "$(basename "$0")" "${DOCKER_HOST-unset}" "${DOCKER_CONTEXT-unset}" \
    "${DOCKER_TLS_VERIFY-unset}" "${DOCKER_CERT_PATH-unset}" "${DOCKER_CONFIG-unset}" \
    >>"$WRAPPER_TEST_LOG"
if [ -n "${FAKE_RUNTIME_STARTED:-}" ]; then
    if [ -n "${FAKE_RUNTIME_PID_FILE:-}" ]; then
        printf '%s\n' "$$" >"$FAKE_RUNTIME_PID_FILE"
    fi
    : >"$FAKE_RUNTIME_STARTED"
    while [ ! -f "$FAKE_RUNTIME_RELEASE" ]; do
        sleep 1
    done
fi
exit "${FAKE_RUNTIME_RC:-0}"
RUNTIME
    chmod 755 "$real_bin/$tool"

    cat >"$real_bin/shit-helper" <<'HELPER'
#!/bin/sh
printf 'helper:%s\n' "$*" >>"$WRAPPER_TEST_LOG"
cat >/dev/null
case "${1:-}" in
    container-prepare)
        [ "${HELPER_PREPARE_RC:-0}" -eq 0 ] || exit "$HELPER_PREPARE_RC"
        if [ -n "${HELPER_PREPARE_STARTED:-}" ]; then
            : >"$HELPER_PREPARE_STARTED"
            while [ ! -f "$HELPER_PREPARE_RELEASE" ]; do
                sleep 1
            done
        fi
        if [ "${HELPER_NESTED_RUNTIME:-0}" -eq 1 ]; then
            SHIT_DURING_UNDO=1 docker inspect helper-nested >/dev/null
        fi
        printf '%s' "${HELPER_PREPARE_TOKEN:-}"
        ;;
    container-finalize)
        if [ -n "${HELPER_FINALIZE_STARTED:-}" ]; then
            : >"$HELPER_FINALIZE_STARTED"
            while [ ! -f "$HELPER_FINALIZE_RELEASE" ]; do
                sleep 1
            done
        fi
        exit "${HELPER_FINALIZE_RC:-0}"
        ;;
    container-event)
        exit "${HELPER_EVENT_RC:-0}"
        ;;
    *)
        exit 97
        ;;
esac
HELPER
    chmod 755 "$real_bin/shit-helper"

    PATH=$wrapper_bin:$real_bin:/usr/bin:/bin
    WRAPPER_TEST_LOG=$test_log
    XDG_RUNTIME_DIR=$runtime_dir
    export PATH WRAPPER_TEST_LOG XDG_RUNTIME_DIR
    reset_case
}

reset_case() {
    : >"$test_log"
    : >"$stdout_log"
    : >"$stderr_log"
    FAKE_RUNTIME_RC=0
    HELPER_PREPARE_RC=0
    HELPER_PREPARE_TOKEN=
    HELPER_FINALIZE_RC=0
    HELPER_EVENT_RC=0
    HELPER_NESTED_RUNTIME=0
    export FAKE_RUNTIME_RC HELPER_PREPARE_RC HELPER_PREPARE_TOKEN
    export HELPER_FINALIZE_RC HELPER_EVENT_RC HELPER_NESTED_RUNTIME
    unset SHIT_DURING_UNDO SHIT_CONTAINER_LOCK_HELD
    unset FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE FAKE_RUNTIME_PID_FILE
    unset HELPER_PREPARE_STARTED HELPER_PREPARE_RELEASE
    unset HELPER_FINALIZE_STARTED HELPER_FINALIZE_RELEASE
    unset SHIT_CONTAINER_TEST_HOOKS
    unset SHIT_CONTAINER_TEST_SPAWN_READY SHIT_CONTAINER_TEST_SPAWN_RELEASE
    unset SHIT_CONTAINER_TEST_WAIT_READY SHIT_CONTAINER_TEST_WAIT_RELEASE
    unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_CONFIG
}

expect_status() {
    expected=$1
    shift
    set +e
    "$@" >"$stdout_log" 2>"$stderr_log"
    actual=$?
    set -e
    [ "$actual" -eq "$expected" ] \
        || fail "expected status $expected, got $actual for: $*"
}

token=v3-rmi1:018e2f5d-77f2-7c84-9b33-123456789abc
batch_id=${token#v3-rmi1:}
lock_uid=$(id -u)
lock_root=/tmp/shit-container-hooks-$lock_uid
docker_lock=$lock_root/docker-engine.lock

# Docker: one valid token brackets the runtime with prepare/finalize.
make_fixture docker "$script_dir/docker-wrapper"
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 0 "$wrapper_bin/docker" rmi --no-prune example:old
assert_contains "helper:container-prepare docker --target-argv-nul-stdin" "$test_log"
assert_contains "runtime:docker:--context default rmi --no-prune example:old" "$test_log"
assert_contains "runtime-env:docker:host=unset:context=unset:tls=unset:cert=unset:config=unset" "$test_log"
assert_contains "helper:container-finalize docker --batch-id $batch_id --exit-code 0 --target-argv-nul-stdin" "$test_log"

# Routing variables are rejected before helper capture, including when set to
# an empty value. The wrapper must never capture one endpoint and mutate another.
for route_var in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_CONFIG; do
    reset_case
    HELPER_PREPARE_TOKEN=$token
    export HELPER_PREPARE_TOKEN
    export "$route_var="
    expect_status 125 "$wrapper_bin/docker" rmi --no-prune example:old
    assert_not_contains "helper:" "$test_log"
    assert_not_contains "runtime:docker:" "$test_log"
    unset "$route_var"
done

# A runtime failure is still finalized and its original status is preserved.
reset_case
HELPER_PREPARE_TOKEN=$token
FAKE_RUNTIME_RC=42
export HELPER_PREPARE_TOKEN FAKE_RUNTIME_RC
expect_status 42 "$wrapper_bin/docker" rmi --no-prune example:old
assert_contains "helper:container-finalize docker --batch-id $batch_id --exit-code 42 --target-argv-nul-stdin" "$test_log"

# Finalize is telemetry-only after pre-authorization confirmation, so a
# transport failure never rewrites the real runtime status.
reset_case
HELPER_PREPARE_TOKEN=$token
HELPER_FINALIZE_RC=9
export HELPER_PREPARE_TOKEN HELPER_FINALIZE_RC
expect_status 0 "$wrapper_bin/docker" rmi --no-prune example:old
reset_case
HELPER_PREPARE_TOKEN=$token
HELPER_FINALIZE_RC=9
FAKE_RUNTIME_RC=23
export HELPER_PREPARE_TOKEN HELPER_FINALIZE_RC FAKE_RUNTIME_RC
expect_status 23 "$wrapper_bin/docker" rmi --no-prune example:old

# Preflight errors and malformed stdout stop before the real runtime.
reset_case
HELPER_PREPARE_RC=8
export HELPER_PREPARE_RC
expect_status 125 "$wrapper_bin/docker" rmi --no-prune example:old
assert_not_contains "runtime:docker:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN='v2:018e2f5d-77f2-7c84-9b33-123456789abc'
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune example:old
assert_not_contains "runtime:docker:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN='v3-rmi1:not-a-uuid'
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune example:old
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" rmi --no-prune example:old
assert_not_contains "runtime:docker:" "$test_log"

# Empty prepare output is the explicit non-destructive path. The legacy post
# hook remains as a compatibility no-op for the reviewed read-only allow-list.
reset_case
expect_status 0 "$wrapper_bin/docker" ps
assert_contains "runtime:docker:ps" "$test_log"
assert_contains "helper:container-event docker post --target-argv-nul-stdin" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" ps
assert_not_contains "runtime:docker:" "$test_log"

# The wrapper's own grammar is authoritative under helper version skew. A
# current-looking token cannot authorize aliases, force, multiple targets,
# raw IDs/digests, global prefixes, or any other engine mutation.
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 0 "$wrapper_bin/docker" rmi example:old --no-prune=true
assert_contains "runtime:docker:--context default rmi example:old --no-prune=true" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune example:old example:new
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune --no-prune=true example:old
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune=false example:old
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune -f example:old
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" image rm --no-prune example:old
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune deadbeef
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" rmi --no-prune example@sha256:abc
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" --context default rmi --no-prune example:old
assert_not_contains "helper:" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker" pull example:old
assert_not_contains "helper:" "$test_log"

# The recursion guard bypasses both phases.
reset_case
SHIT_DURING_UNDO=1
export SHIT_DURING_UNDO
expect_status 0 "$wrapper_bin/docker" rmi example:old
assert_contains "runtime:docker:rmi example:old" "$test_log"
assert_not_contains "helper:" "$test_log"

# Capture-time runtime calls inherit the exact outer-lock token and therefore
# re-enter without deadlocking or recursively calling the helper.
reset_case
HELPER_PREPARE_TOKEN=$token
HELPER_NESTED_RUNTIME=1
export HELPER_PREPARE_TOKEN HELPER_NESTED_RUNTIME
expect_status 0 "$wrapper_bin/docker" rmi --no-prune example:old
assert_contains "runtime:docker:inspect helper-nested" "$test_log"
assert_count 1 "helper:container-prepare docker" "$test_log"

# Empty-token reviewed reads release before runtime, so a streaming `events`
# call cannot retain the canonical lock or prevent a positive mutation batch.
reset_case
FAKE_RUNTIME_STARTED=$test_tmp/stream-runtime-started
FAKE_RUNTIME_RELEASE=$test_tmp/stream-runtime-release
export FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE
"$wrapper_bin/docker" events >"$test_tmp/stream.out" 2>"$test_tmp/stream.err" &
stream_wrapper_pid=$!
wait_loops=0
while [ ! -f "$FAKE_RUNTIME_STARTED" ]; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "streaming read never reached runtime gate"
    sleep 1
done
assert_path_absent "$docker_lock"

HELPER_PREPARE_TOKEN=$token
FAKE_RUNTIME_STARTED=$test_tmp/stream-mutation-started
FAKE_RUNTIME_RELEASE=$test_tmp/stream-mutation-release
export HELPER_PREPARE_TOKEN FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE
"$wrapper_bin/docker" rmi --no-prune example:old \
    >"$test_tmp/stream-mutation.out" 2>"$test_tmp/stream-mutation.err" &
stream_mutation_pid=$!
wait_loops=0
while [ ! -f "$FAKE_RUNTIME_STARTED" ]; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "mutation was blocked by unlocked streaming read"
    sleep 1
done
[ -f "$docker_lock" ] || fail "positive mutation did not retain canonical lock"
: >"$FAKE_RUNTIME_RELEASE"
set +e
wait "$stream_mutation_pid"
stream_mutation_rc=$?
set -e
[ "$stream_mutation_rc" -eq 0 ] || fail "streaming-read mutation exited $stream_mutation_rc"
assert_path_absent "$docker_lock"
: >"$test_tmp/stream-runtime-release"
set +e
wait "$stream_wrapper_pid"
stream_wrapper_rc=$?
set -e
[ "$stream_wrapper_rc" -eq 0 ] || fail "streaming read exited $stream_wrapper_rc"

# Positive Docker batches serialize preflight→runtime→finalize, and standalone
# Compose shares the same engine lock. The second preflight must not begin while
# the mutation runtime is held at the fake gate.
reset_case
cp "$script_dir/docker-compose-wrapper" "$wrapper_bin/docker-compose"
chmod 755 "$wrapper_bin/docker-compose"
cp "$real_bin/docker" "$real_bin/docker-compose"
chmod 755 "$real_bin/docker-compose"
HELPER_PREPARE_TOKEN=$token
FAKE_RUNTIME_STARTED=$test_tmp/runtime-started
FAKE_RUNTIME_RELEASE=$test_tmp/runtime-release
export HELPER_PREPARE_TOKEN FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE
"$wrapper_bin/docker" rmi --no-prune example:old \
    >"$test_tmp/first.out" 2>"$test_tmp/first.err" &
first_wrapper_pid=$!
wait_loops=0
while [ ! -f "$FAKE_RUNTIME_STARTED" ]; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "first Docker wrapper never reached runtime gate"
    sleep 1
done
HELPER_PREPARE_TOKEN=
export HELPER_PREPARE_TOKEN
"$wrapper_bin/docker-compose" ps >"$test_tmp/second.out" 2>"$test_tmp/second.err" &
second_wrapper_pid=$!
sleep 1
assert_count 1 "helper:container-prepare" "$test_log"
: >"$FAKE_RUNTIME_RELEASE"
set +e
wait "$first_wrapper_pid"
first_wrapper_rc=$?
wait "$second_wrapper_pid"
second_wrapper_rc=$?
set -e
[ "$first_wrapper_rc" -eq 0 ] || fail "first serialized wrapper exited $first_wrapper_rc"
if [ "$second_wrapper_rc" -ne 0 ]; then
    sed -n '1,80p' "$test_tmp/second.err" >&2
    fail "second serialized wrapper exited $second_wrapper_rc"
fi
assert_contains "runtime:docker-compose:ps" "$test_log"

# A dead wrapper PID is not proof that its runtime child is gone. Stale locks
# therefore fail closed for explicit operator cleanup rather than being reaped.
reset_case
[ -d "$lock_root" ] || fail "wrapper did not create deterministic lock root"
dead_pid=99999999
if kill -0 "$dead_pid" 2>/dev/null; then
    fail "chosen stale-lock pid unexpectedly exists"
fi
printf 'docker-engine:%s:test-stale\n' "$dead_pid" >"$docker_lock"
expect_status 125 "$wrapper_bin/docker" ps
assert_not_contains "helper:" "$test_log"
assert_not_contains "runtime:docker:" "$test_log"
assert_contains "verify no container helper/runtime remains" "$stderr_log"
rm -f "$docker_lock"

# Corrupt canonical state fails closed and never reaches preflight/runtime.
reset_case
printf '%s\n' 'not-a-container-lock-token' >"$docker_lock"
expect_status 125 "$wrapper_bin/docker" ps
assert_not_contains "helper:" "$test_log"
assert_not_contains "runtime:docker:" "$test_log"
rm -f "$docker_lock"

# A directory at the canonical path cannot exploit POSIX ln's destination-
# directory behavior; it is rejected before any claim link is created inside.
reset_case
mkdir "$docker_lock"
expect_status 125 "$wrapper_bin/docker" ps
assert_not_contains "helper:" "$test_log"
[ -z "$(ls -A "$docker_lock")" ] || fail "claim was linked inside corrupt lock directory"
rmdir "$docker_lock"

# Every catchable termination signal sent only to an authorized wrapper is
# forwarded to the in-flight runtime. The wrapper reaps it exactly once,
# finalizes exactly once while retaining the lock, then returns the exact
# runtime/signal status.
for signal_case in HUP:129 INT:130 TERM:143; do
    signal_name=${signal_case%%:*}
    signal_status=${signal_case#*:}
    runtime_status=$signal_status
    [ "$signal_name" != INT ] || runtime_status=143
    signal_suffix=$(printf '%s' "$signal_name" | tr 'A-Z' 'a-z')
    reset_case
    FAKE_RUNTIME_STARTED=$test_tmp/signal-$signal_suffix-runtime-started
    FAKE_RUNTIME_RELEASE=$test_tmp/signal-$signal_suffix-runtime-release
    HELPER_FINALIZE_STARTED=$test_tmp/signal-$signal_suffix-finalize-started
    HELPER_FINALIZE_RELEASE=$test_tmp/signal-$signal_suffix-finalize-release
    HELPER_PREPARE_TOKEN=$token
    export FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE
    export HELPER_FINALIZE_STARTED HELPER_FINALIZE_RELEASE HELPER_PREPARE_TOKEN
    signal_wrapper_pid_file=$test_tmp/signal-$signal_suffix-wrapper.pid
    (
        wait_loops=0
        while [ ! -f "$signal_wrapper_pid_file" ] \
            || [ ! -f "$FAKE_RUNTIME_STARTED" ]; do
            wait_loops=$((wait_loops + 1))
            [ "$wait_loops" -lt 10 ] || fail "$signal_name test never reached runtime gate"
            sleep 1
        done
        signal_wrapper_pid=$(sed -n '1p' "$signal_wrapper_pid_file")
        [ -f "$docker_lock" ] \
            || fail "$signal_name runtime path did not hold Docker engine lock"
        kill -"$signal_name" "$signal_wrapper_pid"
        wait_loops=0
        while [ ! -f "$HELPER_FINALIZE_STARTED" ]; do
            wait_loops=$((wait_loops + 1))
            [ "$wait_loops" -lt 10 ] \
                || fail "$signal_name test never reached durable finalization"
            sleep 1
        done
        [ -f "$docker_lock" ] \
            || fail "$signal_name wrapper released before durable finalization"
        assert_count 1 "helper:container-finalize docker --batch-id $batch_id --exit-code $runtime_status --target-argv-nul-stdin" "$test_log"
        : >"$HELPER_FINALIZE_RELEASE"
    ) &
    signal_watcher_pid=$!
    set +e
    sh -c 'printf "%s\n" "$$" >"$1"; shift; exec "$@"' \
        signal-driver "$signal_wrapper_pid_file" \
        "$wrapper_bin/docker" rmi --no-prune example:old \
        >"$test_tmp/signal-$signal_suffix.out" \
        2>"$test_tmp/signal-$signal_suffix.err"
    signal_wrapper_rc=$?
    set -e
    wait "$signal_watcher_pid" || fail "$signal_name watcher failed"
    [ "$signal_wrapper_rc" -eq "$signal_status" ] \
        || fail "$signal_name wrapper returned $signal_wrapper_rc instead of runtime status $signal_status"
    assert_count 1 "runtime:docker:--context default rmi --no-prune example:old" "$test_log"
    assert_path_absent "$docker_lock"
done

# HUP/INT/TERM in the spawn-before-$! window are deferred while the canonical
# lock remains owned. Once the pid is registered, each signal is forwarded,
# the runtime is reaped, and the authorized batch is finalized exactly once.
for signal_case in HUP:129 INT:130 TERM:143; do
    signal_name=${signal_case%%:*}
    signal_status=${signal_case#*:}
    runtime_status=$signal_status
    [ "$signal_name" != INT ] || runtime_status=143
    signal_suffix=$(printf '%s' "$signal_name" | tr 'A-Z' 'a-z')
    reset_case
    FAKE_RUNTIME_STARTED=$test_tmp/spawn-$signal_suffix-runtime-started
    FAKE_RUNTIME_RELEASE=$test_tmp/spawn-$signal_suffix-runtime-release
    HELPER_PREPARE_TOKEN=$token
    SHIT_CONTAINER_TEST_HOOKS=1
    SHIT_CONTAINER_TEST_SPAWN_READY=$test_tmp/spawn-$signal_suffix-ready
    SHIT_CONTAINER_TEST_SPAWN_RELEASE=$test_tmp/spawn-$signal_suffix-release
    export FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE HELPER_PREPARE_TOKEN
    export SHIT_CONTAINER_TEST_HOOKS
    export SHIT_CONTAINER_TEST_SPAWN_READY SHIT_CONTAINER_TEST_SPAWN_RELEASE
    spawn_window_pid_file=$test_tmp/spawn-$signal_suffix-wrapper.pid
    (
        wait_loops=0
        while [ ! -f "$spawn_window_pid_file" ] \
            || [ ! -f "$SHIT_CONTAINER_TEST_SPAWN_READY" ] \
            || [ ! -f "$FAKE_RUNTIME_STARTED" ]; do
            wait_loops=$((wait_loops + 1))
            [ "$wait_loops" -lt 10 ] \
                || fail "$signal_name spawn-window test did not reach its barrier"
            sleep 1
        done
        spawn_window_wrapper_pid=$(sed -n '1p' "$spawn_window_pid_file")
        [ -f "$docker_lock" ] \
            || fail "$signal_name spawn-window dropped the lock before signal"
        kill -"$signal_name" "$spawn_window_wrapper_pid"
        sleep 2
        kill -0 "$spawn_window_wrapper_pid" 2>/dev/null \
            || fail "$signal_name spawn-window exited before child pid registration"
        [ -f "$docker_lock" ] \
            || fail "$signal_name spawn-window released while runtime could still live"
        : >"$SHIT_CONTAINER_TEST_SPAWN_RELEASE"
    ) &
    spawn_watcher_pid=$!
    set +e
    sh -c 'printf "%s\n" "$$" >"$1"; shift; exec "$@"' \
        spawn-driver "$spawn_window_pid_file" \
        "$wrapper_bin/docker" rmi --no-prune example:old \
        >"$test_tmp/spawn-$signal_suffix.out" \
        2>"$test_tmp/spawn-$signal_suffix.err"
    spawn_window_wrapper_rc=$?
    set -e
    wait "$spawn_watcher_pid" || fail "$signal_name spawn-window watcher failed"
    [ "$spawn_window_wrapper_rc" -eq "$signal_status" ] \
        || fail "$signal_name spawn-window returned $spawn_window_wrapper_rc instead of $signal_status"
    assert_count 1 "helper:container-finalize docker --batch-id $batch_id --exit-code $runtime_status --target-argv-nul-stdin" "$test_log"
    assert_count 1 "runtime:docker:--context default rmi --no-prune example:old" "$test_log"
    assert_path_absent "$docker_lock"
done

# If a signal lands after wait reaped the runtime but before the pid slot is
# cleared, it reports the signal status rather than a synthetic `wait` 127.
reset_case
HELPER_PREPARE_TOKEN=$token
SHIT_CONTAINER_TEST_HOOKS=1
SHIT_CONTAINER_TEST_WAIT_READY=$test_tmp/post-wait-ready
SHIT_CONTAINER_TEST_WAIT_RELEASE=$test_tmp/post-wait-release
export HELPER_PREPARE_TOKEN SHIT_CONTAINER_TEST_HOOKS
export SHIT_CONTAINER_TEST_WAIT_READY SHIT_CONTAINER_TEST_WAIT_RELEASE
"$wrapper_bin/docker" rmi --no-prune example:old \
    >"$test_tmp/post-wait.out" 2>"$test_tmp/post-wait.err" &
post_wait_wrapper_pid=$!
wait_loops=0
while [ ! -f "$SHIT_CONTAINER_TEST_WAIT_READY" ]; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "post-wait test did not reach its barrier"
    sleep 1
done
[ -f "$docker_lock" ] || fail "post-wait wrapper released before clearing child state"
kill -TERM "$post_wait_wrapper_pid"
: >"$SHIT_CONTAINER_TEST_WAIT_RELEASE"
set +e
wait "$post_wait_wrapper_pid"
post_wait_wrapper_rc=$?
set -e
[ "$post_wait_wrapper_rc" -eq 143 ] \
    || fail "post-wait wrapper returned $post_wait_wrapper_rc instead of signal status 143"
assert_contains "helper:container-finalize docker --batch-id $batch_id --exit-code 0 --target-argv-nul-stdin" "$test_log"
assert_path_absent "$docker_lock"

# A signal while prepare is still the foreground child is remembered without
# releasing serialization. If prepare then returns a valid authorization, the
# runtime is skipped and the unused batch is finalized before the signal exits.
reset_case
HELPER_PREPARE_TOKEN=$token
HELPER_PREPARE_STARTED=$test_tmp/prepare-signal-started
HELPER_PREPARE_RELEASE=$test_tmp/prepare-signal-release
export HELPER_PREPARE_TOKEN HELPER_PREPARE_STARTED HELPER_PREPARE_RELEASE
"$wrapper_bin/docker" rmi --no-prune example:old \
    >"$test_tmp/prepare-signal.out" 2>"$test_tmp/prepare-signal.err" &
prepare_signal_wrapper_pid=$!
wait_loops=0
while [ ! -f "$HELPER_PREPARE_STARTED" ]; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "prepare-signal test never reached helper gate"
    sleep 1
done
kill -TERM "$prepare_signal_wrapper_pid"
sleep 2
kill -0 "$prepare_signal_wrapper_pid" 2>/dev/null \
    || fail "prepare-signal wrapper exited while helper authorization was unresolved"
[ -f "$docker_lock" ] \
    || fail "prepare-signal wrapper released while helper authorization was unresolved"
: >"$HELPER_PREPARE_RELEASE"
set +e
wait "$prepare_signal_wrapper_pid"
prepare_signal_wrapper_rc=$?
set -e
[ "$prepare_signal_wrapper_rc" -eq 143 ] \
    || fail "prepare-signal wrapper returned $prepare_signal_wrapper_rc instead of signal status 143"
assert_not_contains "runtime:docker:--context default rmi" "$test_log"
assert_contains "helper:container-finalize docker --batch-id $batch_id --exit-code 143 --target-argv-nul-stdin" "$test_log"
assert_path_absent "$docker_lock"

# SIGKILL cannot run shell traps and may orphan a still-mutating runtime. The
# dead wrapper's canonical lock remains a hard refusal until that child is
# proven gone and the exact lock/claim are manually removed.
reset_case
FAKE_RUNTIME_STARTED=$test_tmp/kill-runtime-started
FAKE_RUNTIME_RELEASE=$test_tmp/kill-runtime-release
FAKE_RUNTIME_PID_FILE=$test_tmp/kill-runtime.pid
SHIT_DURING_UNDO=1
export FAKE_RUNTIME_STARTED FAKE_RUNTIME_RELEASE FAKE_RUNTIME_PID_FILE SHIT_DURING_UNDO
"$wrapper_bin/docker" ps >"$test_tmp/kill.out" 2>"$test_tmp/kill.err" &
kill_wrapper_pid=$!
wait_loops=0
while [ ! -f "$FAKE_RUNTIME_STARTED" ] || [ ! -f "$FAKE_RUNTIME_PID_FILE" ]; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "SIGKILL test never reached runtime gate"
    sleep 1
done
kill_runtime_pid=$(sed -n '1p' "$FAKE_RUNTIME_PID_FILE")
kill -KILL "$kill_wrapper_pid"
set +e
wait "$kill_wrapper_pid"
kill_wrapper_rc=$?
set -e
[ "$kill_wrapper_rc" -eq 137 ] || fail "SIGKILL wrapper returned $kill_wrapper_rc"
kill -0 "$kill_runtime_pid" 2>/dev/null \
    || fail "fake runtime did not survive wrapper SIGKILL as expected"
expect_status 125 "$wrapper_bin/docker" ps
assert_contains "verify no container helper/runtime remains" "$stderr_log"
: >"$FAKE_RUNTIME_RELEASE"
wait_loops=0
while kill -0 "$kill_runtime_pid" 2>/dev/null; do
    wait_loops=$((wait_loops + 1))
    [ "$wait_loops" -lt 10 ] || fail "orphan fake runtime did not exit after release"
    sleep 1
done
stale_owner_token=$(sed -n '1p' "$docker_lock")
stale_nonce=${stale_owner_token#*:*:}
rm -f "$docker_lock" "$lock_root/.docker-engine.claim.$stale_nonce"

# Only the exact value `1` is a recursion bypass. A stale/defensive `0` must
# not turn destructive capture off in either the wrapper or helper.
reset_case
SHIT_DURING_UNDO=0
HELPER_PREPARE_TOKEN=$token
export SHIT_DURING_UNDO HELPER_PREPARE_TOKEN
expect_status 0 "$wrapper_bin/docker" rmi --no-prune example:old
assert_contains "helper:container-prepare docker --target-argv-nul-stdin" "$test_log"
assert_contains "helper:container-finalize docker --batch-id $batch_id --exit-code 0 --target-argv-nul-stdin" "$test_log"

# Without a helper, every rm/rmi/remove/prune/down spelling is blocked, even
# with namespace/global/compose options and combined destructive flags.
make_fixture docker "$script_dir/docker-wrapper"
rm -f "$real_bin/shit-helper"
expect_status 125 "$wrapper_bin/docker" rm -fv victim
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" --context local container rm -fv victim
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" image remove -f example:old
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" system prune -af
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" stack rm demo
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" --debug service rm api
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" swarm leave --force
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" compose -f stack.yml --project-name demo down --remove-orphans
assert_not_contains "runtime:docker:" "$test_log"

# With no helper, only an exact read-only allow-list remains transparent.
# Creation/unknown verbs default to refusal; destructive-looking target/option
# values on a recognized read verb do not trigger the fallback gate.
reset_case
expect_status 125 "$wrapper_bin/docker" run --rm busybox true
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" frobnicate target
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/docker" inspect rm
assert_contains "runtime:docker:inspect rm" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/docker" --context rm ps
assert_not_contains "runtime:docker:" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/docker" ps
assert_contains "runtime:docker:ps" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/docker" image inspect remove
assert_contains "runtime:docker:image inspect remove" "$test_log"

# Podman has no positive mutation capability in this release. Even a
# syntactically current token from a mismatched helper cannot widen it.
make_fixture podman "$script_dir/podman-wrapper"
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/podman" rmi --no-prune example:old
assert_not_contains "helper:" "$test_log"
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/podman" image inspect rm
assert_contains "runtime:podman:image inspect rm" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/podman" image inspect rm
assert_not_contains "runtime:podman:" "$test_log"
rm -f "$real_bin/shit-helper"
reset_case
expect_status 125 "$wrapper_bin/podman" image prune -af
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" pod rm -af doomed-pod
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" --remote machine rm dev
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" secret rm token
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" manifest rm index
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" kube down app.yml
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" system reset --force
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" untag example:old
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 125 "$wrapper_bin/podman" run --rm busybox true
assert_not_contains "runtime:podman:" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/podman" image inspect rm
assert_contains "runtime:podman:image inspect rm" "$test_log"

# Standalone Compose is independently read-only in this release. Destructive
# argv never reach either helper or runtime, and helper tokens cannot widen it.
make_fixture docker-compose "$script_dir/docker-compose-wrapper"
expect_status 125 "$wrapper_bin/docker-compose" -f stack.yml down
assert_not_contains "helper:" "$test_log"
assert_not_contains "runtime:docker-compose:" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/docker-compose" ps down
assert_contains "runtime:docker-compose:ps down" "$test_log"
reset_case
HELPER_PREPARE_TOKEN=$token
export HELPER_PREPARE_TOKEN
expect_status 125 "$wrapper_bin/docker-compose" ps
assert_not_contains "runtime:docker-compose:" "$test_log"
rm -f "$real_bin/shit-helper"
reset_case
expect_status 125 "$wrapper_bin/docker-compose" -fstack.yml -pdemo down
assert_not_contains "runtime:docker-compose:" "$test_log"
reset_case
expect_status 0 "$wrapper_bin/docker-compose" ps down
assert_contains "runtime:docker-compose:ps down" "$test_log"

echo "container wrapper protocol tests: ok"
