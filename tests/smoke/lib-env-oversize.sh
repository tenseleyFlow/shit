# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared body for env-oversize-{linux,macos}.sh. Sourced after lib.sh.
#
# Issue #6: macOS caps AF_UNIX datagrams at net.local.dgram.maxdgram
# (2048 bytes), so a real env block (3-5 KB) never reached the daemon
# on the hook socket. `shit hook-send pre-exec-env` / `post-exec-env`
# now send frames over HOOK_DGRAM_MAX_FRAME through the ctl stream
# socket (CtlRequest::HookEnv). This drives that path with 6 KB blocks
# and asserts the daemon pairs them and journals an EnvDiff event.

smoke_env_oversize_run() {
    smoke_start_shitd

    local shit_bin="${SHIT_SMOKE_BIN_DIR}/shit"
    if [ ! -x "${shit_bin}" ]; then
        smoke_fail "shit binary missing at ${shit_bin}"
    fi

    local session pid
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    pid="$$"

    "${shit_bin}" hook-send session-open \
        --session "${session}" --pid "${pid}" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    "${shit_bin}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "${pid}" --cwd "$(pwd)" \
        --shell bash --wait-ready-ms 0 --sock "${SHIT_HOOK_SOCK}"

    local big
    big="$(python3 -c 'print("v" * 6000, end="")')"

    smoke_log "pre-exec-env: 6 KB block"
    printf 'SMOKE_BIG=%s\0SMOKE_KEEP=1' "${big}" \
        | "${shit_bin}" hook-send pre-exec-env \
            --session "${session}" --seq 1 --sock "${SHIT_HOOK_SOCK}" \
        || smoke_fail "hook-send pre-exec-env failed for a 6 KB block"

    "${shit_bin}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"

    smoke_log "post-exec-env: 6 KB block with one added var"
    printf 'SMOKE_BIG=%s\0SMOKE_KEEP=1\0SMOKE_ADDED=yes' "${big}" \
        | "${shit_bin}" hook-send post-exec-env \
            --session "${session}" --seq 1 --sock "${SHIT_HOOK_SOCK}" \
        || smoke_fail "hook-send post-exec-env failed for a 6 KB block"

    "${shit_bin}" hook-send session-close \
        --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    smoke_wait_for_event "discriminant = 'EnvDiff'" 1 10 \
        || smoke_fail "no EnvDiff event journaled: oversize env frames did not reach the daemon"

    # Both frames must have arrived on the ctl path, not the datagram.
    smoke_stop_shitd || true
    local logs
    logs="$(cat "${XDG_STATE_HOME}"/shit/log/daemon.jsonl* 2>/dev/null || true)"
    for want in 'pre-exec-env (ctl)' 'post-exec-env (ctl)'; do
        if ! printf '%s' "${logs}" | grep -qF "${want}"; then
            smoke_fail "daemon log has no '${want}' breadcrumb"
        fi
    done
}
