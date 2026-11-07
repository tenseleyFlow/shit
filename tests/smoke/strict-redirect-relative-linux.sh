#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-redirect-relative-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice D — a relative redirect target resolves against the shell's
# working directory, not the daemon's.
#
# The shell sits in <tmp>/sub and runs `echo x > ../out`. The hook sends
# the pre-stash request from the shell's cwd. Before slice D the raw
# string "../out" reached the daemon, which stat'd it against its own
# cwd and stashed nothing, so the truncated bytes were unrecoverable.
#
# Both phases must restore the original bytes. The fix is unconditional,
# so it runs with SHIT_STRICT_CAPTURE=1 and with the flag unset.
#
# Validate-the-gap: on trunk the daemon is started from a different
# directory, "../out" resolves to nothing there, and undo cannot restore.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-redirect-relative-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

ORIGINAL='original content from before the redirect'

run_phase() {
    local label="$1"
    local root="${SHIT_SMOKE_TMP}/${label}"
    local probe="${root}/out"
    mkdir -p "${root}/sub"
    root="$(cd "${root}" && pwd -P)"
    printf '%s\n' "${ORIGINAL}" > "${probe}"
    local pre_sha
    pre_sha="$(sha256sum "${probe}" | awk '{print $1}')"

    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"

    cd "${root}/sub"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "$$" \
        --cwd "${root}/sub" --shell bash --sock "${SHIT_HOOK_SOCK}"
    sleep 0.5
    # The hook runs in the shell's cwd (<root>/sub).
    "${SHIT_BIN}" hook-send pre-exec-redirects \
        --session "${session}" --seq 1 \
        --cmdline "echo x > ../out" \
        --sock "${SHIT_HOOK_SOCK}"
    sleep 0.3
    echo "overwritten by the redirect" > ../out
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    cd "${SHIT_SMOKE_TMP}"
    sleep 1.0

    [ "$(sha256sum "${probe}" | awk '{print $1}')" != "${pre_sha}" ] \
        || smoke_fail "[${label}] workload did not change the probe"
    smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
    # The journaled path is the normalized absolute one, the same string
    # the kernel tiers record, with no "sub/.." component left in it.
    local want="${root}/out"
    if [ "$(smoke_journal_count "discriminant = 'FilePreImage' AND path = '${want}'")" -lt 1 ]; then
        smoke_log "[${label}] FilePreImage paths:"
        smoke_journal_query "SELECT path FROM events WHERE discriminant = 'FilePreImage';" >&2 || true
        smoke_fail "[${label}] pre-image is not keyed to ${want}"
    fi

    set +e
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/${label}.undo.log" 2>&1
    local rc=$?
    set -e
    smoke_log "[${label}] shit undo --yes exit=${rc}"
    sed 's/^/    undo: /' "${SHIT_SMOKE_TMP}/${label}.undo.log" >&2 || true
    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    local post_sha
    post_sha="$(sha256sum "${probe}" | awk '{print $1}')"
    [ "${post_sha}" = "${pre_sha}" ] \
        || smoke_fail "[${label}] relative redirect target was not restored (sha ${post_sha:0:16} vs ${pre_sha:0:16})"
    smoke_log "[${label}] probe restored byte-identical"
}

# The daemon starts in a directory unrelated to the shell's.
cd /

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
run_phase strict
smoke_stop_shitd

unset SHIT_STRICT_CAPTURE
smoke_start_shitd
run_phase default

smoke_log "PASS: strict-redirect-relative-linux (relative target restored in strict and default)"
