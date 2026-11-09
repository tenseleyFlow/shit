#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: shared-cwd-mark-fanotify-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# #254: two commands share one cwd on the fanotify-perm tier. fanotify
# keeps one mark per (group, inode), so both commands' WatchTree land on
# the same mark. Command B (a short command in another shell) starts and
# finishes while command A is still running. A then overwrites a file in
# the cwd. Before the fix, B's UnwatchTree removed the shared mark and
# A's write went uncaptured: no FilePreImage, and undo could not restore
# the file. With the mark refcounted per (dev, ino), A's pre-image is
# captured and undo restores it.
#
# Also checks #235 on this tier: the handshake reports "fanotify".

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: shared-cwd-mark-fanotify-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

set +e
smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
set -e
[ "${caps_rc}" -eq 2 ] && exit 0
[ "${caps_rc}" -eq 0 ] || exit 1
export SHIT_FORCE_TIER=fanotify-perm

smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
FOO="${SCRATCH}/foo.txt"
printf 'shared-cwd-mark canary\n' >"${FOO}"
EXPECTED_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
cd "${SCRATCH}"

# Command B's root process: a sleeper whose cwd is SCRATCH, standing in
# for `ls` run from a second shell in the same directory.
sleep 120 >/dev/null 2>&1 &
B_PID=$!
trap 'kill "${B_PID}" 2>/dev/null || true; smoke_cleanup' EXIT

SESSION_A="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SESSION_B="$(python3 -c 'import uuid; print(uuid.uuid4())')"
TTY="$(tty 2>/dev/null || echo /dev/null)"

"${SHIT_BIN}" hook-send session-open --session "${SESSION_A}" --pid "$$" \
    --shell bash --tty "${TTY}" --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send session-open --session "${SESSION_B}" --pid "${B_PID}" \
    --shell bash --tty "${TTY}" --sock "${SHIT_HOOK_SOCK}"

# B starts first so A is the most recent command for `shit undo`.
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION_B}" --seq 1 --pid "${B_PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION_A}" --seq 1 --pid "$$" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# B finishes while A is still running. Its UnwatchTree must leave the
# shared mark in place.
"${SHIT_BIN}" hook-send post-exec --session "${SESSION_B}" --seq 1 --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

printf 'overwritten by command A\n' | tee "${FOO}" >/dev/null
sleep 0.5

"${SHIT_BIN}" hook-send post-exec --session "${SESSION_A}" --seq 1 --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# The load-bearing assertion: A's overwrite was captured after B left.
smoke_wait_for_event "discriminant = 'FilePreImage' AND path = '${FOO}'" 1 10

metrics_out="$("${SHIT_BIN}" metrics 2>&1)"
if ! grep -q "kernel tier .* fanotify" <<<"${metrics_out}"; then
    smoke_fail "expected 'kernel tier ... fanotify' in metrics; got:
${metrics_out}"
fi

"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}
GOT_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
if [ "${GOT_SHA}" != "${EXPECTED_SHA}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "foo.txt not restored: expected ${EXPECTED_SHA}, got ${GOT_SHA}"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION_A}" --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send session-close --session "${SESSION_B}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: shared-cwd-mark-fanotify-linux (A captured after B unwatched the shared cwd)"
