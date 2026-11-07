#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: non-utf8-cwd-capture-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice A review — a non-UTF-8 cwd must keep its pre-images with the
# strict flag off.
#
# The hook's cwd crosses the wire as a lossy string, so a Latin-1
# directory arrives with U+FFFD in it and cannot be resolved. The helper
# falls back to /proc/<pid>/cwd, which is how trunk found the watch root.
#
# Validate-the-gap: with the fallback removed the command journals no
# FilePreImage at all, on both the LSM and fanotify tiers.
#
# This pins capture only. Undo restores into a sibling spelled with
# U+FFFD on trunk as well, because captured paths are lossy strings too.
# The assertion accepts either location until paths carry bytes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: non-utf8-cwd-capture-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_FORCE_TIER="${SHIT_FORCE_TIER:-ebpf-lsm}"

WATCH="${SHIT_SMOKE_TMP}/caf"$'\xe9'
mkdir -p "${WATCH}"
printf 'keep me\n' > "${WATCH}/victim"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

cd "${WATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${PWD}" --shell bash --cmdline "rm victim" \
    --sock "${SHIT_HOOK_SOCK}"

rm victim
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
REFUSED="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
[ "${REFUSED}" -eq 0 ] || smoke_fail "flag off must not journal a refusal, got ${REFUSED}"

"${SHIT_BIN}" undo --yes 2>&1 | sed 's/^/    /' >&2
cd "${SHIT_SMOKE_TMP}"

# Accepts the lossy sibling; see the header.
RESTORED="$(find "${SHIT_SMOKE_TMP}" -maxdepth 2 -type f -name victim -print -quit)"
[ -n "${RESTORED}" ] || smoke_fail "undo restored no victim anywhere under the smoke root"
[ "$(cat "${RESTORED}")" = "keep me" ] || smoke_fail "restored victim has the wrong content"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: non-utf8-cwd-capture-linux"
