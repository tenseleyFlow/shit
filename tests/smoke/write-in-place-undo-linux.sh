#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: write-in-place-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L04.2 smoke — in-place content overwrite via `open(O_RDWR) +
# write` (no truncate, no rename, no unlink).
#
# Trigger shape: Python's `open(path, "r+b")` opens with O_RDWR
# (no O_TRUNC). A subsequent .write() mutates the file's content
# in place. After close, the kernel fires `lsm/file_release`
# which the helper's L04.2 handler hooks to re-hash and emit a
# CapturedPreImage iff content changed.
#
# Pre-L04.2 capture path: `lsm/file_open` ALSO fires on O_RDWR
# opens (BPF filter is FMODE_WRITE, not specifically O_TRUNC), so
# this workload may have been silently captured even before the
# release hook landed. L04.2's release handler is the safety net
# for cases where file_open's dedupe gets jumped (rare) or where
# the file isn't in pre_snapshots at open time (created mid-
# session). Either way, this smoke gates that the workload's
# undo path stays green.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: write-in-place-undo-linux is Linux-only"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "SKIP: python3 missing on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
if ! printf '%s' "${HELPER_CAPS}" | grep -q cap_sys_admin; then
    smoke_log "FAIL: helper lacks cap_sys_admin (getcap: '${HELPER_CAPS}')"
    smoke_log "  sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${HELPER_BIN}"
    exit 1
fi

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

PRE_CONTENT="before-bytes L04.2 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
FOO="${SCRATCH}/inplace.txt"
printf '%s\n' "${PRE_CONTENT}" >"${FOO}"
PRE_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
PRE_SIZE="$(stat -c '%s' "${FOO}")"
smoke_log "wrote ${FOO} sha256=${PRE_SHA:0:12} size=${PRE_SIZE}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# The workload: open r+b (O_RDWR, no O_TRUNC), seek to a non-zero
# offset, overwrite some bytes in the middle, close. This is the
# canonical "edit-in-place" shape that no rename/unlink/setattr
# capture handler observes.
smoke_log "python in-place write (r+ mode, no truncate)"
python3 -c "
with open('${FOO}', 'r+b') as f:
    f.seek(7)
    f.write(b'AFTER-')
"

POST_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
POST_SIZE="$(stat -c '%s' "${FOO}")"
if [ "${POST_SHA}" = "${PRE_SHA}" ]; then
    smoke_fail "in-place write didn't change content (sha matches pre-write)"
fi
if [ "${POST_SIZE}" != "${PRE_SIZE}" ]; then
    smoke_log "size changed unexpectedly: pre=${PRE_SIZE} post=${POST_SIZE}"
    smoke_log "(in-place 'AFTER-' at offset 7 should preserve length)"
fi
smoke_log "in-place write landed: sha=${POST_SHA:0:12} size=${POST_SIZE}"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
NUM_PRE="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events: ${NUM_PRE}"

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo exited non-zero"
}

if [ ! -f "${FOO}" ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "inplace.txt missing after undo"
fi
GOT_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
if [ "${GOT_SHA}" != "${PRE_SHA}" ]; then
    smoke_log "expected sha=${PRE_SHA}"
    smoke_log "got      sha=${GOT_SHA}"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "in-place write not reverted (content sha mismatch)"
fi
smoke_log "in-place write reverted: sha matches pre-write"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: write-in-place-undo-linux (${NUM_PRE} pre-images captured)"
