#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: mmap-write-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# L04.2 smoke — mmap-based in-place content overwrite.
#
# Trigger shape: Python's `mmap.mmap(fd, length, MAP_SHARED)` over
# a file opened r+b, then write into the mapped region. The
# writes commit via the page cache; no write(2) syscall fires.
# After munmap + close, the kernel's struct-file refcount hits
# zero AND `lsm/file_release` fires. The L04.2 handler diffs
# content against the open-time snapshot and emits a
# CapturedPreImage if they differ.
#
# Important: `file_release` only fires after BOTH the mmap is
# unmapped AND the underlying fd is closed. A program that
# munmaps but never closes (or vice versa) defers release. This
# smoke covers the mmap-then-munmap-then-close happy path. Long-
# held mmaps are documented as v1 limitation in the sprint spec.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: mmap-write-undo-linux is Linux-only"
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

PRE_CONTENT="mmap-pre L04.2 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
FOO="${SCRATCH}/mmap.txt"
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

# The workload: mmap MAP_SHARED, mutate via memory access, msync,
# munmap, close. This is the persistent-mmap shape used by
# sqlite, Postgres shared buffers in test mode, etc.
smoke_log "python mmap MAP_SHARED in-place write"
python3 -c "
import mmap
with open('${FOO}', 'r+b') as f:
    mm = mmap.mmap(f.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
    mm[0:6] = b'MMAP_!'
    mm.flush()
    mm.close()
"

POST_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
POST_SIZE="$(stat -c '%s' "${FOO}")"
if [ "${POST_SHA}" = "${PRE_SHA}" ]; then
    smoke_fail "mmap write didn't change content"
fi
if [ "${POST_SIZE}" != "${PRE_SIZE}" ]; then
    smoke_log "size unexpectedly changed: pre=${PRE_SIZE} post=${POST_SIZE}"
fi
smoke_log "mmap write landed: sha=${POST_SHA:0:12} size=${POST_SIZE}"

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
    smoke_fail "mmap.txt missing after undo"
fi
GOT_SHA="$(sha256sum "${FOO}" | cut -d' ' -f1)"
if [ "${GOT_SHA}" != "${PRE_SHA}" ]; then
    smoke_log "expected sha=${PRE_SHA}"
    smoke_log "got      sha=${GOT_SHA}"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "mmap write not reverted (content sha mismatch)"
fi
smoke_log "mmap write reverted: sha matches pre-write"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: mmap-write-undo-linux (${NUM_PRE} pre-images captured)"
