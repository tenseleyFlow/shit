#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cp-r-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR01.3 smoke — `cp -r src dst` then `shit undo` removes dst entirely
# while leaving src byte-identical. Linux mirror of W03's
# `cp-recursive-undo-fbsd.sh`.
#
# Exercises (bulk-creates stress test on the LSM tier):
#   1. `inode_mkdir` + `inode_create` fire for every new path under
#      dst/ in rapid succession. AR01.4's strict path resolver
#      (capture/linux.rs:resolve_via_parent — no watch-root fallback)
#      requires the parent's (dev, inode) to be in `ws.dir_paths`
#      BEFORE the child's create handler runs. The per-program ringbuf
#      readers (spawn_mkdir + spawn_create in ringbuf_reader.rs) run
#      on separate threads serialized via Mutex<runtime>, so kernel-
#      syscall ordering does NOT guarantee userspace dispatch ordering.
#      If the create handler wins the mutex first for a nested file,
#      it'll drop with "parent_inode not in dir_paths" → no
#      TreeOpCreate → no Unlink inverse → orphan post-undo.
#
#      The "NUM_CREATES >= 6" assertion below detects exactly this
#      race. Don't trust the orchestrator's `remove_dir_all`
#      fallback (W01.B follow-up) to paper over capture-side drops:
#      surface them.
#
#   2. AR01.1's dedupe-on-create (handle_lsm_create marks dedupe as
#      captured) suppresses file_open's redundant FilePreImage for
#      these fresh files. Without it the journal would also carry
#      ~3 spurious empty-content FilePreImages.
#
# Tier: LSM. fanotify-perm has no create-then-write-zero-bytes
# coverage; we'd see the open events but the planner couldn't tell
# the files were newly created (no `inode_create` analog). Wired
# under LSM_SMOKES for the same reason as the other AR01 smokes.
#
# Inheritance from AR00 / AR01.1 / AR01.4:
#   - `WaitWatchReady` removes the pre-cmd settle sleep.
#   - Strict path resolver (no watch-root fallback) — failure mode
#     here is the load-bearing concern.
#   - dedupe-on-create — load-bearing.
#
# Linux-only.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: cp-r-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

CP_BIN="$(command -v cp || true)"
if [ -z "${CP_BIN}" ]; then
    smoke_log "SKIP: cp not on PATH"
    exit 0
fi
smoke_log "cp: ${CP_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight: helper caps.
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing on this system; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
if ! printf '%s' "${HELPER_CAPS}" | grep -q cap_sys_admin; then
    smoke_log "FAIL: helper lacks cap_sys_admin (getcap output: '${HELPER_CAPS}')"
    smoke_log ""
    smoke_log "  Run this on the box first, then re-run the smoke:"
    smoke_log "    sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${HELPER_BIN}"
    exit 1
fi
smoke_log "helper has caps: ${HELPER_CAPS}"

# Build the tree shape we'll copy. Small, deterministic; 3 files
# spread across a top-level + two subdirs. Total 6 paths created at
# cp-time (3 files + 2 subdirs + 1 top-level dst).
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}/src/sub1" "${SCRATCH}/src/sub2"
printf 'alpha\n' > "${SCRATCH}/src/a.txt"
printf 'beta\n'  > "${SCRATCH}/src/sub1/b.txt"
printf 'gamma\n' > "${SCRATCH}/src/sub2/c.txt"

# Snapshot src state — we'll verify it survives undo byte-identical.
PRE_SRC_LIST="$(cd "${SCRATCH}/src" && find . -mindepth 1 | sort)"
# Aggregate content hash: catches any single-file change AND any
# tree-shape change (find list shape is captured separately).
PRE_SRC_AGG="$(cd "${SCRATCH}/src" && find . -type f | sort | xargs -I{} sha256sum {} | sha256sum | cut -d' ' -f1)"
smoke_log "pre-cmd src tree (relative paths):"
echo "${PRE_SRC_LIST}" | sed 's/^/    /'
smoke_log "pre-cmd src aggregate sha256=${PRE_SRC_AGG}"

# dst MUST NOT exist pre-command.
if [ -e "${SCRATCH}/dst" ]; then
    smoke_fail "scratch/dst exists pre-command; setup is broken"
fi

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# PreExec blocks on WaitWatchReady (AR00.5) — no settle sleep needed.
smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# THE workload.
smoke_log "cp -r src dst"
"${CP_BIN}" -r src dst
CP_RC=$?
smoke_log "cp exit=${CP_RC}"
if [ "${CP_RC}" -ne 0 ]; then
    smoke_fail "cp -r failed pre-undo (rc=${CP_RC}) — workload setup broken"
fi

# Confirm dst was actually created with the expected tree shape.
POST_CMD_DST_LIST="$(cd dst && find . -mindepth 1 | sort)"
if [ "${POST_CMD_DST_LIST}" != "${PRE_SRC_LIST}" ]; then
    smoke_log "post-cmd dst tree (relative paths):"
    echo "${POST_CMD_DST_LIST}" | sed 's/^/    /'
    smoke_fail "cp -r produced a different tree shape than src — workload itself is broken"
fi
smoke_log "post-cmd dst tree matches src layout"

# Let LSM events propagate. Matches the AR01.1/AR01.4 budget.
sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. cp -r emits ~6+ events; we accept
# at least one TreeOpCreate as evidence the capture pipeline saw the
# workload.
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10

NUM_CREATES="$(smoke_journal_count "discriminant = 'TreeOpCreate'")"
smoke_log "TreeOpCreate events in journal: ${NUM_CREATES}"

# Capture-pipeline correctness check: cp -r src dst on the 3-file
# 2-subdir source MUST produce 6 TreeOpCreate events (1 for dst + 3
# files + 2 sub-dirs). Without this assertion, capture could silently
# drop events (e.g. the AR01.4 strict-resolver race when
# handle_lsm_create wins the mutex ahead of handle_lsm_mkdir for its
# parent) and undo would only succeed via the orchestrator's
# remove_dir_all fallback — papering over a real bug. Surface the
# gap directly.
if [ "${NUM_CREATES}" -lt 6 ]; then
    smoke_log "journal contents (only ${NUM_CREATES} TreeOpCreate events, expected >= 6):"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "capture missed ${NUM_CREATES}/6 expected TreeOpCreate events"
fi

# Run undo.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_log "scratch dir state:"
    find "${SCRATCH}" -maxdepth 4 2>/dev/null | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: dst is GONE.
if [ -e "${SCRATCH}/dst" ]; then
    smoke_log "dst still exists post-undo:"
    find "${SCRATCH}/dst" 2>/dev/null | sed 's/^/    /' >&2 || true
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal events:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "dst not removed by undo — recursive unlink incomplete"
fi
smoke_log "dst removed: ${SCRATCH}/dst is gone"

# Assertion 2: src is BYTE-IDENTICAL.
POST_UNDO_SRC_LIST="$(cd "${SCRATCH}/src" && find . -mindepth 1 | sort)"
if [ "${POST_UNDO_SRC_LIST}" != "${PRE_SRC_LIST}" ]; then
    smoke_log "src tree shape changed by undo:"
    smoke_log "  was: ${PRE_SRC_LIST}"
    smoke_log "  now: ${POST_UNDO_SRC_LIST}"
    smoke_fail "src tree perturbed — undo touched what it shouldn't have"
fi
POST_UNDO_SRC_AGG="$(cd "${SCRATCH}/src" && find . -type f | sort | xargs -I{} sha256sum {} | sha256sum | cut -d' ' -f1)"
if [ "${POST_UNDO_SRC_AGG}" != "${PRE_SRC_AGG}" ]; then
    smoke_log "src content changed: expected agg=${PRE_SRC_AGG} got agg=${POST_UNDO_SRC_AGG}"
    smoke_fail "src content perturbed — undo touched file contents it shouldn't have"
fi
smoke_log "src intact: tree shape + aggregate content sha match pre-command"

# Assertion 3: scratch contains ONLY src/ (no orphans).
SCRATCH_ENTRIES="$(cd "${SCRATCH}" && find . -mindepth 1 -maxdepth 1 | sort)"
EXPECTED_ENTRIES="./src"
if [ "${SCRATCH_ENTRIES}" != "${EXPECTED_ENTRIES}" ]; then
    smoke_log "scratch dir has unexpected entries:"
    echo "${SCRATCH_ENTRIES}" | sed 's/^/    /'
    smoke_fail "scratch dir contains orphans post-undo"
fi
smoke_log "scratch dir clean: only src/ remains"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: cp-r-undo-linux (dst removed, src byte-identical, ${NUM_CREATES} TreeOpCreate events captured)"
