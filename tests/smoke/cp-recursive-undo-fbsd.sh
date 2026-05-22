#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W03 smoke — `cp -r src dst` then `shit undo` removes dst entirely
# while leaving src byte-identical.
#
# Exercises (bulk-creates stress test):
#   1. S29.2 (new-file auto-add on dir NOTE_WRITE) keeping pace with
#      cp's burst of mkdirs + opens. Without it, only the top-level
#      dst dir would register; everything inside would be invisible.
#   2. Live-baseline new-file path — dst/* didn't exist at session-
#      open, so the LiveBaseline cache has no entries. The
#      CapturedPreImage promote path must correctly fall through
#      (None → use helper's blob); the planner then emits TreeOp::
#      Create + (maybe) FilePreImage for each new path.
#   3. Cohort ordering at undo. The planner emits Unlink per created
#      path. Files must come off before their parent dirs. The file
#      executor's recursive remove_dir_all fallback (W01 follow-up)
#      catches any ENOTEMPTY race, but a clean undo report wants
#      cohorts in the right order.
#   4. After shit undo --yes: dst is gone, src is byte-identical,
#      no orphans.
#
# FreeBSD-only — kqueue producer + BSD smoke convention. Linux
# equivalent: cp-recursive-undo-linux.sh (per W03.L-linux.md,
# user-owned).
#
# See .docs/sprints/W/W03-cp-recursive-undo.md for the cross-platform
# spec and .docs/sprints/W/W03.B-bsd.md for execution notes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: cp-recursive-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

CP_BIN="$(command -v cp || echo /bin/cp)"
[ -x "${CP_BIN}" ] || smoke_fail "cp not found at /bin/cp"
smoke_log "cp: ${CP_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Build the tree shape we'll copy. Small, deterministic; 3 files
# spread across a top-level + two subdirs. Total 6 paths created
# at undo-removal time (3 files + 2 subdirs + 1 top-level dst).
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}/src/sub1" "${SCRATCH}/src/sub2"
printf 'alpha\n' > "${SCRATCH}/src/a.txt"
printf 'beta\n'  > "${SCRATCH}/src/sub1/b.txt"
printf 'gamma\n' > "${SCRATCH}/src/sub2/c.txt"

# Snapshot src state — we'll verify it survives undo byte-identical.
# `find -mindepth 1` skips the src dir itself, giving us the
# canonical relative-path tree shape.
PRE_SRC_LIST="$(cd "${SCRATCH}/src" && find . -mindepth 1 | sort)"
# Aggregate content hash: concatenate each file's sha then re-hash
# the concatenation. Catches any single-file change AND any tree-
# shape change (find list shape is captured separately).
PRE_SRC_AGG="$(cd "${SCRATCH}/src" && find . -type f | sort | xargs -I{} /sbin/sha256 -q {} | /sbin/sha256 -q)"
smoke_log "pre-cmd src tree (relative paths):"
echo "${PRE_SRC_LIST}" | sed 's/^/    /'
smoke_log "pre-cmd src aggregate sha256=${PRE_SRC_AGG}"

# dst MUST NOT exist before the command. The smoke fails loudly if
# it does because our undo assertions depend on dst being created
# entirely by the command under test.
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

smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Let the live-baseline walker finish populating src/* entries into
# the LiveBaseline cache before cp runs. The walk is async; on a
# 4-file scratch dir it's done in <100ms but we give it a beat.
sleep 0.5

# THE workload.
smoke_log "cp -r src dst"
"${CP_BIN}" -r src dst
CP_RC=$?
smoke_log "cp exit=${CP_RC}"
if [ "${CP_RC}" -ne 0 ]; then
    smoke_fail "cp -r failed pre-undo (rc=${CP_RC}) — workload setup broken"
fi

# Confirm dst was actually created with the expected tree shape.
# This isolates "did cp do what we expect" from "did capture see it".
POST_CMD_DST_LIST="$(cd dst && find . -mindepth 1 | sort)"
if [ "${POST_CMD_DST_LIST}" != "${PRE_SRC_LIST}" ]; then
    smoke_log "post-cmd dst tree (relative paths):"
    echo "${POST_CMD_DST_LIST}" | sed 's/^/    /'
    smoke_fail "cp -r produced a different tree shape than src — workload itself is broken"
fi
smoke_log "post-cmd dst tree matches src layout (${PRE_SRC_LIST//$'\n'/, })"

# Let kqueue NOTE_WRITE / NOTE_DELETE / NOTE_RENAME events propagate.
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. cp -r emits ~6+ events; we accept
# at least one TreeOpCreate as evidence the capture pipeline saw
# the workload. The undo will reveal whether ALL of them were
# captured (any missing → orphan files post-undo).
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10

NUM_CREATES="$(smoke_journal_count "discriminant = 'TreeOpCreate'")"
smoke_log "TreeOpCreate events in journal: ${NUM_CREATES}"
# Capture-pipeline correctness check: cp -r src dst on the 3-file
# 2-subdir source MUST produce 6 TreeOpCreate events (1 for dst + 3
# files + 2 sub-dirs). Without this, capture is silently
# dropping events and undo only succeeds because the file
# executor's recursive remove_dir_all fallback (W01.B) papers
# over the gap. Surface the gap; don't hide behind the safety net.
if [ "${NUM_CREATES}" -lt 6 ]; then
    smoke_log "journal contents (only ${NUM_CREATES} TreeOpCreate events):"
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
POST_UNDO_SRC_AGG="$(cd "${SCRATCH}/src" && find . -type f | sort | xargs -I{} /sbin/sha256 -q {} | /sbin/sha256 -q)"
if [ "${POST_UNDO_SRC_AGG}" != "${PRE_SRC_AGG}" ]; then
    smoke_log "src content changed: expected agg=${PRE_SRC_AGG} got agg=${POST_UNDO_SRC_AGG}"
    smoke_fail "src content perturbed — undo touched file contents it shouldn't have"
fi
smoke_log "src intact: tree shape + aggregate content sha match pre-command"

# Assertion 3: scratch contains ONLY src/ (no orphans from a
# partial undo, no leftover dst.tmp / .shit-tmp.* files).
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

smoke_log "PASS: cp-recursive-undo-fbsd (dst removed, src byte-identical, ${NUM_CREATES} TreeOpCreate events captured)"
