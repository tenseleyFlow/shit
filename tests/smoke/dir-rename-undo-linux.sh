#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# DR-CR-54 smoke — when a directory is renamed (mv dirA dirB)
# under an LD_PRELOAD'd command, the shim now captures
# per-file pre-images for every regular file in the source
# subtree and ships them as `extra_pre_images`. The daemon
# journals each as a FilePreImage event keyed to its original
# absolute path.
#
# This isolates the dir-rename plumbing from pip's much more
# complex flow (multiple renames + open(O_CREAT) churn). A
# pass here is the load-bearing signal that DR-CR-54 wired
# end-to-end; the pip smoke is the user-facing motivator.
#
# Verification surface:
#   1. Set up a 5-file subtree under <watched>/orig/
#   2. Run `mv <watched>/orig <watched>/staged` under shim
#   3. Confirm 5+ FilePreImage events in the journal keyed to
#      the ORIGINAL paths (under orig/, not staged/)
#   4. Run `shit undo --yes`; expect at least the renamed dir
#      to be re-placed and the per-file blobs available
#
# The actual byte-level restore of the subtree is gated on
# the planner's RestoreContent path — verified separately
# in unit tests. This smoke is the wire-path validation.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: dir-rename-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
cd "${WATCHED}"

# Build a 5-file subtree with predictable content (including a
# nested level — exercises the depth bookkeeping in the walker).
mkdir -p orig/sub
echo "alpha v1"   > orig/a.txt
echo "bravo v1"   > orig/b.txt
echo "charlie v1" > orig/c.txt
echo "delta v1"   > orig/sub/d.txt
echo "echo v1"    > orig/sub/e.txt
PRE_SHA_A="$(sha256sum orig/a.txt | awk '{print $1}')"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# THE workload — mv (rename) the directory. /bin/mv on most
# systems is a tiny C program that calls rename(2) for same-fs
# moves. Either spelling is fine; the shim catches both.
smoke_log "running: LD_PRELOAD=shim mv orig staged"
LD_PRELOAD="${SHIM_LIB}" mv orig staged
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

# Verify the journal has FilePreImage events for the ORIGINAL
# subtree paths (orig/*.txt, orig/sub/*.txt) — that's the
# DR-CR-54 signal.
N_PRE="$(smoke_journal_count "discriminant = 'FilePreImage' AND path LIKE '%/orig/%'" 2>/dev/null || echo 0)"
smoke_log "FilePreImage events under orig/: ${N_PRE}"
if [ "${N_PRE}" -lt 5 ]; then
    smoke_log "daemon log tail:"
    tail -50 "${SHIT_SMOKE_TMP}/state/shit/log/daemon.jsonl."* 2>/dev/null | sed 's/^/    /' >&2 || true
    smoke_fail "expected >= 5 FilePreImage events under orig/, got ${N_PRE}"
fi

# Confirm rename was journaled.
N_RENAME="$(smoke_journal_count "discriminant = 'TreeOpRename'" 2>/dev/null || echo 0)"
smoke_log "TreeOp::Rename events: ${N_RENAME}"
if [ "${N_RENAME}" -lt 1 ]; then
    smoke_fail "expected the dir rename to be journaled"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: dir-rename-undo-linux (${N_PRE} per-file pre-images journaled for the renamed subtree)"
