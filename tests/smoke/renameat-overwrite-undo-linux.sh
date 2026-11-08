#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: renameat-overwrite-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# #222 and L5 PR B: `renameat(dirfd, ".x.tmp", dirfd, "x")` over an
# existing file, the atomic-save shape, under the shim. The journal
# must hold the Rename (from\tto), the destination's pre-image, the
# call's RenameCall and its RenameOutcome under one call id. A second
# renameat that fails (onto a non-empty directory) must leave no
# reverse rename. Undo puts `x` back to its old bytes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: renameat-overwrite-undo-linux is Linux-only (uname=$(uname -s))"
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
mkdir -p "${WATCHED}/full"
cd "${WATCHED}"
echo "old bytes" > x
echo "new bytes" > .x.tmp
echo "keep" > full/inside
echo "y" > y

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

# os.rename with dir_fd is renameat(2) with a real dirfd.
smoke_log "running: renameat(.x.tmp -> x) and a failing renameat(y -> full)"
LD_PRELOAD="${SHIM_LIB}" python3 - "${WATCHED}" <<'PY'
import errno, os, sys
d = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
os.rename(".x.tmp", "x", src_dir_fd=d, dst_dir_fd=d)
try:
    os.rename("y", "full", src_dir_fd=d, dst_dir_fd=d)
except OSError as e:
    assert e.errno in (errno.EISDIR, errno.ENOTEMPTY, errno.EEXIST), e
else:
    raise SystemExit("rename onto a non-empty directory succeeded")
PY
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

N_RENAME="$(smoke_journal_count "discriminant = 'TreeOpRename' AND path LIKE '%/watched/x'" 2>/dev/null || echo 0)"
N_PRE="$(smoke_journal_count "discriminant = 'FilePreImage' AND path LIKE '%/watched/x'" 2>/dev/null || echo 0)"
N_CALL="$(smoke_journal_count "discriminant = 'RenameCall'" 2>/dev/null || echo 0)"
N_OUT="$(smoke_journal_count "discriminant = 'RenameOutcome'" 2>/dev/null || echo 0)"
smoke_log "Rename onto x: ${N_RENAME}; pre-images of x: ${N_PRE}; RenameCall: ${N_CALL}; RenameOutcome: ${N_OUT}"
[ "${N_RENAME}" -ge 1 ] || smoke_fail "renameat over x not journaled as TreeOp::Rename (#222)"
[ "${N_PRE}" -ge 1 ]    || smoke_fail "x's old bytes not captured"
[ "${N_CALL}" -ge 2 ]   || smoke_fail "expected a RenameCall for each renameat, got ${N_CALL}"
[ "${N_OUT}" -ge 2 ]    || smoke_fail "expected a RenameOutcome for each renameat, got ${N_OUT}"

smoke_log "running: shit undo --yes"
UNDO_OUT="$("${SHIT_BIN}" undo --yes 2>&1 || true)"
echo "${UNDO_OUT}" | sed 's/^/    /' >&2
echo "${UNDO_OUT}" | grep -q "conflicts=0" || smoke_fail "undo reported conflicts"
[ "$(cat x)" = "old bytes" ] || smoke_fail "x not restored: $(cat x)"
[ -f y ] || smoke_fail "the failed rename's source was moved by undo"
[ "$(cat full/inside)" = "keep" ] || smoke_fail "full/ changed"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: renameat-overwrite-undo-linux"
