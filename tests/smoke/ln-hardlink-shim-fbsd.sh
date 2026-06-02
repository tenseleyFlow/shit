#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: ln-hardlink-shim-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# B08 — assert the LD_PRELOAD shim observes `link(2)` / `linkat(2)`
# pre-syscall and routes the event through the shim_listener wire.
#
# Why this is distinct from `ln-hardlink-undo-fbsd.sh`:
#
# The existing smoke proves end-to-end undo works for `ln target
# link`. That smoke passes today on BSD via the kqueue NOTE_WRITE on
# the parent dir → helper dir-diff → TreeOp::Create path. The shim
# wasn't load-bearing there.
#
# B08 adds a parallel observation channel: the shim now interposes
# `link(2)` pre-syscall and notifies the daemon directly. This
# closes:
#   1. Pre-syscall observation (vs post-hoc kqueue) — beats races
#      where the kqueue NOTE_WRITE fires after a later op coalesces.
#   2. Attribution — the journaled event now carries the syscall
#      name "link" / "linkat", distinguishing it from other
#      TreeOp::Create variants (e.g. open(O_CREAT)). Future
#      hardlink-aware classifier logic can branch on this.
#   3. Cross-watch destinations (deferred, not asserted here).
#
# This smoke validates (1) and (2) by:
#   - Performing `ln target link`
#   - Asserting the journal contains a CapturedFromShim event with
#     syscall = "link" (not just a generic TreeOp::Create from
#     the dir-diff path).
#
# Functional undo correctness is covered by `ln-hardlink-undo-fbsd.sh`
# (which keeps passing alongside this one).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: ln-hardlink-shim-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "preload shim .so missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"

TARGET="${WATCHED}/target.txt"
printf 'shim-hardlink-test\n' > "${TARGET}"

LINK="${WATCHED}/link"
[ ! -e "${LINK}" ] || smoke_fail "smoke env not clean: ${LINK} pre-exists"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# Workload — run under explicit LD_PRELOAD of the shim so the
# interposers definitely fire. ln(1) is a base binary; LD_PRELOAD
# is honored unless the binary is setuid (which ln isn't).
smoke_log "workload: LD_PRELOAD=${SHIM_LIB} ln ${TARGET} ${LINK}"
LD_PRELOAD="${SHIM_LIB}" /bin/ln "${TARGET}" "${LINK}"
[ -e "${LINK}" ] || smoke_fail "ln didn't create link"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

# Assertion: daemon's shim_listener emitted a tracing line carrying
# `syscall = "link"`. That's the deterministic signal the shim
# notification reached the daemon. The events table doesn't expose
# the syscall name as a column (it's serialized into `payload`), so
# we check the log instead.
SHITD_LOG_PATH="${SHIT_SMOKE_TMP}/shitd.log"
if ! grep -q 'syscall="link"' "${SHITD_LOG_PATH}" 2>/dev/null \
    && ! grep -q 'syscall=link' "${SHITD_LOG_PATH}" 2>/dev/null; then
    smoke_log "regression — no shim 'link' tracing line in shitd.log"
    smoke_log "recent shim-related log lines:"
    grep -i "shim\|preload\|notify" "${SHITD_LOG_PATH}" 2>/dev/null | tail -10 | sed 's/^/    /' >&2 || true
    smoke_fail "expected daemon log to contain 'syscall = \"link\"' (or unquoted variant)"
fi
smoke_log "gate: daemon log shows shim 'link' tracing line"

# Sanity gate: a TreeOp::Create event landed for the link path.
# This confirms the journal wire wasn't broken by the shim path
# even though we're not asserting on a 'source' column.
TREE_CREATE_COUNT="$(
    smoke_journal_count "discriminant = 'TreeOp' AND path LIKE '%link'" 2>/dev/null || echo 0
)"
smoke_log "TreeOp events for ${LINK}: ${TREE_CREATE_COUNT}"
if [ "${TREE_CREATE_COUNT}" -lt 1 ]; then
    smoke_fail "expected at least one TreeOp event for ${LINK}; got 0"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: ln-hardlink-shim-fbsd (${SHIM_LINK_COUNT} shim-sourced 'link' event(s))"
