#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: backup-and-modify-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.15 smoke — admin "back-up-before-edit" pattern:
#   cp foo foo.bak && sed -i 's/old/new/' foo
#
# Two mutations in one command window:
#   - cp creates foo.bak (TreeOp::Create at out-of-watch dst, or
#     in-watch Create via kqueue dir-diff if dst is in cwd).
#   - sed -i atomic-rename overwrites foo (Rename + PreImage).
#
# Undo should compositionally reverse both:
#   - Unlink foo.bak.
#   - RestoreContent on foo (back to pre-sed bytes).
#
# Both ops individually have working smokes (cp-recursive-undo,
# sed-inline-undo); this verifies they compose.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: backup-and-modify-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
FOO="${WATCHED}/foo.conf"
BAK="${WATCHED}/foo.conf.bak"
printf 'key=old\nother=keep\n' > "${FOO}"
PRE_FOO_SHA="$(/sbin/sha256 -q "${FOO}")"
[ ! -e "${BAK}" ] || smoke_fail "${BAK} already exists pre-cmd"
smoke_log "pre-cmd: foo sha=${PRE_FOO_SHA}; bak absent"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload: backup then in-place edit, in a single bash -c so
# both ops carry the LD_PRELOAD into a child bash that inherits it
# for cp + sed.
smoke_log "bash -c 'cp foo.conf foo.conf.bak && sed -i \"\" s/old/new/ foo.conf'"
LD_PRELOAD="${SHIM_LIB}" bash -c \
    "cd '${WATCHED}' && cp foo.conf foo.conf.bak && sed -i '' s/old/new/ foo.conf"

# Sanity: both effects visible.
[ -f "${BAK}" ] || smoke_fail "cp didn't produce ${BAK}"
POST_BAK_SHA="$(/sbin/sha256 -q "${BAK}")"
[ "${POST_BAK_SHA}" = "${PRE_FOO_SHA}" ] || smoke_fail ".bak content mismatch (cp not byte-perfect?)"
grep -q '^key=new$' "${FOO}" || smoke_fail "sed didn't take effect on foo.conf"
POST_FOO_SHA="$(/sbin/sha256 -q "${FOO}")"
[ "${POST_FOO_SHA}" != "${PRE_FOO_SHA}" ] || smoke_fail "sed didn't change foo.conf content"
smoke_log "post-cmd: foo sha=${POST_FOO_SHA}; bak sha=${POST_BAK_SHA}"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Invariants:
#   1. undo_rc=0
#   2. foo.conf back to pre-bytes
#   3. foo.conf.bak removed
failures=()
[ "${UNDO_RC}" -eq 0 ] || failures+=("undo exited ${UNDO_RC}")
if [ -f "${FOO}" ]; then
    FINAL_FOO_SHA="$(/sbin/sha256 -q "${FOO}")"
    [ "${FINAL_FOO_SHA}" = "${PRE_FOO_SHA}" ] \
        || failures+=("foo.conf not restored: ${FINAL_FOO_SHA} != ${PRE_FOO_SHA}")
else
    failures+=("foo.conf removed by undo (should have been restored, not unlinked)")
fi
[ ! -e "${BAK}" ] || failures+=("foo.conf.bak still present after undo")

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: backup-and-modify-undo-fbsd (cp + sed composed correctly)"
    exit 0
fi
smoke_fail "backup-and-modify undo incomplete: ${failures[*]}"
