#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.20 smoke — `rm foo` when foo has a hardlink alias (`bar`)
# pointing to the same inode. Undo must restore foo as a HARDLINK
# (not a fresh-inode copy) so the foo↔bar relationship survives.
#
# Pre: foo + bar share inode (nlink=2 via `ln foo bar`).
# Cmd: `rm foo`. Post: bar alone, nlink=1.
# Undo (expected): `link(bar, foo)` — foo back, same inode as bar,
#   nlink=2 again.
#
# Why this matters: `cp -al` (archive with hardlinks),
# `git worktree`-style aliasing, time-machine-style snapshots,
# and rsync with --link-dest all rely on hardlinks. Undo that
# silently de-aliases inodes (giving foo a NEW inode) breaks the
# invariant and wastes the storage savings.
#
# Documented gap: crates/shit-planner/src/executors/file.rs:113
# ("Not yet hardlink-aware: when the target has nlink > 1 the
# rename breaks the hardlink relationship.").

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: hardlink-rm-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
FOO="${WATCHED}/foo.txt"
BAR="${WATCHED}/bar.txt"
printf 'shared content via hardlink\n' > "${FOO}"
ln "${FOO}" "${BAR}"  # hardlink — bar now shares foo's inode

FOO_INODE_PRE="$(/usr/bin/stat -f '%i' "${FOO}")"
BAR_INODE_PRE="$(/usr/bin/stat -f '%i' "${BAR}")"
NLINK_PRE="$(/usr/bin/stat -f '%l' "${FOO}")"
PRE_SHA="$(/sbin/sha256 -q "${FOO}")"
[ "${FOO_INODE_PRE}" = "${BAR_INODE_PRE}" ] || smoke_fail "setup: foo and bar inodes differ (${FOO_INODE_PRE} vs ${BAR_INODE_PRE})"
[ "${NLINK_PRE}" = "2" ] || smoke_fail "setup: nlink is ${NLINK_PRE}, want 2"
smoke_log "pre-cmd: inode=${FOO_INODE_PRE} nlink=${NLINK_PRE} sha=${PRE_SHA}"

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

# THE workload: rm foo. bar is the surviving alias.
smoke_log "rm ${FOO}"
rm "${FOO}"
[ ! -e "${FOO}" ] || smoke_fail "rm didn't take effect"
NLINK_POST_CMD="$(/usr/bin/stat -f '%l' "${BAR}")"
[ "${NLINK_POST_CMD}" = "1" ] || smoke_fail "post-rm nlink=${NLINK_POST_CMD}, want 1"
smoke_log "post-cmd: foo gone; bar nlink=${NLINK_POST_CMD} inode=${BAR_INODE_PRE}"

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

failures=()
[ "${UNDO_RC}" -eq 0 ] || failures+=("undo exited ${UNDO_RC}")
if [ ! -e "${FOO}" ]; then
    failures+=("foo not restored by undo")
else
    FOO_INODE_POST="$(/usr/bin/stat -f '%i' "${FOO}")"
    BAR_INODE_POST="$(/usr/bin/stat -f '%i' "${BAR}")"
    NLINK_POST="$(/usr/bin/stat -f '%l' "${FOO}")"
    smoke_log "post-undo: foo inode=${FOO_INODE_POST} bar inode=${BAR_INODE_POST} nlink=${NLINK_POST}"
    [ "${FOO_INODE_POST}" = "${BAR_INODE_POST}" ] \
        || failures+=("undo broke hardlink: foo inode=${FOO_INODE_POST} ≠ bar inode=${BAR_INODE_POST}")
    [ "${NLINK_POST}" = "2" ] \
        || failures+=("nlink=${NLINK_POST}, want 2")
    POST_SHA="$(/sbin/sha256 -q "${FOO}")"
    [ "${POST_SHA}" = "${PRE_SHA}" ] \
        || failures+=("content drift: sha=${POST_SHA}, want ${PRE_SHA}")
fi

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: hardlink-rm-undo-fbsd (foo restored as hardlink, nlink=2)"
    exit 0
fi
smoke_fail "hardlink-rm undo incomplete: ${failures[*]}"
