#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: xattr-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.21 smoke — user-namespace xattr restore round-trip on FreeBSD.
#
# A file has a captured xattr (`user.shit.test=alpha`). The command
# under test changes the value to `beta`. After `shit undo` the value
# must read back as `alpha`. Reverse scenarios also covered: a fresh
# xattr set by the command (no baseline) must be removed by undo.
#
# Skipped if the working FS doesn't support EXTATTR_NAMESPACE_USER.
# ZFS supports user xattrs out of the box; UFS2 needs the `multilabel`
# flag, which the CI image doesn't carry. shit-fbsd is ZFS so it
# passes; the CI VM might not.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: xattr-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# W09.21.1 — xattr capture now runs daemon-side at BaselineCaptured
# ingest (helper can't because cap_enter blocks extattr_*_fd at the
# syscall level, not by per-fd rights — verified empirically on
# FreeBSD 14.4). The daemon is never cap_enter'd, so it reads the
# user-namespace xattrs of every cached file at session-open and
# stores them on the BaselineEntry. Baseline-promotion then carries
# them into FilePreImage's FileMetadata, where the planner's
# RestoreMetadata applies the diff. No SHIT_CAPSICUM=0 escape needed.

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"

FILE="${WATCHED}/data.txt"
printf 'content\n' > "${FILE}"

# Probe FS xattr support. If we can't set a user xattr on the working
# FS, skip — the smoke can't meaningfully assert restore.
if ! /usr/sbin/setextattr user shit.test alpha "${FILE}" 2>/dev/null; then
    smoke_log "SKIP: filesystem under ${SHIT_SMOKE_TMP} doesn't accept user xattrs"
    exit 0
fi
PRE_VALUE="$(/usr/sbin/getextattr -qq user shit.test "${FILE}" 2>/dev/null || true)"
[ "${PRE_VALUE}" = "alpha" ] || smoke_fail "setup: pre xattr=${PRE_VALUE}, want alpha"
smoke_log "pre-cmd: user.shit.test=${PRE_VALUE}"

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

smoke_log "/usr/sbin/setextattr user shit.test beta ${FILE}"
/usr/sbin/setextattr user shit.test beta "${FILE}"
POST_VALUE="$(/usr/sbin/getextattr -qq user shit.test "${FILE}" 2>/dev/null || true)"
[ "${POST_VALUE}" = "beta" ] || smoke_fail "command didn't update xattr (got ${POST_VALUE})"
smoke_log "post-cmd: user.shit.test=${POST_VALUE}"

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
FINAL_VALUE="$(/usr/sbin/getextattr -qq user shit.test "${FILE}" 2>/dev/null || echo MISSING)"
[ "${FINAL_VALUE}" = "alpha" ] \
    || failures+=("xattr value mismatch: got '${FINAL_VALUE}', want 'alpha'")

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: xattr-undo-fbsd (user.shit.test restored to alpha)"
    exit 0
fi
smoke_fail "xattr undo incomplete: ${failures[*]}"
