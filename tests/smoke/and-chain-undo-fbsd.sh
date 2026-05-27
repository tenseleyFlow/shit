#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: and-chain-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.9.and-chain smoke — `cmd1 && cmd2 && cmd3` runs three
# distinct mutations under one PreExec/PostExec window. The
# journal should hold all events from all three commands as a
# single undoable unit. `shit undo --yes` should reverse all
# three mutations in one shot.
#
# Workload: chmod (metadata) && rm (unlink+pre-image) && echo>X
# (Create+content). Three different mutation categories in one
# command.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: and-chain-undo-fbsd is FreeBSD-only"
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

# Pre-existing state:
#   chmod_target.txt: mode 0644 → will be chmod'd to 0700
#   rm_target.txt:    content "REMOVE ME" → will be rm'd
#   (new.txt does NOT exist; will be created by echo)
printf 'mode test\n' > "${WATCHED}/chmod_target.txt"
chmod 0644 "${WATCHED}/chmod_target.txt"
PRE_CHMOD_MODE="$(/usr/bin/stat -f '%Op' "${WATCHED}/chmod_target.txt")"
[ "${PRE_CHMOD_MODE}" = "100644" ] || smoke_fail "pre-state: chmod_target mode unexpected"

printf 'REMOVE ME\n' > "${WATCHED}/rm_target.txt"
PRE_RM_SHA="$(/sbin/sha256 -q "${WATCHED}/rm_target.txt")"

[ ! -e "${WATCHED}/new.txt" ] || smoke_fail "pre-state: new.txt should not exist"

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
sleep 0.7

# THE workload — three mutations chained with &&.
smoke_log "chmod 0700 chmod_target.txt && rm rm_target.txt && echo NEW > new.txt"
chmod 0700 chmod_target.txt && rm rm_target.txt && echo 'NEW' > new.txt

# Sanity: all three mutations took effect.
POST_CHMOD_MODE="$(/usr/bin/stat -f '%Op' "${WATCHED}/chmod_target.txt")"
[ "${POST_CHMOD_MODE}" = "100700" ] || smoke_fail "chmod didn't apply"
[ ! -e "${WATCHED}/rm_target.txt" ] || smoke_fail "rm didn't apply"
[ -f "${WATCHED}/new.txt" ]         || smoke_fail "echo didn't create new.txt"

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
# chmod_target.txt mode back to 0644
m="$(/usr/bin/stat -f '%Op' "${WATCHED}/chmod_target.txt" 2>/dev/null || echo MISSING)"
[ "${m}" = "${PRE_CHMOD_MODE}" ] || failures+=("chmod_target mode ${m} != ${PRE_CHMOD_MODE}")
# rm_target.txt restored byte-identical
if [ ! -f "${WATCHED}/rm_target.txt" ]; then
    failures+=("rm_target.txt not restored")
else
    s="$(/sbin/sha256 -q "${WATCHED}/rm_target.txt")"
    [ "${s}" = "${PRE_RM_SHA}" ] || failures+=("rm_target.txt sha ${s} != ${PRE_RM_SHA}")
fi
# new.txt removed
[ ! -e "${WATCHED}/new.txt" ] || failures+=("new.txt still present post-undo")

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: and-chain-undo-fbsd (3 mutation classes reversed in one undo)"
    exit 0
fi

smoke_fail "&& chain undo failed: ${failures[*]}"
