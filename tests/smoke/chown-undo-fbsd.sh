#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: chown-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.10.chown smoke — `chown` changes a file's group via NOTE_ATTRIB.
# Mirrors chmod's path (S29.3 captures both via the same MetadataChange
# event), but verifies the gid field round-trips correctly (the
# existing chmod smoke only stresses the mode field).
#
# Cannot reliably change UID without root; uses group ownership
# instead. Picks an alternate group from /etc/group that the user
# belongs to, so the chown is permitted without privilege.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: chown-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pick a group the current user is a member of OTHER than the file's
# default group. `id -G` lists numeric group ids the user is in.
USER_GROUPS=( $(id -G) )
if [ "${#USER_GROUPS[@]}" -lt 2 ]; then
    smoke_log "SKIP: user is in <2 groups; cannot chown to a different group without root"
    exit 0
fi

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/owned.txt"
printf 'ownership test\n' > "${SUBJECT}"

PRE_GID="$(/usr/bin/stat -f '%g' "${SUBJECT}")"
# Pick a different group the user is in.
ALT_GID=""
for g in "${USER_GROUPS[@]}"; do
    if [ "${g}" != "${PRE_GID}" ]; then
        ALT_GID="${g}"
        break
    fi
done
[ -n "${ALT_GID}" ] || smoke_fail "no alternate group available (all user groups match file gid ${PRE_GID})"
smoke_log "pre-cmd gid: ${PRE_GID}, will chown to: ${ALT_GID}"

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

# /usr/sbin isn't in the smoke harness's PATH; use the absolute path.
CHOWN_BIN="/usr/sbin/chown"
[ -x "${CHOWN_BIN}" ] || smoke_fail "chown not found at ${CHOWN_BIN}"
smoke_log "${CHOWN_BIN} :${ALT_GID} ${SUBJECT}"
"${CHOWN_BIN}" ":${ALT_GID}" "${SUBJECT}"

POST_GID="$(/usr/bin/stat -f '%g' "${SUBJECT}")"
[ "${POST_GID}" = "${ALT_GID}" ] || smoke_fail "chown didn't change gid (got ${POST_GID})"

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

POST_UNDO_GID="$(/usr/bin/stat -f '%g' "${SUBJECT}")"
if [ "${POST_UNDO_GID}" = "${PRE_GID}" ]; then
    smoke_log "PASS: chown-undo-fbsd (gid ${PRE_GID} → ${ALT_GID} → ${POST_UNDO_GID})"
    exit 0
fi

smoke_fail "gid not restored: got ${POST_UNDO_GID}, expected ${PRE_GID}"
