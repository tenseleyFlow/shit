#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR08.2.ln-hardlink smoke (Linux twin of ln-hardlink-undo-fbsd.sh).
# `ln target link` (no -s) creates a hardlink — a new directory
# entry sharing target's inode. `shit undo` should remove the LINK
# without touching target; nlink should drop back to 1.
#
# Closes the AR08.1 'covered, smoke-gap' entry for hardlinks.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: ln-hardlink-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

STAT_BIN="$(command -v stat)"
[ -x "${STAT_BIN}" ] || smoke_fail "stat not on PATH"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"

# Pre-existing target.
TARGET="${WATCHED}/target.txt"
printf 'i am the original\n' > "${TARGET}"
TARGET_SHA="$(sha256sum "${TARGET}" | awk '{print $1}')"
TARGET_INODE="$("${STAT_BIN}" -c '%i' "${TARGET}")"
# Inode link count pre-op should be 1.
PRE_NLINK="$("${STAT_BIN}" -c '%h' "${TARGET}")"
[ "${PRE_NLINK}" = "1" ] || smoke_fail "pre-state: target nlink=${PRE_NLINK}, expected 1"
smoke_log "pre-cmd target sha=${TARGET_SHA} inode=${TARGET_INODE} nlink=${PRE_NLINK}"

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
sleep 0.5

# THE workload — hardlink (no -s).
ln "${TARGET}" "${LINK}"
smoke_log "ln ${TARGET} ${LINK}"
[ -f "${LINK}" ]      || smoke_fail "ln didn't create link"
LINK_INODE="$("${STAT_BIN}" -c '%i' "${LINK}")"
[ "${LINK_INODE}" = "${TARGET_INODE}" ] || smoke_fail "link inode ${LINK_INODE} != target inode ${TARGET_INODE}"
POST_LN_NLINK="$("${STAT_BIN}" -c '%h' "${TARGET}")"
[ "${POST_LN_NLINK}" = "2" ] || smoke_fail "post-ln: nlink=${POST_LN_NLINK}, expected 2"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Link must be gone. Target must be intact (content + nlink).
if [ -e "${LINK}" ]; then
    smoke_fail "link ${LINK} still exists post-undo"
fi
if [ ! -f "${TARGET}" ]; then
    smoke_fail "target file ${TARGET} deleted by undo"
fi
POST_TARGET_SHA="$(sha256sum "${TARGET}" | awk '{print $1}')"
[ "${POST_TARGET_SHA}" = "${TARGET_SHA}" ] || smoke_fail "target content perturbed: ${TARGET_SHA} → ${POST_TARGET_SHA}"
POST_NLINK="$("${STAT_BIN}" -c '%h' "${TARGET}")"
[ "${POST_NLINK}" = "1" ] || smoke_fail "post-undo: nlink=${POST_NLINK}, expected 1 (link not actually removed?)"

smoke_log "PASS: ln-hardlink-undo-linux (link removed; target intact sha=${TARGET_SHA} nlink=1)"
