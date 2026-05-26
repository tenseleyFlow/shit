#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.12 smoke — `python3 -m venv --without-pip /watched/venv`
# creates ~15 entries in one command: 7 dirs, 5 regular files,
# 4 symlinks. Stresses the in-watch kqueue tier's ability to
# absorb a burst of tree-ops from one pid:
#
#   - kqueue NOTE_WRITE on /watched/venv (mkdir) + descendants
#   - shim's open(O_CREAT|O_WRONLY) for each pyvenv.cfg + bin/*
#   - shim DOES NOT cover symlink(2); kqueue dir-diff handles those
#     as in-watch Create events instead
#
# Validates:
#   - ≥7 journal events (at minimum the regular files; ideally
#     all 15 incl. dirs and symlinks via kqueue)
#   - `shit undo --yes` returns 0 (no failed inverses)
#   - The venv tree is fully removed (no orphaned dirs/symlinks)

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: python-venv-undo-fbsd is FreeBSD-only"
    exit 0
fi

PY3_BIN="$(command -v python3 || echo /usr/local/bin/python3)"
[ -x "${PY3_BIN}" ] || smoke_fail "python3 not found"
"${PY3_BIN}" -c "import venv" 2>/dev/null || smoke_fail "python3 venv module missing"

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
VENV="${WATCHED}/venv"
[ ! -e "${VENV}" ] || smoke_fail "${VENV} already exists"

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

# --without-pip keeps the tree to ~15 entries (vs 2k+ with bundled
# pip). Still meaningful coverage of the multi-create shape.
smoke_log "LD_PRELOAD=${SHIM_LIB} python3 -m venv --without-pip ${VENV}"
LD_PRELOAD="${SHIM_LIB}" "${PY3_BIN}" -m venv --without-pip "${VENV}"

# Sanity-check the create produced the expected shape.
N_ENTRIES="$(find "${VENV}" -mindepth 1 | wc -l | tr -d ' ')"
smoke_log "venv tree entries: ${N_ENTRIES}"
[ "${N_ENTRIES}" -ge 10 ] || smoke_fail "venv tree too small (${N_ENTRIES}); did venv create fail?"

sleep 1.0
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.5

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events after venv create: ${N_EVENTS}"
[ "${N_EVENTS}" -ge 7 ] || smoke_fail "expected ≥7 journal events; got ${N_EVENTS} (under-capture under burst load?)"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

failures=()
[ "${UNDO_RC}" -eq 0 ] || failures+=("shit undo exited ${UNDO_RC}")
if [ -e "${VENV}" ]; then
    REMAINING="$(find "${VENV}" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')"
    failures+=("venv tree still has ${REMAINING} entries after undo")
fi
if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: python-venv-undo-fbsd (${N_ENTRIES} entries → undo applied=$(grep -oE 'applied=[0-9]+' "${SHIT_SMOKE_TMP}/undo.log" | head -1 | cut -d= -f2) → 0 remaining)"
    exit 0
fi
smoke_fail "venv undo incomplete: ${failures[*]}"
