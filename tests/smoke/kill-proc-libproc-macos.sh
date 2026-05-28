#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: kill-proc-libproc-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M06.2 — validates the libproc-based ProcSnapshot path on macOS.
# Before M06.2 the macOS branch of `read_proc_snapshot` returned an
# error ("proc snapshot not implemented on this platform"); now it
# populates argv / cwd / parent_pid via libproc + KERN_PROCARGS2.
#
# Uses `kill <pid>` (not `pkill -f <pattern>`) because the
# pattern-resolver (pids_matching) is FreeBSD/Linux-only today —
# resolving by pid goes through KillTarget::Pid which doesn't
# touch the pgrep path. A pkill-pattern smoke can land once the
# macOS pgrep resolver does (M06.x followup).
#
# Per the kill-undo semantics (see kill-proc-undo-linux.sh's
# header): undo of a kill does NOT resurrect the process. The
# planner emits a RestartSuggestion the user can copy. This smoke
# verifies the journal records a ProcessOp event with non-empty
# snapshot fields — the M06.2 fidelity guarantee.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: kill-proc-libproc-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

PYTHON3="$(command -v /opt/homebrew/bin/python3 2>/dev/null || command -v python3 || true)"
if [ -z "${PYTHON3}" ]; then
    smoke_log "SKIP: python3 not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_HELPER="${HELPER_BIN}"

WRAPPER_SRC="${SHIT_REPO_ROOT}/packaging/proc-hooks/kill-wrapper"
[ -f "${WRAPPER_SRC}" ] || smoke_fail "kill-wrapper missing at ${WRAPPER_SRC}"

smoke_start_shitd

# Stage the wrapper as `kill` in a smoke-private dir so its $0
# basename resolves to "kill" and it finds the real /bin/kill.
WRAPPER_DIR="${SHIT_SMOKE_TMP}/bin"
mkdir -p "${WRAPPER_DIR}"
cp "${WRAPPER_SRC}" "${WRAPPER_DIR}/kill"
chmod +x "${WRAPPER_DIR}/kill"

SESSION="$(${PYTHON3} -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# Distinctive argv tag for the doomed child. Helps prove libproc
# captured the right process when we inspect the snapshot payload.
DOOMED_TAG="shit-m06.2-doomed-$$-$(${PYTHON3} -c 'import os; print(os.urandom(4).hex())')"
( exec -a "${DOOMED_TAG}" bash -c 'while :; do sleep 1; done' ) &
DOOMED_PID=$!
SHIT_SMOKE_PIDS+=("${DOOMED_PID}")
sleep 0.5

if ! kill -0 "${DOOMED_PID}" 2>/dev/null; then
    smoke_fail "doomed child (${DOOMED_PID}) didn't start"
fi
smoke_log "doomed pid=${DOOMED_PID} (tag=${DOOMED_TAG})"

smoke_log "kill ${DOOMED_PID} via wrapper"
"${WRAPPER_DIR}/kill" "${DOOMED_PID}" || true
wait "${DOOMED_PID}" 2>/dev/null || true

if kill -0 "${DOOMED_PID}" 2>/dev/null; then
    smoke_fail "kill didn't kill (pid ${DOOMED_PID} still alive)"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

N_PROC_OPS="$(smoke_journal_count "discriminant = 'ProcessOp'" 2>/dev/null || echo 0)"
smoke_log "ProcessOp events: ${N_PROC_OPS}"
N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

if [ "${N_PROC_OPS}" -lt 1 ]; then
    smoke_log "ProcessOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" 2>/dev/null | sed 's/^/    /' >&2 || true
    smoke_fail "expected ProcessOp event after pkill; saw ${N_PROC_OPS}"
fi

# M06.2 fidelity check: the event payload should mention the
# distinctive tag (proves libproc actually populated argv from
# KERN_PROCARGS2). The payload is postcard-encoded binary; a
# decode-to-ASCII + grep approach trips on macOS tr's handling
# of the `[:print:]` class (locale-dependent byte stripping that
# corrupts otherwise-printable tag bytes).
#
# Simpler + locale-independent: hex-encode the tag and grep the
# raw payload-hex column for that hex pattern. Hex is ASCII-only
# so no locale games.
set +e
PAYLOAD_HEX="$(smoke_journal_query \
    "SELECT hex(payload) FROM events WHERE discriminant = 'ProcessOp' LIMIT 1;" \
    2>/dev/null | tr -d '[:space:]')"
# Build hex repr of the tag (uppercase to match sqlite's hex()).
TAG_HEX="$(printf '%s' "${DOOMED_TAG}" | xxd -p -c 999 | tr -d '\n' | tr '[:lower:]' '[:upper:]')"
smoke_log "ProcessOp payload hex length: ${#PAYLOAD_HEX}"
smoke_log "looking for tag hex: ${TAG_HEX}"
TAG_FOUND="no"
if printf '%s' "${PAYLOAD_HEX}" | grep -qi "${TAG_HEX}"; then
    TAG_FOUND="yes"
fi
set -e
if [ "${TAG_FOUND}" = "yes" ]; then
    smoke_log "ProcessOp payload contains the doomed argv tag — libproc populated argv (M06.2 OK)"
else
    smoke_log "ProcessOp payload hex (first 400 chars):"
    printf '%s\n' "${PAYLOAD_HEX:0:400}" | sed 's/^/    /' >&2
    smoke_fail "ProcessOp payload missing ${DOOMED_TAG} — libproc argv capture didn't work"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: kill-proc-libproc-macos (ProcessOp journaled with libproc-sourced argv)"
