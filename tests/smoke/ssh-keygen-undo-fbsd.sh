#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: ssh-keygen-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.11 smoke — `ssh-keygen -f keyfile -N ""` creates TWO files
# from one command: the private key (mode 0600) and the public key
# (mode 0644). Common high-traffic workload; tests the
# multi-file-Create-from-one-command shape:
#
#   1. Shim's `open(O_CREAT|O_EXCL|O_WRONLY, 0600)` fires for the
#      private key at an unwatched dst → AR05.1 fresh-create
#      branch journals `TreeOp::Create`.
#   2. Same for the public key.
#   3. Undo unlinks BOTH files.
#
# Sub-second back-to-back creates from the same pid stress the
# daemon's shim_listener accept-loop + ancestry resolution.
# ssh-keygen also writes to /dev/urandom (read-only — shouldn't
# leak into the journal).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: ssh-keygen-undo-fbsd is FreeBSD-only"
    exit 0
fi

SSH_KEYGEN_BIN="$(command -v ssh-keygen || echo /usr/bin/ssh-keygen)"
[ -x "${SSH_KEYGEN_BIN}" ] || smoke_fail "ssh-keygen not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
KEY_DIR="${SHIT_SMOKE_TMP}/keys"
mkdir -p "${WATCHED}" "${KEY_DIR}"
KEY_PRIV="${KEY_DIR}/id_test"
KEY_PUB="${KEY_PRIV}.pub"

# Sanity: must not pre-exist (ssh-keygen refuses to overwrite
# without -y, and we want pure Create not Replace).
[ ! -e "${KEY_PRIV}" ] || smoke_fail "${KEY_PRIV} already exists"
[ ! -e "${KEY_PUB}" ]  || smoke_fail "${KEY_PUB} already exists"

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

# -t ed25519 keeps it cheap (4ms vs RSA's ~50ms);
# -q quiet; -N "" no passphrase; -C "" empty comment.
smoke_log "LD_PRELOAD=${SHIM_LIB} ssh-keygen -t ed25519 -f ${KEY_PRIV} -N '' -C '' -q"
LD_PRELOAD="${SHIM_LIB}" "${SSH_KEYGEN_BIN}" -t ed25519 -f "${KEY_PRIV}" -N "" -C "" -q

[ -f "${KEY_PRIV}" ] || smoke_fail "private key not created at ${KEY_PRIV}"
[ -f "${KEY_PUB}" ]  || smoke_fail "public key not created at ${KEY_PUB}"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events after ssh-keygen: ${N_EVENTS}"
[ "${N_EVENTS}" -ge 2 ] || smoke_fail "expected ≥2 Create events for the 2 keyfiles; got ${N_EVENTS}"
# Guard against the /dev/null regression: ssh-keygen opens
# /dev/null for stderr suppression; if the shim journals that as
# a Create, undo will try to unlink /dev/null and fail. Cap at 3
# (private + public + a small slack for the random-art write to
# the same tty); >3 means a /dev/* spurious-Create leaked.
[ "${N_EVENTS}" -le 3 ] || smoke_fail "expected ≤3 events; got ${N_EVENTS} — /dev/null spurious-Create regression?"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

failures=()
[ "${UNDO_RC}" -eq 0 ] || failures+=("shit undo exited ${UNDO_RC} — likely /dev/null spurious-unlink regression")
[ ! -e "${KEY_PRIV}" ] || failures+=("private key still present after undo")
[ ! -e "${KEY_PUB}" ]  || failures+=("public key still present after undo")
if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: ssh-keygen-undo-fbsd (2 keyfiles created + removed by undo, no spurious /dev events)"
    exit 0
fi
smoke_fail "ssh-keygen undo incomplete: ${failures[*]}"
