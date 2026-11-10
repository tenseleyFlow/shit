# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Helpers for the macOS smokes that run SIP-protected binaries
# (`sip-*-undo-macos.sh`). Each smoke sources `lib.sh` first and this
# file next. The command runs the way a hooked shell runs it: between
# PreExec and PostExec, with the command key exported and
# DYLD_INSERT_LIBRARIES set, which dyld drops for SIP binaries.

sip_setup() {
    HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
    SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
    SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.dylib"
    [ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
    [ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
    [ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
    export SHIT_HELPER_BIN="${HELPER_BIN}"
    WATCHED="${SHIT_SMOKE_TMP}/watched"
    mkdir -p "${WATCHED}"
    smoke_start_shitd
    SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    "${SHIT_BIN}" hook-send session-open \
        --session "${SESSION}" --pid "$$" --shell bash --tty /dev/null \
        --sock "${SHIT_HOOK_SOCK}"
}

sip_sha() {
    shasum -a 256 "$1" | awk '{print $1}'
}

# Run "$@" as command 1 of the session. Files the smoke makes before
# this call predate the command; FSEvents may still flag them created.
sip_run_hooked() {
    cd "${WATCHED}" || smoke_fail "cd ${WATCHED}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq 1 --pid "$$" \
        --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
    sleep 0.7
    smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} $*"
    local rc
    set +e
    _SHIT_SESSION="${SESSION}" _SHIT_SEQ=1 DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "$@" \
        > "${SHIT_SMOKE_TMP}/cmd.log" 2>&1
    rc=$?
    set -e
    [ "${rc}" -eq 0 ] || smoke_fail "$* exited ${rc}: $(cat "${SHIT_SMOKE_TMP}/cmd.log")"
    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    sleep 1.0
    local hits
    hits="$(cat "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null \
        | grep -c 'shim pre-mutation' || true)"
    smoke_log "shim notes from $1: ${hits:-0} (0 expected: SIP strips DYLD_INSERT_LIBRARIES)"
    smoke_log "journal:"
    smoke_journal_query "SELECT id, discriminant, path FROM events;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
}

# Run `shit undo --yes`; sets UNDO_RC and UNDO_LOG.
sip_undo() {
    UNDO_LOG="${SHIT_SMOKE_TMP}/undo.log"
    set +e
    "${SHIT_BIN}" undo --yes > "${UNDO_LOG}" 2>&1
    UNDO_RC=$?
    set -e
    smoke_log "shit undo --yes exit=${UNDO_RC}"
    sed 's/^/    /' "${UNDO_LOG}" >&2
}

# Outcome B: undo exited non-zero and said the change was not
# captured. An exit 0 here is the failure this smoke exists for.
sip_require_refusal() {
    local path="$1"
    if [ "${UNDO_RC}" -eq 0 ]; then
        smoke_fail "undo exited 0 but ${path} was not restored: success reported with nothing captured"
    fi
    grep -qiE 'not captured|capture|refus' "${UNDO_LOG}" \
        || smoke_fail "undo exited ${UNDO_RC} without saying the change was not captured"
}
