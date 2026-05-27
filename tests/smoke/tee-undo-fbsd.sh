#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: tee-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.14 smoke — `cmd | tee file` (truncate) and `cmd | tee -a file`
# (append) both write to `file` via the bin/tee dynamic binary.
# Distinct from the shell-redirect case (bash internal open): tee
# is a separate process, so the shim's LD_PRELOAD must propagate
# through the pipeline.
#
# Phase A: tee truncate — pre-content gets overwritten. Undo
#   restores the pre-content byte-identically via the shim's
#   pre-image capture on open(O_WRONLY|O_TRUNC|O_CREAT).
#
# Phase B: tee -a — pre-content gets appended to. Same shim
#   path catches open(O_WRONLY|O_APPEND|O_CREAT) (W09.13-era
#   writes-detection: any of WRONLY/RDWR/TRUNC suffices). Undo
#   should restore to pre-content (shorter file).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: tee-undo-fbsd is FreeBSD-only"
    exit 0
fi

TEE_BIN="$(command -v tee || echo /usr/bin/tee)"
[ -x "${TEE_BIN}" ] || smoke_fail "tee not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

run_phase() {
    local label="$1" tee_args="$2" expected_post_content="$3"

    smoke_log "=== Phase ${label}: tee ${tee_args} ==="
    smoke_start_shitd

    local watched="${SHIT_SMOKE_TMP}/watched-${label}"
    local dst_dir="${SHIT_SMOKE_TMP}/unwatched-${label}"
    mkdir -p "${watched}" "${dst_dir}"
    local target="${dst_dir}/output.txt"
    printf 'ORIGINAL content\n' > "${target}"
    local pre_sha
    pre_sha="$(/sbin/sha256 -q "${target}")"
    smoke_log "pre-cmd sha: ${pre_sha}"

    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    cd "${watched}"

    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "$$" \
        --cwd "${watched}" --shell bash --sock "${SHIT_HOOK_SOCK}"
    sleep 0.7

    # eval the printf|tee pipeline with LD_PRELOAD scoped to it so
    # the tee process picks up the shim. The pipeline shell stays
    # without LD_PRELOAD; tee's open is what we want intercepted.
    smoke_log "printf NEW | LD_PRELOAD=${SHIM_LIB} tee ${tee_args} ${target}"
    LD_PRELOAD="${SHIM_LIB}" bash -c \
        "printf 'NEW PAYLOAD\\n' | '${TEE_BIN}' ${tee_args} '${target}' >/dev/null"
    local post_cmd_sha
    post_cmd_sha="$(/sbin/sha256 -q "${target}")"
    smoke_log "post-cmd sha: ${post_cmd_sha}"
    [ "${post_cmd_sha}" != "${pre_sha}" ] || smoke_fail "phase ${label}: tee didn't modify content"

    # Sanity: content matches what we expect for this phase.
    local actual_post_content
    actual_post_content="$(cat "${target}")"
    [ "${actual_post_content}" = "${expected_post_content}" ] || \
        smoke_fail "phase ${label}: post content mismatch — got '${actual_post_content}' want '${expected_post_content}'"

    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    sleep 1.0

    smoke_log "running: shit undo --yes"
    set +e
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo-${label}.log" 2>&1
    local undo_rc=$?
    set -e
    smoke_log "shit undo --yes exit=${undo_rc}"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-${label}.log" >&2

    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    local post_undo_sha
    post_undo_sha="$(/sbin/sha256 -q "${target}")"
    smoke_log "post-undo sha: ${post_undo_sha}"

    [ "${undo_rc}" -eq 0 ] || smoke_fail "phase ${label}: undo exit=${undo_rc}"
    [ "${post_undo_sha}" = "${pre_sha}" ] || \
        smoke_fail "phase ${label}: undo didn't restore pre-content (got ${post_undo_sha}, want ${pre_sha})"

    smoke_log "PHASE ${label} PASS"
    smoke_stop_shitd
    cd "${SHIT_SMOKE_TMP}"
}

# Phase A: truncate. Post content is just the new payload.
run_phase "truncate" "" "NEW PAYLOAD"

# Phase B: append. Post content is ORIGINAL + NEW.
run_phase "append" "-a" "$(printf 'ORIGINAL content\nNEW PAYLOAD')"

smoke_log "PASS: tee-undo-fbsd (truncate + append modes both restored)"
exit 0
