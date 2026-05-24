#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W08 smoke — `mv` across directories. Three cases of increasing
# architectural difficulty:
#
#   case1 — intra-watch:    mv ${cwd}/src/file ${cwd}/dst/file
#   case2 — unwatched dst:  mv ${cwd}/file     ${outside}/file
#   case3 — unwatched src:  mv ${outside}/file ${cwd}/file
#
# Each case runs under its own (session, seq) so a failure in one
# doesn't poison the next. We want all three results before
# deciding what to fix.
#
# Acceptable per-case outcomes:
#   case1: full undo — src/file restored, dst/file gone.
#   case2: full undo OR refusal-with-reason naming the file.
#          PASS condition: cwd/file restored AND (outside/file gone
#          OR refusal log mentions the boundary issue).
#   case3: full undo OR refusal-with-reason naming the file.
#          PASS condition: cwd/file gone AND outside/file restored,
#          OR refusal-with-reason that prevents DATA LOSS.
#          The bug we're looking for: undo exit 0, cwd/file gone,
#          outside/file ALSO gone (the rename ate it and undo
#          finished the job with a plain Unlink).
#
# FreeBSD-only.
#
# See .docs/sprints/W/W08-mv-across-dirs.md (spec) and
# .docs/sprints/W/W08.B-bsd.md (execution plan).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: mv-across-dirs-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

MV_BIN="$(command -v mv || echo /bin/mv)"
[ -x "${MV_BIN}" ] || smoke_fail "mv not found"
smoke_log "mv: ${MV_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# W06.A.5: LD_PRELOAD the shim when invoking mv. With W06.A.3
# shim→journal wiring landed, the rename(2) syscall fires the
# shim's interposer, which sends a notification to the daemon,
# which journals a TreeOp::Rename event. The planner can now see
# both halves of cross-watch renames (cases 2 + 3) and emit the
# correct Rename inverse. Without LD_PRELOAD here, cases 2/3
# remain the cwd-watch-scope blind spot documented in W08.B-bsd.
MV_LD_PRELOAD="${SHIM_LIB}"
smoke_log "shim: ${MV_LD_PRELOAD}"

# Set up the cwd (watched) and outside (unwatched) locations under
# a shared parent so they're cleaned up by smoke_cleanup's rm -rf.
WATCHED="${SHIT_SMOKE_TMP}/watched"
OUTSIDE="${SHIT_SMOKE_TMP}/outside"
mkdir -p "${WATCHED}" "${OUTSIDE}"

smoke_start_shitd

# Per-case driver. Each case opens its own session and runs one
# PreExec → workload → PostExec → undo cycle. The shared shitd
# stays up across cases.
#
# Args: $1=case-tag (case1/case2/case3), $2=mv-source, $3=mv-dest,
#       $4=expected-restore-path (where the file should end up
#       after undo for full-undo outcome), $5=expected-restore-sha,
#       $6=other-path-that-must-be-gone-or-restored.
#
# The function prints "PASS" or "FAIL <reason>" and returns 0/1.

PID="$$"
CASE1_RESULT="?"
CASE2_RESULT="?"
CASE3_RESULT="?"

# ---- Case 1 — intra-watch ----
case1() {
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    smoke_log "=== case1 (intra-watch mv) session=${session} ==="

    rm -rf "${WATCHED}"/* "${OUTSIDE}"/* 2>/dev/null || true
    mkdir -p "${WATCHED}/src" "${WATCHED}/dst"
    local file_pre="${WATCHED}/src/file.txt"
    local file_post="${WATCHED}/dst/file.txt"
    printf 'case1 content payload\n' > "${file_pre}"
    local prior_sha
    prior_sha="$(/sbin/sha256 -q "${file_pre}")"
    smoke_log "case1 pre-mv: ${file_pre} sha=${prior_sha}"

    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "${PID}" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"

    (cd "${WATCHED}" && "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "${PID}" \
        --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}")
    sleep 0.7

    LD_PRELOAD="${MV_LD_PRELOAD}" "${MV_BIN}" "${file_pre}" "${file_post}"
    sleep 0.3

    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    sleep 0.7

    smoke_log "case1 running: shit undo --yes"
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/case1-undo.log" 2>&1
    local rc=$?
    smoke_log "case1 undo rc=${rc}"
    /usr/bin/sed 's/^/    case1: /' "${SHIT_SMOKE_TMP}/case1-undo.log" >&2

    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    if [ ! -f "${file_pre}" ]; then
        CASE1_RESULT="FAIL src/file.txt not restored"
        return 1
    fi
    local got_sha
    got_sha="$(/sbin/sha256 -q "${file_pre}")"
    if [ "${got_sha}" != "${prior_sha}" ]; then
        CASE1_RESULT="FAIL sha mismatch: got ${got_sha} want ${prior_sha}"
        return 1
    fi
    if [ -e "${file_post}" ]; then
        CASE1_RESULT="FAIL dst/file.txt not removed"
        return 1
    fi
    CASE1_RESULT="PASS"
    return 0
}

# ---- Case 2 — src watched, dst unwatched ----
case2() {
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    smoke_log "=== case2 (mv to unwatched dst) session=${session} ==="

    rm -rf "${WATCHED}"/* "${OUTSIDE}"/* 2>/dev/null || true
    local file_pre="${WATCHED}/local.txt"
    local file_post="${OUTSIDE}/moved.txt"
    printf 'case2 outbound payload\n' > "${file_pre}"
    local prior_sha
    prior_sha="$(/sbin/sha256 -q "${file_pre}")"
    smoke_log "case2 pre-mv: ${file_pre} sha=${prior_sha}"

    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "${PID}" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"

    (cd "${WATCHED}" && "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "${PID}" \
        --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}")
    sleep 0.7

    LD_PRELOAD="${MV_LD_PRELOAD}" "${MV_BIN}" "${file_pre}" "${file_post}"
    sleep 0.3

    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    sleep 0.7

    smoke_log "case2 running: shit undo --yes"
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/case2-undo.log" 2>&1
    local rc=$?
    smoke_log "case2 undo rc=${rc}"
    /usr/bin/sed 's/^/    case2: /' "${SHIT_SMOKE_TMP}/case2-undo.log" >&2

    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    # Acceptable outcomes:
    #   (A) Full undo: file_pre restored AND file_post gone.
    #   (B) Refusal: rc != 0 AND log mentions the moved file's basename
    #       (`local.txt`, `moved.txt`, or `outside`/`watch`/`scope`).
    if [ -f "${file_pre}" ]; then
        local got_sha
        got_sha="$(/sbin/sha256 -q "${file_pre}")"
        if [ "${got_sha}" = "${prior_sha}" ]; then
            if [ ! -e "${file_post}" ]; then
                CASE2_RESULT="PASS (full undo)"
                return 0
            fi
            CASE2_RESULT="PARTIAL (file restored but dst-leftover at ${file_post})"
            return 0  # leftover-on-restore is the open-question outcome; pass for now
        fi
    fi
    if [ "${rc}" -ne 0 ] && grep -qE "local\.txt|moved\.txt|outside|watch|scope|refus" "${SHIT_SMOKE_TMP}/case2-undo.log"; then
        CASE2_RESULT="PASS (loud refusal)"
        return 0
    fi
    if [ -f "${file_post}" ] && [ ! -f "${file_pre}" ]; then
        CASE2_RESULT="FAIL (silent no-op — file left at dst, source missing)"
        return 1
    fi
    CASE2_RESULT="FAIL (unexpected state — undo rc=${rc}, pre exists=$([ -f "${file_pre}" ] && echo yes || echo no), post exists=$([ -f "${file_post}" ] && echo yes || echo no))"
    return 1
}

# ---- Case 3 — src unwatched, dst watched (DATA LOSS risk) ----
case3() {
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    smoke_log "=== case3 (mv from unwatched src — DATA LOSS risk) session=${session} ==="

    rm -rf "${WATCHED}"/* "${OUTSIDE}"/* 2>/dev/null || true
    local file_pre="${OUTSIDE}/external.txt"
    local file_post="${WATCHED}/external.txt"
    printf 'case3 inbound payload\n' > "${file_pre}"
    # Backdate the file's mtime well into the past so the planner's
    # "mtime predates Create event by >1s" heuristic triggers. Real-
    # world mv-from-outside has weeks-to-months-old mtimes; we use
    # 10 minutes ago as a realistic floor that's robust to clock
    # jitter.
    touch -t "$(date -u -v-10M +%Y%m%d%H%M.%S 2>/dev/null || date -u -d '10 minutes ago' +%Y%m%d%H%M.%S)" "${file_pre}"
    local prior_sha
    prior_sha="$(/sbin/sha256 -q "${file_pre}")"
    smoke_log "case3 pre-mv: ${file_pre} sha=${prior_sha} (mtime backdated 10min)"

    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "${PID}" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"

    (cd "${WATCHED}" && "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "${PID}" \
        --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}")
    sleep 0.7

    LD_PRELOAD="${MV_LD_PRELOAD}" "${MV_BIN}" "${file_pre}" "${file_post}"
    sleep 0.3

    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
    sleep 0.7

    smoke_log "case3 running: shit undo --yes"
    "${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/case3-undo.log" 2>&1
    local rc=$?
    smoke_log "case3 undo rc=${rc}"
    /usr/bin/sed 's/^/    case3: /' "${SHIT_SMOKE_TMP}/case3-undo.log" >&2

    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    # Acceptable:
    #   (A) Full undo: file_pre restored AND file_post gone.
    #   (B) Refusal: rc != 0 AND log mentions the file or origin issue.
    #
    # The bug we want to catch:
    #   DATA LOSS: rc == 0, file_post gone (undo's Unlink succeeded),
    #              file_pre also gone (the original mv ate it).
    local pre_exists=no post_exists=no
    [ -f "${file_pre}" ] && pre_exists=yes
    [ -f "${file_post}" ] && post_exists=yes

    if [ "${pre_exists}" = "yes" ] && [ "${post_exists}" = "no" ]; then
        local got_sha
        got_sha="$(/sbin/sha256 -q "${file_pre}")"
        if [ "${got_sha}" = "${prior_sha}" ]; then
            CASE3_RESULT="PASS (full undo)"
            return 0
        fi
        CASE3_RESULT="FAIL (file at src but sha mismatch: ${got_sha} vs ${prior_sha})"
        return 1
    fi
    if [ "${rc}" -ne 0 ] && grep -qE "external\.txt|origin|unwatched|outside|scope|refus" "${SHIT_SMOKE_TMP}/case3-undo.log"; then
        CASE3_RESULT="PASS (loud refusal — data loss averted)"
        return 0
    fi
    if [ "${pre_exists}" = "no" ] && [ "${post_exists}" = "no" ]; then
        CASE3_RESULT="FAIL (DATA LOSS — file gone from both src and dst, undo claimed success)"
        return 1
    fi
    if [ "${pre_exists}" = "no" ] && [ "${post_exists}" = "yes" ]; then
        CASE3_RESULT="FAIL (undo no-op — file at dst, src gone; rename not reversed)"
        return 1
    fi
    CASE3_RESULT="FAIL (unexpected: rc=${rc}, pre=${pre_exists}, post=${post_exists})"
    return 1
}

# Run all three cases; never bail early.
case1 || true
case2 || true
case3 || true

smoke_log "=== W08 case results ==="
smoke_log "case1 (intra-watch):   ${CASE1_RESULT}"
smoke_log "case2 (unwatched dst): ${CASE2_RESULT}"
smoke_log "case3 (unwatched src): ${CASE3_RESULT}"

# Overall verdict (post-W06.A.5): with the shim LD_PRELOAD'd into
# each `mv` invocation, all three cases should now PASS. The shim
# emits `rename(2)` notifications regardless of watch scope; the
# daemon (W06.A.3) attributes them to the active command and
# journals `TreeOp::Rename` events; the planner emits the inverse
# rename. Cross-watch source/destination becomes visible.
#
# Any FAIL here is a real regression — either:
#   - shim not loading (PR #40, #42, #44 territory)
#   - shim → journal wiring broken (PR #47 territory)
#   - planner doesn't pair the Rename events into an inverse
declare -A KNOWN
KNOWN[case1]="${CASE1_RESULT}"
KNOWN[case2]="${CASE2_RESULT}"
KNOWN[case3]="${CASE3_RESULT}"

failed_cases=()
for case_name in case1 case2 case3; do
    result="${KNOWN[$case_name]}"
    if [[ "$result" != PASS* ]]; then
        failed_cases+=("$case_name=$result")
    fi
done

if [ "${#failed_cases[@]}" -gt 0 ]; then
    smoke_fail "regression in cross-watch mv coverage: ${failed_cases[*]}"
fi

smoke_log "PASS: mv-across-dirs-undo-fbsd (case1=${CASE1_RESULT}, case2=${CASE2_RESULT}, case3=${CASE3_RESULT})"
