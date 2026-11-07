#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-preexisting-loss-refuses-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice B — a change to a file that existed before the command, with
# no captured evidence, is loss. Strict capture refuses its undo;
# default mode keeps trunk behavior.
#
# Two workloads, each in its own cwd:
#
#   big:   a sparse file larger than the 1 GiB pre-image cap is in the
#          baseline but has no snapshot. `chmod 600 big` changes it and
#          nothing records the old mode. Strict journals a path-scoped
#          CaptureRefused for it.
#
#   many:  the cwd holds more regular files than the baseline walk's
#          512-file cap. The command appends to every file, so some of
#          the changed files were never walked and cannot be told apart
#          from files outside the tree. Strict journals a command-scoped
#          CaptureRefused saying the walk was incomplete.
#
# Phase 1 runs both with SHIT_STRICT_CAPTURE=1 and expects
# capture-incomplete refusals from `shit undo`. Phase 2 repeats them
# with the flag unset and expects no new CaptureRefused rows and no
# capture-incomplete refusal.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-preexisting-loss-refuses-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

if ! grep -q "\bbpf\b" /sys/kernel/security/lsm 2>/dev/null; then
    smoke_log "FAIL: kernel lacks the bpf LSM (active=$(cat /sys/kernel/security/lsm 2>/dev/null))"
    exit 1
fi
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    printf '%s' "${HELPER_CAPS}" | grep -q "${required}" \
        || smoke_fail "helper lacks ${required} (getcap output: '${HELPER_CAPS}')"
done
export SHIT_FORCE_TIER=ebpf-lsm

# setup <label>: fresh cwds for one phase.
setup() {
    local label="$1"
    BIG_DIR="${SHIT_SMOKE_TMP}/${label}/big"
    MANY_DIR="${SHIT_SMOKE_TMP}/${label}/many"
    mkdir -p "${BIG_DIR}" "${MANY_DIR}"
    truncate -s 1100M "${BIG_DIR}/big"
    chmod 644 "${BIG_DIR}/big"
    local i
    for i in $(seq 1 600); do
        printf 'file %s\n' "${i}" > "${MANY_DIR}/f${i}"
    done
}

# run_cmd <seq> <cwd> <cmdline>: one PreExec/PostExec cycle running
# `sh -c <cmdline>` in <cwd>.
run_cmd() {
    local seq="$1" cwd="$2" cmdline="$3"
    cd "${cwd}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "${seq}" --pid "$$" \
        --cwd "${cwd}" --shell bash --cmdline "${cmdline}" \
        --sock "${SHIT_HOOK_SOCK}"
    smoke_log "[${seq}] ${cmdline} (cwd ${cwd})"
    sh -c "${cmdline}"
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq "${seq}" --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"
    cd "${SHIT_SMOKE_TMP}"
}

# undo_into <log>: `shit undo --yes`, output kept in <log>.
undo_into() {
    local log="$1"
    set +e
    "${SHIT_BIN}" undo --yes > "${log}" 2>&1
    local rc=$?
    set -e
    smoke_log "shit undo --yes exit=${rc}"
    sed 's/^/    undo: /' "${log}" >&2 || true
}

# phase <label>: both workloads in one session, each undone right after.
phase() {
    local label="$1"
    setup "${label}"
    SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    "${SHIT_BIN}" hook-send session-open \
        --session "${SESSION}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    run_cmd 1 "${BIG_DIR}" "chmod 600 big"
    undo_into "${SHIT_SMOKE_TMP}/${label}-big.undo.log"
    run_cmd 2 "${MANY_DIR}" 'for f in f*; do echo more >> "$f"; done'
    undo_into "${SHIT_SMOKE_TMP}/${label}-many.undo.log"
    "${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
}

REFUSED="discriminant = 'CaptureRefused'"

# Phase 1: strict.
SHIT_STRICT_CAPTURE=1 smoke_start_shitd
phase strict
BIG_ROWS="$(smoke_journal_count "${REFUSED} AND path LIKE '%/strict/big/big'")"
[ "${BIG_ROWS}" -ge 1 ] || {
    smoke_journal_query "SELECT seq, path FROM events WHERE ${REFUSED};" | sed 's/^/    refused: /' >&2 || true
    smoke_fail "strict: no CaptureRefused row for the over-cap baseline file"
}
grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/strict-big.undo.log" \
    || smoke_fail "strict: chmod undo did not refuse with capture-incomplete"
grep -q "attribute change had no pre-change snapshot" "${SHIT_SMOKE_TMP}/strict-big.undo.log" \
    || smoke_fail "strict: chmod refusal does not name the missing snapshot"
grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/strict-many.undo.log" \
    || smoke_fail "strict: append undo did not refuse with capture-incomplete"
grep -q "could not be placed in the baseline" "${SHIT_SMOKE_TMP}/strict-many.undo.log" \
    || smoke_fail "strict: append refusal does not name the incomplete walk"
STRICT_ROWS="$(smoke_journal_count "${REFUSED}")"
smoke_log "strict: ${STRICT_ROWS} CaptureRefused row(s)"
smoke_stop_shitd

# Phase 2: flag unset, same workloads.
unset SHIT_STRICT_CAPTURE
smoke_start_shitd
phase default
DEFAULT_ROWS="$(smoke_journal_count "${REFUSED}")"
[ "${DEFAULT_ROWS}" -eq "${STRICT_ROWS}" ] \
    || smoke_fail "default: CaptureRefused rows grew from ${STRICT_ROWS} to ${DEFAULT_ROWS} with the flag unset"
for w in big many; do
    if grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/default-${w}.undo.log"; then
        smoke_fail "default: ${w} undo refused with capture-incomplete although strict mode is off"
    fi
done

smoke_log "PASS: strict-preexisting-loss-refuses-linux (strict refused both losses, default unchanged)"
