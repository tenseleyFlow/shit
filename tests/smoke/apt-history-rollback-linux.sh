#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: apt-history-rollback-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR02.1 smoke — apt-history-rollback delegation path.
#
# Contract: on apt ≥ 3.2 (Debian 14 / Ubuntu 26.04 LTS minimum),
# `shit undo` dispatches to `apt-get history-rollback <txn-id>`
# instead of synthesizing per-package `apt-get remove`. End-state
# matches AR02.5 (package absent post-undo) but the path through
# the planner is different:
#
#   helper pkg/apt.rs::latest_apt_tx_id parses
#     /var/log/apt/history.log for Transaction-ID:
#   → planner sets PackageOp.repo_state_hint = Some(tx_id)
#   → native_delegation_for(Apt, Some(tx_id)) returns
#     Some(NativeDelegation::AptHistoryRollback)
#   → executor runs `apt-get history-rollback <tx_id>` instead of
#     `apt-get remove <pkg>`
#
# Activates on a runner with apt ≥ 3.2. Skips cleanly on older apt
# (current AR00 runner is Ubuntu 24.04 / apt 2.8) — written now so
# it activates automatically when AR00 gains a Ubuntu 26.04 leg.
#
# AR02.5 owns the inverse contract (synthesis-fallback on apt < 3.2).
# This smoke and AR02.5 are mutually-exclusive by apt-version gate;
# both should be in the CI matrix so whichever leg is appropriate
# for the runner's apt version runs and the other skips.
#
# Linux + Debian/Ubuntu family + apt ≥ 3.2. Skips otherwise.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: apt-history-rollback-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v apt-get >/dev/null 2>&1; then
    smoke_log "SKIP: apt-get not on PATH (not a Debian/Ubuntu family system)"
    exit 0
fi
if ! command -v dpkg-query >/dev/null 2>&1; then
    smoke_log "SKIP: dpkg-query not on PATH"
    exit 0
fi

# Apt-version gate: only run on apt ≥ 3.2.
APT_VERSION="$(apt-get --version 2>/dev/null | head -1 | awk '{print $2}')"
APT_MAJOR="$(printf '%s' "${APT_VERSION}" | cut -d. -f1)"
APT_MINOR="$(printf '%s' "${APT_VERSION}" | cut -d. -f2)"
smoke_log "apt version: ${APT_VERSION} (major=${APT_MAJOR} minor=${APT_MINOR})"
DELEGATION_AVAILABLE=0
if [ -n "${APT_MAJOR}" ] && [ "${APT_MAJOR}" -ge 3 ] 2>/dev/null; then
    if [ "${APT_MAJOR}" -gt 3 ] || { [ "${APT_MAJOR}" -eq 3 ] && [ -n "${APT_MINOR}" ] && [ "${APT_MINOR}" -ge 2 ] 2>/dev/null; }; then
        DELEGATION_AVAILABLE=1
    fi
fi
if [ "${DELEGATION_AVAILABLE}" -eq 0 ]; then
    smoke_log "SKIP: apt ${APT_VERSION} pre-dates native history-rollback (need >= 3.2). AR02.5 owns the synthesis-fallback case for this runner; this smoke activates when AR00 gains a Ubuntu 26.04 leg."
    exit 0
fi

PRIV=""
if command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: sudo not on PATH; apt smoke needs root"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

TARGET_PKG="jq"
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; removing for clean baseline"
    ${PRIV} DEBIAN_FRONTEND=noninteractive apt-get remove -y "${TARGET_PKG}" \
        >/dev/null 2>&1 || true
fi
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "could not establish clean baseline (${TARGET_PKG} still installed after remove)"
fi
smoke_log "baseline: ${TARGET_PKG} absent"

# Snapshot the apt history Transaction-ID seen pre-install. After
# the install we'll re-snapshot; the diff is the new tx_id captured
# by the helper. After undo we expect a SECOND new entry (the
# rollback) referencing the install tx_id.
PRE_LAST_TX_ID="$(${PRIV} grep '^Transaction-ID:' /var/log/apt/history.log 2>/dev/null | tail -1 || true)"
smoke_log "pre-install last Transaction-ID: ${PRE_LAST_TX_ID:-<none>}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

smoke_log "pkg-event apt pre"
"${HELPER_BIN}" pkg-event apt pre --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} DEBIAN_FRONTEND=noninteractive apt-get install -y ${TARGET_PKG}"
${PRIV} DEBIAN_FRONTEND=noninteractive apt-get install -y "${TARGET_PKG}" >/dev/null 2>&1
if ! dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "apt-get install failed; ${TARGET_PKG} not present after install"
fi

POST_INSTALL_TX_ID="$(${PRIV} grep '^Transaction-ID:' /var/log/apt/history.log 2>/dev/null | tail -1 || true)"
smoke_log "post-install last Transaction-ID: ${POST_INSTALL_TX_ID}"
if [ -z "${POST_INSTALL_TX_ID}" ] || [ "${POST_INSTALL_TX_ID}" = "${PRE_LAST_TX_ID}" ]; then
    smoke_fail "apt did not emit a new Transaction-ID for the install (apt ${APT_VERSION} should write one in /var/log/apt/history.log; check apt-helper config)"
fi
INSTALL_TX_ID_NUM="$(printf '%s' "${POST_INSTALL_TX_ID}" | sed -e 's/^Transaction-ID:[[:space:]]*//')"
smoke_log "install tx_id captured by apt: ${INSTALL_TX_ID_NUM}"

smoke_log "pkg-event apt post"
"${HELPER_BIN}" pkg-event apt post --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'PackageOp'" 1 10

# AR02.1 contract: shit undo must dispatch to native history-rollback.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: target pkg is absent (end-state matches both
# delegation and synthesis paths — necessary but not sufficient).
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_PKG} still installed after undo"
fi
smoke_log "post-undo: ${TARGET_PKG} absent"

# Assertion 2: apt history shows a Rollback entry referencing the
# install tx_id. This is what distinguishes delegation (history-
# rollback ran, leaves a Rollback entry) from synthesis (apt-get
# remove ran, leaves an install/remove entry but NOT a Rollback).
HISTORY_TAIL="$(${PRIV} tail -50 /var/log/apt/history.log 2>/dev/null || true)"
if ! printf '%s' "${HISTORY_TAIL}" | grep -qiE 'rollback|Rolled-back'; then
    smoke_log "apt history tail (post-undo):"
    printf '%s\n' "${HISTORY_TAIL}" | sed 's/^/    /' >&2
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "apt history does NOT show a rollback entry — undo took the synthesis path (apt-get remove) instead of the delegation path (apt-get history-rollback). Either the helper failed to capture apt_tx_id at PostExec OR the executor didn't honor the NativeDelegation hint."
fi
smoke_log "apt history shows rollback entry — native delegation path fired"

# Assertion 3 (diagnostic): undo report's applied count.
APPLIED=$(grep -oE 'applied=[0-9]+' "${SHIT_SMOKE_TMP}/undo.log" | head -1 || true)
smoke_log "undo report fragment: ${APPLIED}"
if ! printf '%s' "${APPLIED}" | grep -qE 'applied=[1-9]'; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "undo report shows applied=0 -- delegation was expected to fire one PackageRollback inverse"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: apt-history-rollback-linux (apt ${APT_VERSION} delegation-path: ${TARGET_PKG} install tx_id=${INSTALL_TX_ID_NUM}, rollback verified via apt history)"
