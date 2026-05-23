#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR02.5 smoke — validates that when a package manager LACKS native
# undo (apt < 3.2 here), `shit undo` falls back to the synthesized
# inverse cleanly. The contract per AR02.5 is:
#
#   "when a tool LACKS native undo (e.g., apt < 3.2, brew,
#   freebsd-pkg on Linux which we don't ship), `shit undo` either:
#     - Falls back to the synthesized inverse cleanly, OR
#     - Refuses with a clear error if no synthesis is possible."
#
# This smoke exercises the FIRST branch (synthesis-fallback).
#
# Why this is the AR02.5 contract and not AR02.1: AR02.1 specifically
# tests the delegation path (apt-get history-rollback) which requires
# apt ≥ 3.2 (Debian 14 / Ubuntu 26.04 LTS minimum). The current AR00
# runner image is Ubuntu 24.04 (apt 2.7), where native delegation is
# unavailable. AR02.5 validates the synthesis fallback that runs
# instead.
#
# Tautology proof: with apt < 3.2 the helper's pkg/apt.rs:
# `latest_apt_tx_id` returns None at PostExec time, so the journaled
# `PackageOp.repo_state_hint` is None, so `native_delegation_for` in
# plan.rs returns None, so the planner emits `PackageRollback {
# delegation: None }`, and the executor synthesizes `apt-get remove
# -y <pkg>`. The apt-version gate below makes the "synthesis was
# the chosen path" claim a structural certainty rather than an
# observed string match.
#
# This is the "honest about can't" preview of AR07 -- when shipped
# tools genuinely don't expose native rollback (or expose it only on
# newer releases), shit's behavior is documented + verified.
#
# Linux + Debian/Ubuntu family + apt < 3.2. Skips cleanly otherwise.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: refuse-without-native-delegate is Linux-only (uname=$(uname -s))"
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

# Apt-version gate: this smoke only validates the SYNTHESIS branch.
# On apt ≥ 3.2, AR02.1 owns the delegation-path test instead.
APT_VERSION="$(apt-get --version 2>/dev/null | head -1 | awk '{print $2}')"
APT_MAJOR="$(printf '%s' "${APT_VERSION}" | cut -d. -f1)"
APT_MINOR="$(printf '%s' "${APT_VERSION}" | cut -d. -f2)"
smoke_log "apt version: ${APT_VERSION} (major=${APT_MAJOR} minor=${APT_MINOR})"
if [ -n "${APT_MAJOR}" ] && [ "${APT_MAJOR}" -ge 3 ] 2>/dev/null; then
    if [ "${APT_MAJOR}" -gt 3 ] || { [ "${APT_MAJOR}" -eq 3 ] && [ -n "${APT_MINOR}" ] && [ "${APT_MINOR}" -ge 2 ] 2>/dev/null; }; then
        smoke_log "SKIP: apt ${APT_VERSION} supports native history-rollback; AR02.1 owns this case (delegation path), not AR02.5 (synthesis fallback)"
        exit 0
    fi
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

# Target pkg: small, deterministic, widely available. jq is the
# canonical L03 / AR02.5 test target (matches apt-install-undo-linux.sh).
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

# Make the ctl socket reachable by root (XDG env strips on escalation).
chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

smoke_log "pkg-event apt pre"
"${HELPER_BIN}" pkg-event apt pre --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} DEBIAN_FRONTEND=noninteractive apt-get install -y ${TARGET_PKG}"
${PRIV} DEBIAN_FRONTEND=noninteractive apt-get install -y "${TARGET_PKG}" >/dev/null 2>&1
if ! dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "apt-get install failed; ${TARGET_PKG} not present after install"
fi
smoke_log "post-install: ${TARGET_PKG} present (apt synthesis-path will be the inverse)"

smoke_log "pkg-event apt post"
"${HELPER_BIN}" pkg-event apt post --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'PackageOp'" 1 10

# AR02.5 contract: on apt < 3.2, the synthesis path is the ONLY
# available inverse. The undo must apply it cleanly, NOT refuse.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero on the synthesis path -- 'refuse' branch fired when 'synthesis' branch was expected"
}

# Assertion: jq was uninstalled. End-state proves the SYNTHESIS path
# fired (no delegation was possible at apt 2.x → no history-rollback
# command exists).
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_PKG} still installed after undo -- synthesis path didn't fire OR fired but failed"
fi
smoke_log "post-undo: ${TARGET_PKG} absent (synthesis-path inverse ran cleanly)"

# Diagnostic: the undo report's `applied >= 1` confirms at least one
# inverse op fired. For this workload it's exactly one
# PackageRollback. Quoted in the smoke log for the operator.
APPLIED=$(grep -oE 'applied=[0-9]+' "${SHIT_SMOKE_TMP}/undo.log" | head -1 || true)
smoke_log "undo report fragment: ${APPLIED}"
if ! printf '%s' "${APPLIED}" | grep -qE 'applied=[1-9]'; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "undo report shows applied=0 -- synthesis path was expected to fire one PackageRollback inverse"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: refuse-without-native-delegate (apt ${APT_VERSION} synthesis-path: ${TARGET_PKG} installed → undone via synthesized apt-get remove, no native delegation possible)"
