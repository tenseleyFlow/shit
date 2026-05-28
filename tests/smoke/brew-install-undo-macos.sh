#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: brew-install-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M05.1 — end-to-end brew install → undo round-trip on macOS.
# Companion to (not replacement for) `brew-pkg.sh`, which validates
# that the brew wrapper bracket-fires a PackageOp event. This smoke
# goes further: after the PackageOp lands, `shit undo` is invoked
# and the assertion is that the package is actually uninstalled.
# Exercises the brew_argv planner inverse + the executor's spawn of
# `brew uninstall`.
#
# Target: `hello` (tiny, no deps). Pre-flight uninstalls any
# leftover from a prior run.
#
# Outcomes:
#   A. Full undo: package gone post-undo, undo exits 0.
#   B. Loud refusal: undo non-zero AND log mentions the package or
#      "unsupported"-style wording. Accepted as graceful failure.
#   C. Silent partial undo (FAIL): package remains + undo exits 0.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: brew-install-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

TARGET_PKG="hello"

if ! command -v brew >/dev/null 2>&1; then
    smoke_log "SKIP: brew not on PATH"
    exit 0
fi

# Pre-flight: ensure package isn't already installed.
if brew list "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; uninstalling for clean baseline"
    brew uninstall --quiet "${TARGET_PKG}" >/dev/null 2>&1 || true
fi
# Sanity: didn't leak from a prior run.
if brew list "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "${TARGET_PKG} still installed after pre-flight uninstall"
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/pkg-hooks/brew-wrapper"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing at ${SHIT_BIN}"
[ -x "${WRAPPER}" ]    || smoke_fail "brew-wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SESSION="$(/opt/homebrew/bin/python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null \
    || python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# Brew is unprivileged on macOS — no sudo. Wrapper handles bracketing.
export SHIT_HELPER="${HELPER_BIN}"
smoke_log "brew wrapper install ${TARGET_PKG}"
set +e
"${WRAPPER}" install --quiet "${TARGET_PKG}" >"${SHIT_SMOKE_TMP}/brew-install.log" 2>&1
INSTALL_RC=$?
set -e
if [ "${INSTALL_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/brew-install.log" >&2
    smoke_fail "brew install via wrapper exited rc=${INSTALL_RC}"
fi
if ! brew list "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "brew install claimed success but ${TARGET_PKG} not present"
fi
smoke_log "post-install: brew list ${TARGET_PKG} OK"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

N_PKG_OPS="$(smoke_journal_count "discriminant = 'PackageOp'" 2>/dev/null || echo 0)"
smoke_log "PackageOp events: ${N_PKG_OPS}"
N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

POST_UNDO_PRESENT="no"
if brew list "${TARGET_PKG}" >/dev/null 2>&1; then
    POST_UNDO_PRESENT="yes"
fi
smoke_log "post-undo: brew list ${TARGET_PKG} → ${POST_UNDO_PRESENT}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Cleanup leftover whether we pass or fail.
brew uninstall --quiet "${TARGET_PKG}" >/dev/null 2>&1 || true

# Outcome A — full undo
if [ "${POST_UNDO_PRESENT}" = "no" ] && [ "${UNDO_RC}" -eq 0 ]; then
    smoke_log "OUTCOME A — full undo (${TARGET_PKG} uninstalled by undo)"
    smoke_log "PASS: brew-install-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "${TARGET_PKG}|brew|unsupported|refus|conflict" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named brew/package/refusal)"
    smoke_log "PASS: brew-install-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent partial undo"
smoke_log "  pre:        not installed"
smoke_log "  post-cmd:   installed"
smoke_log "  post-undo:  ${POST_UNDO_PRESENT}"
smoke_log "  undo exit:  ${UNDO_RC}"
smoke_log "  PackageOp:  ${N_PKG_OPS}"
smoke_log "  journal:    ${N_EVENTS}"
smoke_fail "brew install undo did NOT remove ${TARGET_PKG} (Outcome C)"
