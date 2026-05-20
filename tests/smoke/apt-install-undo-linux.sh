#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# L03 smoke — `apt-get install -y <target>; shit undo` removes it.
#
# Exercises:
#   1. helper's `pkg-event apt pre` collects the pre-state package list
#      via dpkg-query.
#   2. The real `apt-get install -y` runs (as root).
#   3. helper's `pkg-event apt post` collects the post-state.
#   4. Daemon diffs pre/post → journals a PackageOp event for the new
#      package.
#   5. `shit undo` plans `InverseOp::PackageRollback { uninstall: [target] }`
#      and executes via the PackageExecutor (shells out to
#      `apt-get remove -y` through sudo).
#
# Skips cleanly on NixOS (no apt) and any other non-Debian-family
# system. Validate this smoke in an Ubuntu environment — CI's
# ubuntu-24.04 runner (L07) or a local docker container.
#
# Prereqs (when run):
#   - apt-get available (Debian/Ubuntu).
#   - sudo configured for the test user (NOPASSWD on apt-get and
#     dpkg if running unattended).
#   - Network access for the apt repos.
#   - `python3`, `sqlite3`.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: apt-install-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v apt-get >/dev/null 2>&1; then
    smoke_log "SKIP: apt-get not on PATH (this isn't a Debian-family system)"
    exit 0
fi
if ! command -v dpkg-query >/dev/null 2>&1; then
    smoke_log "SKIP: dpkg-query not on PATH (apt without dpkg shouldn't happen, but be defensive)"
    exit 0
fi

PRIV=""
if command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: sudo not on PATH; apt-install smoke needs root"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Target pkg: small, no daemons, no scripts. `jq` is ~50 KB plus libs,
# pure userspace, widely available in the apt repos. If already
# installed, remove first for a clean baseline.
TARGET_PKG="jq"
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; removing for clean baseline"
    ${PRIV} DEBIAN_FRONTEND=noninteractive apt-get remove -y "${TARGET_PKG}" \
        >/dev/null 2>&1 || true
fi
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "could not establish clean baseline (${TARGET_PKG} still installed after remove)"
fi

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

# Make the ctl socket readable by root (escalation strips XDG env).
chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

# Drive the pkg-event hooks directly. Production deployment would
# install an apt DPkg::Pre-Invoke / Post-Invoke hook config under
# /etc/apt/apt.conf.d/; the smoke skips that step so the test
# remains hermetic and doesn't leave config behind.
smoke_log "pkg-event apt pre"
"${HELPER_BIN}" pkg-event apt pre --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} DEBIAN_FRONTEND=noninteractive apt-get install -y ${TARGET_PKG}"
${PRIV} DEBIAN_FRONTEND=noninteractive apt-get install -y "${TARGET_PKG}" >/dev/null 2>&1
if ! dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "apt-get install failed; ${TARGET_PKG} not present after install"
fi

smoke_log "pkg-event apt post"
"${HELPER_BIN}" pkg-event apt post --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'PackageOp'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: target pkg should be gone.
if dpkg-query -s "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_PKG} still installed after undo — package rollback didn't fire"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: apt-install-undo-linux (${TARGET_PKG} installed→undone)"
