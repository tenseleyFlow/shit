#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: pkg-install-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# S29.5 smoke — `pkg install -y <target>; shit undo` removes the package.
#
# Exercises:
#   1. helper's `pkg-event pkg pre` collects the pre-state package list.
#   2. The real `pkg install` runs (as root).
#   3. helper's `pkg-event pkg post` collects the post-state.
#   4. Daemon diffs pre/post → journals a PackageOp event for the new pkg.
#   5. `shit undo` plans `InverseOp::PackageRollback { uninstall: [target] }`
#      and executes via the PackageExecutor (shells out to `pkg delete`).
#
# Prereqs on the FreeBSD VM:
#   - `doas` installed (or `sudo`) with the freebsd user permitted to
#     run `pkg install`/`pkg delete` without password prompts. The
#     project's standing rule is the FreeBSD VM is the validation
#     target; configuring it once is fine.
#   - Network access for the FreeBSD pkg repo (or local mirror).
#   - `python3`, `sqlite3` (already on the VM after the S24.C pkg
#     install round).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: pkg-install-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

# Pre-flight: pick the privilege-escalation tool. Standard FreeBSD
# install has neither; the VM should have `doas` configured per S29.5
# prereqs. Skip cleanly if absent so devs can iterate without
# triggering install prompts.
PRIV=""
if command -v doas >/dev/null 2>&1; then
    PRIV="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: neither doas nor sudo on PATH; pkg-install smoke needs root"
    smoke_log "      one-time VM setup (run from your dev box):"
    smoke_log "      ssh -t freebsd@<vm> 'echo \"pkg install -y doas && echo permit nopass :wheel > /usr/local/etc/doas.conf\" | su -'"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
if [ ! -x "${HELPER_BIN}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
fi
export SHIT_HELPER_BIN="${HELPER_BIN}"

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

# Target pkg: small, no daemons, no scripts. `jot` is a base-utility
# rewrite ported separately — ~50 KB and pure data. If `jot` is
# already installed, pick a fallback.
TARGET_PKG="jot"
if /usr/sbin/pkg info -e "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; removing for clean baseline"
    ${PRIV} /usr/sbin/pkg delete -y "${TARGET_PKG}" >/dev/null 2>&1 || true
fi
if /usr/sbin/pkg info -e "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "could not establish clean baseline (${TARGET_PKG} still installed after delete)"
fi

smoke_start_shitd

# Register a command window for $$. Without this the daemon's
# active_commands::resolve_by_descendant walk finds nothing and the
# pkg-event is dropped.
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

# Manually invoke the pkg-event hooks bracketing the real install.
# Production path is pkg(8)'s EVENT_PIPE; for the smoke we drive the
# wire directly so we don't have to install /usr/local/etc/pkg.conf.d
# config that would persist between runs.
smoke_log "pkg-event pre"
"${HELPER_BIN}" pkg-event pkg pre --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} pkg install -y ${TARGET_PKG}"
${PRIV} /usr/sbin/pkg install -y "${TARGET_PKG}" >/dev/null 2>&1
if ! /usr/sbin/pkg info -e "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "pkg install failed; ${TARGET_PKG} not present after install"
fi

smoke_log "pkg-event post"
"${HELPER_BIN}" pkg-event pkg post --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Wait for the daemon to journal the PackageOp event.
smoke_wait_for_event "discriminant = 'PackageOp'" 1 10

smoke_log "running: shit undo --yes"
# Tell the executor where doas/sudo lives so it can re-escalate.
export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: target pkg should be gone.
if /usr/sbin/pkg info -e "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_PKG} still installed after undo — package rollback didn't fire"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: pkg-install-undo-fbsd (${TARGET_PKG} installed→undone)"
