#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR02.2 smoke — dnf-history-undo delegation path.
#
# Contract: on a Fedora-family system with `dnf` present, `shit undo`
# dispatches to `dnf history undo <id>` instead of synthesizing a
# per-package `dnf remove`. End-state matches AR02.5's apt synthesis
# (package absent post-undo) but the path through the planner is
# different:
#
#   helper pkg/dnf.rs::latest_dnf_history_id parses
#     `dnf history --reverse` output
#   → planner sets PackageOp.repo_state_hint = Some(history_id)
#   → native_delegation_for(Dnf, Some(history_id)) returns
#     Some(NativeDelegation::DnfHistoryUndo)
#   → executor runs `dnf history undo <history_id>` instead of
#     `dnf remove <pkg>`
#
# Activates on a runner with dnf installed. Skips cleanly on
# Debian/Ubuntu systems (current AR00 runner is Debian-family) --
# written now so it activates automatically when AR00 gains a
# Fedora leg. See AR10.7 for un-skip work tracking.
#
# Unlike AR02.1/AR02.5 (which are mutually-exclusive by apt-version
# gate on the same Debian-family runner), AR02.2 has NO synthesis-
# fallback counterpart on a Fedora system because dnf's history
# verb has always existed in mainline dnf. The skip on the current
# Debian-family runner is total -- if you want dnf coverage, you
# need a dnf-bearing runner.
#
# Linux + Fedora family + dnf present. Skips otherwise.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: dnf-history-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v dnf >/dev/null 2>&1; then
    smoke_log "SKIP: dnf not on PATH (not a Fedora-family system). AR10.7 tracks adding a Fedora CI leg."
    exit 0
fi
if ! command -v rpm >/dev/null 2>&1; then
    smoke_log "SKIP: rpm not on PATH (dnf without rpm shouldn't happen, but be defensive)"
    exit 0
fi

# Log the dnf version for diagnostic visibility -- dnf5 (Fedora 41+)
# and dnf2 (Fedora <= 40) have different `history` output schemas;
# the helper's pkg/dnf.rs should handle both, but the smoke logs the
# detected version so any schema-drift failure is easy to attribute.
DNF_VERSION="$(dnf --version 2>/dev/null | head -1 || true)"
smoke_log "dnf version: ${DNF_VERSION:-<unknown>}"

PRIV=""
if command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: sudo not on PATH; dnf smoke needs root"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Target pkg: small, deterministic. jq is in Fedora's default repos.
TARGET_PKG="jq"
if rpm -q "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; removing for clean baseline"
    ${PRIV} dnf remove -y "${TARGET_PKG}" >/dev/null 2>&1 || true
fi
if rpm -q "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "could not establish clean baseline (${TARGET_PKG} still installed after remove)"
fi
smoke_log "baseline: ${TARGET_PKG} absent"

# Snapshot the highest dnf history ID pre-install. After install we
# expect a NEW id. After undo we expect that id to show as type
# `Undone` (dnf5) / `Rollback` (dnf2) in the history listing.
PRE_LAST_HISTORY_ID="$(${PRIV} dnf history --reverse 2>/dev/null | awk '/^[[:space:]]*[0-9]+/ {print $1; exit}' || true)"
smoke_log "pre-install last dnf history id: ${PRE_LAST_HISTORY_ID:-<none>}"

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

smoke_log "pkg-event dnf pre"
"${HELPER_BIN}" pkg-event dnf pre --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} dnf install -y ${TARGET_PKG}"
${PRIV} dnf install -y "${TARGET_PKG}" >/dev/null 2>&1
if ! rpm -q "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_fail "dnf install failed; ${TARGET_PKG} not present after install"
fi

POST_INSTALL_HISTORY_ID="$(${PRIV} dnf history --reverse 2>/dev/null | awk '/^[[:space:]]*[0-9]+/ {print $1; exit}' || true)"
smoke_log "post-install last dnf history id: ${POST_INSTALL_HISTORY_ID}"
if [ -z "${POST_INSTALL_HISTORY_ID}" ] || [ "${POST_INSTALL_HISTORY_ID}" = "${PRE_LAST_HISTORY_ID}" ]; then
    smoke_fail "dnf did not emit a new history id for the install"
fi

smoke_log "pkg-event dnf post"
"${HELPER_BIN}" pkg-event dnf post --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'PackageOp'" 1 10

# AR02.2 contract: shit undo dispatches to `dnf history undo <id>`.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: target pkg absent (necessary; not sufficient).
if rpm -q "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${TARGET_PKG} still installed after undo"
fi
smoke_log "post-undo: ${TARGET_PKG} absent"

# Assertion 2: dnf history shows the install id as Undone / Rollback.
# dnf5 marks undone entries with `Action(s): Removed` in the
# detail view + an `Undone` indicator in the list output. dnf2 marks
# with `Action(s)` and the entry shows the install in `Reverted-By`.
# Grep loosely for the matching id followed by an undo indicator.
HISTORY_TAIL="$(${PRIV} dnf history --reverse 2>/dev/null | head -30 || true)"
if ! printf '%s' "${HISTORY_TAIL}" | grep -qiE 'undone|rollback|reverted'; then
    smoke_log "dnf history --reverse (head -30):"
    printf '%s\n' "${HISTORY_TAIL}" | sed 's/^/    /' >&2
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "dnf history does NOT show an undone/rollback entry -- undo took the synthesis path (dnf remove) instead of the delegation path (dnf history undo). Either the helper failed to capture dnf_history_id at PostExec OR the executor didn't honor the NativeDelegation hint."
fi
smoke_log "dnf history shows undone/rollback entry -- native delegation path fired"

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

smoke_log "PASS: dnf-history-undo-linux (dnf delegation-path: ${TARGET_PKG} install id=${POST_INSTALL_HISTORY_ID}, rollback verified via dnf history)"
