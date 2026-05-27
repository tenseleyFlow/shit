#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: brew-pkg
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# DR-22 smoke — brew wrapper bracket-fires the daemon, PackageOp
# event lands in the journal.
#
# brew is unprivileged on macOS (Homebrew lives under the user's
# prefix), so no sudo. Picks a small package and uninstalls after.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

TARGET_PKG="hello"  # tiny, no deps

if ! command -v brew >/dev/null 2>&1; then
    smoke_log "brew not present; skipping brew smoke"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "python3 not present; skipping brew smoke"
    exit 0
fi

# Pre-flight: uninstall if leftover from a previous run.
if brew list "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; uninstalling for clean baseline"
    brew uninstall --quiet "${TARGET_PKG}" >/dev/null 2>&1 || true
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/pkg-hooks/brew-wrapper"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Brew is unprivileged — no sudo, env passes through.
export SHIT_HELPER="${HELPER}"
smoke_log "wrapper install ${TARGET_PKG}"
"${WRAPPER}" install --quiet "${TARGET_PKG}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

# Cleanup before assert so a fail doesn't leak the package.
brew uninstall --quiet "${TARGET_PKG}" >/dev/null 2>&1 || true

n="$(smoke_journal_count "discriminant = 'PackageOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_log "PackageOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected PackageOp event after brew install; saw ${n}"
fi
smoke_log "PackageOp events: ${n}"
smoke_log "PASS: brew-pkg"
