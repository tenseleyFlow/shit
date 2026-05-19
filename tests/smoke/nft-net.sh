#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# DR-40 smoke — nft wrapper bracket-fires the daemon, NetworkOp
# event lands in the journal.
#
# nft needs CAP_NET_ADMIN; we invoke the wrapper under sudo and
# preserve the XDG-overridden env + SHIT_HELPER explicitly. Skip
# cleanly when nft or sudo are absent.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

TEST_TABLE="shit_smoke_$$"

if ! command -v nft >/dev/null 2>&1; then
    smoke_log "nft not present; skipping nft smoke"
    exit 0
fi
if ! command -v sudo >/dev/null 2>&1; then
    smoke_log "sudo not present; skipping nft smoke"
    exit 0
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/nft-wrapper"

# The daemon's ctl socket lives under the smoke user's
# XDG_RUNTIME_DIR; root opening it through the socket fs path is
# fine, but the helper has to look up XDG_RUNTIME_DIR to find the
# default. Preserve it across sudo via `env`.
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Allow root to write to the ctl socket. The socket is owned by the
# runner user; root would normally be allowed via UDS perms (Linux
# unix-domain DGRAM check is the listening side's read mode + the
# sender process's connect rights) — relax to 0666 to be safe under
# the runner's umask.
chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

smoke_log "sudo wrapper add table inet ${TEST_TABLE}"
sudo env "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}" "SHIT_HELPER=${HELPER}" \
    bash "${WRAPPER}" add table inet "${TEST_TABLE}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Cleanup before asserting.
sudo nft delete table inet "${TEST_TABLE}" >/dev/null 2>&1 || true

n="$(smoke_journal_count "discriminant = 'NetworkOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_log "NetworkOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected NetworkOp event; saw ${n}"
fi
smoke_log "NetworkOp events: ${n}"
smoke_log "PASS: nft-net"
