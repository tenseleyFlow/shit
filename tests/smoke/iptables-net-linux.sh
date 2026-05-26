#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR08.2.iptables smoke (Linux twin pattern of nft-net.sh) — the
# iptables wrapper bracket-fires the daemon, a NetworkOp event
# lands in the journal. Closes the AR08.1 'covered, smoke-gap'
# entry for iptables.
#
# iptables needs CAP_NET_ADMIN; we invoke the wrapper under
# sudo and preserve the XDG-overridden env + SHIT_HELPER
# explicitly. Skip cleanly when iptables or sudo are absent.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

TEST_CHAIN="SHIT_SMOKE_$$"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: iptables-net-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v iptables >/dev/null 2>&1; then
    smoke_log "iptables not present; skipping iptables smoke"
    exit 0
fi
if ! command -v sudo >/dev/null 2>&1; then
    smoke_log "sudo not present; skipping iptables smoke"
    exit 0
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/iptables-wrapper"
[ -x "${WRAPPER}" ] || smoke_fail "iptables wrapper missing at ${WRAPPER}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Allow root to write to the ctl socket. Socket is owned by the
# runner user; relax mode so the sudo'd helper can connect.
chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

smoke_log "sudo wrapper -N ${TEST_CHAIN} (create test chain)"
sudo env "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}" "SHIT_HELPER=${HELPER}" \
    bash "${WRAPPER}" -N "${TEST_CHAIN}"

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Cleanup before asserting.
sudo iptables -X "${TEST_CHAIN}" >/dev/null 2>&1 || true

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
smoke_log "PASS: iptables-net-linux"
