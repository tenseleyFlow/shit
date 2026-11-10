#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: ufw-allow-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# L8 smoke: `ufw allow <port>/tcp` through the shipped ufw wrapper, then
# `shit undo`. The wrapper brackets the command with net-event calls, so
# the daemon journals a NetworkOp with before/after `ufw status` blobs.
# ufw must be enabled for those blobs to list rules, so the smoke enables
# it first and disables it again on exit.
#
# Pass conditions: a NetworkOp lands in the journal, and then either the
# rule is gone after `shit undo` (Outcome A), or undo exits non-zero and
# says why (Outcome B, for example when the daemon cannot run ufw as
# non-root). Undo exiting 0 with the rule still present fails the smoke.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: ufw-allow-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
for t in ufw sudo python3; do
    if ! command -v "${t}" >/dev/null 2>&1; then
        smoke_log "SKIP: ${t} not present"
        exit 0
    fi
done
if ! sudo -n true 2>/dev/null; then
    smoke_log "SKIP: passwordless sudo unavailable"
    exit 0
fi

PORT=54321
# Host safety. Enabling ufw can cut an SSH session and a stray rule
# changes the host's firewall, so outside CI the smoke runs only when ufw
# is already active.
UFW_WAS_ACTIVE=0
if sudo ufw status | grep -q '^Status: active'; then
    UFW_WAS_ACTIVE=1
fi
if [ -z "${CI:-}" ] && [ -z "${GITHUB_ACTIONS:-}" ] && [ "${UFW_WAS_ACTIVE}" = "0" ]; then
    smoke_log "SKIP: ufw is inactive and this is not CI; not enabling a firewall on a personal host"
    exit 0
fi
# Never touch a rule that is not ours.
if sudo ufw show added 2>/dev/null | grep -q "${PORT}/tcp"; then
    smoke_fail "a ${PORT}/tcp rule already exists on this host; refusing to touch it"
fi
UFW_RULE_ADDED=0
cleanup_ufw() {
    if [ "${UFW_RULE_ADDED}" = "1" ]; then
        sudo ufw --force delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
    fi
    if [ "${UFW_WAS_ACTIVE}" = "0" ]; then
        sudo ufw --force disable >/dev/null 2>&1 || true
    fi
}
# Keep lib.sh's cleanup (it stops shitd) and run ours first.
trap 'cleanup_ufw; smoke_cleanup' EXIT

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
WRAPPER="${SHIT_REPO_ROOT}/packaging/net-hooks/ufw-wrapper"
[ -x "${WRAPPER}" ] || smoke_fail "ufw wrapper missing at ${WRAPPER}"
export SHIT_HELPER_BIN="${HELPER}"
# The wrapper derives nothing from its own name, but keep the same
# symlink shape as the iptables smoke.
WRAPPER_LINK="${SHIT_SMOKE_TMP}/ufw"
ln -sf "${WRAPPER}" "${WRAPPER_LINK}"

sudo ufw --force enable >/dev/null

chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "" --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

UFW_RULE_ADDED=1
smoke_log "sudo ufw allow ${PORT}/tcp (via wrapper)"
sudo env "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR}" "SHIT_HELPER=${HELPER}" "PATH=${SHIT_SMOKE_TMP}:${PATH}" \
    "${WRAPPER_LINK}" allow "${PORT}/tcp"

if ! sudo ufw status | grep -q "${PORT}/tcp"; then
    smoke_fail "ufw allow did not add the rule"
fi

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

n="$(smoke_journal_count "discriminant = 'NetworkOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_journal_query "SELECT id, discriminant FROM events;" | sed 's/^/    /' >&2 || true
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected a NetworkOp event; saw ${n}"
fi
smoke_log "NetworkOp events: ${n}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if ! sudo ufw status | grep -q "${PORT}/tcp"; then
    smoke_log "OUTCOME A: rule removed by undo"
    smoke_log "PASS: ufw-allow-undo-linux (Outcome A)"
    exit 0
fi

smoke_log "rule ${PORT}/tcp still present after undo"
if [ "${SHIT_REQUIRE_OUTCOME_A:-}" = "1" ]; then
    smoke_fail "SHIT_REQUIRE_OUTCOME_A=1: ufw rule not removed"
fi
if [ "${UNDO_RC}" -ne 0 ]; then
    smoke_log "OUTCOME B: undo failed loudly (exit ${UNDO_RC}), rule left in place"
    smoke_log "PASS: ufw-allow-undo-linux (Outcome B)"
    exit 0
fi
smoke_fail "undo exited 0 but the ufw rule is still present"
