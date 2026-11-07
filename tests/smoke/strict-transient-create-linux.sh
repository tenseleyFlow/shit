#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-transient-create-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice B — files born inside a command need no pre-image.
#
# One command, under SHIT_STRICT_CAPTURE=1:
#   sh -c 'echo a > t; chmod 600 t; mv t f; echo b > u; rm u'
# `t` is created, written, chmodded and renamed to `f`; `u` is created,
# written and removed. None existed when the command started, so none
# needs a pre-image. A pre-existing `keep` file in the same directory
# is not touched and stays byte-identical.
#
# Asserts: the command journals zero CaptureRefused rows, undo exits 0
# with no capture-incomplete refusal, `u` and `t` are absent after
# undo, and `keep` is unchanged.
#
# Not asserted: that undo removes `f`. The journal holds Create(t) and
# Rename(t -> f), and the trunk planner plans no inverse for that pair,
# in either capture mode. That is a planner gap, not a capture one; the
# smoke logs whether `f` survived so the gap stays visible.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-transient-create-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

if ! grep -q "\bbpf\b" /sys/kernel/security/lsm 2>/dev/null; then
    smoke_log "FAIL: kernel lacks the bpf LSM (active=$(cat /sys/kernel/security/lsm 2>/dev/null))"
    exit 1
fi
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    printf '%s' "${HELPER_CAPS}" | grep -q "${required}" \
        || smoke_fail "helper lacks ${required} (getcap output: '${HELPER_CAPS}')"
done
export SHIT_FORCE_TIER=ebpf-lsm

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
printf 'keep me\n' > "${SCRATCH}/keep"
KEEP_SHA="$(sha256sum "${SCRATCH}/keep" | cut -d' ' -f1)"

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${SCRATCH}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

WORKLOAD='echo a > t; chmod 600 t; mv t f; echo b > u; rm u'
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${SCRATCH}" --shell bash --cmdline "sh -c '${WORKLOAD}'" \
    --sock "${SHIT_HOOK_SOCK}"
smoke_log "sh -c '${WORKLOAD}'"
sh -c "${WORKLOAD}"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
[ -f "${SCRATCH}/f" ] || smoke_fail "workload did not leave f"
[ ! -e "${SCRATCH}/u" ] || smoke_fail "workload left u"

set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
sed 's/^/    undo: /' "${SHIT_SMOKE_TMP}/undo.log" >&2 || true
"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

REFUSALS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
if [ "${REFUSALS}" -ne 0 ]; then
    smoke_journal_query "SELECT kind_json FROM events WHERE discriminant = 'CaptureRefused';" \
        | sed 's/^/    refused: /' >&2 || true
    smoke_fail "strict capture journaled ${REFUSALS} CaptureRefused row(s) for born files"
fi
[ "${UNDO_RC}" -eq 0 ] || smoke_fail "shit undo exit=${UNDO_RC}"
if grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_fail "strict undo refused with capture-incomplete"
fi
if [ -e "${SCRATCH}/f" ]; then
    smoke_log "note: undo left f in place (planner has no inverse for Create + Rename of a born file)"
fi
[ ! -e "${SCRATCH}/u" ] || smoke_fail "undo recreated u"
[ ! -e "${SCRATCH}/t" ] || smoke_fail "undo recreated t"
[ "$(sha256sum "${SCRATCH}/keep" | cut -d' ' -f1)" = "${KEEP_SHA}" ] \
    || smoke_fail "keep changed"

smoke_log "PASS: strict-transient-create-linux (born files needed no pre-image; zero refusals)"
