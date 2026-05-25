#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.8.xargs smoke — `... | xargs rm` deletes multiple files via
# an exec'd `rm` process whose ancestry chain is:
#     shell → xargs → rm
# The shim runs inside the rm process; its pid → CommandId
# resolver (ActiveCommands::resolve_by_descendant) walks the
# parent chain via `ps -p` on FreeBSD. A multi-hop chain plus
# a fast-dying rm is the canonical attribution-race scenario
# that W06.A.3's pre-ack synchronous resolution closed.
#
# If this smoke fails, the rm child's notification arrives but
# the daemon's ancestor walk misses the tracked shell — events
# get orphaned and dropped silently.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: xargs-rm-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"

declare -A PRE_SHAS
for name in alpha bravo charlie delta echo_; do
    f="${WATCHED}/${name}.txt"
    printf 'content for %s\n' "${name}" > "${f}"
    PRE_SHAS[$name]="$(/sbin/sha256 -q "${f}")"
    smoke_log "pre-cmd ${name}.txt sha: ${PRE_SHAS[$name]}"
done

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# THE workload: pipe filenames into `xargs rm`. xargs collects
# argv from stdin and exec's `rm a b c d e_` in one batch.
smoke_log "ls *.txt | xargs rm"
ls *.txt | xargs rm

# Sanity: all 5 files gone.
for name in alpha bravo charlie delta echo_; do
    [ ! -e "${WATCHED}/${name}.txt" ] || smoke_fail "xargs rm didn't delete ${name}.txt"
done

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

failures=()
for name in alpha bravo charlie delta echo_; do
    f="${WATCHED}/${name}.txt"
    if [ ! -f "${f}" ]; then
        failures+=("${name}.txt MISSING post-undo")
        continue
    fi
    post="$(/sbin/sha256 -q "${f}")"
    if [ "${post}" != "${PRE_SHAS[$name]}" ]; then
        failures+=("${name}.txt content mismatch: ${post} != ${PRE_SHAS[$name]}")
    fi
done

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: xargs-rm-undo-fbsd (5 files restored byte-identical via 3-hop ancestry)"
    exit 0
fi

smoke_fail "xargs rm undo failed: ${failures[*]}"
