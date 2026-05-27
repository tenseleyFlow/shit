#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AU11 smoke — assert that BSD kqueue non-Delete events ship a
# populated `post_content_hash` instead of NULL.
#
# Pre-AU11: `crates/shit-helper/src/capture/bsd.rs:424` carried a
# TODO that left post_content_hash = None for every event. The
# planner's drift-detection (Hard conflict when post != current
# at undo time) couldn't fire for any non-Delete event on BSD.
#
# Post-AU11: non-Delete events ship the held fd's hash (which on
# post-hoc kqueue is the post-mutation content). Delete events
# correctly stay None (no post-content exists).
#
# Verification surface:
#   1. mkdir watched/; write known-content foo.txt
#   2. Pre-exec the watched dir
#   3. Write NEW content to foo.txt (Write event, not Delete)
#   4. Post-exec
#   5. Assert: the resulting FilePreImage event has
#      post_content_hash IS NOT NULL.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: post-hash-non-delete-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
cd "${WATCHED}"
printf 'pre-content v1\n' > foo.txt

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.3

# Workload: overwrite foo.txt — a Write event (NOT a Delete).
smoke_log "overwriting foo.txt with post content"
printf 'post-content v2\n' > foo.txt
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# Assert a FilePreImage event was journaled for foo.txt.
N_PRE="$(smoke_journal_count "discriminant = 'FilePreImage' AND path LIKE '%foo.txt'" 2>/dev/null || echo 0)"
smoke_log "FilePreImage events for foo.txt: ${N_PRE}"
if [ "${N_PRE}" -lt 1 ]; then
    smoke_log "journal dump:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id" \
        | sed 's/^/    /' >&2 || true
    smoke_fail "expected FilePreImage event for foo.txt, got ${N_PRE}"
fi

# THE AU11 assertion: post_content_hash IS NOT NULL on the non-Delete
# FilePreImage. Pre-AU11 this was NULL; post-AU11 it carries the
# helper's view of the held-fd content (which on post-hoc kqueue is
# the post-mutation hash).
N_WITH_POST="$(smoke_journal_count "discriminant = 'FilePreImage' AND path LIKE '%foo.txt' AND post_content_hash IS NOT NULL" 2>/dev/null || echo 0)"
smoke_log "FilePreImage events for foo.txt with post_content_hash set: ${N_WITH_POST}"
if [ "${N_WITH_POST}" -lt 1 ]; then
    smoke_log "AU11 regression — post_content_hash is NULL on a non-Delete event"
    smoke_log "journal dump (relevant columns):"
    smoke_journal_query "SELECT id, discriminant, path, length(post_content_hash) AS post_hash_len FROM events WHERE path LIKE '%foo.txt' ORDER BY id" \
        | sed 's/^/    /' >&2 || true
    smoke_fail "expected post_content_hash populated, got NULL for foo.txt non-Delete event"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: post-hash-non-delete-fbsd (${N_WITH_POST} non-Delete event(s) journaled with post_content_hash)"
