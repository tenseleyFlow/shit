#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: post-hash-drift-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU11 — planner-side drift detection.
#
# `post-hash-non-delete-fbsd.sh` already proves the BSD capture
# tier ships `post_content_hash` for non-Delete events. This smoke
# closes the loop: when the user edits a file AFTER the original
# command (so current bytes diverge from the recorded post-hash),
# `shit undo --dry-run` must surface a Hard conflict — not silently
# clobber the post-command edits.
#
# Flow:
#   1. mkdir watched/; write foo.txt = "pre-content"
#   2. pre-exec
#   3. Overwrite foo.txt = "post-content" (BSD captures
#      post_content_hash = blake3("post-content"))
#   4. post-exec
#   5. The "user" now edits foo.txt = "drifted-content"
#      (this is what plan.rs:657-669 detects as drift)
#   6. shit undo --dry-run --on-conflict=abort
#   7. Assert: exit non-zero AND output mentions "modified since"
#      (the substring from plan.rs:664).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: post-hash-drift-fbsd is FreeBSD-only (uname=$(uname -s))"
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

# Step 3 — workload: overwrite foo.txt. BSD captures the post-image
# hash (claimed_hash from stream_copy_to_staging).
smoke_log "step 3: workload — overwrite foo.txt with post content"
printf 'post-content v2\n' > foo.txt
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 0.8

# Sanity gate — confirm the captured event actually has a non-NULL
# post_content_hash. If this fails, the drift assertion below would
# false-negative (no drift signal possible without the hash).
N_WITH_POST="$(smoke_journal_count "discriminant = 'FilePreImage' AND path LIKE '%foo.txt' AND post_content_hash IS NOT NULL" 2>/dev/null || echo 0)"
if [ "${N_WITH_POST}" -lt 1 ]; then
    smoke_log "AU11 regression — post_content_hash is NULL on the Write event"
    smoke_journal_query "SELECT id, discriminant, path, length(post_content_hash) AS post_hash_len FROM events WHERE path LIKE '%foo.txt' ORDER BY id" \
        | sed 's/^/    /' >&2 || true
    smoke_fail "expected post_content_hash populated; got NULL"
fi
smoke_log "gate: post_content_hash populated (${N_WITH_POST} event(s))"

# Step 5 — simulate post-command user edit. This is the drift the
# planner must detect.
smoke_log "step 5: user edits foo.txt after the captured command"
printf 'drifted-content v3 — user edit after command\n' > foo.txt
sleep 0.3

# Step 6 — shit undo --dry-run. Plan.rs:657-669 should compare the
# stored post_content_hash against the current file's hash; they
# differ, so Conflict::Hard fires.
smoke_log "step 6: shit undo --dry-run --on-conflict=abort"
set +e
"${SHIT_BIN}" undo --dry-run --on-conflict=abort > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2 || true

# Step 7 — assertions.
if [ "${UNDO_RC}" -eq 0 ]; then
    smoke_fail "expected non-zero exit when post-hash drift is detected; got 0"
fi

if ! grep -qE "modified since|ConflictHard|conflicted" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "expected drift signal absent from output"
    smoke_fail "no 'modified since' / 'ConflictHard' / 'conflicted' in undo output"
fi

# And confirm the live file is still the user's drifted content —
# dry-run must not have applied anything.
CURRENT="$(cat foo.txt)"
case "${CURRENT}" in
    *drifted-content*) ;;
    *)
        smoke_fail "dry-run mutated foo.txt — got '${CURRENT}'"
        ;;
esac

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: post-hash-drift-fbsd (planner surfaced Hard conflict on user-edit-after-command)"
