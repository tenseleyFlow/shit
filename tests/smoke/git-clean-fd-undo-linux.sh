#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: git-clean-fd-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# `git clean -fd` command-atomic refusal smoke.
#
# The regular-file unlinks have complete content pre-images, but the final
# directory removals have metadata-only evidence that cannot yet reproduce
# all directory metadata. Those typed markers become CaptureRefused. The
# planner must then refuse the entire command: applying only the regular-file
# inverses would leave a misleading half-restored tree.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: git-clean-fd-undo-linux is Linux-only"
    exit 0
fi
if [ -z "${GIT_BIN}" ]; then
    smoke_log "SKIP: git not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"
smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
[ "${caps_rc}" = "0" ] || exit "${caps_rc}"

REPO="${SHIT_SMOKE_TMP}/scratch/repo"
mkdir -p "${REPO}"

git_invoke -C "${REPO}" init -q
echo "tracked" > "${REPO}/tracked.txt"
git_invoke -C "${REPO}" add tracked.txt
git_invoke -C "${REPO}" commit -q -m "anchor"

# Untracked files at the top level + nested under an untracked dir.
echo "alpha" > "${REPO}/untracked-a.txt"
echo "bravo" > "${REPO}/untracked-b.txt"
mkdir -p "${REPO}/junk/nested"
echo "charlie" > "${REPO}/junk/c.txt"
echo "delta"   > "${REPO}/junk/nested/d.txt"

# Pin a non-default mode so the metadata-only marker is nontrivial; the
# current model still cannot claim that this is the complete pre-state.
chmod 0750 "${REPO}/junk"
smoke_log "pre-clean dir mode: junk=$(stat -c '%a' "${REPO}/junk")"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${REPO}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${REPO}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# THE workload.
smoke_log "git clean -fd"
git_invoke -C "${REPO}" clean -fd 2>&1 | sed 's/^/    /' >&2

# Sanity: all untracked entries gone.
for p in untracked-a.txt untracked-b.txt junk; do
    [ ! -e "${REPO}/${p}" ] || smoke_fail "clean didn't remove ${p}"
done
smoke_log "clean landed: all untracked gone"

sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
NUM_PRE="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events: ${NUM_PRE}"
smoke_wait_for_event "discriminant = 'CaptureRefused' AND path LIKE '%/junk%'" 1 10
NUM_REFUSED="$(smoke_journal_count "discriminant = 'CaptureRefused' AND path LIKE '%/junk%'")"
smoke_log "directory CaptureRefused events: ${NUM_REFUSED}"

# The top-level directory marker must not also become an actionable unlink.
N_LOSSY_DIR_OPS="$(smoke_journal_count "discriminant = 'TreeOpUnlink' AND path LIKE '%/junk'")"
if [ "${N_LOSSY_DIR_OPS}" -ne 0 ]; then
    smoke_fail "git clean directory also journaled ${N_LOSSY_DIR_OPS} lossy TreeOpUnlink event(s)"
fi

smoke_log "running: shit undo --yes (expecting command-atomic refusal)"
UNDO_RC=0
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || UNDO_RC=$?
if [ "${UNDO_RC}" -eq 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "git clean CaptureRefused unexpectedly exited 0"
fi

if ! grep -qiE "Refused|capture-incomplete|metadata-only deletion marker" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "undo failed without surfacing the git-clean directory refusal"
fi
if ! grep -q "applied=0" "${SHIT_SMOKE_TMP}/undo.log"; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "command-atomic refusal still applied one or more file inverses"
fi

# None of the otherwise-actionable regular-file pre-images may be replayed.
# Every path removed by git clean must remain absent after the refusal.
for p in untracked-a.txt untracked-b.txt junk junk/nested junk/c.txt junk/nested/d.txt; do
    if [ -e "${REPO}/${p}" ]; then
        smoke_log "unexpected post-refusal path: ${REPO}/${p}"
        find "${REPO}" -name '.git' -prune -o -print 2>/dev/null | sed 's/^/    /' >&2 || true
        smoke_fail "git-clean refusal applied a partial or lossy inverse"
    fi
done
[ -f "${REPO}/tracked.txt" ] || smoke_fail "refused undo perturbed tracked.txt"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-clean-fd-undo-linux (${NUM_PRE} file pre-images suppressed by ${NUM_REFUSED} directory refusal(s); no partial inverse applied)"
