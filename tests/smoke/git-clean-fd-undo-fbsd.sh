#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# G01.5 smoke — `git clean -fd` deletes untracked files and
# (with `-d`) untracked directories. `shit undo` recreates
# everything byte-identical.
#
# File path: covered by W09.5 unlink-with-pre-image atomic-replace,
# extended by G01.3 to also cover gone-at-undo.
#
# Directory path: G01.5 predicted-gap area. `unlinkat(AT_REMOVEDIR)`
# fires the LSM unlink hook, but the helper's fstat-on-fd returns
# FileType::Directory which fails the `file_type == Regular` check
# → marker-only event with no pre-image bytes (dirs don't have
# content). The planner then emits RecreatePath{kind: Regular,
# mode: 0o100644} — wrong; restores a regular file where a dir
# should be. Fix path lands in this PR if the smoke confirms.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: git-clean-fd-undo-fbsd is FreeBSD-only"
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

# Sha each untracked file so we can assert byte-identity after undo.
SHA_A="$(/sbin/sha256 -q "${REPO}/untracked-a.txt")"
SHA_B="$(/sbin/sha256 -q "${REPO}/untracked-b.txt")"
SHA_C="$(/sbin/sha256 -q "${REPO}/junk/c.txt")"
SHA_D="$(/sbin/sha256 -q "${REPO}/junk/nested/d.txt")"
smoke_log "untracked: a=${SHA_A:0:8} b=${SHA_B:0:8} c=${SHA_C:0:8} d=${SHA_D:0:8}"

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

# BSD-specific: the kqueue capture pipeline runs the baseline walk
# asynchronously after PreExec. Wait for it to complete before the
# workload runs, otherwise the workload races baseline and its
# modifications happen before LiveBaseline can record them. The
# Linux equivalent doesn't need this because LSM is synchronous.
sleep 0.5

# BSD-specific: the kqueue capture pipeline does the baseline walk
# asynchronously after PreExec. Wait for it to complete before
# running the workload, otherwise the workload races baseline and
# its modifications happen before the LiveBaseline can record
# them (= no FilePreImage events captured). The Linux equivalent
# doesn't need this because LSM is synchronous.
sleep 0.5

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

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo exited non-zero"
}

# Assertions: every file restored byte-identical, dirs back.
check_file() {
    local path="$1" expected="$2"
    [ -f "${path}" ] || { smoke_log "missing: ${path}"; return 1; }
    local got
    got="$(/sbin/sha256 -q "${path}")"
    [ "${got}" = "${expected}" ] || {
        smoke_log "sha mismatch ${path}: expected=${expected} got=${got}"
        return 1
    }
    return 0
}

ok=1
check_file "${REPO}/untracked-a.txt" "${SHA_A}" || ok=0
check_file "${REPO}/untracked-b.txt" "${SHA_B}" || ok=0
[ -d "${REPO}/junk" ]              || { smoke_log "missing dir: junk"; ok=0; }
[ -d "${REPO}/junk/nested" ]       || { smoke_log "missing dir: junk/nested"; ok=0; }
check_file "${REPO}/junk/c.txt" "${SHA_C}"            || ok=0
check_file "${REPO}/junk/nested/d.txt" "${SHA_D}"     || ok=0

if [ "${ok}" != "1" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_log "current tree:"
    find "${REPO}" -name '.git' -prune -o -print 2>/dev/null | sed 's/^/    /' >&2 || true
    smoke_fail "clean -fd undo didn't restore all entries"
fi

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: git-clean-fd-undo-fbsd (files + dirs restored, ${NUM_PRE} pre-images)"
