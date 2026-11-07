#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-git-lockfile-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice B — git's lock-file dance is not loss under strict capture,
# kqueue tier. FreeBSD mirror of strict-git-lockfile-linux.
#
# kqueue reports writes after they happen, so a pre-existing file's
# pre-write content comes from the live-baseline walk at attach. A
# tracked file missing from the attach listing was added by a
# directory diff and was born in the command; it needs no pre-image.
#
# `git config`, `git commit` and `git branch -D` each create a
# `*.lock` (and object temp files), write, chmod, then rename the lock
# over the real file or unlink it. Every one of those files is born
# inside the command, so its pre-state is "absent" and it needs no
# pre-image. The per-hook ring readers deliver these events in any
# order on Linux; on FreeBSD the lock files show up in directory diffs
# after the fact.
#
# One session, SHIT_STRICT_CAPTURE=1, three commands, each undone right
# after it runs:
#   1. git config core.shitprobe yes   -> undo leaves .git/config as before
#   2. git commit                      -> undo restores HEAD and the index
#   3. git branch -D feat              -> undo restores refs/heads/feat
# Then: zero CaptureRefused rows in the journal.
#
# Validate-the-gap: before slice B the kqueue producer reported no loss
# at all, so strict mode could not tell this dance from a real loss.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: strict-git-lockfile-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi
if [ -z "${GIT_BIN:-}" ]; then
    smoke_log "SKIP: git not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"


REPO="${SHIT_SMOKE_TMP}/scratch/repo"
mkdir -p "${REPO}"
git_invoke -C "${REPO}" init -q
echo "initial content" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m "anchor commit"
git_invoke -C "${REPO}" branch feat
echo "feature line" >> "${REPO}/README.md"
git_invoke -C "${REPO}" commit -q -am "feature commit"
FEAT_SHA="$(git_invoke -C "${REPO}" rev-parse HEAD)"
git_invoke -C "${REPO}" branch -f feat "${FEAT_SHA}"
git_invoke -C "${REPO}" reset -q --hard HEAD~1
PRIOR_HEAD="$(git_invoke -C "${REPO}" rev-parse HEAD)"
echo "staged line" >> "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
CONFIG_SHA="$(sha256 -q "${REPO}/.git/config")"
smoke_log "anchor=${PRIOR_HEAD} feat=${FEAT_SHA} config sha256=${CONFIG_SHA}"

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${REPO}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# run_cmd <seq> <cmdline> <git args...>: one PreExec/PostExec cycle.
run_cmd() {
    local seq="$1" cmdline="$2"
    shift 2
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "${seq}" --pid "$$" \
        --cwd "${REPO}" --shell bash --cmdline "${cmdline}" \
        --sock "${SHIT_HOOK_SOCK}"
    smoke_log "[${seq}] ${cmdline}"
    git_invoke -C "${REPO}" "$@"
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq "${seq}" --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"
}

# undo_last <label>: run `shit undo --yes`, fail on a refusal.
undo_last() {
    local label="$1"
    local log="${SHIT_SMOKE_TMP}/undo-${label}.log"
    set +e
    "${SHIT_BIN}" undo --yes > "${log}" 2>&1
    local rc=$?
    set -e
    sed 's/^/    undo: /' "${log}" >&2 || true
    [ "${rc}" -eq 0 ] || smoke_fail "[${label}] shit undo exit=${rc}"
    if grep -q "capture-incomplete" "${log}"; then
        smoke_fail "[${label}] strict undo refused with capture-incomplete"
    fi
}

run_cmd 1 "git config core.shitprobe yes" config core.shitprobe yes
[ "$(git_invoke -C "${REPO}" config --get core.shitprobe)" = "yes" ] \
    || smoke_fail "[config] git config did not take effect"
undo_last config
if git_invoke -C "${REPO}" config --get core.shitprobe >/dev/null 2>&1; then
    smoke_fail "[config] core.shitprobe still set after undo"
fi
[ "$(sha256 -q "${REPO}/.git/config")" = "${CONFIG_SHA}" ] \
    || smoke_fail "[config] .git/config differs from its pre-command bytes"

run_cmd 2 "git commit -m staged" commit -q -m staged
undo_last commit
[ "$(git_invoke -C "${REPO}" rev-parse HEAD)" = "${PRIOR_HEAD}" ] \
    || smoke_fail "[commit] HEAD not restored to ${PRIOR_HEAD}"
[ "$(git_invoke -C "${REPO}" status --porcelain)" = "M  README.md" ] \
    || smoke_fail "[commit] index not restored (status: $(git_invoke -C "${REPO}" status --porcelain))"

run_cmd 3 "git branch -D feat" branch -q -D feat
undo_last branch
[ "$(git_invoke -C "${REPO}" rev-parse --verify -q feat)" = "${FEAT_SHA}" ] \
    || smoke_fail "[branch] refs/heads/feat not restored to ${FEAT_SHA}"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
cd "${SHIT_SMOKE_TMP}"

REFUSALS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
if [ "${REFUSALS}" -ne 0 ]; then
    smoke_journal_query "SELECT command_seq, kind_json FROM events WHERE discriminant = 'CaptureRefused';" \
        | sed 's/^/    refused: /' >&2 || true
    smoke_fail "strict capture journaled ${REFUSALS} CaptureRefused row(s) for born lock files"
fi

smoke_log "PASS: strict-git-lockfile-fbsd (config, commit and branch -D undone; zero refusals)"
