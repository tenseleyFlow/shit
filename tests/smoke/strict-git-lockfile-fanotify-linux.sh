#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-git-lockfile-fanotify-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R3 slice B — the born-set rule on the fanotify-perm tier, under
# SHIT_STRICT_CAPTURE=1.
#
# The per-command fanotify mark covers the cwd's direct children only,
# so this tier never sees writes inside a subdirectory such as `.git/`.
# Two phases:
#
#   flat:  a cwd with no subdirectories. One command does the lock-file
#          dance at the top level (`cfg.lock` written then renamed over
#          `cfg`) and runs `sed -i` on `data`. The lock and sed's temp
#          file were born in the command, so no CaptureRefused row is
#          journaled, and undo restores `cfg` and `data`.
#
#   repo:  a git repository. `git config` writes `.git/config.lock`,
#          which no mark covers. Strict journals a command-scoped
#          refusal naming the unwatched subdirectories, and undo
#          refuses with capture-incomplete.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: strict-git-lockfile-fanotify-linux is Linux-only (uname=$(uname -s))"
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

set +e
smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
set -e
[ "${caps_rc}" -eq 2 ] && exit 0
[ "${caps_rc}" -eq 0 ] || exit 1
export SHIT_FORCE_TIER=fanotify-perm

FLAT="${SHIT_SMOKE_TMP}/flat"
REPO="${SHIT_SMOKE_TMP}/repo"
mkdir -p "${FLAT}" "${REPO}"
printf 'key = old\n' > "${FLAT}/cfg"
printf 'banana\nbanana split\n' > "${FLAT}/data"
CFG_SHA="$(sha256sum "${FLAT}/cfg" | cut -d' ' -f1)"
DATA_SHA="$(sha256sum "${FLAT}/data" | cut -d' ' -f1)"
git_invoke -C "${REPO}" init -q
echo "initial" > "${REPO}/README.md"
git_invoke -C "${REPO}" add README.md
git_invoke -C "${REPO}" commit -q -m anchor

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
if ! grep -q "fanotify" "${SHIT_SMOKE_TMP}/shitd.log"; then
    smoke_log "note: shitd.log does not name fanotify yet; continuing"
fi
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# run_cmd <seq> <cwd> <cmdline> <argv...>
run_cmd() {
    local seq="$1" cwd="$2" cmdline="$3"
    shift 3
    cd "${cwd}"
    set +e
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "${seq}" --pid "$$" \
        --cwd "${cwd}" --shell bash --cmdline "${cmdline}" \
        --sock "${SHIT_HOOK_SOCK}" 2> "${SHIT_SMOKE_TMP}/hook-${seq}.log"
    set -e
    sed 's/^/    hook: /' "${SHIT_SMOKE_TMP}/hook-${seq}.log" >&2 || true
    if grep -q "not-ready" "${SHIT_SMOKE_TMP}/hook-${seq}.log"; then
        smoke_fail "[${seq}] fanotify attach did not become ready"
    fi
    smoke_log "[${seq}] ${cmdline}"
    "$@"
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq "${seq}" --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"
    cd "${SHIT_SMOKE_TMP}"
}

undo_into() {
    local log="$1"
    set +e
    "${SHIT_BIN}" undo --yes > "${log}" 2>&1
    local rc=$?
    set -e
    smoke_log "shit undo --yes exit=${rc}"
    sed 's/^/    undo: /' "${log}" >&2 || true
}

REFUSED="discriminant = 'CaptureRefused'"
FLAT_WORK='cat cfg > cfg.lock && echo "key = new" > cfg.lock && mv cfg.lock cfg && sed -i s/banana/PINEAPPLE/g data'
run_cmd 1 "${FLAT}" "sh -c '${FLAT_WORK}'" sh -c "${FLAT_WORK}"
undo_into "${SHIT_SMOKE_TMP}/flat.undo.log"
FLAT_ROWS="$(smoke_journal_count "${REFUSED}")"
if [ "${FLAT_ROWS}" -ne 0 ]; then
    smoke_dump_refusals
    smoke_fail "flat: strict journaled ${FLAT_ROWS} CaptureRefused row(s) for born files"
fi
if grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/flat.undo.log"; then
    smoke_fail "flat: strict undo refused with capture-incomplete"
fi
[ "$(sha256sum "${FLAT}/cfg" | cut -d' ' -f1)" = "${CFG_SHA}" ] || smoke_fail "flat: cfg not restored"
[ "$(sha256sum "${FLAT}/data" | cut -d' ' -f1)" = "${DATA_SHA}" ] || smoke_fail "flat: data not restored"
# fanotify reads a pre-image on every first open, including the empty
# one of a file it just created, so undo writes `cfg.lock` back as an
# empty file. That is how this tier captures on trunk; logged, not failed.
if [ -e "${FLAT}/cfg.lock" ]; then
    smoke_log "note: undo recreated an empty cfg.lock (fanotify captures the creating open)"
fi

run_cmd 2 "${REPO}" "git config core.shitprobe yes" git_invoke -C "${REPO}" config core.shitprobe yes
undo_into "${SHIT_SMOKE_TMP}/repo.undo.log"
grep -q "capture-incomplete" "${SHIT_SMOKE_TMP}/repo.undo.log" \
    || smoke_fail "repo: strict undo did not refuse although .git/ is not watched"
grep -q "not watched" "${SHIT_SMOKE_TMP}/repo.undo.log" \
    || smoke_fail "repo: refusal does not say which subdirectories are not watched"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: strict-git-lockfile-fanotify-linux (flat dance undone with zero refusals; unwatched .git refused)"
