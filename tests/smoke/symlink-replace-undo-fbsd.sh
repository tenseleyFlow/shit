#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: symlink-replace-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W09.16.1 smoke — `ln -sf newtarget existing_link` replaces the
# symlink's target. Distinct from ln-symlink-undo-fbsd (which tests
# fresh symlink CREATE): here `link` pre-exists pointing to
# `target1`, and we point it at `target2`. Internally `ln -sf`
# does `unlink(link); symlink(target2, link)`, which the kqueue
# dir-diff now observes via baseline-recorded symlink target:
# same-name + different-inode + old-kind-was-symlink → emit
# `SymlinkRemoved { target: target1, path: link }` BEFORE the
# Create event for the new symlink. Planner inverses:
#   - Create at link → Unlink(link)              (newer event, runs first)
#   - SymlinkRemoved → CreateSymlink(target1, link)  (older, runs second)
# Net: link points back to target1.
#
# Where this matters: GNU stow / `update-alternatives` /
# `current → release-N` deployment swaps / pyenv-style version
# switchers / nix profile updates — every config-management
# workflow that repoints symlinks.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: symlink-replace-undo-fbsd is FreeBSD-only"
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

TARGET1="${WATCHED}/target1.txt"
TARGET2="${WATCHED}/target2.txt"
LINK="${WATCHED}/config"
printf 'first target\n' > "${TARGET1}"
printf 'second target\n' > "${TARGET2}"
# Use a relative target so the smoke is portable.
ln -s target1.txt "${LINK}"
[ "$(readlink "${LINK}")" = "target1.txt" ] || smoke_fail "setup: link points to $(readlink "${LINK}")"
smoke_log "pre-cmd: link -> $(readlink "${LINK}")"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

smoke_log "ln -sf target2.txt ${LINK}"
ln -sf target2.txt "${LINK}"
POST_TARGET="$(readlink "${LINK}")"
[ "${POST_TARGET}" = "target2.txt" ] || smoke_fail "ln -sf didn't update target (got ${POST_TARGET})"
smoke_log "post-cmd: link -> ${POST_TARGET}"

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
[ "${UNDO_RC}" -eq 0 ] || failures+=("undo exited ${UNDO_RC}")
if [ ! -L "${LINK}" ]; then
    if [ -e "${LINK}" ]; then
        failures+=("link is no longer a symlink (became regular file?)")
    else
        failures+=("link removed by undo (should be restored as symlink → target1.txt)")
    fi
else
    FINAL_TARGET="$(readlink "${LINK}")"
    [ "${FINAL_TARGET}" = "target1.txt" ] \
        || failures+=("symlink target mismatch: got '${FINAL_TARGET}', want 'target1.txt'")
fi

if [ "${#failures[@]}" -eq 0 ]; then
    smoke_log "PASS: symlink-replace-undo-fbsd (target restored to target1.txt)"
    exit 0
fi
smoke_fail "symlink-replace undo incomplete: ${failures[*]}"
