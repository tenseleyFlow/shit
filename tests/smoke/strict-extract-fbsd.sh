#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: strict-extract-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# B4 review: `tar xf` and `cp -p` restore archived mtimes with utimes(2),
# and FreeBSD moves a file's birth time back to an mtime older than it.
# The files these commands create then carry a birth time from before
# the command. Strict mode must not read that as a pre-existing file
# moved in from outside the watched tree: a plain extract or `cp -p`
# inside the watched root journals no CaptureRefused row, and undo
# removes what it created.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: strict-extract-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Sources live outside the watched root, with mtimes from 2020.
SRC="${SHIT_SMOKE_TMP}/src"
ROOT="${SHIT_SMOKE_TMP}/root"
mkdir -p "${SRC}/tree/sub" "${ROOT}"
printf 'archived a\n' > "${SRC}/tree/a.txt"
printf 'archived b\n' > "${SRC}/tree/sub/b.txt"
printf 'copied with -p\n' > "${SRC}/single.txt"
find "${SRC}" -exec touch -h -t 202001010000 {} +
(cd "${SRC}" && tar cf "${SHIT_SMOKE_TMP}/tree.tar" tree)
printf 'pre-existing\n' > "${ROOT}/keep.txt"
ROOT="$(cd "${ROOT}" && pwd -P)"

SHIT_STRICT_CAPTURE=1 smoke_start_shitd
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
cd "${ROOT}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

run_cmd() {
    local seq="$1" cmdline="$2"
    shift 2
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "${seq}" --pid "$$" \
        --cwd "${ROOT}" --shell bash --cmdline "${cmdline}" \
        --sock "${SHIT_HOOK_SOCK}"
    smoke_log "[${seq}] ${cmdline}"
    "$@" || smoke_fail "[${seq}] ${cmdline} failed"
    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq "${seq}" --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"
    sleep 0.5
}

undo_last() {
    local label="$1" log="${SHIT_SMOKE_TMP}/undo-$1.log" rc
    set +e
    "${SHIT_BIN}" undo --yes > "${log}" 2>&1
    rc=$?
    set -e
    sed 's/^/    undo: /' "${log}" >&2 || true
    [ "${rc}" -eq 0 ] || smoke_fail "[${label}] shit undo exit=${rc}"
    if grep -q "capture-incomplete" "${log}"; then
        smoke_fail "[${label}] strict undo refused with capture-incomplete"
    fi
}

run_cmd 1 "tar xf tree.tar" tar xf "${SHIT_SMOKE_TMP}/tree.tar"
[ "$(stat -f '%m' "${ROOT}/tree/a.txt")" = "$(stat -f '%m' "${SRC}/tree/a.txt")" ] \
    || smoke_fail "tar did not restore the archived mtime"
smoke_log "tree/a.txt birth $(stat -f '%B' "${ROOT}/tree/a.txt"), mtime $(stat -f '%m' "${ROOT}/tree/a.txt")"
undo_last tar
[ ! -e "${ROOT}/tree" ] || smoke_fail "[tar] undo left ${ROOT}/tree in place"

run_cmd 2 "cp -p single.txt copied.txt" cp -p "${SRC}/single.txt" "${ROOT}/copied.txt"
undo_last cp-p
[ ! -e "${ROOT}/copied.txt" ] || smoke_fail "[cp -p] undo left ${ROOT}/copied.txt in place"

run_cmd 3 "cp -pR tree tree2" cp -pR "${SRC}/tree" "${ROOT}/tree2"
undo_last cp-pR
[ ! -e "${ROOT}/tree2" ] || smoke_fail "[cp -pR] undo left ${ROOT}/tree2 in place"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
cd "${SHIT_SMOKE_TMP}"

[ "$(cat "${ROOT}/keep.txt")" = "pre-existing" ] || smoke_fail "keep.txt changed"
REFUSALS="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
if [ "${REFUSALS}" -ne 0 ]; then
    smoke_dump_refusals
    smoke_fail "strict capture journaled ${REFUSALS} CaptureRefused row(s) for an extract and cp -p"
fi
smoke_log "PASS: strict-extract-fbsd (tar xf, cp -p and cp -pR in strict mode: zero refusals, undone)"
