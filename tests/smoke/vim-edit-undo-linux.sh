#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR01.2 smoke — `vim -es -c '%s/...' -c 'wq' foo.txt` then `shit undo`
# restores foo.txt to its pre-edit byte-identical state. Linux mirror
# of W02's `vim-edit-undo-fbsd.sh`.
#
# Exercises (LSM tier integration):
#   1. vim's atomic-save dance (forced via `set writebackup
#      backupcopy=no nobackup`): rename `foo.txt → foo.txt~`, write
#      new content as fresh `foo.txt`, unlink `foo.txt~`. Plus the
#      transient swap (`.foo.txt.swp`) and writability probe
#      (`4913`) lifecycle.
#   2. The planner's W01.B + AR01.1 atomic-replace classifier picks
#      up `foo.txt` as a Rename-destination + PreImage + Unlink shape
#      (the AR01.1 fix-rename-target-preimage path via
#      `handle_lsm_rename`) and emits a single RestoreContent inverse.
#   3. The same classifier flags `.foo.txt.swp` and `4913` as transient
#      (Create + Unlink, no pre-image). AR01.1's dedupe-on-create
#      suppresses spurious empty FilePreImage emits for those.
#   4. After `shit undo --yes`: foo.txt content byte-identical, no
#      leftover vim artifacts (`.foo.txt.swp`, `4913`, `foo.txt~`).
#
# Linux-side architecture note: BSD's W02.B.live-baseline exists to
# work around kqueue NOTE_WRITE's post-write pre-image race. Linux
# LSM's equivalent is `ws.pre_snapshots`, populated by the recursive
# `pre_open_tree` (AR01.1) at WatchTree dispatch -- both
# `handle_lsm_open` and `handle_lsm_setattr` read from it
# (race-free), and `handle_lsm_rename`'s fix-rename-target-preimage
# reaches into it via `ws.path_to_inode`. No live-baseline scaffolding
# needed on Linux.
#
# Tier: LSM. fanotify-perm can see the file_open on foo.txt but not
# the rename of `foo.txt → foo.txt~`, so the OLD-content capture for
# the rename-source path wouldn't fire and undo would silently
# diverge. Wired under LSM_SMOKES.
#
# Linux-only.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: vim-edit-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

VIM_BIN="$(command -v vim || true)"
if [ -z "${VIM_BIN}" ]; then
    smoke_log "SKIP: vim not on PATH"
    exit 0
fi
smoke_log "vim: ${VIM_BIN} ($("${VIM_BIN}" --version 2>/dev/null | head -1))"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight: helper caps.
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing on this system; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
if ! printf '%s' "${HELPER_CAPS}" | grep -q cap_sys_admin; then
    smoke_log "FAIL: helper lacks cap_sys_admin (getcap output: '${HELPER_CAPS}')"
    smoke_log ""
    smoke_log "  Run this on the box first, then re-run the smoke:"
    smoke_log "    sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${HELPER_BIN}"
    exit 1
fi
smoke_log "helper has caps: ${HELPER_CAPS}"

# Hermetic vim: disable user .vimrc + plugins so site-local config
# can't perturb the workload (e.g. a custom `set backupcopy`).
VIM_HERMETIC=(-u NONE)

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
TARGET="${SCRATCH}/foo.txt"

# Pre-edit content — two lines so the substitution has something
# unambiguous to match.
printf 'initial line one\ninitial line two\n' > "${TARGET}"
PRIOR_SHA="$(sha256sum "${TARGET}" | cut -d' ' -f1)"
smoke_log "pre-edit foo.txt sha256=${PRIOR_SHA}"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# PreExec blocks on WaitWatchReady (AR00.5) -- no settle sleep needed.
smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# THE workload under test.
#   -e     ex mode (line editor; no fullscreen terminal UI)
#   -s     silent (no prompts, no messages to stderr)
#   -u NONE  skip user/system vimrc (hermetic)
#   -c 'set writebackup backupcopy=no nobackup'  force vim into the
#       canonical atomic-rename write path:
#         1. rename foo.txt -> foo.txt~      (OLD content preserved
#            on the renamed-away inode -- this is what
#            handle_lsm_rename's fix-rename-target-preimage captures)
#         2. write new content as new foo.txt (NEW inode)
#         3. unlink foo.txt~                 (because `nobackup`)
#   -c '%s/.../.../'  substitution
#   -c 'wq'  write + quit
smoke_log "vim -es 'set writebackup backupcopy=no nobackup | %s/... | wq'"
"${VIM_BIN}" "${VIM_HERMETIC[@]}" -es \
    -c 'set writebackup backupcopy=no nobackup' \
    -c '%s/initial line two/MODIFIED line two/' \
    -c 'wq' "${TARGET}"
VIM_RC=$?
smoke_log "vim exit=${VIM_RC}"
POST_EDIT_SHA="$(sha256sum "${TARGET}" | cut -d' ' -f1)"
smoke_log "post-edit foo.txt sha256=${POST_EDIT_SHA}"
if [ "${POST_EDIT_SHA}" = "${PRIOR_SHA}" ]; then
    smoke_fail "vim didn't actually edit the file (sha unchanged) -- workload setup is broken"
fi

# Let LSM events propagate. Matches the AR01.1/3/4 budget.
sleep 1

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. vim's dance produces several
# events; the FilePreImage on foo.txt (from the rename-target capture
# path) is the load-bearing one.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10

NUM_PREIMAGES="$(smoke_journal_count "discriminant = 'FilePreImage'")"
smoke_log "FilePreImage events in journal: ${NUM_PREIMAGES}"

# Run undo.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal contents:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "shit undo --yes exited non-zero"
}

# Assertion 1: foo.txt content restored byte-identical.
POST_UNDO_SHA="$(sha256sum "${TARGET}" | cut -d' ' -f1)"
if [ "${POST_UNDO_SHA}" != "${PRIOR_SHA}" ]; then
    smoke_log "foo.txt sha256 mismatch: expected=${PRIOR_SHA} got=${POST_UNDO_SHA}"
    smoke_log "foo.txt content (current):"
    /usr/bin/sed 's/^/    /' "${TARGET}" >&2 || true
    smoke_log "undo log:"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal events:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | /usr/bin/sed 's/^/    /' >&2 || true
    smoke_fail "foo.txt content not restored -- atomic-replace undo failed"
fi
smoke_log "foo.txt restored: sha256=${POST_UNDO_SHA} matches pre-edit"

# Assertion 2: no leftover vim artifacts. `:wq` should have cleaned
# up its own swap; `:set nobackup` (set above) should have removed
# the backup. The undo planner must not RECREATE them either (that
# would be a transient-classification bug surfacing as
# "shit undo conjures vim's lock files back").
ORPHANS=()
[ -f "${SCRATCH}/.foo.txt.swp" ] && ORPHANS+=(".foo.txt.swp")
[ -f "${SCRATCH}/4913" ]         && ORPHANS+=("4913")
[ -f "${SCRATCH}/foo.txt~" ]     && ORPHANS+=("foo.txt~")
# Catch anything vim-shaped we didn't anticipate.
for f in "${SCRATCH}"/.foo.txt.sw[a-z] "${SCRATCH}"/foo.txt.tmp; do
    [ -f "${f}" ] && ORPHANS+=("$(basename "${f}")")
done
if [ "${#ORPHANS[@]}" -gt 0 ]; then
    smoke_log "leftover artifacts in ${SCRATCH}:"
    ls -la "${SCRATCH}" | /usr/bin/sed 's/^/    /' >&2
    smoke_fail "scratch dir has leftover vim artifacts: ${ORPHANS[*]}"
fi
smoke_log "scratch dir clean: no swap, no probe, no backup"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: vim-edit-undo-linux (foo.txt restored byte-identical, ${NUM_PREIMAGES} pre-images captured)"
