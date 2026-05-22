#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W02 smoke — `vim -es -c '%s/...' -c 'wq' foo.txt` then `shit undo`
# restores foo.txt to its pre-edit byte-identical state.
#
# Exercises (cross-tier integration):
#   1. kqueue NOTE_WRITE / NOTE_DELETE / NOTE_RENAME on vim's classic
#      atomic-save dance: open `.foo.txt.swp`, drop `4913` writability
#      probe, write new content via tmpfile, rename onto foo.txt,
#      delete swap + (sometimes) backup.
#   2. The planner's W01.B classify_replace_paths classifier should
#      recognize:
#        - `.foo.txt.swp` as transient (Create+Unlink, no pre-image)
#        - `4913` as transient (same shape)
#        - `foo.txt` as atomic-replace (Create+PreImage+Unlink, path
#          exists at undo time → restore bytes over current inode,
#          suppress Tree-op inverses)
#   3. shit undo --yes restores foo.txt content byte-for-byte.
#
# FreeBSD-only — kqueue producer + BSD smoke convention. The Linux
# equivalent is `vim-edit-undo-linux.sh` (per W02.L-linux.md, owned
# by the Linux engineer).
#
# See .docs/sprints/W/W02-vim-edit-undo.md for the cross-platform
# spec and .docs/sprints/W/W02.B-bsd.md for execution notes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: vim-edit-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

# vim lives at /usr/local/bin/vim after `pkg install vim`. Default
# FreeBSD has nvi (`vi`) but not vim. We need vim specifically
# because its atomic-rename + swap-file dance is what this workload
# tests — nvi does in-place writes which W01 / rm-undo / chmod-undo
# already exercise.
export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
VIM_BIN="$(command -v vim || true)"
if [ -z "${VIM_BIN}" ]; then
    smoke_log "SKIP: vim not on PATH (install via 'doas pkg install -y vim')"
    exit 0
fi
smoke_log "vim: ${VIM_BIN} ($("${VIM_BIN}" --version | head -1))"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Hermetic vim: disable user .vimrc so site-local config can't
# perturb the workload (e.g. plugins running shell-outs, custom
# `set backupcopy` overriding defaults). `-u NONE` skips both
# .vimrc and plugins.
VIM_HERMETIC=(-u NONE)

# Build the target file under a watched scratch dir.
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
TARGET="${SCRATCH}/foo.txt"

# Pre-edit content — two lines so the substitution has something
# unambiguous to match.
printf 'initial line one\ninitial line two\n' > "${TARGET}"
PRIOR_SHA="$(/sbin/sha256 -q "${TARGET}")"
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

smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Give the pump a moment to register the watch + baseline the scratch
# dir before vim creates its swap file. If we race PreExec, the swap
# may appear before the watch is live and our auto-add path can't
# subscribe in time.
sleep 0.5

# THE workload under test.
#   -e   ex mode (line editor; no fullscreen terminal UI)
#   -s   silent (no prompts, no messages to stderr)
#   -u NONE  skip user/system vimrc (hermetic)
#   -c 'set writebackup backupcopy=no nobackup'  force vim into the
#       canonical atomic-rename write path:
#         1. rename foo.txt → foo.txt~      (old content preserved)
#         2. write new content as new foo.txt (NEW inode)
#         3. unlink foo.txt~                (because `nobackup`)
#       This is the workload W02 is supposed to exercise. WITHOUT
#       this, vim 9 on FreeBSD UFS defaults to in-place truncate+write,
#       which doesn't exercise rename — and which kqueue's NOTE_WRITE
#       can't pre-image cleanly (BSD captures content AFTER the write
#       completes, so the "pre-image" is the post-write bytes;
#       restoration is a no-op). The rename pattern avoids that race
#       because the OLD inode is still readable at unlink time.
#   -c '%s/.../.../'  substitution
#   -c 'wq'  write + quit
smoke_log "vim -es 'set writebackup backupcopy=no nobackup | %s/... | wq'"
"${VIM_BIN}" "${VIM_HERMETIC[@]}" -es \
    -c 'set writebackup backupcopy=no nobackup' \
    -c '%s/initial line two/MODIFIED line two/' \
    -c 'wq' "${TARGET}"
VIM_RC=$?
smoke_log "vim exit=${VIM_RC}"
POST_EDIT_SHA="$(/sbin/sha256 -q "${TARGET}")"
smoke_log "post-edit foo.txt sha256=${POST_EDIT_SHA}"
if [ "${POST_EDIT_SHA}" = "${PRIOR_SHA}" ]; then
    smoke_fail "vim didn't actually edit the file (sha unchanged) — workload setup is broken"
fi

# Let kqueue NOTE_DELETE / WRITE / RENAME events propagate.
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle. vim's dance produces a handful of
# events; the FilePreImage on foo.txt is the load-bearing one.
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
POST_UNDO_SHA="$(/sbin/sha256 -q "${TARGET}")"
if [ "${POST_UNDO_SHA}" != "${PRIOR_SHA}" ]; then
    smoke_log "foo.txt sha256 mismatch: expected=${PRIOR_SHA} got=${POST_UNDO_SHA}"
    smoke_log "foo.txt content (current):"
    sed 's/^/    /' "${TARGET}" >&2 || true
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "journal events:"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id;" 2>/dev/null \
        | sed 's/^/    /' >&2 || true
    smoke_fail "foo.txt content not restored — atomic-replace undo failed"
fi
smoke_log "foo.txt restored: sha256=${POST_UNDO_SHA} matches pre-edit"

# Assertion 2: no leftover scratch artifacts. vim's `:wq` should
# have cleaned up its own swap; `:set nobackup` (default) should
# have removed the backup. The undo planner must not RECREATE them
# either (that would be a transient-classification bug surfacing as
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
    ls -la "${SCRATCH}" | sed 's/^/    /' >&2
    smoke_fail "scratch dir has leftover vim artifacts: ${ORPHANS[*]}"
fi
smoke_log "scratch dir clean: no swap, no probe, no backup"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: vim-edit-undo-fbsd (foo.txt restored byte-identical, ${NUM_PREIMAGES} pre-images captured)"
