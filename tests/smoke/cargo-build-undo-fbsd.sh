#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W05 smoke — `cargo build --offline` in a tiny no-dep crate, then
# `shit undo --yes` removes target/ entirely while leaving the
# source tree byte-identical.
#
# Exercises (stretch — scale / cost-model claim validation):
#   1. Bulk burst-creates under a single new dir (target/). cargo's
#      link step writes 30-50 files in a tight window; S29.2's
#      recursive auto-add (W03.B) + handle_dir_change's diff-against-
#      baseline rescan need to keep pace.
#   2. The live-baseline cost claim (W02.B). Pre-cargo, the watched
#      subtree has 3 paths (Cargo.toml + src/ + src/main.rs). The
#      walker should baseline these inline in sub-ms. Anything
#      noticeable here is an architecture-level finding.
#   3. Bulk recursive undo. shit undo --yes emits Unlink inverses
#      for every created path. File executor's recursive
#      remove_dir_all fallback (W01 follow-up) is the safety net for
#      any cohort-ordering race during dir rmdirs.
#
# FreeBSD-only — kqueue producer + BSD smoke convention. Linux
# equivalent (per the spec) is npm-install-undo-linux.sh, owned by
# the Linux engineer.
#
# See .docs/sprints/W/W05-npm-cargo-install.md for the cross-platform
# spec and .docs/sprints/W/W05.B-bsd.md for execution notes.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: cargo-build-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

CARGO_BIN="$(command -v cargo || true)"
if [ -z "${CARGO_BIN}" ]; then
    smoke_log "SKIP: cargo not on PATH"
    exit 0
fi
smoke_log "cargo: ${CARGO_BIN} ($(${CARGO_BIN} --version 2>/dev/null | head -1))"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Build a tiny no-dep crate skeleton under the watched scratch dir.
# 3 paths pre-cargo: Cargo.toml + src/ + src/main.rs.
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}/src"
cat > "${SCRATCH}/Cargo.toml" <<'TOML'
[package]
name = "w05-smoke"
version = "0.0.1"
edition = "2024"

[[bin]]
name = "w05-smoke"
path = "src/main.rs"

[profile.dev]
incremental = false
TOML
cat > "${SCRATCH}/src/main.rs" <<'RS'
fn main() {
    println!("hello from w05");
}
RS

# Pre-state — tree shape + content hash. Note we deliberately do
# NOT pre-create Cargo.lock; cargo will create it at build time
# and we expect undo to remove it.
PRE_TREE_LIST="$(cd "${SCRATCH}" && find . -mindepth 1 | sort)"
PRE_AGG_SHA="$(cd "${SCRATCH}" && find . -type f -print0 | sort -z | xargs -0 /sbin/sha256 -q | /sbin/sha256 -q)"
smoke_log "pre-cmd scratch tree (relative):"
echo "${PRE_TREE_LIST}" | /usr/bin/sed 's/^/    /'
smoke_log "pre-cmd source-tree aggregate sha256=${PRE_AGG_SHA}"

if [ -e "${SCRATCH}/target" ]; then
    smoke_fail "scratch/target exists pre-command; setup broken"
fi

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# Wall-clock around PreExec → live-baseline walker completion.
# The walker is async but in helper logs it stamps "live-baseline
# walk emitted"; lib.sh dumps shitd.log on FAIL so we can read
# the timing post-hoc.
PRE_EXEC_T="$(date -u +%s.%N)"
smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH} t=${PRE_EXEC_T}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Settling time for the baseline walker. 3-entry tree should finish
# in <100ms; we give it 500ms for safety. Real-world latency
# observation goes in the spec's cross-platform notes.
sleep 0.5

# THE workload. --offline so the smoke can't flake on transient
# crates.io issues; our no-dep crate needs nothing.
smoke_log "cargo build --offline"
BUILD_START="$(date -u +%s.%N)"
"${CARGO_BIN}" build --offline 2> "${SHIT_SMOKE_TMP}/cargo.log"
CARGO_RC=$?
BUILD_END="$(date -u +%s.%N)"
smoke_log "cargo exit=${CARGO_RC}, took $(echo "${BUILD_END} - ${BUILD_START}" | bc -l) sec"
if [ "${CARGO_RC}" -ne 0 ]; then
    smoke_log "cargo stderr:"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/cargo.log" >&2 || true
    smoke_fail "cargo build failed pre-undo (rc=${CARGO_RC}) — workload setup broken"
fi
if [ ! -d "${SCRATCH}/target" ]; then
    smoke_fail "cargo build claimed success but target/ doesn't exist"
fi
N_PATHS_FS="$(find target -mindepth 1 | wc -l | tr -d ' ')"
smoke_log "cargo created ${N_PATHS_FS} paths under target/"

# Let kqueue events settle.
sleep 1.0

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Wait for the journal to settle.
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10

N_CREATES_JOURNAL="$(smoke_journal_count "discriminant = 'TreeOpCreate'")"
smoke_log "TreeOpCreate events in journal: ${N_CREATES_JOURNAL}"
smoke_log "filesystem paths created: ${N_PATHS_FS}"

# Capture-pipeline correctness check. cargo's burst of mkdirs/opens
# under target/ must produce a TreeOpCreate per new path —
# otherwise undo leaves orphans (modulo the W01.B remove_dir_all
# fallback).
#
# The journal also includes the Cargo.lock create + any source-tree
# events that S29.2 caught. We accept >= 80% of the fs count as
# "captured enough that undo can recursively clean" — exact match
# is unrealistic given kqueue coalescing, but a big drop is a real
# gap.
THRESHOLD=$(( N_PATHS_FS * 80 / 100 ))
if [ "${N_CREATES_JOURNAL}" -lt "${THRESHOLD}" ]; then
    smoke_log "ratio: ${N_CREATES_JOURNAL}/${N_PATHS_FS} TreeOpCreate events (threshold ${THRESHOLD})"
    smoke_log "journal events (first 60):"
    smoke_journal_query "SELECT id, discriminant, path FROM events ORDER BY id LIMIT 60;" 2>/dev/null \
        | /usr/bin/sed 's/^/    /' >&2 || true
    smoke_fail "capture pipeline dropped > 20% of TreeOpCreate events at burst rate"
fi
smoke_log "capture ratio acceptable: ${N_CREATES_JOURNAL}/${N_PATHS_FS} (>= ${THRESHOLD})"

# Run undo. Time it.
UNDO_START="$(date -u +%s.%N)"
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "scratch state:"
    find "${SCRATCH}" -maxdepth 5 2>/dev/null | /usr/bin/sed 's/^/    /' >&2 || true
    smoke_fail "shit undo --yes exited non-zero"
}
UNDO_END="$(date -u +%s.%N)"
smoke_log "undo took $(echo "${UNDO_END} - ${UNDO_START}" | bc -l) sec"

# Assertion 1: target/ is GONE.
if [ -e "${SCRATCH}/target" ]; then
    smoke_log "target/ still exists post-undo:"
    find "${SCRATCH}/target" 2>/dev/null | head -20 | /usr/bin/sed 's/^/    /' >&2 || true
    smoke_fail "target/ not removed by undo — recursive unlink incomplete"
fi
smoke_log "target/ removed"

# Assertion 2: pre-command source tree byte-identical.
POST_UNDO_LIST="$(cd "${SCRATCH}" && find . -mindepth 1 | sort)"
if [ "${POST_UNDO_LIST}" != "${PRE_TREE_LIST}" ]; then
    smoke_log "scratch tree shape changed by undo:"
    smoke_log "  was: ${PRE_TREE_LIST}"
    smoke_log "  now: ${POST_UNDO_LIST}"
    smoke_fail "scratch dir has orphans or missing pre-state files"
fi
POST_UNDO_SHA="$(cd "${SCRATCH}" && find . -type f -print0 | sort -z | xargs -0 /sbin/sha256 -q | /sbin/sha256 -q)"
if [ "${POST_UNDO_SHA}" != "${PRE_AGG_SHA}" ]; then
    smoke_log "source content perturbed: expected agg=${PRE_AGG_SHA} got agg=${POST_UNDO_SHA}"
    smoke_fail "undo touched source file contents it shouldn't have"
fi
smoke_log "source tree intact: shape + aggregate content sha match pre-command"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: cargo-build-undo-fbsd (target/ removed, source byte-identical, ${N_CREATES_JOURNAL}/${N_PATHS_FS} TreeOpCreate events)"
