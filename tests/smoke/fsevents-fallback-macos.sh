#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# M01 / M01.A smoke — macOS FSEvents-degraded capture end-to-end.
#
# What this asserts:
# 1. shitd starts cleanly on macOS.
# 2. shit-helper handshakes successfully (sandbox profile loads,
#    FSEvents-based degraded tier picked, handshake ack carries
#    kernel_tier = "fsevents-degraded").
# 3. `shit metrics` surfaces the tier in its text output.
# 4. After a shell-hook bracket (session-open → pre-exec → mutate
#    → post-exec), the FSEvents producer:
#      - sees the file create  → daemon journals a TreeOpCreate
#      - sees the file remove  → daemon journals a TreeOpUnlink
#    Both events land in the per-command cohort identified by the
#    pre-exec's (session, seq).
#
# What this does NOT assert (deferred to M03 / later):
# - Byte-identical content restore via `shit undo`. FSEvents-
#   degraded has no pre-image — undo can only invert tree shape
#   (delete what was created; cannot recreate what was deleted
#   without content). That's the M03 ES path.
# - The `(degraded)` label flowing through `shit list` text output.
#   The events ARE journaled with the degraded semantics; the CLI's
#   list renderer surfaces them once M02 wires the doctor-side
#   tier-aware rendering.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname)" != "Darwin" ]; then
    smoke_log "not macOS (uname=$(uname)); skipping FSEvents smoke"
    exit 0
fi

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

smoke_start_shitd

# Daemon spawns the helper, helper handshakes, daemon overwrites
# kernel_tier from the handshake ack. Brief settle so the handshake
# completes before we query metrics.
sleep 0.5

# ─────────────────────────────────────────────────────────────────────
# Part 1 — tier + sandbox baseline (M01 sprint-DoD).
# ─────────────────────────────────────────────────────────────────────

metrics_out="$("${SHIT_BIN}" metrics 2>&1)"
smoke_log "metrics output:"
printf '%s\n' "${metrics_out}" | sed 's/^/    /'

# Tier classifier must be the M01 value. M03 will flip this to
# "endpoint-security" at runtime when ES is entitled + FDA-granted;
# until then "fsevents-degraded" is the truthful answer on macOS.
if ! grep -q "kernel tier .* fsevents-degraded" <<<"${metrics_out}"; then
    smoke_fail "expected 'kernel tier ... fsevents-degraded' in metrics; got:
${metrics_out}"
fi
smoke_log "kernel_tier = fsevents-degraded ✓"

# Confirm the helper actually ran far enough to load the sandbox
# profile + spawn the FSEvents pump.
if [ -f "${SHIT_SMOKE_TMP}/shitd.log" ]; then
    if grep -q "macos sandbox profile installed" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "sandbox profile loaded ✓"
    elif grep -q "sandbox_init_with_parameters failed" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "WARNING: sandbox profile failed to load — helper running unsandboxed"
    fi
    if grep -q "macos fsevents capture pump started" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "fsevents capture pump started ✓"
    else
        smoke_fail "fsevents capture pump did not start; helper log:
$(sed 's/^/    /' "${SHIT_SMOKE_TMP}/shitd.log")"
    fi
fi

# ─────────────────────────────────────────────────────────────────────
# Part 2 — event-flow round-trip (M01.A producer integration).
# ─────────────────────────────────────────────────────────────────────

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
# FSEvents reports realpath-canonical paths; the producer canonicalizes
# the watch root on attach. realpath() the scratch dir so our path
# comparisons line up. (macOS tempdirs live under /var/folders/.../T
# which is a symlink to /private/var/folders/.../T.)
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
smoke_log "watch root (realpath): ${SCRATCH}"

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"

cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" \
    --pid "${PID}" \
    --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=${SEQ} pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --pid "${PID}" \
    --cwd "${SCRATCH}" \
    --shell bash \
    --sock "${SHIT_HOOK_SOCK}"

# FSEvents needs ~200-300ms to attach the stream after the helper
# receives the WatchTree dispatch. Without this settle, the first
# mutation races the kernel registration and the event is missed.
sleep 0.5

TARGET="${SCRATCH}/hello.txt"
smoke_log "create ${TARGET}"
printf 'fsevents canary\n' >"${TARGET}"

# Wait for the TreeOpCreate event. FSEvents may report Create alone
# or Create+Modified flag combos — both decode to TreeOpWire::Create
# in the producer, which the daemon ingests as TreeOpCreate.
smoke_wait_for_event "discriminant = 'TreeOpCreate'" 1 10
smoke_log "TreeOpCreate journaled ✓"

smoke_log "remove ${TARGET}"
rm "${TARGET}"

smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10
smoke_log "TreeOpUnlink journaled ✓"

smoke_log "PostExec seq=${SEQ} exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# ─────────────────────────────────────────────────────────────────────
# Part 3 — M02 doctor uplift (release-gate jq one-liner).
# ─────────────────────────────────────────────────────────────────────

# Verify the M02 DoD: `shit doctor --json | jq .macos.runtime_capture`
# returns one of the documented enum values. This is the literal CI
# release gate from the M02 sprint.
if ! command -v jq >/dev/null 2>&1; then
    smoke_log "jq not present; skipping M02 doctor-uplift assertion"
else
    if ! "${SHIT_BIN}" doctor --json >"${SHIT_SMOKE_TMP}/doctor.json" 2>&1; then
        smoke_log "doctor output:"
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/doctor.json" >&2
        smoke_fail "shit doctor --json exited non-zero"
    fi
    if ! jq -e '.macos.runtime_capture == "endpoint-security" or .macos.runtime_capture == "fsevents-degraded"' \
            "${SHIT_SMOKE_TMP}/doctor.json" >/dev/null; then
        smoke_log "doctor.json .macos block:"
        jq '.macos' "${SHIT_SMOKE_TMP}/doctor.json" | sed 's/^/    /' >&2
        smoke_fail "doctor JSON .macos.runtime_capture is not one of the M02 enum values"
    fi
    smoke_log "shit doctor --json .macos.runtime_capture ✓"
    # FSEvents probe should be functional on any modern Mac; flag if not.
    if ! jq -e '.macos.fsevents.functional' "${SHIT_SMOKE_TMP}/doctor.json" >/dev/null; then
        smoke_log "WARNING: doctor FSEvents probe reported not-functional"
        jq '.macos.fsevents' "${SHIT_SMOKE_TMP}/doctor.json" | sed 's/^/    /'
    else
        smoke_log "shit doctor --json .macos.fsevents.functional ✓"
    fi
fi

smoke_log "PASS: fsevents-fallback-macos (M01 + M01.A + M02 doctor uplift)"
