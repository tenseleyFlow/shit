#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-unlink-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: M03-vm-runner
# EXCLUDED_REASON: macOS smokes need a signed binary on a Tart VM; GH-hosted macos-14 runner cannot satisfy the EndpointSecurity entitlement 
#
# M03.1.I.7 end-to-end smoke — macOS EndpointSecurity producer.
#
# Exercises the full ES path that landed in M03.1.I.1-6:
#   1. shitd boots and spawns shit-helper. Helper handshakes with
#      kernel_tier="endpoint-security" (the runtime probe in
#      handshake.rs::kernel_tier_classifier confirms ES creates
#      cleanly in this environment).
#   2. PreExec triggers daemon → helper WatchTree. Helper dispatches
#      to BOTH producers per the coexistence design (Decision 3):
#      capture::macos (FSEvents) and capture::macos_es (ES).
#   3. The shell's `rm` of a known-content file in the tracked tree
#      fires ES AUTH_UNLINK. The producer's kernel callback:
#        - decodes the message (path + stat + audit_token)
#        - filters on tracked_tokens (set was populated via
#          NOTIFY_FORK from the shell's audit_token)
#        - inline-clonefiles the victim → staging
#        - enqueues a CaptureRecord with the staging fd
#        - responds ALLOW
#   4. The pump-thread worker hashes the staging file (pread, no
#      offset disturbance) and emits HelperResponse::CapturedPreImage
#      via send_response_with_fd (SCM_RIGHTS).
#   5. The daemon dispatch_loop ingests the blob, verifies the hash,
#      journals a FilePreImage event + paired TreeOp::Unlink.
#   6. `shit undo --yes` replays the inverse: restores the blob to
#      the original path.
#   7. Restored file is byte-identical to the original (sha256 match).
#
# ─────────────────────────────────────────────────────────────────────
# Environment requirements (any one missing → skip cleanly)
# ─────────────────────────────────────────────────────────────────────
#
# - macOS host (uname Darwin)
# - shit-helper signed with com.apple.developer.endpoint-security.client
#   AND running where AMFI honors the claim:
#     * Production: signed + notarized + Apple-granted entitlement
#     * Dev: SIP+AuthRoot+AMFI-bypassed Tart VM
#       (tools/macos-tart-vm/build-signed.sh handles this)
# - Running as root (sudo) — ES requires it
#
# Outside an ES-entitled env the script logs a clear skip and exits 0.
# That keeps the smoke harmless on a stock dev mac in CI; the real
# validation happens via tools/macos-tart-vm/run-smoke.sh which boots
# the VM, builds-signed, syncs, and runs the smoke under sudo there.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-unlink-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
if [ ! -x "${HELPER_BIN}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
fi

# ES probe: ask the helper itself. The es-probe subcommand emits one
# JSON line describing the outcome (success / not_entitled / etc.).
# We skip cleanly on anything other than Success — that's the signal
# this host isn't an ES-capable environment.
probe_out="$("${HELPER_BIN}" es-probe 2>/dev/null || true)"
if [ -z "${probe_out}" ]; then
    smoke_log "SKIP: shit-helper es-probe produced no output (binary too old?)"
    exit 0
fi
smoke_log "es-probe: ${probe_out}"
if ! grep -q '"result":"Success"' <<<"${probe_out}"; then
    smoke_log "SKIP: ES not entitled in this environment (need SIP+AuthRoot+AMFI VM or signed-prod build)"
    exit 0
fi

# ES requires root. We don't try to escalate; fail-skip if not.
if [ "$(id -u)" -ne 0 ]; then
    smoke_log "SKIP: ES capture requires sudo; rerun as root"
    exit 0
fi

export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

# ─────────────────────────────────────────────────────────────────────
# Part 1 — handshake tier
# ─────────────────────────────────────────────────────────────────────

# Allow the daemon-helper handshake to complete before we query metrics.
sleep 0.5

metrics_out="$("${SHIT_BIN}" metrics 2>&1)"
smoke_log "metrics output:"
printf '%s\n' "${metrics_out}" | sed 's/^/    /'

if ! grep -q "kernel tier .* endpoint-security" <<<"${metrics_out}"; then
    smoke_fail "expected 'kernel tier ... endpoint-security' in metrics; got:
${metrics_out}"
fi
smoke_log "kernel_tier = endpoint-security ✓"

# Helper should have spawned BOTH FSEvents + ES pumps (coexistence).
if [ -f "${SHIT_SMOKE_TMP}/shitd.log" ]; then
    if grep -q "macos fsevents capture runtime spawned" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "fsevents capture spawned ✓"
    fi
    if grep -q "macos endpoint-security capture runtime spawned" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "endpoint-security capture spawned ✓"
    else
        smoke_log "shitd log:"
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/shitd.log" >&2
        smoke_fail "ES capture pump did not spawn"
    fi
fi

# ─────────────────────────────────────────────────────────────────────
# Part 2 — round-trip: rm → CapturedPreImage → undo → byte match
# ─────────────────────────────────────────────────────────────────────

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
# macOS /tmp on the VM image is an APFS volume so clonefile works.
# Realpath-canonicalize to match ES's path normalization (/private/tmp
# vs /tmp on macOS).
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
smoke_log "watch root (realpath): ${SCRATCH}"

KNOWN_CONTENT="es-unlink-undo canary $(date -u +%Y-%m-%dT%H:%M:%SZ)"
FOO="${SCRATCH}/foo.txt"
printf '%s\n' "${KNOWN_CONTENT}" >"${FOO}"
EXPECTED_SHA="$(shasum -a 256 "${FOO}" | awk '{print $1}')"
smoke_log "wrote ${FOO} sha256=${EXPECTED_SHA}"

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

# Give the ES producer time to: receive the WatchTree, attempt
# pid→audit_token resolve (root_pid is None today — I.5 follow-up),
# settle. NOTIFY_FORK will auto-add descendants once the child shell
# execs `rm`.
sleep 0.5

smoke_log "rm ${FOO}"
rm "${FOO}"

# Settle: ES AUTH callback → inline clonefile → enqueue → ALLOW,
# pump thread drain → hash → sendmsg → daemon recvmsg → blob put →
# journal.
sleep 0.5

smoke_log "PostExec seq=${SEQ} exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# FilePreImage from the ES producer's CapturedPreImage emission.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
# TreeOpUnlink from FSEvents (the coexistence sibling). ES doesn't
# emit a TreeOp directly; FSEvents picks up the unlink and emits one.
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

# Sanity: the file is gone now.
if [ -e "${FOO}" ]; then
    smoke_fail "foo.txt should have been rm'd but still exists"
fi

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -f "${FOO}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "foo.txt was not restored by shit undo"
fi
GOT_SHA="$(shasum -a 256 "${FOO}" | awk '{print $1}')"
if [ "${GOT_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${GOT_SHA}"
    smoke_fail "restored content sha256 mismatch"
fi
smoke_log "restored content sha256 matches original ✓"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: es-unlink-undo-macos (M03.1.I.7)"
