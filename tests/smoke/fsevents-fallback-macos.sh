#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# M01 smoke — macOS helper reports kernel_tier=fsevents-degraded.
#
# What this asserts:
# - shitd starts cleanly on macOS.
# - shit-helper handshakes successfully (sandbox profile loads,
#   FSEvents-based degraded tier picked, handshake ack carries
#   kernel_tier = "fsevents-degraded").
# - `shit metrics` surfaces the tier in its text output.
#
# What this does NOT assert (deferred to M01.A producer integration):
# - FSEvents callbacks reach the daemon as CapturedPreImage events.
# - `shit list` shows `(degraded)` after a tracked-dir mutation.
# - Full hook → mutation → list-entry round-trip on macOS.
#
# M01.A lands the FSEvents producer + integration test that closes
# that gap. This smoke is the M01 sprint-DoD line:
# "shit-helper started on a macOS box reports kernel_tier =
#  fsevents-degraded in the handshake."

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname)" != "Darwin" ]; then
    smoke_log "not macOS (uname=$(uname)); skipping FSEvents smoke"
    exit 0
fi

smoke_start_shitd

# The daemon spawns the helper, the helper handshakes, the daemon
# overwrites kernel_tier from the handshake ack. Brief settle so
# the handshake completes before we query metrics.
sleep 0.5

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

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
# profile. The helper's log emits the sandbox-installed line at
# tracing::info level after sandbox_init_with_parameters returns 0.
# (Failure mode is warn-and-continue per M01.6, so this line might
# be absent if the profile failed to load — that's worth flagging.)
if [ -f "${SHIT_SMOKE_TMP}/shitd.log" ]; then
    if grep -q "macos sandbox profile installed" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "sandbox profile loaded ✓"
    elif grep -q "sandbox_init_with_parameters failed" "${SHIT_SMOKE_TMP}/shitd.log"; then
        smoke_log "WARNING: sandbox profile failed to load — helper running unsandboxed"
        smoke_log "(this is a warn-and-continue path; M03 tightens to hard-fail)"
    else
        smoke_log "sandbox profile log line not observed (handshake may have completed before sandbox::enter)"
    fi
fi

smoke_log "PASS: fsevents-fallback-macos (M01 tier-reporting baseline)"
smoke_log "next: M01.A wires the FSEvents producer; this smoke will gain"
smoke_log "      event-flow assertions then"
