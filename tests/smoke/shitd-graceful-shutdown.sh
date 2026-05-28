#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: shitd-graceful-shutdown
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU09 smoke — `shit doctor --shutdown-daemon` is the documented
# graceful path: it sends `CtlRequest::Shutdown` over the ctl
# socket, the daemon acks, then the daemon's main loop tears down
# WatchTree subscriptions, drains in-flight blob writes, and exits.
# This smoke validates the round-trip end-to-end:
#
#   1. shitd boots; ctl socket up; pid alive.
#   2. `shit doctor --shutdown-daemon` exits 0 after the ack.
#   3. The daemon process disappears within a 2s grace window.
#   4. The ctl socket is gone (post-exit cleanup).
#   5. No leftover staging entries under XDG_STATE_HOME/shit/staging.
#
# If any step fails, the smoke calls smoke_fail which prints the
# daemon's JSON log + shitd.log tail so the run's CI surface includes
# the breadcrumbs.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

shit_bin="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${shit_bin}" ]; then
    smoke_fail "shit binary missing at ${shit_bin}"
fi

smoke_start_shitd

# Sanity: pid alive, ctl socket present.
if ! kill -0 "${SHITD_PID}" 2>/dev/null; then
    smoke_fail "shitd pid ${SHITD_PID} not alive after smoke_start_shitd"
fi
if [ ! -S "${SHIT_CTL_SOCK}" ]; then
    smoke_fail "ctl socket missing at ${SHIT_CTL_SOCK} after smoke_start_shitd"
fi
smoke_log "pre-shutdown: pid=${SHITD_PID} ctl_sock=${SHIT_CTL_SOCK}"

# Step 1+2 — invoke graceful shutdown directly.
shutdown_out="${SHIT_SMOKE_TMP}/shutdown-out.txt"
if ! "${shit_bin}" doctor --shutdown-daemon >"${shutdown_out}" 2>&1; then
    smoke_log "shit doctor --shutdown-daemon non-zero output:"
    sed 's/^/    /' "${shutdown_out}" >&2 || true
    smoke_fail "shit doctor --shutdown-daemon exited non-zero"
fi
if ! grep -q 'shutdown acked' "${shutdown_out}"; then
    smoke_log "shutdown stdout (expected 'shutdown acked'):"
    sed 's/^/    /' "${shutdown_out}" >&2 || true
    smoke_fail "graceful shutdown did not emit 'shutdown acked'"
fi
smoke_log "ack received"

# Step 3 — daemon exits within the grace window.
gone=0
for i in $(seq 1 40); do
    if ! kill -0 "${SHITD_PID}" 2>/dev/null; then
        gone=1
        smoke_log "daemon pid ${SHITD_PID} gone after ack (i=${i}, ~${i}00ms)"
        break
    fi
    sleep 0.1
done
if [ "${gone}" -ne 1 ]; then
    smoke_fail "daemon pid ${SHITD_PID} still alive 4s after ack"
fi

# Reap the backgrounded shitd so the cleanup hook doesn't try to
# stop a pid that's already gone (avoids harmless but noisy
# `[stop-shitd] not alive` breadcrumbs).
wait "${SHITD_PID}" 2>/dev/null || true
shitd_rc=$?
smoke_log "shitd exit rc=${shitd_rc}"
SHITD_PID=""

# Step 4 — ctl socket gone. The daemon unlinks it on graceful exit;
# the inode-level disappearance is the strongest signal the unwind
# ran to completion (vs. SIGKILL, which leaves the socket dangling
# on disk).
if [ -S "${SHIT_CTL_SOCK}" ]; then
    smoke_fail "ctl socket lingers at ${SHIT_CTL_SOCK} after graceful exit"
fi
smoke_log "ctl socket cleared"

# Step 5 — no leftover staging. Graceful exit is supposed to drain
# in-flight blob writes; any residual staging file is a regression.
# (A fresh smoke with no PreExec hook activity will have nothing
# under staging/ — so the "empty or absent" assertion is the
# right shape, not "exactly N files".)
staging_dir="${XDG_STATE_HOME}/shit/staging"
if [ -d "${staging_dir}" ]; then
    leftover="$(find "${staging_dir}" -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
    if [ "${leftover}" -ne 0 ]; then
        smoke_log "staging dir contents:"
        find "${staging_dir}" -type f 2>/dev/null | sed 's/^/    /' >&2 || true
        smoke_fail "${leftover} leftover staging file(s) after graceful exit"
    fi
fi
smoke_log "staging dir clean"

smoke_log "PASS: shitd-graceful-shutdown"
