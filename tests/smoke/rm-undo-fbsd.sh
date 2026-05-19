#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# S24.C end-to-end smoke — FreeBSD only.
#
# Exercises:
#   1. shitd boots and spawns shit-helper (which brings up the BSD kqueue
#      capture runtime via capture::bsd::spawn).
#   2. PreExec triggers daemon -> helper WatchTree dispatch; helper's
#      pump thread calls register_subtree under the test process's cwd.
#   3. A `rm` of a known-content file in the watched tree fires NOTE_DELETE.
#      The kqueue producer reads the pre-image via the surviving fd,
#      stages it, and sends HelperResponse::CapturedPreImage with the
#      staging fd attached via SCM_RIGHTS.
#   4. The daemon's dispatch_loop ingests the blob, verifies the hash,
#      journals a FilePreImage event plus a paired TreeOp::Unlink.
#   5. `shit undo --yes` replays the inverse: rewrites the blob to the
#      original path.
#   6. The restored file is byte-identical to the original (sha256 match).
#
# FreeBSD-only because the kqueue producer + procstat cwd resolver are
# BSD-specific. Linux equivalent will reuse the wire (S25.A).
#
# Run inside the FreeBSD VM (tools/freebsd-vm/run-smoke.sh).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: rm-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

# Helper binary must be discoverable so shitd can spawn it. The smoke
# script runs after `cargo build --release` so the release path exists.
HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
if [ ! -x "${HELPER_BIN}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
fi
export SHIT_HELPER_BIN="${HELPER_BIN}"

smoke_start_shitd

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${SHIT_BIN}" ]; then
    smoke_fail "shit binary missing at ${SHIT_BIN}"
fi

# Carve out a UFS-backed scratch dir for the test. /tmp on the dev VM is
# UFS, which is what the open-fd-survives-unlink trick depends on.
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

KNOWN_CONTENT="rm-undo-fbsd canary $(date -u +%Y-%m-%dT%H:%M:%SZ)"
FOO="${SCRATCH}/foo.txt"
printf '%s\n' "${KNOWN_CONTENT}" >"${FOO}"
EXPECTED_SHA="$(/sbin/sha256 -q "${FOO}")"
smoke_log "wrote ${FOO} sha256=${EXPECTED_SHA}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"

# Move our shell into the watched tree so the helper's procstat($$) cwd
# resolves under SCRATCH. register_subtree walks that whole subtree.
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

# Give the helper a moment to wire up the kqueue watch before we rm.
# The pump thread polls the control channel + drain channel at 50ms,
# so a 250ms wait is comfortable.
sleep 0.5

smoke_log "rm ${FOO}"
rm "${FOO}"

# Let the kqueue NOTE_DELETE propagate: drain -> pump -> read_pre_image
# -> staging write -> sendmsg -> daemon recvmsg -> blob put -> index.
sleep 0.5

smoke_log "PostExec seq=${SEQ} exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq "${SEQ}" \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

# Wait up to 10s for the FilePreImage event to land in the index.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
# And for the paired TreeOpUnlink — that's what `shit undo` consults
# to know "this command unlinked foo.txt" rather than just "this command
# wrote some blob".
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

# Verify restoration: the file should exist with byte-identical content.
if [ ! -f "${FOO}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "foo.txt was not restored by shit undo"
fi
GOT_SHA="$(/sbin/sha256 -q "${FOO}")"
if [ "${GOT_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${GOT_SHA}"
    smoke_fail "restored content sha256 mismatch"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: rm-undo-fbsd"
