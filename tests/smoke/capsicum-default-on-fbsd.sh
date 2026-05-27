#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: capsicum-default-on-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# B05 smoke — verify the BSD undo pipeline works with Capsicum
# capability mode default-on. Mirrors rm-undo-fbsd.sh's shape but
# adds:
#   1. doctor JSON check confirming `capsicum_default_on=true` in
#      the live binary (i.e. SHIT_CAPSICUM env is unset).
#   2. helper log grep confirming "entered Capsicum capability mode
#      (default-on)" actually fired (cap_enter succeeded).
#   3. The rm-undo flow as proof that capture works post-cap_enter:
#      register_subtree (via openat against slash_fd), read_dir
#      (via fdopendir on tracked dir-fds), write_to_staging (via
#      openat against the pre-cap_enter-opened staging dir-fd),
#      and the cwd_path wire (HookMessage::PreExec → daemon →
#      HelperRequest::WatchTree).
#
# FreeBSD-only — capsicum is FreeBSD-specific.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: capsicum-default-on-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

# Belt-and-suspenders: explicitly unset SHIT_CAPSICUM so we test the
# default-on path, not an opt-out from the surrounding env.
unset SHIT_CAPSICUM

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pre-flight: `shit doctor --json` should report capsicum_default_on=true.
# We don't need a running daemon for this — it's a static config probe.
DOCTOR_JSON="${SHIT_SMOKE_TMP}/doctor.json"
"${SHIT_BIN}" doctor --json > "${DOCTOR_JSON}" 2>/dev/null \
    || smoke_fail "shit doctor --json exited non-zero"
if ! grep -qE '"capsicum_default_on":[[:space:]]*true' "${DOCTOR_JSON}"; then
    smoke_log "doctor JSON (relevant fields):"
    grep -E "capsicum" "${DOCTOR_JSON}" | sed 's/^/    /' >&2
    smoke_fail "doctor reports capsicum_default_on=false; expected true"
fi
smoke_log "pre-flight OK: doctor reports capsicum_default_on=true"

smoke_start_shitd

# Stage a known file under a watched cwd.
SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
echo "capsicum-test-content-$(date -u +%s)" > "${SCRATCH}/cap-foo.txt"
PRE_SHA="$(/sbin/sha256 -q "${SCRATCH}/cap-foo.txt")"
smoke_log "wrote ${SCRATCH}/cap-foo.txt sha256=${PRE_SHA}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

# Move into the watched tree (mirrors rm-undo-fbsd.sh: helper-side
# fall-back paths still consult our cwd in some code paths).
cd "${SCRATCH}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Give the helper a moment to wire up the kqueue watch before rm.
# The pump thread polls control + drain channels at 50ms cadence,
# so 500ms is comfortable headroom.
sleep 0.5

smoke_log "rm ${SCRATCH}/cap-foo.txt"
rm "${SCRATCH}/cap-foo.txt"

# Let the kqueue NOTE_DELETE propagate: drain → pump →
# read_pre_image → staging write → SCM_RIGHTS send → daemon ingest.
sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

# Verify the helper actually entered capability mode. The marker
# string is logged at startup; we tail shitd.log which captures the
# helper's stderr.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
if ! grep -q "entered Capsicum capability mode (default-on)" "${SHIT_SMOKE_TMP}/shitd.log"; then
    smoke_log "shitd log (relevant lines):"
    grep -E "Capsicum|cap_enter|capability" "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "helper didn't enter capsicum mode — log marker missing"
fi
smoke_log "confirmed: helper entered Capsicum capability mode (default-on)"

# Undo and verify byte-identical restore.
smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" \
    || smoke_fail "shit undo --yes exited non-zero"

[ -f "${SCRATCH}/cap-foo.txt" ] \
    || smoke_fail "cap-foo.txt not restored after undo"
POST_SHA="$(/sbin/sha256 -q "${SCRATCH}/cap-foo.txt")"
[ "${POST_SHA}" = "${PRE_SHA}" ] \
    || smoke_fail "restored content sha mismatch: pre=${PRE_SHA} post=${POST_SHA}"

"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: capsicum-default-on-fbsd (helper cap_enter'd; rm-undo round-tripped)"
