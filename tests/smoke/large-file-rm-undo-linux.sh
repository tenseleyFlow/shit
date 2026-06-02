#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: large-file-rm-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 600
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU25 — Linux streaming pre-image for files > 32 MiB / > 256 MiB.
#
# Validate-the-gap:
#   Pre-AU25 `read_pre_image` materialized the whole file into
#   `Vec<u8>` and refused capture for any file > `MAX_PRE_IMAGE_BYTES`
#   (256 MiB). `rm` of a >256 MiB file logged "pre-image read failed:
#   FileTooLarge" and returned without journaling — `shit undo` then
#   had no content to restore.
#
#   Post-AU25 the capture path streams 64 KiB chunks through an
#   in-flight blake3 hasher directly into the staging file, and the
#   cap is raised to 1 GiB. A 300 MiB rm now captures + restores
#   byte-identically.
#
# This smoke MUST fail pre-AU25 (FileTooLarge → no journal → undo
# can't restore) and pass post-AU25.
#
# Mirrors the BSD `dd-large-file-undo-fbsd.sh` shape but on the LSM
# unlink path: 300 MiB urandom file, sha256 the pre-state, rm,
# `shit undo --yes`, sha256 the restored file, assert match.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: large-file-rm-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# LSM-tier pre-flight (same shape as rm-undo-linux.sh)
if [ ! -r /sys/kernel/security/lsm ]; then
    smoke_log "SKIP: /sys/kernel/security/lsm unreadable; cannot verify lsm=bpf"
    exit 0
fi
ACTIVE_LSMS="$(cat /sys/kernel/security/lsm 2>/dev/null || echo)"
if ! printf '%s' "${ACTIVE_LSMS}" | grep -q "\bbpf\b"; then
    smoke_log "FAIL: kernel boot cmdline lacks bpf LSM (active=${ACTIVE_LSMS})"
    smoke_log "  See rm-undo-linux.sh for the boot-param fix."
    exit 1
fi
if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing; cannot verify helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_bpf cap_perfmon cap_sys_admin; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required} (getcap output: '${HELPER_CAPS}')"
        smoke_log "  sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done

export SHIT_FORCE_TIER=ebpf-lsm
smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"

# 300 MiB urandom file — comfortably above the pre-AU25 256 MiB cap,
# small enough that hasu / a runner with 4+ GB RAM can hold it on
# tmpfs (SHIT_SMOKE_TMP) and re-write it during restore.
BIG="${SCRATCH}/big.bin"
BIG_MB=300
smoke_log "generating ${BIG_MB} MiB urandom at ${BIG}"
dd if=/dev/urandom of="${BIG}" bs=1M count="${BIG_MB}" status=none \
    || smoke_fail "dd failed generating ${BIG_MB} MiB file"
EXPECTED_SHA="$(sha256sum "${BIG}" | cut -d' ' -f1)"
smoke_log "${BIG} sha256=${EXPECTED_SHA}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SEQ=1
PID="$$"

cd "${SCRATCH}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=${SEQ} pid=${PID} cwd=${SCRATCH}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq "${SEQ}" --pid "${PID}" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "rm ${BIG}"
rm "${BIG}"

# Streaming capture is slower than the inline path for the largest
# files — give the LSM handler a generous window to drain. At
# ~500 MB/s pread + hash + write the 300 MiB capture is ~600ms;
# under contention a few seconds.
sleep 3

smoke_log "PostExec seq=${SEQ} exit=0"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq "${SEQ}" --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

if [ -e "${BIG}" ]; then
    smoke_fail "${BIG} should have been rm'd but still exists"
fi

# Pre-AU25 the helper logs "pre-image read failed: FileTooLarge"
# and does NOT journal a FilePreImage. This wait will time out and
# the smoke fails fast — that's the validate-the-gap signal.
smoke_wait_for_event "discriminant = 'FilePreImage'" 1 30
smoke_wait_for_event "discriminant = 'TreeOpUnlink'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

if [ ! -f "${BIG}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${BIG} was not restored by shit undo"
fi
GOT_SHA="$(sha256sum "${BIG}" | cut -d' ' -f1)"
if [ "${GOT_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${GOT_SHA}"
    smoke_fail "restored content sha256 mismatch (${BIG_MB} MiB)"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: large-file-rm-undo-linux (${BIG_MB} MiB sha256=${EXPECTED_SHA})"
