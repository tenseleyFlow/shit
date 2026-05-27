#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: es-open-write-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: mocked-es
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# M03.1.I.B end-to-end smoke — macOS ES AUTH_OPEN(W).
#
# AUTH_OPEN fires for every open(2) call. We filter on the FWRITE bit
# in fflag and capture the pre-write bytes via inline clonefile.
#
# This smoke uses `dd conv=notrunc of=file ...` which opens with
# O_WRONLY but NOT O_TRUNC (so AUTH_TRUNCATE doesn't fire), then
# overwrites a portion of the file. AUTH_OPEN(W) is the ONLY source
# for the pre-image in this case — confirming the producer captures
# from open-write, not just from truncate/unlink.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-open-write-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
if [ ! -x "${HELPER_BIN}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
fi

probe_out="$("${HELPER_BIN}" es-probe 2>/dev/null || true)"
if [ -z "${probe_out}" ]; then
    smoke_log "SKIP: shit-helper es-probe produced no output"
    exit 0
fi
smoke_log "es-probe: ${probe_out}"
if ! grep -q '"result":"Success"' <<<"${probe_out}"; then
    smoke_log "SKIP: ES not entitled (need SIP+AuthRoot+AMFI VM)"
    exit 0
fi

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

sleep 0.5

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
smoke_log "watch root: ${SCRATCH}"

# Original content — long enough that dd's partial overwrite leaves
# tail bytes intact (proving the file wasn't truncated).
KNOWN_CONTENT="es-open-write canary original content $(date -u +%Y-%m-%dT%H:%M:%SZ) padding-padding-padding"
FILE="${SCRATCH}/data.txt"
printf '%s\n' "${KNOWN_CONTENT}" >"${FILE}"
EXPECTED_SHA="$(shasum -a 256 "${FILE}" | awk '{print $1}')"
ORIG_BYTES="$(wc -c <"${FILE}" | awk '{print $1}')"
smoke_log "wrote ${FILE} sha256=${EXPECTED_SHA} bytes=${ORIG_BYTES}"

SESSION="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" \
    --pid "${PID}" \
    --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" \
    --seq 1 \
    --pid "${PID}" \
    --cwd "${SCRATCH}" \
    --shell bash \
    --sock "${SHIT_HOOK_SOCK}"

sleep 0.5

# dd conv=notrunc opens the file O_WRONLY (no O_TRUNC) and overwrites
# a portion. Pre-image must come from AUTH_OPEN(W) capture, not
# AUTH_TRUNCATE.
smoke_log "dd conv=notrunc of=${FILE}  # O_WRONLY without O_TRUNC"
printf 'OVERWRITE' | dd conv=notrunc of="${FILE}" bs=1 count=9 2>/dev/null

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" \
    --seq 1 \
    --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
smoke_log "FilePreImage from AUTH_OPEN(W) journaled ✓"

# Sanity: post-overwrite the file is the original size + contents differ.
POST_BYTES="$(wc -c <"${FILE}" | awk '{print $1}')"
if [ "${POST_BYTES}" -ne "${ORIG_BYTES}" ]; then
    smoke_fail "post-overwrite file size changed: ${ORIG_BYTES} → ${POST_BYTES}"
fi
if ! grep -q '^OVERWRITE' "${FILE}"; then
    smoke_fail "expected overwrite prefix 'OVERWRITE' in ${FILE}"
fi
smoke_log "file overwritten (size unchanged, content differs) ✓"

# Verify the captured blob landed in the store. Blob layout:
# `<state>/blobs/<aa>/<bb>/<aabbcc...>` where the file body is a
# 1-byte flag (0x00 raw or 0x01 zstd) + the bytes. For sub-COMPRESS-
# MIN (4 KiB) payloads the body is raw, so stripping byte 0 and
# sha256ing the rest recovers the original file's hash.
BLOB_HASH_HEX="$(smoke_journal_query "SELECT hex(blob_hash) FROM events WHERE discriminant = 'FilePreImage' AND path LIKE '%data.txt';" 2>/dev/null | tr 'A-Z' 'a-z')"
if [ -z "${BLOB_HASH_HEX}" ] || [ "${#BLOB_HASH_HEX}" -ne 64 ]; then
    smoke_fail "FilePreImage row missing blob_hash or wrong length (${#BLOB_HASH_HEX})"
fi
smoke_log "journal blob_hash (blake3): ${BLOB_HASH_HEX}"

# The BlobStore is rooted at $XDG_STATE_HOME/shit/blobs and then
# creates a `blobs/` subdir for the sharded layout (so blobs live at
# `$STATE/shit/blobs/blobs/<aa>/<bb>/<aabbcc...>`).
BLOB_PATH="${XDG_STATE_HOME}/shit/blobs/blobs/${BLOB_HASH_HEX:0:2}/${BLOB_HASH_HEX:2:2}/${BLOB_HASH_HEX}"
if [ ! -f "${BLOB_PATH}" ]; then
    smoke_log "expected blob path: ${BLOB_PATH}"
    find "${XDG_STATE_HOME}/shit/blobs" -type f 2>/dev/null | sed 's/^/    /'
    smoke_fail "captured blob missing from store"
fi
# Strip the 1-byte flag header, sha256 the rest, compare to original.
BLOB_SHA="$(tail -c +2 "${BLOB_PATH}" | shasum -a 256 | awk '{print $1}')"
if [ "${BLOB_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${BLOB_SHA}"
    smoke_fail "captured blob sha256 mismatch with original file"
fi
smoke_log "captured blob bytes match original file sha256 ✓"

# Full undo round-trip — the planner (M03.x.OPEN-UNDO) suppresses
# the FSEvents-Create's Unlink inverse when a same-path FilePreImage
# exists and the path is still on disk, so RestoreContent can
# rewrite the original bytes without racing a delete.
smoke_log "shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"; sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}
if [ ! -f "${FILE}" ]; then
    smoke_log "undo log:"; sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${FILE} missing after undo — M03.x.OPEN-UNDO regression"
fi
RESTORED_SHA="$(shasum -a 256 "${FILE}" | awk '{print $1}')"
if [ "${RESTORED_SHA}" != "${EXPECTED_SHA}" ]; then
    smoke_log "expected sha=${EXPECTED_SHA}"
    smoke_log "got      sha=${RESTORED_SHA}"
    smoke_fail "restored content sha256 mismatch"
fi
smoke_log "restored content sha256 matches original ✓"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: es-open-write-undo-macos (M03.1.I.B + M03.x.OPEN-UNDO)"
