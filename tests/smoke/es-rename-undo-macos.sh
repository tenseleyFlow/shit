#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# M03.1.I.A end-to-end smoke — macOS ES AUTH_RENAME overwrite.
#
# Two scenarios:
#
#   (a) rename-over-existing: src and dst both exist before the
#       rename. Post-rename, dst has src's bytes and the OLD dst
#       content is lost — unless we captured it via clonefile. The
#       ES producer emits CapturedPreImage(dst-bytes) +
#       TreeMutation(Rename src→dst). undo restores dst's old bytes
#       via the captured blob.
#
#   (b) rename-to-new-path: src exists, dst does NOT exist. Pure
#       namespace shift. The producer emits TreeMutation(Rename)
#       only; no content lost, no CapturedPreImage required.
#
# Both scenarios share the same skip-checks as the unlink smoke
# (need macOS, ES-entitled environment, root).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: es-rename-undo-macos is macOS-only (uname=$(uname -s))"
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

# ─────────────────────────────────────────────────────────────────────
# Scenario (a) — overwrite rename
# ─────────────────────────────────────────────────────────────────────

SCRATCH="${SHIT_SMOKE_TMP}/scratch-a"
mkdir -p "${SCRATCH}"
SCRATCH="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${SCRATCH}")"
smoke_log "scenario (a) watch root: ${SCRATCH}"

DST="${SCRATCH}/dst.txt"
SRC="${SCRATCH}/src.txt"
DST_OLD="overwrite-dst original $(date -u +%Y-%m-%dT%H:%M:%SZ)"
SRC_BYTES="overwrite-src $(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s\n' "${DST_OLD}" >"${DST}"
printf '%s\n' "${SRC_BYTES}" >"${SRC}"
DST_OLD_SHA="$(shasum -a 256 "${DST}" | awk '{print $1}')"
smoke_log "wrote ${DST} (old sha=${DST_OLD_SHA}) and ${SRC}"

SESSION_A="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${SCRATCH}"
"${SHIT_BIN}" hook-send session-open --session "${SESSION_A}" --pid "${PID}" --shell bash --tty "$(tty 2>/dev/null || echo /dev/null)" --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION_A}" --seq 1 --pid "${PID}" --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

smoke_log "mv ${SRC} ${DST}  # overwrites dst"
mv "${SRC}" "${DST}"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec --session "${SESSION_A}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
smoke_log "FilePreImage (dst-overwrite bytes) journaled ✓"
smoke_wait_for_event "discriminant = 'TreeOpRename'" 1 10
smoke_log "TreeOpRename journaled ✓"

if [ ! -e "${DST}" ]; then
    smoke_fail "dst.txt should still exist after rename"
fi
POST_RENAME_SHA="$(shasum -a 256 "${DST}" | awk '{print $1}')"
SRC_SHA="$(printf '%s\n' "${SRC_BYTES}" | shasum -a 256 | awk '{print $1}')"
if [ "${POST_RENAME_SHA}" != "${SRC_SHA}" ]; then
    smoke_fail "post-rename dst.txt should contain src bytes; got sha=${POST_RENAME_SHA}, expected=${SRC_SHA}"
fi
smoke_log "post-rename dst.txt has src bytes ✓"

smoke_log "shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo-a.log" || {
    smoke_log "undo log:"; sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo-a.log" >&2
    smoke_fail "shit undo --yes exited non-zero (scenario a)"
}
if [ ! -f "${DST}" ]; then
    smoke_fail "dst.txt was not restored"
fi
RESTORED_SHA="$(shasum -a 256 "${DST}" | awk '{print $1}')"
if [ "${RESTORED_SHA}" != "${DST_OLD_SHA}" ]; then
    smoke_log "expected sha=${DST_OLD_SHA}"
    smoke_log "got      sha=${RESTORED_SHA}"
    smoke_fail "restored dst.txt sha256 mismatch (lost the overwrite pre-image)"
fi
smoke_log "scenario (a) restored dst.txt to original bytes ✓"

"${SHIT_BIN}" hook-send session-close --session "${SESSION_A}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: es-rename-undo-macos (M03.1.I.A — overwrite-rename only)"
