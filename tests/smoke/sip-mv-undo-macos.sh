#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: sip-mv-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M4: `/bin/mv` is SIP-protected, so the shim never loads. The mv
# here replaces an existing file, whose bytes nothing captured on the
# default tier.
#
# Outcomes:
#   A. Full undo: both files are back with their exact bytes.
#   B. Loud refusal: undo exits non-zero and says the change was not
#      captured.
#   Anything else fails, above all an undo that exits 0 and leaves
#   the replaced file's bytes lost.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-sip.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-sip.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: sip-mv-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

sip_setup
SRC="${WATCHED}/src.txt"
DST="${WATCHED}/dst.txt"
printf 'source bytes\n' > "${SRC}"
printf 'destination bytes mv replaces\n' > "${DST}"
SRC_SHA="$(sip_sha "${SRC}")"
DST_SHA="$(sip_sha "${DST}")"

sip_run_hooked /bin/mv "${SRC}" "${DST}"
[ -e "${SRC}" ] && smoke_fail "/bin/mv left ${SRC} in place"

sip_undo

if [ -f "${SRC}" ] && [ "$(sip_sha "${SRC}")" = "${SRC_SHA}" ] \
    && [ -f "${DST}" ] && [ "$(sip_sha "${DST}")" = "${DST_SHA}" ]; then
    smoke_log "PASS: sip-mv-undo-macos (Outcome A: both files restored, undo exit ${UNDO_RC})"
    exit 0
fi
sip_require_refusal "${DST}"
smoke_log "PASS: sip-mv-undo-macos (Outcome B: refused, not captured)"
