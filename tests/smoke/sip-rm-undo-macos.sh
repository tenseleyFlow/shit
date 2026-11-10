#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: sip-rm-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 180
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M4: `/bin/rm` is SIP-protected, so dyld drops DYLD_INSERT_LIBRARIES
# and the shim never loads. Without EndpointSecurity the removal is
# not captured, and undo has no bytes to put back.
#
# Outcomes:
#   A. Full undo: the file is back with its exact bytes (only possible
#      with a capture tier that sees SIP binaries).
#   B. Loud refusal: undo exits non-zero and says the change was not
#      captured.
#   Anything else fails, above all an undo that exits 0 without
#   putting the bytes back.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-sip.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-sip.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: sip-rm-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

sip_setup
TARGET="${WATCHED}/victim.txt"
printf 'bytes undo must not fake\n' > "${TARGET}"
PRE_SHA="$(sip_sha "${TARGET}")"

sip_run_hooked /bin/rm "${TARGET}"
[ -e "${TARGET}" ] && smoke_fail "/bin/rm did not remove ${TARGET}"

sip_undo

if [ -f "${TARGET}" ] && [ "$(sip_sha "${TARGET}")" = "${PRE_SHA}" ]; then
    smoke_log "PASS: sip-rm-undo-macos (Outcome A: bytes restored, undo exit ${UNDO_RC})"
    exit 0
fi
sip_require_refusal "${TARGET}"
smoke_log "PASS: sip-rm-undo-macos (Outcome B: refused, not captured)"
