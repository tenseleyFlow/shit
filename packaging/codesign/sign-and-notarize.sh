#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# sign-and-notarize.sh — macOS release codesign + notarize pipeline (M04.1).
#
# Two operating modes, distinguished by the `--mode` arg:
#
#   --mode=dry-run   (default): ad-hoc sign the binary with the
#                    ES entitlement plist embedded. Skip notarize.
#                    No Apple secrets needed. The exact same flow
#                    `shit setup-es-mode --apply` runs on the user's
#                    machine — release tarballs ship the binary
#                    pre-shaped for the local install flow.
#
#   --mode=real:     Developer ID sign + Apple notary submit + staple.
#                    Requires `APPLE_NOTARY_API_KEY_ID`,
#                    `APPLE_NOTARY_API_ISSUER_ID`,
#                    `APPLE_NOTARY_API_P8` (path to .p8 file), and
#                    `APPLE_SIGN_IDENTITY` env vars. This mode
#                    requires Apple to have granted the
#                    EndpointSecurity entitlement; bails loud
#                    when secrets are missing.
#
# The dry-run mode is shipped today because Apple denied the
# entitlement application (see `.docs/audits/apple-entitlement.md`).
# When/if that resolves, flipping the GHA workflow's `--mode=real`
# is the entire integration — the script's `real` path is exercised
# and ready.
#
# Usage:
#   sign-and-notarize.sh --mode=dry-run --bin <path>
#   sign-and-notarize.sh --mode=real    --bin <path>
#
# Required args:
#   --bin <path>                  binary to sign (must exist + be Mach-O)
#
# Optional args:
#   --mode=<dry-run|real>         default: dry-run
#   --entitlements <plist-path>   default: packaging/codesign/macos-entitlements.plist
#   --info-plist <plist-path>     default: packaging/codesign/macos-info.plist
#
# Exit codes:
#   0  success
#   1  invalid args / missing inputs
#   2  codesign failed
#   3  notary submit/wait/staple failed (real mode only)
#   4  required env vars missing (real mode only)

set -euo pipefail

MODE="dry-run"
BIN=""
ENTITLEMENTS=""
INFO_PLIST=""

while [ $# -gt 0 ]; do
    case "$1" in
        --mode=*)         MODE="${1#--mode=}"; shift ;;
        --bin)            BIN="$2"; shift 2 ;;
        --entitlements)   ENTITLEMENTS="$2"; shift 2 ;;
        --info-plist)     INFO_PLIST="$2"; shift 2 ;;
        --help|-h)
            sed -n 's/^# \?//;1,/^$/p' "$0" >&2
            exit 0
            ;;
        *)
            echo "ERROR: unrecognized arg: $1" >&2
            exit 1
            ;;
    esac
done

err() { printf '%s\n' "sign-and-notarize: ERROR: $*" >&2; }
log() { printf '%s\n' "sign-and-notarize: $*"; }

if [ "$(uname -s)" != "Darwin" ]; then
    err "this script only runs on macOS (got uname=$(uname -s))"
    exit 1
fi

if [ -z "${BIN}" ]; then
    err "--bin is required"
    exit 1
fi
if [ ! -f "${BIN}" ]; then
    err "binary ${BIN} does not exist"
    exit 1
fi

# Default plist paths: alongside this script in the release tarball
# layout, falling back to repo-relative `packaging/codesign/`.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${ENTITLEMENTS}" ]; then
    for cand in "${SCRIPT_DIR}/macos-entitlements.plist" \
                "packaging/codesign/macos-entitlements.plist"; do
        if [ -f "${cand}" ]; then ENTITLEMENTS="${cand}"; break; fi
    done
fi
if [ -z "${ENTITLEMENTS}" ] || [ ! -f "${ENTITLEMENTS}" ]; then
    err "could not locate macos-entitlements.plist; pass --entitlements"
    exit 1
fi
if [ -z "${INFO_PLIST}" ]; then
    for cand in "${SCRIPT_DIR}/macos-info.plist" \
                "packaging/codesign/macos-info.plist"; do
        if [ -f "${cand}" ]; then INFO_PLIST="${cand}"; break; fi
    done
fi
if [ -z "${INFO_PLIST}" ] || [ ! -f "${INFO_PLIST}" ]; then
    err "could not locate macos-info.plist; pass --info-plist"
    exit 1
fi

log "mode:          ${MODE}"
log "bin:           ${BIN}"
log "entitlements:  ${ENTITLEMENTS}"
log "info plist:    ${INFO_PLIST}"

case "${MODE}" in
    dry-run)
        log "running: codesign --force --options runtime --entitlements ${ENTITLEMENTS} --sign - ${BIN}"
        if ! codesign --force --options runtime \
                       --entitlements "${ENTITLEMENTS}" \
                       --sign - "${BIN}"; then
            err "codesign (dry-run / ad-hoc) failed"
            exit 2
        fi
        # Post-verify the entitlement landed in the binary's signature.
        verify_out="$(codesign -d --entitlements - "${BIN}" 2>&1 || true)"
        if ! grep -q "com.apple.developer.endpoint-security.client" <<<"${verify_out}"; then
            err "post-sign entitlement check failed; ES key not present"
            printf '%s\n' "${verify_out}" | sed 's/^/    /' >&2
            exit 2
        fi
        log "OK — ${BIN} ad-hoc-signed with ES entitlement (dry-run mode)"
        log "Notarize skipped (Apple entitlement paperwork pending — see .docs/audits/apple-entitlement.md)"
        exit 0
        ;;
    real)
        # Real mode: Developer ID sign + notarize + staple. Gated
        # behind the four env vars below — fail loud if any is missing
        # rather than silently fall back to dry-run.
        for var in APPLE_SIGN_IDENTITY APPLE_NOTARY_API_KEY_ID \
                   APPLE_NOTARY_API_ISSUER_ID APPLE_NOTARY_API_P8; do
            if [ -z "${!var:-}" ]; then
                err "--mode=real requires ${var}; set it in CI secrets"
                exit 4
            fi
        done
        if [ ! -f "${APPLE_NOTARY_API_P8}" ]; then
            err "APPLE_NOTARY_API_P8 (${APPLE_NOTARY_API_P8}) is not a readable file"
            exit 4
        fi

        log "real-mode sign: identity=${APPLE_SIGN_IDENTITY}"
        if ! codesign --force --options runtime \
                       --entitlements "${ENTITLEMENTS}" \
                       --sign "${APPLE_SIGN_IDENTITY}" "${BIN}"; then
            err "codesign (Developer ID) failed"
            exit 2
        fi

        # Notary submit. macOS' notarytool returns 0 on success and
        # writes the submission ID + status to stdout. We submit
        # synchronously (--wait) so the script's exit code reflects
        # the Apple notary result.
        log "submitting to Apple notary (this can take 1-10 min)…"
        if ! xcrun notarytool submit "${BIN}" \
                --key "${APPLE_NOTARY_API_P8}" \
                --key-id "${APPLE_NOTARY_API_KEY_ID}" \
                --issuer "${APPLE_NOTARY_API_ISSUER_ID}" \
                --wait; then
            err "notary submit/wait failed; binary is signed but not notarized"
            exit 3
        fi

        # Staple the notary ticket onto the binary so Gatekeeper
        # can verify offline. Required for distribution.
        log "stapling notary ticket"
        if ! xcrun stapler staple "${BIN}"; then
            err "stapler failed; notarization recorded but ticket not embedded"
            exit 3
        fi

        log "OK — ${BIN} Developer-ID-signed + notarized + stapled (real mode)"
        exit 0
        ;;
    *)
        err "unknown --mode: ${MODE} (expected: dry-run | real)"
        exit 1
        ;;
esac
