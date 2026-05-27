#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# sign-for-power-user.sh — ad-hoc codesigns the installed shit-helper
# binary with the EndpointSecurity entitlement plist embedded
# (M03.x.POWER-USER.4).
#
# Apple denied us the EndpointSecurity entitlement for general
# distribution (see `.docs/audits/apple-entitlement.md`), so the
# install pipeline cannot ship a pre-signed binary that carries
# the entitlement claim. The workaround the M03.x.POWER-USER sprint
# productionizes is: ship an UNSIGNED helper in the release tarball
# alongside the entitlement plist + this script, and have the user
# (or the installer's postinstall hook) run this script once to
# ad-hoc-sign the helper locally. The user's SIP+AuthRoot+AMFI-
# bypassed environment is what makes AMFI accept the claim from an
# ad-hoc signature — no Developer ID required.
#
# Usage:
#   sign-for-power-user.sh                      # use defaults
#   sign-for-power-user.sh <helper-path>        # explicit helper
#   sign-for-power-user.sh <helper> <plist>     # both explicit
#
# Defaults (tried in order):
#   helper: SHIT_HELPER_BIN env, then /usr/local/bin/shit-helper,
#           then /opt/homebrew/bin/shit-helper
#   plist:  SHIT_ENTITLEMENT_PLIST env, then alongside this script
#           (packaging/codesign/macos-entitlements.plist),
#           then /usr/local/share/shit/macos-entitlements.plist,
#           then /opt/homebrew/share/shit/macos-entitlements.plist
#
# Exits non-zero on any failure (helper missing, plist missing,
# codesign failed, embedded entitlement not detectable after sign).
# Caller (the user or the installer's postinstall hook) treats
# non-zero as "ES capture won't work" and surfaces remediation.
#
# Side note: this is RUN-AS-ROOT only on the helper's install path;
# self-signing your own user's local copy works without sudo if the
# helper file is in a path you own.

set -euo pipefail

err() { printf '%s\n' "sign-for-power-user.sh: ERROR: $*" >&2; }
log() { printf '%s\n' "sign-for-power-user.sh: $*"; }

resolve_helper() {
    if [ -n "${1:-}" ]; then
        printf '%s\n' "$1"
        return
    fi
    if [ -n "${SHIT_HELPER_BIN:-}" ] && [ -x "${SHIT_HELPER_BIN}" ]; then
        printf '%s\n' "${SHIT_HELPER_BIN}"
        return
    fi
    for candidate in /usr/local/bin/shit-helper /opt/homebrew/bin/shit-helper; do
        if [ -x "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return
        fi
    done
    printf '\n'  # signal not-found
}

resolve_plist() {
    if [ -n "${1:-}" ]; then
        printf '%s\n' "$1"
        return
    fi
    if [ -n "${SHIT_ENTITLEMENT_PLIST:-}" ] && [ -f "${SHIT_ENTITLEMENT_PLIST}" ]; then
        printf '%s\n' "${SHIT_ENTITLEMENT_PLIST}"
        return
    fi
    # Alongside this script (release tarball layout).
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local local_plist="${script_dir}/macos-entitlements.plist"
    if [ -f "${local_plist}" ]; then
        printf '%s\n' "${local_plist}"
        return
    fi
    for candidate in \
        /usr/local/share/shit/macos-entitlements.plist \
        /opt/homebrew/share/shit/macos-entitlements.plist; do
        if [ -f "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return
        fi
    done
    printf '\n'  # signal not-found
}

if [ "$(uname -s)" != "Darwin" ]; then
    err "this script only runs on macOS (got uname=$(uname -s))"
    exit 1
fi

HELPER="$(resolve_helper "${1:-}")"
if [ -z "${HELPER}" ]; then
    err "could not find shit-helper. Pass the path explicitly, or set SHIT_HELPER_BIN."
    err "Searched: SHIT_HELPER_BIN, /usr/local/bin/shit-helper, /opt/homebrew/bin/shit-helper"
    exit 2
fi
if [ ! -x "${HELPER}" ]; then
    err "helper path ${HELPER} is not executable"
    exit 2
fi

PLIST="$(resolve_plist "${2:-}")"
if [ -z "${PLIST}" ]; then
    err "could not find macos-entitlements.plist. Pass it explicitly as arg 2, or set SHIT_ENTITLEMENT_PLIST."
    err "Searched: SHIT_ENTITLEMENT_PLIST, $(dirname "${BASH_SOURCE[0]}")/macos-entitlements.plist, /usr/local/share/shit/, /opt/homebrew/share/shit/"
    exit 2
fi
if [ ! -f "${PLIST}" ]; then
    err "entitlement plist ${PLIST} does not exist"
    exit 2
fi

log "helper:           ${HELPER}"
log "entitlement plist: ${PLIST}"

# Quick sanity: the plist must actually contain the ES entitlement
# key. A wrong/empty plist would silently codesign a useless claim.
if ! grep -q "com.apple.developer.endpoint-security.client" "${PLIST}"; then
    err "plist ${PLIST} does not contain com.apple.developer.endpoint-security.client"
    err "Bad plist? Re-extract the release tarball or pass the right plist explicitly."
    exit 3
fi

# Codesign with the embedded entitlement. --force replaces any prior
# signature (typical: the release tarball ships ad-hoc-signed without
# the entitlement; we replace with ad-hoc-signed WITH the entitlement).
# --options runtime opts into hardened runtime, which AMFI bypass mode
# accepts the entitlement against.
log "running: codesign --force --options runtime --entitlements ${PLIST} --sign - ${HELPER}"
if ! codesign --force --options runtime --entitlements "${PLIST}" --sign - "${HELPER}"; then
    err "codesign failed (rc=$?). On a stock Mac with SIP enabled this is expected;"
    err "see 'shit setup-es-mode --print' for the SIP/AuthRoot/AMFI prereqs."
    exit 4
fi

# Verify the entitlement is actually present in the signed binary.
# codesign -d --entitlements - writes the embedded plist to stdout on
# newer macOS, stderr on older. Check both.
log "verifying embedded entitlement"
verify_out="$(codesign -d --entitlements - "${HELPER}" 2>&1 || true)"
if ! grep -q "com.apple.developer.endpoint-security.client" <<<"${verify_out}"; then
    err "post-sign verification: the ES entitlement key is NOT present in the signed binary."
    err "codesign -d --entitlements - output:"
    printf '%s\n' "${verify_out}" | sed 's/^/    /' >&2
    exit 5
fi

log "OK — ${HELPER} is ad-hoc-signed with com.apple.developer.endpoint-security.client"
log "Next step: run 'shit setup-es-mode --check' to confirm all prereqs are green."
