#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build shit-helper on the tart VM AND ad-hoc-sign it with the
# EndpointSecurity entitlement embedded. The VM has AMFI bypassed
# (boot-arg amfi_get_out_of_my_way=0x1 + auth-root disabled), which
# lets the kernel accept the entitlement claim from an ad-hoc
# signature. Without the codesign step the binary has NO entitlements
# at all, and `es_new_client` returns NotEntitled regardless of AMFI
# state — see `.docs/audits/macos-tart-vm-setup.md`.
#
# Usage:
#   tools/macos-tart-vm/build-signed.sh             # signs bin/shit-helper
#   tools/macos-tart-vm/build-signed.sh --test      # also signs every
#                                                   # cargo test binary
#                                                   # that links shit-helper
#   tools/macos-tart-vm/build-signed.sh --release   # release profile + sign
#
# Production note: this is dev-only. The M04 release pipeline does
# the same plist + sign + notarize flow with a real Developer ID
# Application certificate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROFILE="debug"
SIGN_TESTS=0
for a in "$@"; do
    case "${a}" in
        --release) PROFILE="release" ;;
        --test) SIGN_TESTS=1 ;;
        *) echo "unknown flag: ${a}" >&2; exit 2 ;;
    esac
done
CARGO_PROFILE_FLAG=""
if [ "${PROFILE}" = "release" ]; then
    CARGO_PROFILE_FLAG="--release"
fi

# Always re-sync the repo first — typical workflow is "edit on host,
# build on VM."
echo "[build-signed] syncing repo to VM"
"${SCRIPT_DIR}/sync.sh"

# Build + sign. The codesign --force ensures we replace any prior
# ad-hoc signature.
"${SCRIPT_DIR}/ssh.sh" "
    set -euo pipefail
    cd shit
    source \$HOME/.cargo/env

    echo '[build-signed] cargo build ${CARGO_PROFILE_FLAG} -p shit-helper'
    cargo build ${CARGO_PROFILE_FLAG} -p shit-helper 2>&1 | tail -5

    BIN=target/${PROFILE}/shit-helper
    echo \"[build-signed] codesign \${BIN}\"
    codesign --force --options runtime \
        --entitlements packaging/codesign/macos-entitlements.plist \
        --sign - \"\${BIN}\"
    codesign -d --entitlements - \"\${BIN}\" 2>&1 | grep -E '\\[Key\\]|\\[Bool\\]' | head -4

    if [ ${SIGN_TESTS} -eq 1 ]; then
        echo '[build-signed] cargo test --no-run'
        cargo test ${CARGO_PROFILE_FLAG} -p shit-helper --bin shit-helper --no-run 2>&1 | tail -3
        # cargo test produces N timestamped test binaries; sign each.
        for TB in target/${PROFILE}/deps/shit_helper-*; do
            case \"\${TB}\" in
                *.d|*.dSYM) continue ;;
            esac
            if [ -x \"\${TB}\" ]; then
                echo \"[build-signed] codesign test bin \${TB##*/}\"
                codesign --force --options runtime \
                    --entitlements packaging/codesign/macos-entitlements.plist \
                    --sign - \"\${TB}\"
            fi
        done
    fi

    echo '[build-signed] done'
"
