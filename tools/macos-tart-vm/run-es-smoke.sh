#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# M03 ES smoke runner. Mirrors run-smoke.sh but knows to:
#   - build + ad-hoc-sign shit-helper with the ES entitlement embedded
#     (without this the binary returns NotEntitled on AMFI-bypass VMs)
#   - build shit + shitd plain (no entitlement needed)
#   - run the smoke as root (ES requires it)
#   - fail if the smoke logged a SKIP: on this host every ES
#     precondition holds, so a skip means the setup broke
#
# Usage:
#   tools/macos-tart-vm/run-es-smoke.sh                     # default smoke
#   tools/macos-tart-vm/run-es-smoke.sh <smoke-rel>         # specific smoke
#   tools/macos-tart-vm/run-es-smoke.sh --user <smoke-rel>  # as the guest's
#                                                           # admin user, no sudo
#
# --user is for smokes that check the non-root fallback tier
# (fsevents-fallback-macos). Set SHIT_ES_ALLOW_SKIP=1 to accept a SKIP.
#
# Default smoke is tests/smoke/es-unlink-undo-macos.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

AS_USER=0
if [ "${1:-}" = "--user" ]; then
    AS_USER=1
    shift
fi
SMOKE="${1:-tests/smoke/es-unlink-undo-macos.sh}"

if [ ! -f "${REPO_ROOT}/${SMOKE}" ]; then
    echo "smoke script not found: ${REPO_ROOT}/${SMOKE}" >&2
    exit 2
fi

echo "[run-es-smoke] building + signing shit-helper (release)"
"${SCRIPT_DIR}/build-signed.sh" --release

echo "[run-es-smoke] building shit + shitd (release, unsigned — no ES needed)"
"${SCRIPT_DIR}/ssh.sh" '
    set -euo pipefail
    cd shit
    source $HOME/.cargo/env
    cargo build --release -p shit -p shitd 2>&1 | tail -3
'

# Verify the helper IS signed with the ES entitlement before we
# bother running the smoke. Catches a stale build-signed.sh skip.
echo "[run-es-smoke] verifying helper entitlement"
"${SCRIPT_DIR}/ssh.sh" '
    set -euo pipefail
    cd shit
    codesign -d --entitlements - target/release/shit-helper 2>&1 \
        | grep -q "com.apple.developer.endpoint-security.client" \
        || { echo "helper missing ES entitlement" >&2; exit 1; }
'

LOG="$(mktemp -t run-es-smoke)"
trap 'rm -f "${LOG}"' EXIT
if [ "${AS_USER}" -eq 1 ]; then
    echo "[run-es-smoke] running ${SMOKE} (as admin)"
    REMOTE="cd shit && SHIT_SMOKE_BIN_DIR=\$(pwd)/target/release ${SMOKE}"
else
    echo "[run-es-smoke] running ${SMOKE} (as root)"
    REMOTE="cd shit && sudo SHIT_SMOKE_BIN_DIR=\$(pwd)/target/release ${SMOKE}"
fi
set +e
"${SCRIPT_DIR}/ssh.sh" "${REMOTE}" 2>&1 | tee "${LOG}"
rc="${PIPESTATUS[0]}"
set -e
if [ "${rc}" -ne 0 ]; then
    exit "${rc}"
fi
if grep -q '\] SKIP:' "${LOG}" && [ "${SHIT_ES_ALLOW_SKIP:-0}" != "1" ]; then
    echo "[run-es-smoke] ${SMOKE} skipped on the ES host; treating as failure" >&2
    exit 1
fi
