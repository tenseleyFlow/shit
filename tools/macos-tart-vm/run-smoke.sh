#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Sync + ssh + run a smoke script on the tart VM. Output streams
# back to host stdout. Failures propagate via exit code so CI /
# wrapper scripts see them.
#
# Usage:  tools/macos-tart-vm/run-smoke.sh <smoke-script>
# Example: tools/macos-tart-vm/run-smoke.sh tests/smoke/fsevents-fallback-macos.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <smoke-script-relative-to-repo-root> [args...]" >&2
    echo "example: $0 tests/smoke/fsevents-fallback-macos.sh" >&2
    exit 2
fi

SMOKE="$1"
shift

if [ ! -f "${REPO_ROOT}/${SMOKE}" ]; then
    echo "smoke script not found: ${REPO_ROOT}/${SMOKE}" >&2
    exit 2
fi

echo "[run-smoke] syncing repo to VM"
"${SCRIPT_DIR}/sync.sh"

echo "[run-smoke] building release binaries on VM (idempotent)"
"${SCRIPT_DIR}/ssh.sh" 'cd shit && cargo build --release -p shit -p shitd -p shit-helper 2>&1 | tail -3'

echo "[run-smoke] running ${SMOKE}"
"${SCRIPT_DIR}/ssh.sh" "cd shit && ${SMOKE} $*"
