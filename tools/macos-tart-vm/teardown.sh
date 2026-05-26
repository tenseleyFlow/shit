#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tear down the tart-managed macOS VM. Idempotent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"

: "${SHIT_TART_VM:=shit-m03}"

# Stop the VM if it's running.
if pgrep -f "tart run.* ${SHIT_TART_VM}" >/dev/null; then
    echo "[teardown] stopping ${SHIT_TART_VM}"
    tart stop "${SHIT_TART_VM}" || true
fi

# Delete the VM clone. The base image stays cached.
if tart list | awk '{print $2}' | grep -qxF "${SHIT_TART_VM}"; then
    echo "[teardown] deleting ${SHIT_TART_VM} (base image stays cached)"
    tart delete "${SHIT_TART_VM}"
fi

# Clear per-VM state from work/. Keep the SSH key for the next run
# unless --wipe-key is passed.
if [ "${1:-}" = "--wipe-key" ]; then
    echo "[teardown] wiping per-VM SSH key from ${WORK_DIR}"
    rm -f "${WORK_DIR}/id_ed25519" "${WORK_DIR}/id_ed25519.pub"
fi
rm -f "${WORK_DIR}/known_hosts" "${WORK_DIR}/vm.ip" "${WORK_DIR}/tart-run.pid"

echo "[teardown] done. Base image still cached:"
tart list | grep cirruslabs/macos || true
