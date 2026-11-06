#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Run a smoke script inside the FreeBSD VM. Builds the workspace
# binaries (release profile) before invoking the script so binaries
# resolve to ${SHIT_SMOKE_BIN_DIR}/{shit,shitd,shit-helper}.
#
# Usage: run-smoke.sh <smoke-script-name>
#   e.g. ./tools/freebsd-vm/run-smoke.sh rm-undo-fbsd.sh
#
# Expects the smoke under tests/smoke/<name>. SMOKE_TMPDIR=/tmp/zfs
# runs the smoke's scratch tree on the amd64 guest's ZFS dataset
# instead of the UFS root.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

SMOKE_NAME="${1:?usage: run-smoke.sh <smoke-script-name>}"
SMOKE_TMPDIR="${SMOKE_TMPDIR:-/tmp}"

# Sync first so the VM has the latest sources + smoke script.
bash "${FBSD_VM_SCRIPT_DIR}/sync.sh" >/dev/null

ssh "${SSH_OPTS[@]}" freebsd@127.0.0.1 \
  "SMOKE_NAME=${SMOKE_NAME} SMOKE_TMPDIR=${SMOKE_TMPDIR} bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail
export PATH="${HOME}/.cargo/bin:/usr/local/bin:${PATH}"
cd ~/shit

# Build release binaries we need for the smoke. Cached after the first
# pass; ~30s incremental after a code change.
echo "[fbsd-vm-remote] cargo build --release -p shit -p shitd -p shit-helper -p shit-preload-shim"
cargo build --release -p shit -p shitd -p shit-helper -p shit-preload-shim --locked 2>&1 | tail -5

# The smoke script auto-discovers SHIT_SMOKE_BIN_DIR=${SHIT_REPO_ROOT}/target/release.
SMOKE_PATH="tests/smoke/${SMOKE_NAME}"
if [ ! -f "${SMOKE_PATH}" ]; then
  echo "[fbsd-vm-remote] smoke script missing: ${SMOKE_PATH}" >&2
  exit 2
fi

TMPDIR="${SMOKE_TMPDIR}" bash "${SMOKE_PATH}"
REMOTE_SCRIPT
