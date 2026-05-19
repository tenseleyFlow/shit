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
# Expects the smoke under tests/smoke/<name>.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

SMOKE_NAME="${1:?usage: run-smoke.sh <smoke-script-name>}"

# Sync first so the VM has the latest sources + smoke script.
bash "${SCRIPT_DIR}/sync.sh" >/dev/null

ssh \
  -p 2225 \
  -i "${SSH_KEY}" \
  -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
  -o "StrictHostKeyChecking=accept-new" \
  -o "IdentitiesOnly=yes" \
  freebsd@127.0.0.1 \
  "SMOKE_NAME=${SMOKE_NAME} bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail
cd ~/shit

# Build release binaries we need for the smoke. Cached after the first
# pass; ~30s incremental after a code change.
echo "[fbsd-vm-remote] cargo build --release -p shit -p shitd -p shit-helper"
cargo build --release -p shit -p shitd -p shit-helper --locked 2>&1 | tail -5

# The smoke script auto-discovers SHIT_SMOKE_BIN_DIR=${SHIT_REPO_ROOT}/target/release.
SMOKE_PATH="tests/smoke/${SMOKE_NAME}"
if [ ! -f "${SMOKE_PATH}" ]; then
  echo "[fbsd-vm-remote] smoke script missing: ${SMOKE_PATH}" >&2
  exit 2
fi

bash "${SMOKE_PATH}"
REMOTE_SCRIPT
