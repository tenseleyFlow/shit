#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build `shit` inside the VM and run `shit doctor`. The first
# build pulls crates from crates.io (cloud-init installed `rust`
# already; we add `--locked` so we don't churn lockfile versions).
#
# Output is captured to stdout — append to .docs/audits/bsd-coverage.md
# as the first runtime sanity check.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

ssh \
  -p 2225 \
  -i "${SSH_KEY}" \
  -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
  -o "StrictHostKeyChecking=accept-new" \
  -o "IdentitiesOnly=yes" \
  freebsd@127.0.0.1 <<'REMOTE_SCRIPT'
set -euo pipefail
cd ~/shit
if ! command -v cargo >/dev/null; then
  echo "[fbsd-vm-remote] rust not installed — cloud-init should have done this" >&2
  exit 2
fi
echo "[fbsd-vm-remote] os: $(uname -a)"
echo "[fbsd-vm-remote] rustc: $(rustc --version)"
echo "[fbsd-vm-remote] cargo: $(cargo --version)"
echo "[fbsd-vm-remote] uname -m: $(uname -m)"

# Build shit (the CLI binary) so doctor can run. The helper isn't
# strictly needed for stage 1 — doctor reads the bsd_probe from
# shit-capture directly.
cargo build --release -p shit --locked 2>&1 | tail -5

echo "----- shit doctor output -----"
./target/release/shit doctor || true
echo "----- end -----"
REMOTE_SCRIPT
