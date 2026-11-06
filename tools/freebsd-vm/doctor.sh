#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build `shit` inside the VM and run `shit doctor`. The first
# build pulls crates from crates.io (`--locked` so we don't churn
# lockfile versions).
#
# Output is captured to stdout — append to .docs/audits/bsd-coverage.md
# as the first runtime sanity check.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

ssh "${SSH_OPTS[@]}" freebsd@127.0.0.1 bash -s <<'REMOTE_SCRIPT'
set -euo pipefail
export PATH="${HOME}/.cargo/bin:/usr/local/bin:${PATH}"
cd ~/shit
if ! command -v cargo >/dev/null; then
  echo "[fbsd-vm-remote] rust not installed; rerun provision.sh" >&2
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
