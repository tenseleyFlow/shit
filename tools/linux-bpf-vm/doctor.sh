#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build `shit` inside the VM, run `shit doctor`, and run a separate
# Linux-specific LSM probe smoke. Output captured to stdout — append
# to .docs/audits/linux-bpf-vm-doctor.md as the first runtime
# sanity check on the Linux BPF-LSM tier.
#
# Standing-rule reminder: this is a *read-only* probe surface. The
# helper binary is built but NOT executed with elevated capabilities
# here. Loading an actual LSM probe is DR-01..DR-04 — gated on at
# least one clean doctor run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

ssh \
  -p 2226 \
  -i "${SSH_KEY}" \
  -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
  -o "StrictHostKeyChecking=accept-new" \
  -o "IdentitiesOnly=yes" \
  ubuntu@127.0.0.1 <<'REMOTE_SCRIPT'
set -euo pipefail
# rustup installs cargo at ~/.cargo/bin/cargo for the ubuntu user;
# add it to PATH for this session.
export PATH="$HOME/.cargo/bin:$PATH"
cd ~/shit
if ! command -v cargo >/dev/null; then
  echo "[linux-vm-remote] rust not installed — cloud-init should have done this" >&2
  exit 2
fi
echo "[linux-vm-remote] os: $(uname -a)"
echo "[linux-vm-remote] rustc: $(rustc --version)"
echo "[linux-vm-remote] cargo: $(cargo --version)"
echo "[linux-vm-remote] uname -m: $(uname -m)"

echo "----- LSM stack -----"
if [[ -r /sys/kernel/security/lsm ]]; then
  cat /sys/kernel/security/lsm
else
  echo "/sys/kernel/security/lsm not readable (securityfs not mounted?)"
fi

echo "----- bpftool feature probe (subset) -----"
if command -v bpftool >/dev/null 2>&1; then
  sudo bpftool feature probe kernel 2>/dev/null | grep -E "BPF_PROG_TYPE_LSM|HAVE_BTF" || true
else
  echo "bpftool not installed"
fi

echo "----- shit build -----"
# Build the CLI for `shit doctor`. The helper is built but its
# privileged sidecar is NOT spawned here — that's separate, gated
# on this run reporting OK first.
cargo build --release -p shit -p shit-helper --locked 2>&1 | tail -5

echo "----- shit doctor output -----"
./target/release/shit doctor || true
echo "----- end -----"
REMOTE_SCRIPT
