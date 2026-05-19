#!/bin/sh
# Install + enable Tailscale on the FreeBSD VM. Run from the host:
#   tools/freebsd-vm/install-tailscale.sh
#
# Network model: Tailscale runs *inside* the VM; the userspace
# WireGuard tunnel connects out through QEMU's user-mode NAT — no
# host configuration needed. After auth, the VM gets a tailnet IP +
# MagicDNS name reachable from anywhere on your tailnet (the same
# flow you use to reach `hasu`).
#
# The auth step is interactive: `tailscale up` prints a URL you open
# in a browser to log in. This script forwards stdin/stdout through
# SSH so the URL lands in your terminal.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

if ! [ -f work/vm.pid ] || ! kill -0 "$(cat work/vm.pid)" 2>/dev/null; then
    echo "FreeBSD VM not running. Run tools/freebsd-vm/boot.sh first." >&2
    exit 1
fi

echo "[1/4] pkg install -y tailscale"
./ssh.sh "sudo pkg install -y tailscale"

echo "[2/4] enable tailscaled at boot"
./ssh.sh "sudo sysrc tailscaled_enable=YES"

echo "[3/4] start tailscaled"
./ssh.sh "sudo service tailscaled start || sudo service tailscaled restart"

echo "[4/4] tailscale up — open the printed URL in your browser to authenticate"
# --ssh enables Tailscale SSH so you can reach the VM by tailnet name
# without managing a separate authorized_keys file.
./ssh.sh -t "sudo tailscale up --ssh"

echo
echo "Done. Check status with:"
echo "  tools/freebsd-vm/ssh.sh 'tailscale status'"
echo "Then on the host, the VM is reachable as:"
echo "  ssh freebsd@<tailnet-name>   # see tailscale status output"
