#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Boot a tart-managed macOS VM for M03+ ES dev. Idempotent: clones
# the base image if no VM exists, starts the VM headless, prints the
# assigned IP when ready.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
mkdir -p "${WORK_DIR}"

: "${SHIT_TART_VM:=shit-m03}"
: "${SHIT_TART_BASE:=ghcr.io/cirruslabs/macos-sonoma-base:latest}"
: "${SHIT_TART_DISK_GB:=80}"

if ! command -v tart >/dev/null 2>&1; then
    echo "tart not installed; run:  brew install cirruslabs/cli/tart" >&2
    exit 1
fi

if [ "$(uname -m)" != "arm64" ]; then
    echo "tart requires Apple Silicon (uname -m == arm64); got $(uname -m)" >&2
    exit 1
fi

# 1. Clone the base image into our VM name if it doesn't exist.
if ! tart list | awk '{print $2}' | grep -qxF "${SHIT_TART_VM}"; then
    echo "[boot] cloning ${SHIT_TART_BASE} -> ${SHIT_TART_VM}"
    tart clone "${SHIT_TART_BASE}" "${SHIT_TART_VM}"
    tart set "${SHIT_TART_VM}" --disk-size "${SHIT_TART_DISK_GB}"
else
    echo "[boot] ${SHIT_TART_VM} already exists; skipping clone"
fi

# 2. Generate an SSH key for this VM if we haven't already. The key
# stays per-VM and per-tooling-dir, never touches the user's
# ~/.ssh/.
SSH_KEY="${WORK_DIR}/id_ed25519"
if [ ! -f "${SSH_KEY}" ]; then
    echo "[boot] generating SSH key at ${SSH_KEY}"
    ssh-keygen -t ed25519 -N "" -C "shit-tart-vm" -f "${SSH_KEY}" >/dev/null
fi

# 3. Boot in the background. Tart's --no-graphics keeps the VM
# headless; the script returns once the VM has a reachable IP.
if pgrep -f "tart run.* ${SHIT_TART_VM}" >/dev/null; then
    echo "[boot] ${SHIT_TART_VM} already running"
else
    echo "[boot] starting ${SHIT_TART_VM} headless"
    nohup tart run --no-graphics "${SHIT_TART_VM}" \
        >"${WORK_DIR}/tart-run.log" 2>&1 &
    echo $! >"${WORK_DIR}/tart-run.pid"
fi

# 4. Wait for the VM to acquire an IP. Boot takes ~30s on a warm
# clone, ~5 min on first-ever boot (Setup Assistant).
echo -n "[boot] waiting for VM IP "
for i in $(seq 1 300); do
    ip="$(tart ip "${SHIT_TART_VM}" 2>/dev/null || true)"
    if [ -n "${ip}" ]; then
        echo
        echo "[boot] ${SHIT_TART_VM} reachable at ${ip}"
        echo "${ip}" >"${WORK_DIR}/vm.ip"
        break
    fi
    echo -n "."
    sleep 1
    if [ "${i}" -eq 300 ]; then
        echo
        echo "[boot] ${SHIT_TART_VM} never got an IP; check ${WORK_DIR}/tart-run.log" >&2
        exit 1
    fi
done

# 5. Wait for sshd. Default Cirrus base images come with sshd enabled
# + admin/admin login. We don't add the SSH key on first boot —
# that's the user's job (see audit doc setup steps). After they've
# added it, subsequent boots get passwordless.
echo -n "[boot] waiting for sshd at ${ip} "
for i in $(seq 1 120); do
    if nc -z -G 2 "${ip}" 22 2>/dev/null; then
        echo
        echo "[boot] sshd up on ${ip}:22"
        break
    fi
    echo -n "."
    sleep 1
    if [ "${i}" -eq 120 ]; then
        echo
        echo "[boot] sshd never came up on ${ip}:22" >&2
        exit 1
    fi
done

echo
echo "ready:"
echo "  VM:   ${SHIT_TART_VM}"
echo "  IP:   ${ip}"
echo "  SSH:  tools/macos-tart-vm/ssh.sh    # wrapped"
echo "  key:  ${SSH_KEY}.pub  (add to admin@${ip} ~/.ssh/authorized_keys)"
echo
echo "next steps:"
echo "  1. ssh-copy-id -i ${SSH_KEY}.pub -p 22 admin@${ip}"
echo "     (password: admin; only needed once per VM)"
echo "  2. tools/macos-tart-vm/sync.sh"
echo "  3. tools/macos-tart-vm/ssh.sh 'csrutil status'"
echo "     (expect: 'disabled' — see audit doc for one-time setup)"
