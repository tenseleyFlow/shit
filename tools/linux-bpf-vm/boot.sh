#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Boot the provisioned Linux VM headless. cidata.iso is not
# attached — cloud-init already ran during provision.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"

UBUNTU_RELEASE="${UBUNTU_RELEASE:-noble}"
DISK_QCOW2="${WORK_DIR}/ubuntu-${UBUNTU_RELEASE}-arm64.qcow2"
EFI_VARS="${WORK_DIR}/efivars.fd"
EFI_FIRMWARE_CANDIDATES=(
  "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
  "/usr/local/share/qemu/edk2-aarch64-code.fd"
)
QEMU_PIDFILE="${WORK_DIR}/vm.pid"
QEMU_LOG="${WORK_DIR}/vm.log"

log() { printf '[linux-bpf-vm] %s\n' "$*" >&2; }

if [[ ! -f "${DISK_QCOW2}" ]]; then
  log "no disk image — run provision.sh first"
  exit 2
fi

if [[ -f "${QEMU_PIDFILE}" ]] && kill -0 "$(cat "${QEMU_PIDFILE}")" 2>/dev/null; then
  log "VM already running (pid $(cat "${QEMU_PIDFILE}"))"
  exit 0
fi

EFI_FIRMWARE=""
for candidate in "${EFI_FIRMWARE_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    EFI_FIRMWARE="${candidate}"
    break
  fi
done
if [[ -z "${EFI_FIRMWARE}" ]]; then
  log "edk2-aarch64-code.fd not found; install qemu via brew"
  exit 2
fi

qemu-system-aarch64 \
  -name "shit-linux-bpf-vm" \
  -machine virt,accel=hvf \
  -cpu host \
  -smp 4 \
  -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file="${EFI_FIRMWARE}" \
  -drive if=pflash,format=raw,file="${EFI_VARS}" \
  -drive if=virtio,format=qcow2,file="${DISK_QCOW2}" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2226-:22 \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -serial file:"${QEMU_LOG}" \
  -pidfile "${QEMU_PIDFILE}" \
  -monitor none \
  -daemonize

log "VM up at 127.0.0.1:2226 (pid $(cat "${QEMU_PIDFILE}"))"
