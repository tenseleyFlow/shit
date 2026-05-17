#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provision an Ubuntu 24.04 (Noble) arm64 VM under qemu-system-aarch64
# for the Linux BPF-LSM validation surface. Designed for macOS Apple
# Silicon hosts. Idempotent: re-running from a clean tree is the same
# as running for the first time.
#
# Standing-rule reminder (see DEFERRED-RUNTIME.md): this is the only
# sanctioned path for first-attempt exercise of the Linux LSM tier
# (DR-01..DR-04). Do not run helper binaries with elevated caps on
# the developer workstation or on hasu until this VM is green for
# at least three full cycles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
mkdir -p "${WORK_DIR}"

# Ubuntu release / arch. Noble (24.04 LTS) — kernel 6.8 baseline ships
# with CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y. Cloud images live at
# https://cloud-images.ubuntu.com/.
UBUNTU_RELEASE="${UBUNTU_RELEASE:-noble}"
UBUNTU_IMAGE_NAME="${UBUNTU_RELEASE}-server-cloudimg-arm64.img"
UBUNTU_IMAGE_URL="https://cloud-images.ubuntu.com/${UBUNTU_RELEASE}/current/${UBUNTU_IMAGE_NAME}"

DISK_QCOW2="${WORK_DIR}/ubuntu-${UBUNTU_RELEASE}-arm64.qcow2"
SEED_ISO="${WORK_DIR}/cidata.iso"
SSH_KEY="${WORK_DIR}/id_ed25519"
EFI_VARS="${WORK_DIR}/efivars.fd"
EFI_FIRMWARE_CANDIDATES=(
  "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
  "/usr/local/share/qemu/edk2-aarch64-code.fd"
)

log() {
  printf '[linux-bpf-vm] %s\n' "$*" >&2
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "missing dependency: $1"
    exit 2
  fi
}

require qemu-system-aarch64
require qemu-img
require curl
require ssh-keygen
if ! command -v mkisofs >/dev/null 2>&1 && ! command -v hdiutil >/dev/null 2>&1; then
  log "need mkisofs or hdiutil to build cidata.iso (install cdrtools via brew, or use macOS hdiutil)"
  exit 2
fi

# 1. Download base image if not present.
if [[ ! -f "${WORK_DIR}/${UBUNTU_IMAGE_NAME}" ]]; then
  log "downloading ${UBUNTU_IMAGE_NAME} (one-off, ~700 MB)"
  curl -fL --progress-bar -o "${WORK_DIR}/${UBUNTU_IMAGE_NAME}.part" "${UBUNTU_IMAGE_URL}"
  mv "${WORK_DIR}/${UBUNTU_IMAGE_NAME}.part" "${WORK_DIR}/${UBUNTU_IMAGE_NAME}"
else
  log "base image already present: ${UBUNTU_IMAGE_NAME}"
fi

# 2. Make the working qcow2 (idempotent: bail if present — call
# teardown.sh first to redo).
if [[ ! -f "${DISK_QCOW2}" ]]; then
  log "copying base image -> ${DISK_QCOW2}"
  # cp(1) preserves sparseness on qcow2.
  cp "${WORK_DIR}/${UBUNTU_IMAGE_NAME}" "${DISK_QCOW2}.tmp"
  mv "${DISK_QCOW2}.tmp" "${DISK_QCOW2}"
  log "resizing disk to 20 GB to fit rust toolchain + bpf build deps + build dirs"
  qemu-img resize "${DISK_QCOW2}" 20G
else
  log "working disk already present: ${DISK_QCOW2}"
fi

# 3. Generate a host-only SSH keypair if missing.
if [[ ! -f "${SSH_KEY}" ]]; then
  log "generating SSH keypair (VM-only, never leaves work/)"
  ssh-keygen -q -t ed25519 -N '' -C 'shit-linux-bpf-vm' -f "${SSH_KEY}"
fi

# 4. Build cidata ISO with cloud-init user-data that:
#    - installs our SSH key on the ubuntu user,
#    - installs rust + bpf userspace (clang, llvm, libbpf-dev, bpftool, linux-tools),
#    - appends `bpf` to the kernel lsm= cmdline via grub,
#    - reboots once so the LSM stack change takes effect.
SSH_PUB="$(cat "${SSH_KEY}.pub")"
TMP_USER_DATA="$(mktemp -t linux-userdata)"
TMP_META_DATA="$(mktemp -t linux-metadata)"
trap 'rm -f "${TMP_USER_DATA}" "${TMP_META_DATA}"' EXIT

cat > "${TMP_META_DATA}" <<EOF
instance-id: shit-linux-bpf-vm-$(date +%s)
local-hostname: shit-linux-bpf
EOF

cat > "${TMP_USER_DATA}" <<USERDATA_EOF
#cloud-config
users:
  - name: ubuntu
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${SSH_PUB}
ssh_pwauth: false
disable_root: false
package_update: true
package_upgrade: false
packages:
  - rsync
  - build-essential
  - pkg-config
  - clang
  - llvm
  - libelf-dev
  - libbpf-dev
  - libssl-dev
  - bpftool
  - linux-tools-common
  - curl
  - ca-certificates
runcmd:
  # Drop a grub.d override that sorts after Ubuntu's cloud-image
  # 50-cloudimg-settings.cfg (which clobbers GRUB_CMDLINE_LINUX_DEFAULT).
  # Without this the lsm= argument doesn't reach /proc/cmdline.
  - |
    cat > /etc/default/grub.d/99-shit-vm-lsm-bpf.cfg <<'GRUBCFG'
    GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=lockdown,yama,integrity,apparmor,bpf"
    GRUBCFG
    update-grub
  # Install rustup as the ubuntu user so MSRV >= 1.85 is satisfied
  # (the apt 'rustc' package on noble is 1.75, below our MSRV).
  - |
    su - ubuntu -c 'curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal'
  - touch /var/lib/cloud/instance/shit-vm-provisioned
  - shutdown -r +1 shit-linux-bpf-vm-reboot-for-lsm
USERDATA_EOF

log "building cidata.iso"
STAGE_DIR="$(mktemp -d -t linux-cidata)"
cp "${TMP_USER_DATA}" "${STAGE_DIR}/user-data"
cp "${TMP_META_DATA}" "${STAGE_DIR}/meta-data"
if command -v mkisofs >/dev/null 2>&1; then
  # cdrtools mkisofs: build from a staged directory (its argv-rename
  # syntax isn't compatible with the genisoimage `src=dest` form).
  mkisofs -quiet -output "${SEED_ISO}" -volid cidata -joliet -rock \
    "${STAGE_DIR}"
else
  hdiutil makehybrid -quiet -o "${SEED_ISO}" -hfs -joliet -iso \
    -default-volume-name cidata "${STAGE_DIR}"
fi
rm -rf "${STAGE_DIR}"

# 5. EFI firmware (same as the FreeBSD VM).
EFI_FIRMWARE=""
for candidate in "${EFI_FIRMWARE_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    EFI_FIRMWARE="${candidate}"
    break
  fi
done
if [[ -z "${EFI_FIRMWARE}" ]]; then
  log "edk2-aarch64-code.fd not found in homebrew share dir; install qemu via brew"
  exit 2
fi

if [[ ! -f "${EFI_VARS}" ]]; then
  log "initializing EFI vars store"
  dd if=/dev/zero of="${EFI_VARS}" bs=1M count=64 2>/dev/null
fi

# 6. First boot: run with no graphical display, attach cidata ISO,
# wait for cloud-init + reboot to complete. The script returns once
# qemu daemonizes; SSH won't be available until cloud-init finishes
# (~6-8 min — apt + grub + reboot).
log "first boot — cloud-init + apt + grub + reboot (~6-8 min)"
log "  (serial log -> ${WORK_DIR}/vm.log)"

QEMU_PIDFILE="${WORK_DIR}/vm.pid"
QEMU_LOG="${WORK_DIR}/vm.log"

qemu-system-aarch64 \
  -name "shit-linux-bpf-vm" \
  -machine virt,accel=hvf \
  -cpu host \
  -smp 4 \
  -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file="${EFI_FIRMWARE}" \
  -drive if=pflash,format=raw,file="${EFI_VARS}" \
  -drive if=virtio,format=qcow2,file="${DISK_QCOW2}" \
  -drive if=virtio,format=raw,file="${SEED_ISO}",readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2226-:22 \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -serial file:"${QEMU_LOG}" \
  -pidfile "${QEMU_PIDFILE}" \
  -monitor none \
  -daemonize

log "VM booting. SSH will come up at 127.0.0.1:2226 once cloud-init + reboot finish."
log "test with: tools/linux-bpf-vm/ssh.sh true"
log "follow boot: tail -f ${QEMU_LOG}"
