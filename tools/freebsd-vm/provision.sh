#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provision a FreeBSD 14 arm64 VM under qemu-system-aarch64.
# Designed for macOS Apple Silicon hosts. Idempotent: re-running
# from a clean tree is the same as running for the first time.
#
# Standing rule reminder (see DEFERRED-RUNTIME.md): this is the only
# sanctioned path for exercising shit's BSD runtime tier. Don't run
# helper binaries with elevated caps on the developer workstation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
mkdir -p "${WORK_DIR}"

# FreeBSD release / arch / variant. Bump when the project moves to a
# newer FreeBSD; keep the URL pinned for reproducibility.
#
# We deliberately use the BASIC-CLOUDINIT-zfs variant. Two reasons:
# 1. CLOUDINIT means cloud-init is pre-installed — our cidata.iso
#    works on first boot with no manual intervention.
# 2. zfs root unlocks the ZFS-tier code path during `shit doctor`
#    validation. UFS would only exercise the kqueue-only tier.
FBSD_VERSION="${FBSD_VERSION:-14.4}"
FBSD_ARCH="${FBSD_ARCH:-aarch64}"
FBSD_VARIANT="${FBSD_VARIANT:-BASIC-CLOUDINIT-zfs}"
FBSD_IMAGE_NAME="FreeBSD-${FBSD_VERSION}-RELEASE-arm64-${FBSD_ARCH}-${FBSD_VARIANT}.qcow2.xz"
FBSD_IMAGE_URL="https://download.freebsd.org/releases/VM-IMAGES/${FBSD_VERSION}-RELEASE/${FBSD_ARCH}/Latest/${FBSD_IMAGE_NAME}"

DISK_QCOW2="${WORK_DIR}/freebsd14-arm64.qcow2"
SEED_ISO="${WORK_DIR}/cidata.iso"
SSH_KEY="${WORK_DIR}/id_ed25519"
EFI_VARS="${WORK_DIR}/efivars.fd"
EFI_FIRMWARE_CANDIDATES=(
  "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
  "/usr/local/share/qemu/edk2-aarch64-code.fd"
)

log() {
  printf '[fbsd-vm] %s\n' "$*" >&2
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
require xz
require ssh-keygen
if ! command -v mkisofs >/dev/null 2>&1 && ! command -v hdiutil >/dev/null 2>&1; then
  log "need mkisofs or hdiutil to build cidata.iso (install cdrtools via brew, or use macOS hdiutil)"
  exit 2
fi

# 1. Download base image if not present.
if [[ ! -f "${WORK_DIR}/${FBSD_IMAGE_NAME}" ]]; then
  log "downloading ${FBSD_IMAGE_NAME} (one-off, ~500 MB)"
  curl -fL --progress-bar -o "${WORK_DIR}/${FBSD_IMAGE_NAME}.part" "${FBSD_IMAGE_URL}"
  mv "${WORK_DIR}/${FBSD_IMAGE_NAME}.part" "${WORK_DIR}/${FBSD_IMAGE_NAME}"
else
  log "base image already present: ${FBSD_IMAGE_NAME}"
fi

# 2. Decompress into the working qcow2 (idempotent: bail if the
# disk already exists — call teardown.sh first to redo).
if [[ ! -f "${DISK_QCOW2}" ]]; then
  log "decompressing base image -> ${DISK_QCOW2}"
  xz -dc "${WORK_DIR}/${FBSD_IMAGE_NAME}" > "${DISK_QCOW2}.tmp"
  mv "${DISK_QCOW2}.tmp" "${DISK_QCOW2}"
  log "resizing disk to 20 GB to fit rust toolchain + build dirs"
  qemu-img resize "${DISK_QCOW2}" 20G
else
  log "working disk already present: ${DISK_QCOW2}"
fi

# 3. Generate a host-only SSH keypair if missing.
if [[ ! -f "${SSH_KEY}" ]]; then
  log "generating SSH keypair (VM-only, never leaves work/)"
  ssh-keygen -q -t ed25519 -N '' -C 'shit-freebsd-vm' -f "${SSH_KEY}"
fi

# 4. Build a cidata ISO with cloud-init user-data that:
#    - sets root password to a known value (VM-only),
#    - installs our SSH key on the freebsd user,
#    - enables sshd,
#    - tells the OS to extend the root partition to the new disk size.
SSH_PUB="$(cat "${SSH_KEY}.pub")"
TMP_USER_DATA="$(mktemp -t fbsd-userdata)"
TMP_META_DATA="$(mktemp -t fbsd-metadata)"
trap 'rm -f "${TMP_USER_DATA}" "${TMP_META_DATA}"' EXIT

cat > "${TMP_META_DATA}" <<EOF
instance-id: shit-freebsd-vm-$(date +%s)
local-hostname: shit-fbsd
EOF

cat > "${TMP_USER_DATA}" <<EOF
#cloud-config
users:
  - name: freebsd
    groups: [wheel]
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${SSH_PUB}
chpasswd:
  list: |
    root:shit-vm
  expire: false
ssh_pwauth: true
disable_root: false
package_update: true
packages:
  - rust
  - rsync
  - gmake
  - pkgconf
runcmd:
  - service sshd onestart || service sshd restart
  # The BASIC-CLOUDINIT-zfs image grows its zpool via cloud-init's
  # own growpart module when the disk is bigger than the image —
  # nothing to do manually here.
EOF

log "building cidata.iso"
if command -v mkisofs >/dev/null 2>&1; then
  mkisofs -quiet -output "${SEED_ISO}" -volid cidata -joliet -rock \
    "${TMP_USER_DATA}=user-data" "${TMP_META_DATA}=meta-data"
else
  # macOS-native fallback: hdiutil with -joliet
  STAGE_DIR="$(mktemp -d -t fbsd-cidata)"
  cp "${TMP_USER_DATA}" "${STAGE_DIR}/user-data"
  cp "${TMP_META_DATA}" "${STAGE_DIR}/meta-data"
  hdiutil makehybrid -quiet -o "${SEED_ISO}" -hfs -joliet -iso \
    -default-volume-name cidata "${STAGE_DIR}"
  rm -rf "${STAGE_DIR}"
fi

# 5. EFI firmware: qemu's aarch64 needs the edk2 binary blob. Homebrew
# ships it with qemu under share/qemu/.
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

# 6. EFI vars (writable) — one-off init from a 64MB zero blob.
if [[ ! -f "${EFI_VARS}" ]]; then
  log "initializing EFI vars store"
  dd if=/dev/zero of="${EFI_VARS}" bs=1M count=64 2>/dev/null
fi

# 7. First boot: run with no graphical display, attach the cidata ISO,
# wait for cloud-init to complete (sshd up + key installed).
log "first boot — cloud-init runs once (~3-5 min depending on pkg install)"
log "  (press Ctrl-A then X to abort; serial log -> ${WORK_DIR}/vm.log)"

QEMU_PIDFILE="${WORK_DIR}/vm.pid"
QEMU_LOG="${WORK_DIR}/vm.log"

qemu-system-aarch64 \
  -name "shit-freebsd-vm" \
  -machine virt,accel=hvf \
  -cpu host \
  -smp 2 \
  -m 2048 \
  -drive if=pflash,format=raw,readonly=on,file="${EFI_FIRMWARE}" \
  -drive if=pflash,format=raw,file="${EFI_VARS}" \
  -drive if=virtio,format=qcow2,file="${DISK_QCOW2}" \
  -drive if=virtio,format=raw,file="${SEED_ISO}",readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2225-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic \
  -serial file:"${QEMU_LOG}" \
  -pidfile "${QEMU_PIDFILE}" \
  -monitor none \
  -daemonize

log "VM booting. SSH will come up at 127.0.0.1:2225 once cloud-init finishes."
log "test with: tools/freebsd-vm/ssh.sh true"
log "follow boot: tail -f ${QEMU_LOG}"
