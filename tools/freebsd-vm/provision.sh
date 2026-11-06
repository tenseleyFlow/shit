#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provision a FreeBSD 14 VM under qemu. On an x86_64 Linux host this
# is an amd64 guest under KVM; on Apple Silicon it is an arm64 guest
# under HVF (see common.sh). Idempotent: re-running from a clean tree
# is the same as running for the first time.
#
# Standing rule reminder (see DEFERRED-RUNTIME.md): this is the only
# sanctioned path for exercising shit's BSD runtime tier. Don't run
# helper binaries with elevated caps on the developer workstation.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require "${QEMU_BIN}"
require qemu-img
require curl
require xz
require ssh-keygen
ISO_TOOL=""
for t in mkisofs genisoimage xorriso hdiutil; do
  if command -v "${t}" >/dev/null 2>&1; then
    ISO_TOOL="${t}"
    break
  fi
done
if [[ -z "${ISO_TOOL}" ]]; then
  log "need mkisofs, genisoimage, xorriso or hdiutil to build cidata.iso"
  exit 2
fi

sha512_of() {
  if command -v sha512sum >/dev/null 2>&1; then
    sha512sum "$1" | awk '{print $1}'
  else
    shasum -a 512 "$1" | awk '{print $1}'
  fi
}

if vm_running; then
  log "VM already running (pid $(cat "${QEMU_PIDFILE}")); run teardown.sh first"
  exit 2
fi

# 1. Download the base image and verify it against the release
# CHECKSUM.SHA512 before anything reads it.
mkdir -p "${DOWNLOAD_DIR}"
IMAGE_PATH="${DOWNLOAD_DIR}/${FBSD_IMAGE_NAME}"
log "fetching ${FBSD_CHECKSUM_URL}"
curl -fsSL -o "${DOWNLOAD_DIR}/CHECKSUM.SHA512" "${FBSD_CHECKSUM_URL}"
EXPECTED_SHA="$(sed -n "s/^SHA512 (${FBSD_IMAGE_NAME}) = //p" "${DOWNLOAD_DIR}/CHECKSUM.SHA512")"
if [[ -z "${EXPECTED_SHA}" ]]; then
  log "no SHA512 line for ${FBSD_IMAGE_NAME} in CHECKSUM.SHA512"
  exit 2
fi
if [[ ! -f "${IMAGE_PATH}" ]]; then
  log "downloading ${FBSD_IMAGE_NAME} (one-off, ~650 MB)"
  curl -fL --progress-bar -C - -o "${IMAGE_PATH}.part" "${FBSD_IMAGE_URL}"
  mv "${IMAGE_PATH}.part" "${IMAGE_PATH}"
else
  log "base image already present: ${FBSD_IMAGE_NAME}"
fi
ACTUAL_SHA="$(sha512_of "${IMAGE_PATH}")"
if [[ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]]; then
  log "SHA512 mismatch for ${IMAGE_PATH}; deleting it"
  log "  expected ${EXPECTED_SHA}"
  log "  actual   ${ACTUAL_SHA}"
  rm -f "${IMAGE_PATH}"
  exit 1
fi
log "SHA512 verified"

# 2. Decompress into the working qcow2 (bail if the disk already
# exists; call teardown.sh first to redo).
if [[ ! -f "${DISK_QCOW2}" ]]; then
  log "decompressing base image -> ${DISK_QCOW2}"
  xz -dc "${IMAGE_PATH}" >"${DISK_QCOW2}.tmp"
  mv "${DISK_QCOW2}.tmp" "${DISK_QCOW2}"
  DISK_SIZE=20G
  [[ "${FBSD_VM_ARCH}" == amd64 ]] && DISK_SIZE=40G
  log "resizing disk to ${DISK_SIZE} to fit rust toolchain + build dirs"
  qemu-img resize -q "${DISK_QCOW2}" "${DISK_SIZE}"
else
  log "working disk already present: ${DISK_QCOW2}"
fi

# The amd64 guest gets a blank second disk; guest-setup.sh makes it
# the `shitzfs` pool so ZFS runs alongside the UFS root.
if [[ "${FBSD_VM_ARCH}" == amd64 && ! -f "${ZPOOL_QCOW2}" ]]; then
  log "creating 8 GB zpool disk -> ${ZPOOL_QCOW2}"
  qemu-img create -q -f qcow2 "${ZPOOL_QCOW2}" 8G
fi

# 3. Generate a host-only SSH keypair if missing.
if [[ ! -f "${SSH_KEY}" ]]; then
  log "generating SSH keypair (VM-only, never leaves the work dir)"
  ssh-keygen -q -t ed25519 -N '' -C 'shit-freebsd-vm' -f "${SSH_KEY}"
fi

# 4. Build a cidata ISO. FreeBSD 14's CLOUDINIT images run nuageinit,
# which reads a subset of cloud-config: users with keys, packages,
# and runcmd. The amd64 path keeps it minimal (user, key, sudo) and
# leaves toolchain setup to guest-setup.sh over ssh, where failures
# are visible on the host.
SSH_PUB="$(cat "${SSH_KEY}.pub")"
STAGE_DIR="${WORK_DIR}/cidata-stage"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"
trap 'rm -rf "${STAGE_DIR}"' EXIT

cat >"${STAGE_DIR}/meta-data" <<EOF
instance-id: shit-freebsd-vm-$(date +%s)
local-hostname: shit-fbsd
EOF

if [[ "${FBSD_VM_ARCH}" == amd64 ]]; then
  cat >"${STAGE_DIR}/user-data" <<EOF
#cloud-config
users:
  - name: freebsd
    gecos: shit VM user
    groups: wheel
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${SSH_PUB}
ssh_pwauth: false
packages:
  - sudo
runcmd:
  - mkdir -p /usr/local/etc/sudoers.d
  - echo 'freebsd ALL=(ALL) NOPASSWD:ALL' > /usr/local/etc/sudoers.d/freebsd
  - chmod 0440 /usr/local/etc/sudoers.d/freebsd
  - sysrc sshd_enable=YES
  - service sshd onestart || service sshd restart
EOF
else
  cat >"${STAGE_DIR}/user-data" <<EOF
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
fi

log "building cidata.iso with ${ISO_TOOL}"
rm -f "${SEED_ISO}"
case "${ISO_TOOL}" in
  mkisofs | genisoimage)
    "${ISO_TOOL}" -quiet -output "${SEED_ISO}" -volid cidata -joliet -rock \
      "${STAGE_DIR}/user-data" "${STAGE_DIR}/meta-data"
    ;;
  xorriso)
    xorriso -as mkisofs -quiet -output "${SEED_ISO}" -volid cidata -joliet -rock \
      "${STAGE_DIR}/user-data" "${STAGE_DIR}/meta-data"
    ;;
  hdiutil)
    hdiutil makehybrid -quiet -o "${SEED_ISO}" -hfs -joliet -iso \
      -default-volume-name cidata "${STAGE_DIR}"
    ;;
esac

# 5. EFI vars (aarch64 only): one-off init from a 64MB zero blob.
if [[ "${FBSD_VM_ARCH}" == aarch64 && ! -f "${EFI_VARS}" ]]; then
  log "initializing EFI vars store"
  dd if=/dev/zero of="${EFI_VARS}" bs=1M count=64 2>/dev/null
fi

# 6. First boot with the seed attached.
log "first boot (${FBSD_VM_ARCH}, ${QEMU_BIN}); serial log -> ${QEMU_LOG}"
rm -f "${QEMU_LOG}"
build_qemu_args "${SEED_ISO}"
BOOT_START=${SECONDS}
"${QEMU_BIN}" "${QEMU_ARGS[@]}"

if [[ "${FBSD_VM_ARCH}" == aarch64 && "${FBSD_VM_GUEST_SETUP:-0}" != 1 ]]; then
  # The Mac path installs pkg rust through cloud-init and stops here.
  log "VM booting. SSH will come up at 127.0.0.1:${SSH_PORT} once cloud-init finishes."
  log "test with: tools/freebsd-vm/ssh.sh true"
  log "follow boot: tail -f ${QEMU_LOG}"
  exit 0
fi

log "waiting for sshd + key (nuageinit first boot)"
wait_for_ssh 900
log "ssh up after $((SECONDS - BOOT_START))s"

# 7. Guest setup over ssh: packages, rustup 1.88, doas, zpool.
SETUP_START=${SECONDS}
ssh "${SSH_OPTS[@]}" freebsd@127.0.0.1 \
  "FBSD_VM_ARCH=${FBSD_VM_ARCH} sh -s" <"${FBSD_VM_SCRIPT_DIR}/guest-setup.sh"
log "guest setup done in $((SECONDS - SETUP_START))s"
log "VM ready at 127.0.0.1:${SSH_PORT}; next: sync.sh, run-smoke.sh <name>"
