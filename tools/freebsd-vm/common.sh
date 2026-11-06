# SPDX-License-Identifier: AGPL-3.0-or-later
# shellcheck shell=bash disable=SC2034,SC2054
# (variables are consumed by the sourcing scripts; qemu args carry commas)
#
# Shared settings for the FreeBSD VM scripts. Sourced, not executed.
#
# Two guest/host pairs are supported:
#
#   amd64    qemu-system-x86_64, KVM on Linux (HVF on Intel macOS),
#            BASIC-CLOUDINIT-ufs image (same FS as the CI VM), plus a
#            second blank disk that guest-setup.sh turns into a zpool
#            for ZFS evidence.
#   aarch64  qemu-system-aarch64 with HVF on Apple Silicon,
#            BASIC-CLOUDINIT-zfs image, EFI firmware from Homebrew.
#
# The guest arch defaults from the host (`uname -m`). Override with
# FBSD_VM_ARCH=amd64|aarch64. FBSD_VM_WORK_DIR moves the disk images
# and keys out of the tree (default: tools/freebsd-vm/work/).

FBSD_VM_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${FBSD_VM_WORK_DIR:-${FBSD_VM_SCRIPT_DIR}/work}"
mkdir -p "${WORK_DIR}"

if [[ -z "${FBSD_VM_ARCH:-}" ]]; then
  case "$(uname -m)" in
    x86_64 | amd64) FBSD_VM_ARCH=amd64 ;;
    arm64 | aarch64) FBSD_VM_ARCH=aarch64 ;;
    *)
      printf '[fbsd-vm] unsupported host arch %s; set FBSD_VM_ARCH\n' "$(uname -m)" >&2
      exit 2
      ;;
  esac
fi

FBSD_VERSION="${FBSD_VERSION:-14.4}"
SSH_PORT="${FBSD_VM_SSH_PORT:-2225}"

case "${FBSD_VM_ARCH}" in
  amd64)
    QEMU_BIN=qemu-system-x86_64
    FBSD_VARIANT="${FBSD_VARIANT:-BASIC-CLOUDINIT-ufs}"
    FBSD_IMAGE_NAME="FreeBSD-${FBSD_VERSION}-RELEASE-amd64-${FBSD_VARIANT}.qcow2.xz"
    FBSD_IMAGE_DIR_URL="https://download.freebsd.org/releases/VM-IMAGES/${FBSD_VERSION}-RELEASE/amd64/Latest"
    DISK_QCOW2="${WORK_DIR}/freebsd14-amd64.qcow2"
    # A Linux host builds the workspace with 8 jobs comfortably.
    VM_SMP="${FBSD_VM_SMP:-8}"
    VM_MEM="${FBSD_VM_MEM:-8192}"
    ;;
  aarch64)
    QEMU_BIN=qemu-system-aarch64
    # zfs root unlocks the ZFS-tier code path during `shit doctor`
    # validation; CLOUDINIT means the cidata ISO works on first boot.
    FBSD_VARIANT="${FBSD_VARIANT:-BASIC-CLOUDINIT-zfs}"
    FBSD_IMAGE_NAME="FreeBSD-${FBSD_VERSION}-RELEASE-arm64-aarch64-${FBSD_VARIANT}.qcow2.xz"
    FBSD_IMAGE_DIR_URL="https://download.freebsd.org/releases/VM-IMAGES/${FBSD_VERSION}-RELEASE/aarch64/Latest"
    DISK_QCOW2="${WORK_DIR}/freebsd14-arm64.qcow2"
    VM_SMP="${FBSD_VM_SMP:-2}"
    VM_MEM="${FBSD_VM_MEM:-2048}"
    ;;
  *)
    printf '[fbsd-vm] FBSD_VM_ARCH must be amd64 or aarch64 (got %s)\n' "${FBSD_VM_ARCH}" >&2
    exit 2
    ;;
esac

# Downloads go in their own directory: they are untrusted until the
# SHA512 from the release CHECKSUM file matches.
DOWNLOAD_DIR="${WORK_DIR}/download"
FBSD_IMAGE_URL="${FBSD_IMAGE_DIR_URL}/${FBSD_IMAGE_NAME}"
FBSD_CHECKSUM_URL="${FBSD_IMAGE_DIR_URL}/CHECKSUM.SHA512"
ZPOOL_QCOW2="${WORK_DIR}/zpool-disk.qcow2"
SEED_ISO="${WORK_DIR}/cidata.iso"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"
EFI_VARS="${WORK_DIR}/efivars.fd"
QEMU_PIDFILE="${WORK_DIR}/vm.pid"
QEMU_LOG="${WORK_DIR}/vm.log"
EFI_FIRMWARE_CANDIDATES=(
  "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
  "/usr/local/share/qemu/edk2-aarch64-code.fd"
)

# One option array for ssh, scp and rsync -e: `-o Port=` works for
# all three, where ssh's `-p` and scp's `-P` differ.
SSH_OPTS=(
  -o "Port=${SSH_PORT}"
  -i "${SSH_KEY}"
  -o "UserKnownHostsFile=${KNOWN_HOSTS}"
  -o "StrictHostKeyChecking=accept-new"
  -o "IdentitiesOnly=yes"
  -o "LogLevel=ERROR"
)

log() {
  printf '[fbsd-vm] %s\n' "$*" >&2
}

# rsync splits its -e string itself: single and double quotes protect
# spaces, backslashes do not, so printf %q output would break. Wrap
# every word in single quotes and refuse words that contain one.
rsync_rsh() {
  local out=ssh word
  for word in "${SSH_OPTS[@]}"; do
    if [[ "${word}" == *"'"* ]]; then
      log "work dir path contains a single quote; rsync -e cannot carry it: ${word}"
      exit 2
    fi
    out+=" '${word}'"
  done
  printf '%s' "${out}"
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "missing dependency: $1"
    exit 2
  fi
}

find_efi_firmware() {
  local candidate
  for candidate in "${EFI_FIRMWARE_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

host_accel() {
  case "$(uname -s)" in
    Linux)
      if [[ -w /dev/kvm ]]; then
        echo kvm
      else
        log "/dev/kvm not writable; falling back to TCG (slow)"
        echo tcg
      fi
      ;;
    Darwin) echo hvf ;;
    *) echo tcg ;;
  esac
}

# Fill QEMU_ARGS for a headless boot. $1 = optional seed ISO to attach.
build_qemu_args() {
  local seed="${1:-}"
  local accel
  accel="$(host_accel)"
  QEMU_ARGS=(
    -name "shit-freebsd-vm"
    -smp "${VM_SMP}"
    -m "${VM_MEM}"
  )
  case "${FBSD_VM_ARCH}" in
    amd64)
      local cpu=host
      [[ "${accel}" == tcg ]] && cpu=max
      # Legacy BIOS boot: the amd64 VM images carry a gptboot
      # partition, so no OVMF is needed. The zpool disk stays the
      # second virtio disk (vtbd1) because the seed ISO goes on IDE.
      QEMU_ARGS+=(
        -machine "q35,accel=${accel}"
        -cpu "${cpu}"
        -drive "if=virtio,format=qcow2,file=${DISK_QCOW2}"
        -drive "if=virtio,format=qcow2,file=${ZPOOL_QCOW2}"
      )
      if [[ -n "${seed}" ]]; then
        QEMU_ARGS+=(-drive "if=ide,media=cdrom,format=raw,readonly=on,file=${seed}")
      fi
      ;;
    aarch64)
      local efi
      efi="$(find_efi_firmware)" || {
        log "edk2-aarch64-code.fd not found in homebrew share dir; install qemu via brew"
        exit 2
      }
      QEMU_ARGS+=(
        -machine "virt,accel=${accel}"
        -cpu host
        -drive "if=pflash,format=raw,readonly=on,file=${efi}"
        -drive "if=pflash,format=raw,file=${EFI_VARS}"
        -drive "if=virtio,format=qcow2,file=${DISK_QCOW2}"
      )
      if [[ -n "${seed}" ]]; then
        QEMU_ARGS+=(-drive "if=virtio,format=raw,file=${seed},readonly=on")
      fi
      ;;
  esac
  QEMU_ARGS+=(
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22"
    -device virtio-net-pci,netdev=net0
    -display none
    -serial "file:${QEMU_LOG}"
    -pidfile "${QEMU_PIDFILE}"
    -monitor none
    -daemonize
  )
}

vm_running() {
  [[ -f "${QEMU_PIDFILE}" ]] && kill -0 "$(cat "${QEMU_PIDFILE}")" 2>/dev/null
}

# Poll until sshd answers with our key. $1 = timeout in seconds.
wait_for_ssh() {
  local deadline=$((SECONDS + ${1:-600}))
  while ((SECONDS < deadline)); do
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 -o BatchMode=yes \
      freebsd@127.0.0.1 true 2>/dev/null; then
      return 0
    fi
    if ! vm_running; then
      log "qemu exited; see ${QEMU_LOG}"
      return 1
    fi
    sleep 5
  done
  log "ssh did not come up within ${1:-600}s; see ${QEMU_LOG}"
  return 1
}
