#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stop the VM and delete the disk images. The downloaded base image
# stays cached under download/ for the next provision. Pass --stop to
# only stop qemu and keep the disks.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ -f "${QEMU_PIDFILE}" ]]; then
  pid="$(cat "${QEMU_PIDFILE}")"
  if kill -0 "${pid}" 2>/dev/null; then
    # A clean guest shutdown keeps UFS from needing fsck on next boot.
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 -o BatchMode=yes freebsd@127.0.0.1 \
      'sudo shutdown -p now' >/dev/null 2>&1; then
      log "guest powering off (pid ${pid})"
      for _ in $(seq 1 30); do
        if kill -0 "${pid}" 2>/dev/null; then sleep 1; else break; fi
      done
    fi
    if kill -0 "${pid}" 2>/dev/null; then
      log "stopping VM (pid ${pid})"
      kill "${pid}" || true
      for _ in 1 2 3 4 5; do
        if kill -0 "${pid}" 2>/dev/null; then sleep 1; else break; fi
      done
    fi
    if kill -0 "${pid}" 2>/dev/null; then
      log "VM still up after 5s; sending SIGKILL"
      kill -9 "${pid}" || true
    fi
  fi
  rm -f "${QEMU_PIDFILE}"
fi

if [[ "${1:-}" == --stop ]]; then
  log "stopped; disks kept"
  exit 0
fi

log "removing disk images + EFI vars + cidata + ssh key + log"
rm -f \
  "${DISK_QCOW2}" \
  "${ZPOOL_QCOW2}" \
  "${EFI_VARS}" \
  "${SEED_ISO}" \
  "${SSH_KEY}" \
  "${SSH_KEY}.pub" \
  "${KNOWN_HOSTS}" \
  "${QEMU_LOG}"

log "leaving base image (${DOWNLOAD_DIR}/FreeBSD-*.qcow2.xz) cached for re-provision"
