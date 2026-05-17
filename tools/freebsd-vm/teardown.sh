#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stop the VM and delete the disk image. The downloaded base image
# stays cached for the next provision.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
QEMU_PIDFILE="${WORK_DIR}/vm.pid"

log() { printf '[fbsd-vm] %s\n' "$*" >&2; }

if [[ -f "${QEMU_PIDFILE}" ]]; then
  pid="$(cat "${QEMU_PIDFILE}")"
  if kill -0 "${pid}" 2>/dev/null; then
    log "stopping VM (pid ${pid})"
    kill "${pid}" || true
    # Give qemu a few seconds to flush.
    for _ in 1 2 3 4 5; do
      if kill -0 "${pid}" 2>/dev/null; then sleep 1; else break; fi
    done
    if kill -0 "${pid}" 2>/dev/null; then
      log "VM still up after 5s — sending SIGKILL"
      kill -9 "${pid}" || true
    fi
  fi
  rm -f "${QEMU_PIDFILE}"
fi

log "removing disk image + EFI vars + cidata + ssh key + log"
rm -f \
  "${WORK_DIR}/freebsd14-arm64.qcow2" \
  "${WORK_DIR}/efivars.fd" \
  "${WORK_DIR}/cidata.iso" \
  "${WORK_DIR}/id_ed25519" \
  "${WORK_DIR}/id_ed25519.pub" \
  "${WORK_DIR}/known_hosts" \
  "${WORK_DIR}/vm.log"

log "leaving base image (${WORK_DIR}/FreeBSD-*.qcow2.xz) cached for re-provision"
