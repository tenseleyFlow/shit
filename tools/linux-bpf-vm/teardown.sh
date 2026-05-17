#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stop the VM and delete the working disk. Keeps the downloaded base
# image cached for the next provision.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"

UBUNTU_RELEASE="${UBUNTU_RELEASE:-noble}"
DISK_QCOW2="${WORK_DIR}/ubuntu-${UBUNTU_RELEASE}-arm64.qcow2"
EFI_VARS="${WORK_DIR}/efivars.fd"
QEMU_PIDFILE="${WORK_DIR}/vm.pid"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

log() { printf '[linux-bpf-vm] %s\n' "$*" >&2; }

# 1. Stop the VM if running.
if [[ -f "${QEMU_PIDFILE}" ]]; then
  pid="$(cat "${QEMU_PIDFILE}")"
  if kill -0 "${pid}" 2>/dev/null; then
    log "stopping VM (pid ${pid})"
    kill "${pid}"
    # Wait up to 10s for clean shutdown, then SIGKILL.
    for _ in $(seq 1 10); do
      if ! kill -0 "${pid}" 2>/dev/null; then break; fi
      sleep 1
    done
    if kill -0 "${pid}" 2>/dev/null; then
      log "VM did not exit; SIGKILL"
      kill -9 "${pid}" 2>/dev/null || true
    fi
  fi
  rm -f "${QEMU_PIDFILE}"
fi

# 2. Delete the working disk + EFI vars + known_hosts. Keep the base
# image (re-provisioning is fast without re-download).
for f in "${DISK_QCOW2}" "${EFI_VARS}" "${KNOWN_HOSTS}" "${WORK_DIR}/cidata.iso"; do
  if [[ -e "${f}" ]]; then
    log "removing ${f}"
    rm -f "${f}"
  fi
done

log "teardown complete; base image retained at ${WORK_DIR}/$(ls "${WORK_DIR}" 2>/dev/null | grep cloudimg || echo '<absent>')"
