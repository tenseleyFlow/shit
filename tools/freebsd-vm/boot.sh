#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Boot the provisioned FreeBSD VM headless. cidata.iso is not
# attached; the first boot in provision.sh already consumed it.
# Pass --wait to block until sshd answers.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ ! -f "${DISK_QCOW2}" ]]; then
  log "no disk image at ${DISK_QCOW2}; run provision.sh first"
  exit 2
fi

if vm_running; then
  log "VM already running (pid $(cat "${QEMU_PIDFILE}"))"
  exit 0
fi

build_qemu_args
BOOT_START=${SECONDS}
"${QEMU_BIN}" "${QEMU_ARGS[@]}"
log "VM starting at 127.0.0.1:${SSH_PORT} (pid $(cat "${QEMU_PIDFILE}"))"

if [[ "${1:-}" == --wait ]]; then
  wait_for_ssh 300
  log "ssh up after $((SECONDS - BOOT_START))s"
fi
