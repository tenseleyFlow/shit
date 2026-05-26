#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# SSH wrapper for the tart-managed macOS VM. Same role as
# tools/freebsd-vm/ssh.sh: uses per-VM keys + a throwaway known_hosts
# so the host's real ~/.ssh state stays clean.
#
# Args pass through to ssh, e.g.:
#   tools/macos-tart-vm/ssh.sh                       # interactive shell
#   tools/macos-tart-vm/ssh.sh 'csrutil status'      # remote command

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

: "${SHIT_TART_VM:=shit-m03}"

if [ ! -f "${WORK_DIR}/vm.ip" ]; then
    # Re-query in case boot.sh hasn't been re-run since reboot.
    ip="$(tart ip "${SHIT_TART_VM}" 2>/dev/null || true)"
    if [ -z "${ip}" ]; then
        echo "no VM IP recorded; run tools/macos-tart-vm/boot.sh first" >&2
        exit 1
    fi
    echo "${ip}" >"${WORK_DIR}/vm.ip"
fi
ip="$(cat "${WORK_DIR}/vm.ip")"

exec ssh \
    -i "${SSH_KEY}" \
    -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
    -o "StrictHostKeyChecking=accept-new" \
    -o "IdentitiesOnly=yes" \
    -o "LogLevel=ERROR" \
    -o "ServerAliveInterval=30" \
    "admin@${ip}" \
    "$@"
