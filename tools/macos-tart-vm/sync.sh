#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# rsync the repo into the tart VM. Mirror of tools/freebsd-vm/sync.sh.
# Excludes target/ (the VM rebuilds its own), .docs/ + .refs/ + .git/
# + tooling work dirs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

: "${SHIT_TART_VM:=shit-m03}"

if [ ! -f "${WORK_DIR}/vm.ip" ]; then
    ip="$(tart ip "${SHIT_TART_VM}" 2>/dev/null || true)"
    if [ -z "${ip}" ]; then
        echo "no VM IP recorded; run tools/macos-tart-vm/boot.sh first" >&2
        exit 1
    fi
    echo "${ip}" >"${WORK_DIR}/vm.ip"
fi
ip="$(cat "${WORK_DIR}/vm.ip")"

exec rsync -av --delete \
    --exclude=target/ \
    --exclude=vendor/ \
    --exclude=.docs/ \
    --exclude=.refs/ \
    --exclude=.git/ \
    --exclude=.claude/ \
    --exclude=tools/freebsd-vm/work/ \
    --exclude=tools/linux-bpf-vm/work/ \
    --exclude=tools/macos-tart-vm/work/ \
    -e "ssh -i ${SSH_KEY} -o UserKnownHostsFile=${KNOWN_HOSTS} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -o LogLevel=ERROR" \
    "${REPO_ROOT}/" \
    "admin@${ip}:/Users/admin/shit/"
