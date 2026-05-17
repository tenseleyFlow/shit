#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# SSH wrapper. Use this instead of plain `ssh` so we don't accumulate
# the VM's host key in your real ~/.ssh/known_hosts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

exec ssh \
  -p 2225 \
  -i "${SSH_KEY}" \
  -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
  -o "StrictHostKeyChecking=accept-new" \
  -o "IdentitiesOnly=yes" \
  -o "LogLevel=ERROR" \
  freebsd@127.0.0.1 "$@"
