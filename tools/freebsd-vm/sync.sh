#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# rsync the codebase into the VM. Excludes target/, vendor/, .docs/,
# .refs/, .git/. The VM rebuilds its own target dir.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SSH_KEY="${WORK_DIR}/id_ed25519"
KNOWN_HOSTS="${WORK_DIR}/known_hosts"

exec rsync -av --delete \
  --exclude=target/ \
  --exclude=vendor/ \
  --exclude=.docs/ \
  --exclude=.refs/ \
  --exclude=.git/ \
  --exclude=tools/freebsd-vm/work/ \
  -e "ssh -p 2225 -i ${SSH_KEY} -o UserKnownHostsFile=${KNOWN_HOSTS} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes" \
  "${REPO_ROOT}/" \
  "freebsd@127.0.0.1:shit/"
