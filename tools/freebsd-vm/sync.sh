#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# rsync the codebase into the VM. Excludes target/, vendor/, .docs/,
# .refs/, .git. The VM rebuilds its own target dir.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
REPO_ROOT="$(cd "${FBSD_VM_SCRIPT_DIR}/../.." && pwd)"

# .git is a file (not a dir) in a worktree checkout, so exclude both.
exec rsync -a --delete \
  --exclude=/target/ \
  --exclude=/vendor/ \
  --exclude=/.docs/ \
  --exclude=/.refs/ \
  --exclude=/.claude/ \
  --exclude=/.git \
  --exclude=/tools/freebsd-vm/work/ \
  --exclude=/tools/linux-bpf-vm/work/ \
  --exclude=/tools/macos-tart-vm/work/ \
  -e "$(rsync_rsh)" \
  "${REPO_ROOT}/" \
  "freebsd@127.0.0.1:shit/"
