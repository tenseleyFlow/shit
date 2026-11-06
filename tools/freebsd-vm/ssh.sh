#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# SSH wrapper. Use this instead of plain `ssh` so we don't accumulate
# the VM's host key in your real ~/.ssh/known_hosts.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

exec ssh "${SSH_OPTS[@]}" freebsd@127.0.0.1 "$@"
