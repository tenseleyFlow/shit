#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# rsync the codebase to the bare-metal Linux validation box (hasu)
# over Tailscale. Excludes build artifacts and per-platform VM work
# dirs. The remote rebuilds its own target/ tree.
#
# Standing memory: `mfwolffe@hasu` is the Linux validation box for
# privileged kernel-tier work; other tailnet Linux hosts are
# production and must not be disrupted.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Default to the Tailscale IP for portability (some hosts don't have
# `hasu` in ssh_config or MagicDNS); override via SHIT_HASU_HOST if
# you've added an alias.
HASU_HOST="${SHIT_HASU_HOST:-mfwolffe@100.69.85.34}"
REMOTE_DIR="${SHIT_HASU_REMOTE_DIR:-shit}"

exec rsync -az --delete \
    --exclude=target/ \
    --exclude=vendor/ \
    --exclude=.docs/ \
    --exclude=.refs/ \
    --exclude=.git/ \
    --exclude=.claude/ \
    --exclude=tools/freebsd-vm/work/ \
    --exclude=tools/linux-bpf-vm/work/ \
    "${REPO_ROOT}/" \
    "${HASU_HOST}:${REMOTE_DIR}/"
