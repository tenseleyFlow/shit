#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Snapshot the tart VM's state. Mirror of tools/freebsd-vm/doctor.sh.
# Reports: VM exists, VM running, IP assigned, sshd reachable, SIP
# state, repo synced, last-built helper binary present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"

: "${SHIT_TART_VM:=shit-m03}"

ok() { printf "  \033[32m✓\033[0m  %s\n" "$*"; }
bad() { printf "  \033[31m✗\033[0m  %s\n" "$*"; }
warn() { printf "  \033[33m⚠\033[0m  %s\n" "$*"; }

echo "tart-vm:doctor"

# 1. VM exists?
if tart list | awk '{print $2}' | grep -qxF "${SHIT_TART_VM}"; then
    ok "VM ${SHIT_TART_VM} exists"
else
    bad "VM ${SHIT_TART_VM} does not exist (run boot.sh)"
    exit 1
fi

# 2. VM running?
if pgrep -f "tart run.* ${SHIT_TART_VM}" >/dev/null; then
    ok "VM ${SHIT_TART_VM} is running"
else
    bad "VM ${SHIT_TART_VM} is not running (run boot.sh)"
    exit 1
fi

# 3. IP assigned?
ip="$(tart ip "${SHIT_TART_VM}" 2>/dev/null || true)"
if [ -n "${ip}" ]; then
    ok "VM IP: ${ip}"
else
    bad "VM has no IP (still booting?)"
    exit 1
fi

# 4. sshd reachable?
if nc -z -G 2 "${ip}" 22 2>/dev/null; then
    ok "sshd reachable at ${ip}:22"
else
    bad "sshd not reachable at ${ip}:22"
    exit 1
fi

# 5. SIP state?
sip="$("${SCRIPT_DIR}/ssh.sh" 'csrutil status 2>&1' 2>/dev/null || echo 'query failed')"
if printf '%s' "${sip}" | grep -qi 'disabled'; then
    ok "SIP disabled (required for ES dev without entitlement)"
elif printf '%s' "${sip}" | grep -qi 'enabled'; then
    warn "SIP enabled — ES dev will get NOT_ENTITLED; see audit doc for Recovery-boot steps"
else
    warn "SIP state unknown: ${sip}"
fi

# 6. Repo synced?
if "${SCRIPT_DIR}/ssh.sh" 'test -d /Users/admin/shit/crates/shit-helper' 2>/dev/null; then
    ok "/Users/admin/shit/ present (last sync ok)"
else
    warn "/Users/admin/shit/ missing — run sync.sh"
fi

# 7. shit-helper built?
if "${SCRIPT_DIR}/ssh.sh" 'test -x /Users/admin/shit/target/debug/shit-helper -o -x /Users/admin/shit/target/release/shit-helper' 2>/dev/null; then
    ok "shit-helper binary present on VM"
else
    warn "shit-helper not yet built on VM — run: tools/macos-tart-vm/ssh.sh 'cd shit && cargo build -p shit-helper'"
fi

echo
echo "VM ready for M03 ES dev."
