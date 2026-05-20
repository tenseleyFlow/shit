#!/usr/bin/env bash
# L01.5 — seccomp allowlist audit driver.
#
# Runs the helper under a representative workload with the seccomp
# filter set to LOG mode (kernel records violations to the audit
# subsystem but does NOT block). Surfaces every syscall the helper
# made that's NOT in the current allowlist, with x86_64 syscall-number
# → name resolution via the kernel's linux-headers package.
#
# Use after adding new code paths to the helper, or when the
# `seccomp_post_sandbox` integration test fails with an unexpected
# SIGSYS. The workflow:
#
#   1. Boot the daemon.
#   2. Drive a representative workload (the L01 chunk-5 e2e probe).
#   3. Collect SECCOMP audit lines from journalctl with comm=shit-helper.
#   4. Print syscall numbers + names.
#   5. Update crates/shit-helper/src/seccomp_linux.rs ALLOWED_SYSCALLS
#      with the missing entries (with audit notes per
#      .docs/audits/seccomp-policy.md).
#
# Usage:
#   bash tools/seccomp-audit.sh [PROBE_SCRIPT]
#
# PROBE_SCRIPT defaults to /tmp/l01-chunk5-e2e.sh — adjust as new
# workloads come online (L02 milestone, L03 per-tier smokes).
#
# Prerequisites on the box:
#   - shit-helper built (cd <repo> && cargo build --release -p shit-helper)
#   - setcap cap_sys_admin,cap_bpf,cap_perfmon+ep on the helper binary
#   - audit subsystem available (journalctl SECCOMP records)
#   - linux-headers available somewhere (NixOS: /nix/store/...)

set -euo pipefail

PROBE="${1:-/tmp/l01-chunk5-e2e.sh}"

if [ ! -x "$PROBE" ]; then
    echo "audit: probe script $PROBE not found / not executable" >&2
    exit 1
fi

# Find unistd_64.h for syscall-number → name resolution. NixOS doesn't
# ship /usr/include; locate via nix store. Other distros fall back to
# the standard path.
HEADER=""
for candidate in \
    /usr/include/asm/unistd_64.h \
    /usr/include/x86_64-linux-gnu/asm/unistd_64.h \
    "$(find /nix/store -maxdepth 5 -name 'unistd_64.h' 2>/dev/null | head -1)"; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        HEADER="$candidate"
        break
    fi
done
if [ -z "$HEADER" ]; then
    echo "audit: WARN — no unistd_64.h found; syscall names will show as numbers only" >&2
fi

START_TS=$(date '+%Y-%m-%d %H:%M:%S')

# Set log mode so violations are recorded without killing the helper.
# Lets us collect ALL needed syscalls in one run instead of fixing one
# per crash.
export SHIT_HELPER_SECCOMP_MODE=log

echo "audit: running probe under SHIT_HELPER_SECCOMP_MODE=log"
bash "$PROBE" >/tmp/seccomp-audit-probe.log 2>&1 || true

# Give the kernel a moment to flush audit records.
sleep 0.5

echo
echo "=== SECCOMP entries since probe start ($START_TS) ==="
echo

# Filter to kernel-audit lines only (the `audit[PID]:` prefix). Without
# this, ssh-session log lines from tailscaled / sshd that happen to
# contain "SECCOMP" and "shit-helper" as plain-text command echoes get
# picked up — silent false positives that look like real violations.
journalctl --since "$START_TS" --no-pager 2>&1 \
    | grep -E 'audit\[[0-9]+\]:.*SECCOMP' \
    | grep 'comm="shit-helper"' \
    | awk -F 'syscall=' '{print $2}' \
    | awk '{print $1}' \
    | sort -un \
    | while read -r sysnum; do
        if [ -n "$HEADER" ]; then
            name=$(grep -E "#define +__NR_[a-z_0-9]+ +$sysnum$" "$HEADER" 2>/dev/null \
                | head -1 | awk '{print $2}' | sed 's/^__NR_//')
        fi
        if [ -n "${name:-}" ]; then
            printf '  %3d  %s\n' "$sysnum" "$name"
        else
            printf '  %3d  (unknown)\n' "$sysnum"
        fi
        name=""
    done

echo
echo "=== probe stdout (last 5 lines) ==="
tail -5 /tmp/seccomp-audit-probe.log

echo
echo "Next steps if any entries appeared above:"
echo "  1. Add the syscalls to crates/shit-helper/src/seccomp_linux.rs"
echo "     ALLOWED_SYSCALLS with a comment explaining why each is needed."
echo "  2. Update .docs/audits/seccomp-policy.md with the same entries."
echo "  3. Rebuild + re-setcap the helper; re-run this script. Expect zero."
echo "  4. Run \`cargo test -p shit-helper --test seccomp_post_sandbox\` to"
echo "     confirm the helper survives post-sandbox under KILL mode."
