#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# L04 BPF build helper — invokes `make` on the BPF tree against the
# right libbpf headers + unwrapped clang on hasu (or any NixOS box).
#
# Why the wrapper:
#   - NixOS's default `clang` wrapper auto-injects flags BPF target
#     can't accept (e.g. -fzero-call-used-regs). Use clang-unwrapped.
#   - libbpf headers (bpf_helpers.h, bpf_core_read.h, bpf_tracing.h)
#     live under the kernel-dev nix-store path, not /usr/include.
#   - vmlinux.h is checked in (crates/shit-helper/bpf/include/vmlinux.h).
#
# Run after editing any .bpf.c file in crates/shit-helper/bpf/src/.
# Outputs .o files under crates/shit-helper/bpf/build/ which are
# include_bytes!'d by the userspace loader.
#
# Usage:
#   bash tools/linux/build-bpf.sh                       # build all
#   bash tools/linux/build-bpf.sh inode_unlink          # build one

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BPF_DIR="${REPO_ROOT}/crates/shit-helper/bpf"

TARGET="${1:-}"

# Discover the unwrapped clang. Pinning to a specific store path
# isn't portable across nix-store reflows; resolve at runtime.
UNWRAPPED_CLANG="$(find /nix/store -maxdepth 4 -path '*clang-21*/bin/clang' 2>/dev/null | head -1)"
if [ -z "${UNWRAPPED_CLANG}" ]; then
    # Fallback: any major-version unwrapped clang.
    UNWRAPPED_CLANG="$(find /nix/store -maxdepth 4 -path '*clang-2*/bin/clang' 2>/dev/null | head -1)"
fi
if [ -z "${UNWRAPPED_CLANG}" ]; then
    echo "build-bpf: no clang-unwrapped found in /nix/store" >&2
    echo "  one-time setup: nix-shell -p llvmPackages.clang-unwrapped --run 'echo ok'" >&2
    exit 1
fi

# Discover libbpf headers — they're inside the linux-X.Y.Z-dev tree.
LIBBPF_INC="$(find /nix/store -maxdepth 12 -path '*linux-*-dev/lib/modules/*/build/tools/bpf/resolve_btfids/libbpf/include' -type d 2>/dev/null | head -1)"
if [ -z "${LIBBPF_INC}" ]; then
    echo "build-bpf: libbpf headers not found in /nix/store" >&2
    echo "  one-time setup: nix-shell -p libbpf --run 'echo ok'" >&2
    exit 1
fi

echo "[build-bpf] CLANG=${UNWRAPPED_CLANG}"
echo "[build-bpf] LIBBPF_INC=${LIBBPF_INC}"

cd "${BPF_DIR}"
if [ -n "${TARGET}" ]; then
    make CLANG="${UNWRAPPED_CLANG}" BPF_HELPERS_INCLUDE="${LIBBPF_INC}" "build/${TARGET}.bpf.o"
else
    make CLANG="${UNWRAPPED_CLANG}" BPF_HELPERS_INCLUDE="${LIBBPF_INC}" all
fi

echo "[build-bpf] outputs:"
ls -la build/
