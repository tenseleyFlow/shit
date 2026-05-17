// SPDX-License-Identifier: AGPL-3.0-or-later
//
// shit-helper — minimal tracepoint program (S09 stage 3).
//
// This program is the *simplest possible* eBPF program that:
//   - Attaches to a tracepoint (read-only — cannot deny syscalls)
//   - Always returns 0 (no side effects)
//   - Carries the right ELF metadata for aya::Ebpf::load to recognize it
//
// **Safety**: tracepoint programs are observational only. They cannot
// return a non-zero "deny" verdict like LSM hooks can. The worst this
// program can do is be slow (CPU overhead on every sched_process_exec
// syscall). That cost is bounded — a return-0 program adds ~50ns.
//
// **No header dependencies on purpose.** We don't include
// <linux/bpf.h>, vmlinux.h, or libbpf's bpf_helpers.h, because every
// one of those is sensitive to the build host's kernel version. By
// stripping the program to just the syntax clang needs to emit BPF
// bytecode, we make it portable across kernels.
//
// Regenerate with:
//   make -C crates/shit-helper/bpf
//
// Verify with:
//   llvm-objdump -d crates/shit-helper/bpf/build/noop_tracepoint.bpf.o

// Force the ELF section name. aya looks for "tp/<category>/<name>" or
// "tracepoint/<category>/<name>" sections when loading tracepoints.
__attribute__((section("tracepoint/sched/sched_process_exec"), used))
int noop_tracepoint(void *ctx)
{
    (void)ctx;
    return 0;
}

// License symbol — required for any BPF program that uses helpers,
// and harmless to include even when no helpers are called. The kernel
// verifier checks this on load.
char _license[] __attribute__((section("license"), used)) = "GPL";
