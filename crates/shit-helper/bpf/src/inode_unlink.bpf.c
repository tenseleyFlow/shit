/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_unlink` (L04).
 *
 * Fires on every `unlinkat(2)` call right before the kernel
 * actually removes the directory entry. The hook:
 *
 *   1. Reads the (dev, inode) of the about-to-be-deleted file via
 *      CO-RE on the dentry's d_inode and its containing superblock.
 *   2. Captures the calling process's pid/tgid/comm.
 *   3. Pushes a `shit_unlink_event` onto the userspace-side ringbuf.
 *   4. Returns 0 (always ALLOW).
 *
 * HP-18 / blast radius: LSM hooks are *security-relevant*. A
 * verifier rejection on a kernel diff would BREAK every unlinkat on
 * the affected box. Mitigations:
 *
 *   - Strict CO-RE via BPF_CORE_READ for every kernel-struct field.
 *   - No unbounded loops. The program is straight-line code.
 *   - Always returns 0 ("allow"). Cannot deny syscalls.
 *   - The ringbuf reserve can fail under load — we drop the event
 *     silently rather than block or return non-zero. Tracking gap:
 *     drops surface via the ringbuf overflow counter (DR coming).
 *
 * The shipped .bpf.o lives in `crates/shit-helper/bpf/build/` and is
 * `include_bytes!`'d by the userspace loader. Regenerate via the
 * Makefile next to this file:
 *
 *     make -C crates/shit-helper/bpf inode_unlink
 *
 * Kernel prerequisites:
 *   - CONFIG_BPF_LSM=y
 *   - `lsm=...,bpf,...` in /proc/cmdline (boot param)
 *   - CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN) on the loading
 *     process (shit-helper has these via setcap).
 *
 * Verified on hasu (NixOS, kernel 7.0.8). See
 * `.docs/audits/bpf-coverage.md` for the kernel matrix.
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* 256 KiB ringbuf — sized for ~1k events/sec p99 without overflow at
 * userspace drain rates we've measured. If overflow becomes a real
 * concern (cargo build storms etc.), bump to 1 MiB and revisit. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} unlink_events SEC(".maps");

SEC("lsm/inode_unlink")
int BPF_PROG(shit_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    struct shit_unlink_event *e =
        bpf_ringbuf_reserve(&unlink_events, sizeof(*e), 0);
    if (!e) {
        /* Ringbuf full. Drop the event but always ALLOW the syscall
         * — LSM hooks that block under pressure can wedge the box. */
        return 0;
    }

    /* Header. */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_UNLINK;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    /* Body — read (dev, inode) via CO-RE so the program stays
     * portable across kernels whose struct layouts differ. */
    struct inode *target = BPF_CORE_READ(dentry, d_inode);
    e->inode = BPF_CORE_READ(target, i_ino);
    e->dev = BPF_CORE_READ(target, i_sb, s_dev);

    /* Parent inode lets userspace disambiguate which directory the
     * unlink happened in — useful when the calling pid has multiple
     * candidate cwds (chroot, mount namespaces). The `dir` LSM arg
     * is the parent inode directly. */
    e->parent_inode = BPF_CORE_READ(dir, i_ino);

    /* Basename via CO-RE on the dentry's qstr. The verifier rejects
     * unbounded string reads, so we clamp to SHIT_NAME_MAX and use
     * bpf_core_read_str which writes at most `sz` bytes and returns
     * the byte count actually written (incl. NUL). */
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    /* Initialize to 0 in case the str_read fails (returns < 0). */
    e->name_len = 0;
    e->_pad3 = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        /* Strip the trailing NUL from the reported length. */
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
