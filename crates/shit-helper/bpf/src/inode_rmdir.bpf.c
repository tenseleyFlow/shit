/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_rmdir` (G03).
 *
 * Sibling of inode_unlink.bpf.c. `unlinkat(2, AT_REMOVEDIR)` and
 * `rmdir(2)` go through the kernel's `inode_rmdir` LSM hook rather
 * than `inode_unlink`, so the latter alone misses every untracked-
 * directory removal (canonical trigger: `git clean -fd`).
 *
 * Same struct/wire shape as shit_unlink_event — the LSM hook
 * signature is identical: `(struct inode *dir, struct dentry
 * *dentry)`. The only differences are:
 *   - kind tag in the event header is SHIT_EVT_RMDIR
 *   - dedicated ringbuf for clean userspace dispatch
 *
 * Mitigations (same posture as inode_unlink):
 *   - Strict CO-RE via BPF_CORE_READ for every kernel-struct field.
 *   - No unbounded loops. Straight-line code.
 *   - Always returns 0 (allow). Cannot deny syscalls.
 *
 * Kernel prerequisites:
 *   - CONFIG_BPF_LSM=y
 *   - `lsm=...,bpf,...` in /proc/cmdline
 *   - CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN) on the loading process.
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* 256 KiB ringbuf — same sizing as inode_unlink. rmdir events are
 * much rarer than unlinks (most workloads have a few rmdirs at the
 * tail of a cleanup pass) so this is comfortably oversized. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rmdir_events SEC(".maps");

SEC("lsm/inode_rmdir")
int BPF_PROG(shit_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
    struct shit_unlink_event *e =
        bpf_ringbuf_reserve(&rmdir_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_RMDIR;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    struct inode *target = BPF_CORE_READ(dentry, d_inode);
    e->inode = BPF_CORE_READ(target, i_ino);
    e->dev = BPF_CORE_READ(target, i_sb, s_dev);

    e->parent_inode = BPF_CORE_READ(dir, i_ino);

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    e->name_len = 0;
    e->_pad3 = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
