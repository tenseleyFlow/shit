/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_rmdir` (G03).
 *
 * Fires on every `rmdir(2)` / `unlinkat(AT_REMOVEDIR)` right before
 * the kernel removes the directory entry. The hook:
 *
 *   1. Reads the (dev, inode, mode) of the about-to-be-removed
 *      directory via CO-RE on the dentry's d_inode and its
 *      containing superblock.
 *   2. Captures the calling process's pid/tgid/comm + parent.
 *   3. Pushes a `shit_rmdir_event` onto the userspace-side ringbuf.
 *   4. Returns 0 (always ALLOW).
 *
 * The whole point of G03 is the `mode` field: pre-G03 the planner's
 * RecreatePath for a removed dir restored at mkdir-p's umask-moderated
 * 0o755 because the helper had no captured mode. Reading `i_mode` at
 * the LSM hook (before the kernel commits the rmdir) gives userspace
 * the real pre-removal mode.
 *
 * HP-18 / blast radius: identical to inode_unlink — straight-line
 * code, always allow, ringbuf drops are silent. See inode_unlink.bpf.c
 * for the full rationale.
 *
 * Kernel prerequisites: same as inode_unlink. The 2-arg LSM signature
 * `(inode *dir, dentry *dentry)` is stable since BPF-LSM landed in
 * 5.7; no v1/v2 dispatch needed unless a future kernel adds mnt_idmap
 * (the inode_setattr drift pattern).
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* 256 KiB ringbuf — sized to match the other LSM hooks. rmdir is far
 * lower frequency than unlink in real workloads (one per emptied
 * dir, not one per file), so this is generous. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rmdir_events SEC(".maps");

SEC("lsm/inode_rmdir")
int BPF_PROG(shit_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
    struct shit_rmdir_event *e =
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
    e->mode = BPF_CORE_READ(target, i_mode);
    e->parent_inode = BPF_CORE_READ(dir, i_ino);

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    e->name_len = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
