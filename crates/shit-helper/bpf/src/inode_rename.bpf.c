/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_rename` (L04.1).
 *
 * Fires on every `rename(2)` / `renameat(2)` / `renameat2(2)`
 * BEFORE the kernel applies the rename. The hook captures both
 * ends of the rename:
 *
 *   - (old_dir->i_ino, old_dentry->d_name) — pre-rename location
 *   - (new_dir->i_ino, new_dentry->d_name) — post-rename location
 *
 * The (dev, inode) of the renamed file/dir is invariant across
 * the operation (rename doesn't allocate a new inode on the same
 * filesystem). We read it from `old_dentry->d_inode`.
 *
 * Userspace handler emits `HelperResponse::TreeMutation { op:
 * TreeOpWire::Rename { from, to, dev, inode } }`. Daemon journals
 * `TreeOp::Rename`; undo replays the inverse rename.
 *
 * LSM hook signature (verified via vmlinux.h on hasu 7.0.8):
 *   int inode_rename(struct inode *old_dir,
 *                    struct dentry *old_dentry,
 *                    struct inode *new_dir,
 *                    struct dentry *new_dentry);
 *
 * No mnt_idmap arg; no flags arg. Cross-arch rename flags (RENAME_
 * EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT) aren't visible here
 * — the LSM hook is called from vfs_rename after flags have been
 * dispatched. If we need to handle EXCHANGE specifically, we'd
 * need security_path_rename instead; deferred.
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rename_events SEC(".maps");

SEC("lsm/inode_rename")
int BPF_PROG(shit_inode_rename,
             struct inode *old_dir,
             struct dentry *old_dentry,
             struct inode *new_dir,
             struct dentry *new_dentry)
{
    struct shit_rename_event *e =
        bpf_ringbuf_reserve(&rename_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_RENAME;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    /* Target identity — invariant across rename. */
    struct inode *target = BPF_CORE_READ(old_dentry, d_inode);
    e->inode = BPF_CORE_READ(target, i_ino);
    e->dev = BPF_CORE_READ(target, i_sb, s_dev);

    e->old_parent_inode = BPF_CORE_READ(old_dir, i_ino);
    e->new_parent_inode = BPF_CORE_READ(new_dir, i_ino);

    /* Basenames via CO-RE. */
    const unsigned char *old_name_ptr = BPF_CORE_READ(old_dentry, d_name.name);
    e->old_name_len = 0;
    long n = bpf_core_read_str(&e->old_name, sizeof(e->old_name), old_name_ptr);
    if (n > 0) {
        e->old_name_len = (__u32)(n - 1);
    }

    const unsigned char *new_name_ptr = BPF_CORE_READ(new_dentry, d_name.name);
    e->new_name_len = 0;
    n = bpf_core_read_str(&e->new_name, sizeof(e->new_name), new_name_ptr);
    if (n > 0) {
        e->new_name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
