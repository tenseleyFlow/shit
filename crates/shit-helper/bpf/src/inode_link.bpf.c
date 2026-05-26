/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_link` (DR-CR-55).
 *
 * Fires on every `link(2)` / `linkat(2)` (hardlink creation). Mirrors
 * the `inode_create` design: emit a `shit_create_event` for the new
 * directory entry, userspace stats the resolved path post-syscall to
 * fill in (dev, inode), journals a `TreeOp::Create`. Undo's inverse
 * is `Unlink(link_path)` — removes the directory entry, which drops
 * the target inode's `nlink` from 2 back to 1 as a side effect. No
 * content is lost: the target file still has its own directory entry.
 *
 * LSM hook signature (verified via hasu kernel 7.0.8 BTF; stable):
 *   int inode_link(struct dentry *old_dentry, struct inode *dir,
 *                  struct dentry *new_dentry);
 *
 * Args:
 *   old_dentry — the EXISTING file's dentry (the link target). We
 *                deliberately ignore this; nothing to capture
 *                about a hardlink that we don't already know.
 *   dir        — the parent directory the new entry lands in.
 *   new_dentry — the new directory entry being created.
 *
 * Reuses `shit_create_event` for the same reason inode_symlink.bpf.c
 * does: the unlink-as-undo path doesn't need extra info, and the
 * existing on_create sink + planner code path handles this with no
 * userspace changes beyond a new ringbuf reader thread.
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
} link_events SEC(".maps");

SEC("lsm/inode_link")
int BPF_PROG(shit_inode_link,
             struct dentry *old_dentry,
             struct inode *dir,
             struct dentry *new_dentry)
{
    (void)old_dentry;
    struct shit_create_event *e =
        bpf_ringbuf_reserve(&link_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_CREATE;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    e->parent_inode = BPF_CORE_READ(dir, i_ino);
    e->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
    /* Hardlink shares its target's mode. We don't have it at hook
     * time without dereferencing old_dentry; ship 0 and let
     * userspace's post-syscall stat fill in the real mode. */
    e->mode = 0;

    const unsigned char *name_ptr = BPF_CORE_READ(new_dentry, d_name.name);
    e->name_len = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
