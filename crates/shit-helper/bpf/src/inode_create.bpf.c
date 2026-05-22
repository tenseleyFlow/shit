/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_create` (L04 phase 5).
 *
 * Fires on every regular-file creation: `open(O_CREAT)`, `creat(2)`,
 * mknod for regular files. The userspace consumer:
 *   1. Stats the resolved path to fill in (dev, inode) for the new
 *      file.
 *   2. Opens an `O_RDONLY` fd and stashes it in `pre_opens` —
 *      mirrors the WatchTree-time `pre_open_tree` mechanism, but
 *      for files born mid-session. A subsequent `inode_unlink` for
 *      this file can then dup that fd to read pre-image content.
 *   3. Sends `HelperResponse::TreeMutation { op: Create { kind:
 *      Regular, ... } }`. Daemon journals `TreeOp::Create`.
 *
 * LSM hook signature (verified via vmlinux.h on hasu 7.0.8):
 *   int inode_create(struct inode *dir, struct dentry *dentry,
 *                    umode_t mode);
 *
 * Notably the same shape as inode_mkdir. Wrong-signature BPF_PROG
 * gotcha: see `.docs/audits/bpf-coverage.md` and the memory note.
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
} create_events SEC(".maps");

SEC("lsm/inode_create")
int BPF_PROG(shit_inode_create,
             struct inode *dir,
             struct dentry *dentry,
             umode_t mode)
{
    struct shit_create_event *e =
        bpf_ringbuf_reserve(&create_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_CREATE;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    /* AR00.5 ancestry — see inode_unlink.bpf.c for rationale. */
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    e->parent_inode = BPF_CORE_READ(dir, i_ino);
    e->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
    e->mode = (__u32)mode;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    e->name_len = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
