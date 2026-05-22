/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_mkdir` (L04 phase 4).
 *
 * Fires on every `mkdir(2)` / `mkdirat(2)` BEFORE the kernel
 * actually creates the directory. The hook:
 *
 *   1. Reads `dir->i_ino` (parent directory's inode) and
 *      `dir->i_sb->s_dev` for parent identification.
 *   2. Reads `dentry->d_name.name` for the basename of the
 *      new-to-be-created directory.
 *   3. Reads the umask-applied `mode` argument.
 *   4. Pushes a `shit_mkdir_event` onto the userspace ringbuf.
 *   5. Returns 0 (always ALLOW).
 *
 * HP-18 / blast radius: same contract as the other LSM hooks in this
 * tree. Always returns 0; never blocks; verifier-rejection on a
 * kernel diff would break every mkdir on the affected box.
 * Mitigations identical: CO-RE reads, straight-line code, ringbuf
 * full ↦ drop silently.
 *
 * LSM hook signature (observed via vmlinux.h BTF on hasu 7.0.8):
 *   int inode_mkdir(struct inode *dir,
 *                   struct dentry *dentry,
 *                   umode_t mode);
 *
 * Note: mkdir does NOT take `struct mnt_idmap *` (unlike inode_setattr
 * which does, or inode_create which does). The LSM hook table for
 * this kernel ships only the 3-arg form. A BPF_PROG with the wrong
 * arg count loads (verifier accepts any LSM signature with matching
 * types) but reads arg slots offset by one — every field ends up
 * zero/empty. Verified via `bpftool btf dump file /sys/kernel/btf/
 * vmlinux format c | grep inode_mkdir`.
 *
 * Verified on hasu (NixOS, kernel 7.0.8).
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
} mkdir_events SEC(".maps");

SEC("lsm/inode_mkdir")
int BPF_PROG(shit_inode_mkdir,
             struct inode *dir,
             struct dentry *dentry,
             umode_t mode)
{
    struct shit_mkdir_event *e =
        bpf_ringbuf_reserve(&mkdir_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    /* Header. */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_MKDIR;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    /* AR00.5 ancestry — see inode_unlink.bpf.c for rationale. */
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    /* Parent identity via CO-RE. */
    e->parent_inode = BPF_CORE_READ(dir, i_ino);
    e->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);

    /* The umask-applied mode that will be assigned to the new dir.
     * The kernel applies `mode & ~current_umask()` before reaching
     * this hook (path_mkdirat → vfs_mkdir → security_inode_mkdir),
     * so this is the actual on-disk mode. */
    e->mode = (__u32)mode;

    /* Basename via CO-RE on the dentry's qstr. Same pattern as
     * inode_unlink. */
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    e->name_len = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
