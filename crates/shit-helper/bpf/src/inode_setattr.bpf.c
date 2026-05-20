/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_setattr` (L04 phase 3).
 *
 * Fires on every `chmod(2)` / `chown(2)` / `utimes(2)` / `truncate(2)`
 * before the kernel applies the change. The hook:
 *
 *   1. Reads (dev, inode) of the target file.
 *   2. Reads pre-change (mode, uid, gid, size) from `dentry->d_inode`.
 *   3. Reads requested-change (mode, uid, gid, size, ia_valid) from
 *      the `struct iattr *attr` argument.
 *   4. Pushes a `shit_setattr_event` onto the userspace ringbuf.
 *   5. Returns 0 (always ALLOW).
 *
 * HP-18 / blast radius: same contract as inode_unlink.bpf.c. Never
 * blocks the syscall; verifier-rejection on a kernel diff would
 * break every chmod on the affected box. Mitigations are identical:
 *
 *   - Strict CO-RE via BPF_CORE_READ for every kernel-struct field.
 *   - No unbounded loops; straight-line code.
 *   - Always returns 0.
 *   - Ringbuf-reserve failures drop the event silently.
 *
 * LSM hook signature (kernel 6.3+):
 *   int inode_setattr(struct mnt_idmap *idmap,
 *                     struct dentry *dentry,
 *                     struct iattr *attr);
 *
 * On 5.12–6.2 the first arg was `struct user_namespace *mnt_userns`;
 * on pre-5.12 it was absent. We use the 6.3+ signature here — hasu
 * runs 7.0.8 so verifier-attach succeeds. Back-compat for older
 * kernels in a follow-up.
 *
 * Verified on hasu (NixOS, kernel 7.0.8).
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* 256 KiB ringbuf — same sizing as unlink_events. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} setattr_events SEC(".maps");

/* Kernel ATTR_* bit positions in `struct iattr::ia_valid`. These are
 * stable across the 5.7+ window (linux/fs.h). Mirror only the ones
 * we re-emit on the wire in common.h's SHIT_ATTR_* set. */
#define KERN_ATTR_MODE  (1 << 0)
#define KERN_ATTR_UID   (1 << 1)
#define KERN_ATTR_GID   (1 << 2)
#define KERN_ATTR_SIZE  (1 << 3)
#define KERN_ATTR_ATIME (1 << 4)
#define KERN_ATTR_MTIME (1 << 5)
#define KERN_ATTR_CTIME (1 << 6)

static __always_inline __u32 translate_ia_valid(__u32 ia_valid)
{
    __u32 out = 0;
    if (ia_valid & KERN_ATTR_MODE)  out |= SHIT_ATTR_MODE;
    if (ia_valid & KERN_ATTR_UID)   out |= SHIT_ATTR_UID;
    if (ia_valid & KERN_ATTR_GID)   out |= SHIT_ATTR_GID;
    if (ia_valid & KERN_ATTR_SIZE)  out |= SHIT_ATTR_SIZE;
    if (ia_valid & KERN_ATTR_ATIME) out |= SHIT_ATTR_ATIME;
    if (ia_valid & KERN_ATTR_MTIME) out |= SHIT_ATTR_MTIME;
    if (ia_valid & KERN_ATTR_CTIME) out |= SHIT_ATTR_CTIME;
    return out;
}

SEC("lsm/inode_setattr")
int BPF_PROG(shit_inode_setattr,
             struct mnt_idmap *idmap,
             struct dentry *dentry,
             struct iattr *attr)
{
    struct shit_setattr_event *e =
        bpf_ringbuf_reserve(&setattr_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    /* Header. */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_SETATTR;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    /* Identify the file. */
    struct inode *target = BPF_CORE_READ(dentry, d_inode);
    e->inode = BPF_CORE_READ(target, i_ino);
    e->dev = BPF_CORE_READ(target, i_sb, s_dev);

    /* Pre-change values from the live inode. */
    e->old_mode = BPF_CORE_READ(target, i_mode);
    e->old_uid = BPF_CORE_READ(target, i_uid.val);
    e->old_gid = BPF_CORE_READ(target, i_gid.val);
    e->old_size = BPF_CORE_READ(target, i_size);

    /* Requested-change values from the iattr. ia_valid tells us
     * which fields are meaningful; we still copy them all into the
     * event since the userspace decoder masks based on attr_valid. */
    __u32 ia_valid = BPF_CORE_READ(attr, ia_valid);
    e->attr_valid = translate_ia_valid(ia_valid);
    e->new_mode = BPF_CORE_READ(attr, ia_mode);
    e->new_uid = BPF_CORE_READ(attr, ia_uid.val);
    e->new_gid = BPF_CORE_READ(attr, ia_gid.val);
    e->new_size = BPF_CORE_READ(attr, ia_size);
    e->_pad3 = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
