/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_symlink` (DR-CR-55).
 *
 * Fires on every `symlink(2)` / `symlinkat(2)`. Mirrors the
 * `inode_create` design exactly: emit a `shit_create_event` into a
 * dedicated ringbuf, userspace stats the resolved path post-syscall
 * to fill in the (dev, inode) of the new symlink, journals a
 * `TreeOp::Create` event. Undo's inverse is `Unlink(link_path)` —
 * removes the symlink without touching the target (the target was
 * a separate pre-existing inode whose nlink count we never
 * modified).
 *
 * Reusing the create-event shape (vs. defining a `shit_symlink_event`
 * with the target string) trades fidelity for code-reuse: we lose
 * the ability to RE-create the symlink with the same target on undo,
 * but `Unlink` doesn't need that — and a future PR can promote this
 * to a richer event type if a different smoke needs symlink
 * recreation.
 *
 * LSM hook signature (verified via hasu kernel 7.0.8 BTF, stable
 * across the 5.7+ window — no mnt_idmap drift to worry about):
 *   int inode_symlink(struct inode *dir, struct dentry *dentry,
 *                     const char *old_name);
 *
 * `old_name` is the target string the symlink will point at. We
 * deliberately don't read it into the event — userspace would have
 * to truncate to NAME_MAX anyway, and the unlink-as-undo path
 * doesn't need it.
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
} symlink_events SEC(".maps");

SEC("lsm/inode_symlink")
int BPF_PROG(shit_inode_symlink,
             struct inode *dir,
             struct dentry *dentry,
             const char *old_name)
{
    struct shit_create_event *e =
        bpf_ringbuf_reserve(&symlink_events, sizeof(*e), 0);
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
    /* S_IFLNK | 0o777 — the canonical mode for symlinks; the kernel
     * sets it explicitly and ignores any umask for symlinks. */
    e->mode = 0120777;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    e->name_len = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
