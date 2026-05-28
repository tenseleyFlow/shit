/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `inode_mknod` (AU29).
 *
 * Captures FIFO / Socket / Block / Char device creation that
 * `inode_create` doesn't see. The kernel routes `mkfifo(3)` and
 * device creation via `mknod(2)` through `vfs_mknod` →
 * `security_inode_mknod`, NOT `security_inode_create` (which fires
 * for regular-file `open(O_CREAT)` / `creat(2)`).
 *
 * Wire shape: same `shit_create_event` payload as inode_create
 * (parent_dev/parent_inode/mode/name). Userspace routes both via
 * `on_create` → `handle_lsm_create`; the discriminator is the mode
 * bits (S_IF*) carried in `e->mode`. AU22's helper-IPC mknod
 * restore path consumes the resulting RecreatePath{Fifo|Socket|...}
 * with byte-identical kind.
 *
 * LSM hook signature (verified via vmlinux.h on hasu 7.0.8):
 *   int inode_mknod(struct inode *dir, struct dentry *dentry,
 *                   umode_t mode, dev_t dev);
 *
 * The `dev` arg matters only for Block/Char devices (where it
 * encodes major:minor). For FIFOs (the AU22-load-bearing case)
 * it's zero. We don't ship it on the wire in this iteration —
 * DR-15.2 (Block/Char restore) will plumb it through when it
 * lands.
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
} mknod_events SEC(".maps");

SEC("lsm/inode_mknod")
int BPF_PROG(shit_inode_mknod,
             struct inode *dir,
             struct dentry *dentry,
             umode_t mode,
             dev_t dev)
{
    struct shit_create_event *e =
        bpf_ringbuf_reserve(&mknod_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    /* AU29 ships its own event tag so userspace can route mknod
     * events through a dedicated handler if a future change wants
     * to (current handler reuses on_create). */
    e->hdr.kind = SHIT_EVT_MKNOD;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    e->parent_inode = BPF_CORE_READ(dir, i_ino);
    e->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
    /* mode carries the full S_IFMT|perm composite — the wire MUST
     * preserve the S_IF bits so the daemon's kind_from_mode_bits
     * recovers Fifo/Socket/Block/Char correctly. (For inode_create
     * the bits are always S_IFREG so it doesn't matter; for mknod
     * they're load-bearing.) */
    e->mode = (__u32)mode;
    /* Suppress unused-arg warning; AU22 ships without dev plumbing.
     * DR-15.2 will plumb dev through when Block/Char restore lands. */
    (void)dev;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    e->name_len = 0;
    long n = bpf_core_read_str(&e->name, sizeof(e->name), name_ptr);
    if (n > 0) {
        e->name_len = (__u32)(n - 1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
