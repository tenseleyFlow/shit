/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `file_release` (L04.2).
 *
 * Fires when the kernel's struct file's refcount hits zero — the
 * last close(2) of a writable fd (plus the last mmap unmap for
 * MAP_SHARED regions). The hook:
 *
 *   1. Filters BPF-side on `f_mode & FMODE_WRITE`. Read-only
 *      releases (the common case) never reach userspace; the
 *      ringbuf only carries closes that could have committed
 *      content changes.
 *   2. Captures (dev, inode, f_mode, f_flags) so userspace can
 *      diff the inode's current content against the open-time
 *      `pre_snapshots` entry and emit a `CapturedPreImage` iff
 *      they differ.
 *   3. Always returns 0 (ALLOW). LSM hooks never block.
 *
 * The companion to `lsm/file_open`: open-time we snapshot the
 * pre-image (via `pre_open_tree` at WatchTree, or via
 * handle_lsm_open's race-snapshot); release-time we confirm
 * whether the snapshot actually needs to become a journaled
 * FilePreImage event. Closes the in-place-write gap where
 * `open(O_RDWR) + write(2)/pwrite(2)/mmap` never fires
 * unlink/setattr/O_TRUNC.
 *
 * LSM hook signature (verified via vmlinux.h on hasu 7.0.8):
 *   int file_release(struct file *file);
 *
 * Single-arg hook; no mnt_idmap drift across the supported
 * kernel matrix. Cross-check BTF before declaring done — see
 * bpf_lsm_signature_drift memory note.
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* FMODE_WRITE is a kernel #define (linux/fs.h), not exposed in
 * vmlinux.h BTF. Mirror its value here. Stable across all
 * supported kernels (5.7+). Same constant as file_open.bpf.c. */
#define SHIT_FMODE_WRITE 0x2

/* 256 KiB ringbuf — same sizing as the other LSM programs. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} release_events SEC(".maps");

SEC("lsm/file_release")
int BPF_PROG(shit_file_release, struct file *file)
{
    /* Filter in BPF: skip read-only releases. The common case is
     * read-only file lookups (PATH searches, cat $libfoo, etc.);
     * carrying those would multiply ringbuf traffic by ~100x for
     * no signal. */
    fmode_t f_mode = BPF_CORE_READ(file, f_mode);
    if (!(f_mode & SHIT_FMODE_WRITE)) {
        return 0;
    }

    struct shit_release_event *e =
        bpf_ringbuf_reserve(&release_events, sizeof(*e), 0);
    if (!e) {
        /* Ringbuf full — drop the event, ALLOW the syscall. */
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_RELEASE;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    /* AR00.5 ancestry — see inode_unlink.bpf.c for rationale. */
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    /* f_inode is populated for any file-backed struct file. For
     * anon-inode releases (memfd, perf fd), the pre_snapshots
     * lookup in userspace simply misses and the event is dropped
     * silently. */
    struct inode *target = BPF_CORE_READ(file, f_inode);
    e->dev = BPF_CORE_READ(target, i_sb, s_dev);
    e->inode = BPF_CORE_READ(target, i_ino);

    e->f_mode = (__u32)f_mode;
    e->f_flags = BPF_CORE_READ(file, f_flags);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
