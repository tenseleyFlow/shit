/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * shit-helper — eBPF-LSM hook on `file_open` (L04.1).
 *
 * Fires inside the `open(2)` / `openat(2)` syscall path AFTER the
 * fd is allocated but BEFORE userspace can write through it. The
 * hook:
 *
 *   1. Reads `file->f_mode` and filters out non-write-intent opens
 *      (FMODE_WRITE bit). This dramatically cuts ringbuf traffic —
 *      typical workloads do ~100x more read opens than writes.
 *   2. Reads `file->f_inode->{i_ino, i_sb->s_dev}` for ID.
 *   3. Reads `file->f_flags` for downstream userspace logic
 *      (distinguish O_TRUNC, O_APPEND, etc.).
 *   4. Ringbufs `shit_open_event`. Always returns 0.
 *
 * Companion to `lsm/inode_unlink`: file_open captures the
 * about-to-be-modified file's pre-image at userspace time via the
 * pre_opens fd that handle_lsm_open dups from. The fanotify-perm
 * tier captured this same wire via FAN_OPEN_PERM; under the LSM
 * tier file_open is the equivalent trigger.
 *
 * LSM hook signature (verified via vmlinux.h on hasu 7.0.8):
 *   int file_open(struct file *file);
 *
 * Single-arg hook; no mnt_idmap. The wrong-signature gotcha from
 * the memory note doesn't apply here, but always cross-check BTF
 * before declaring done.
 */

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* FMODE_WRITE is a kernel #define (linux/fs.h), not exposed in
 * vmlinux.h BTF. Mirror its value here. Stable across all
 * supported kernels (5.7+). */
#define SHIT_FMODE_WRITE 0x2

/* 256 KiB ringbuf — same sizing as the other LSM programs. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} open_events SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(shit_file_open, struct file *file)
{
    /* Filter in BPF: skip read-only opens. */
    fmode_t f_mode = BPF_CORE_READ(file, f_mode);
    if (!(f_mode & SHIT_FMODE_WRITE)) {
        return 0;
    }

    struct shit_open_event *e =
        bpf_ringbuf_reserve(&open_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->hdr.kind = SHIT_EVT_OPEN;
    e->hdr.pid = (__u32)pid_tgid;
    e->hdr.tgid = (__u32)(pid_tgid >> 32);
    e->hdr.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    /* AR00.5 ancestry — see inode_unlink.bpf.c for rationale. */
    struct task_struct *__t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *__parent = BPF_CORE_READ(__t, real_parent);
    e->hdr.parent_pid = BPF_CORE_READ(__parent, tgid);

    /* f_inode is what the kernel populates for any file with a
     * persistent backing (regular files, dirs, FIFOs, sockets,
     * device files). For anon-inode opens (memfd, perf fd) it's
     * an anonymous inode whose dev/inode aren't useful — but the
     * pre_opens lookup will simply miss in those cases. */
    struct inode *target = BPF_CORE_READ(file, f_inode);
    e->dev = BPF_CORE_READ(target, i_sb, s_dev);
    e->inode = BPF_CORE_READ(target, i_ino);

    e->f_mode = (__u32)f_mode;
    e->f_flags = BPF_CORE_READ(file, f_flags);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
