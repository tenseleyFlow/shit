/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Event-struct definitions shared across the L04 LSM hook programs
 * (inode_unlink, inode_setattr, inode_mkdir, file_open). Mirrored on
 * the userspace side in `crates/shit-helper/src/ebpf/ringbuf_reader.rs`
 * via `#[repr(C)]` structs; keep the two in sync.
 *
 * Include ORDER in each .bpf.c file:
 *   1. vmlinux.h    (provides __u8/__u32/__u64/__s32 + kernel structs)
 *   2. bpf/bpf_helpers.h (SEC, __uint, bpf_*)
 *   3. bpf/bpf_core_read.h, bpf/bpf_tracing.h
 *   4. common.h     (this file)
 *
 * common.h DOES NOT include vmlinux.h itself — vmlinux.h is huge
 * (~140k lines) and the compile cost difference between "include it
 * once per .c" vs "include it transitively from common.h" matters at
 * iteration speed. We forward-declare the few types we need here so
 * stand-alone LSP/IDE reads of common.h don't fail; vmlinux.h's
 * typedefs are identical so the redefinitions are safe (C11). */

#ifndef SHIT_BPF_COMMON_H
#define SHIT_BPF_COMMON_H

/* No type forward-declarations — vmlinux.h is the source of truth
 * for __u8/__u32/__u64. This file MUST be included AFTER vmlinux.h
 * in every .bpf.c. Standalone LSP/IDE reads of this file will show
 * "unknown type" diagnostics on the bare integer types; that's
 * expected. The build (which sees vmlinux.h first) compiles clean. */

/* Wire-shared event-kind tag in the first byte of every ringbuf
 * record. Lets a single ringbuf carry multiple event kinds if we
 * consolidate later; v1 ships one ringbuf per program for clarity. */
enum shit_event_kind {
    SHIT_EVT_UNLINK = 1,
    SHIT_EVT_SETATTR = 2,
    SHIT_EVT_MKDIR = 3,
    SHIT_EVT_OPEN = 4,
};

/* Bounded comm length matches kernel's TASK_COMM_LEN. */
#define SHIT_COMM_LEN 16

/* Common header at the start of every event. Userspace decodes the
 * kind byte first, then casts to the kind-specific tail. */
struct shit_event_hdr {
    __u8  kind;
    __u8  _pad[3];
    __u32 pid;
    __u32 tgid;
    __u32 _pad2;
    __u64 ts_ns;
    char  comm[SHIT_COMM_LEN];
};

/* Max bytes captured for a file's basename. Matches kernel NAME_MAX.
 * Used as the buffer size in `shit_unlink_event::name`. We do NOT
 * include the trailing NUL count in NAME_MAX; the buffer carries one
 * extra byte so a NUL-terminated basename always fits. */
#define SHIT_NAME_MAX 255

/* lsm/inode_unlink — `rm`-style deletes. dev/inode identify the
 * about-to-be-unlinked file; (parent_inode, name) are captured so
 * userspace can race-to-open `/proc/<pid>/cwd/<name>` (or any other
 * candidate parent) before vfs_unlink completes its d_drop.
 *
 * `name_len` is the byte length of the basename (excluding NUL),
 * clamped to SHIT_NAME_MAX. Set to 0 if the read failed (defensive —
 * the userspace consumer treats name_len==0 as "name unavailable",
 * falls back to marker-only handling). */
struct shit_unlink_event {
    struct shit_event_hdr hdr;
    __u64 dev;
    __u64 inode;
    __u64 parent_inode;
    __u32 name_len;
    __u32 _pad3;
    char  name[SHIT_NAME_MAX + 1];
};

#endif /* SHIT_BPF_COMMON_H */
