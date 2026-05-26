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
    SHIT_EVT_CREATE = 5,
    SHIT_EVT_RENAME = 6,
    /* G03 — `lsm/inode_rmdir` event. Same struct shape as
     * shit_unlink_event (the kernel LSM hook signature is identical:
     * (inode *dir, dentry *target)). Userspace dispatches by kind tag
     * and routes to handle_lsm_rmdir, which fstat's the held fd for
     * the dir's mode so the planner can emit RecreatePath{Directory,
     * <captured mode>} instead of mkdir-p'ing at the default 0o755. */
    SHIT_EVT_RMDIR = 7,
};

/* Bounded comm length matches kernel's TASK_COMM_LEN. */
#define SHIT_COMM_LEN 16

/* Common header at the start of every event. Userspace decodes the
 * kind byte first, then casts to the kind-specific tail.
 *
 * parent_pid: the kernel `task->real_parent->tgid` at hook-fire time.
 * Captured in BPF so userspace can match the event's process tree
 * against tracked roots WITHOUT a `/proc/<pid>/stat` walk -- short-
 * lived subprocesses (`rm`, `mv`, `chmod`, `mkdir`, etc.) exit
 * between the syscall and the userspace ringbuf consume; their
 * `/proc` entries are then gone and a `/proc`-based ancestry walk
 * fails. The smoke shell (the WatchTree root_pid) is still alive,
 * so checking `parent_pid` directly against the tracked root closes
 * the race for any direct child of the tracked root. Deeper trees
 * (grandchildren and beyond) still need the slow `/proc` walk as a
 * fallback, but most CLI tools spawned by a shell are direct
 * children. */
struct shit_event_hdr {
    __u8  kind;
    __u8  _pad[3];
    __u32 pid;
    __u32 tgid;
    __u32 parent_pid;
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

/* `ia_valid` bit set on `struct iattr` for the fields the syscall
 * wants to change. We mirror the kernel's ATTR_* constants here so
 * the userspace decoder doesn't have to depend on a kernel header.
 * Only the ones we care about for undo (mode/uid/gid/utime/size) are
 * exported; the rest of ATTR_* (KILL_SUID, FILE, etc.) are kernel
 * internal. */
#define SHIT_ATTR_MODE  (1 << 0)
#define SHIT_ATTR_UID   (1 << 1)
#define SHIT_ATTR_GID   (1 << 2)
#define SHIT_ATTR_SIZE  (1 << 3)
#define SHIT_ATTR_ATIME (1 << 4)
#define SHIT_ATTR_MTIME (1 << 5)
#define SHIT_ATTR_CTIME (1 << 6)

/* lsm/inode_setattr — `chmod`/`chown`/`utimes`/`truncate`. The hook
 * fires BEFORE the kernel applies the change. We capture the
 * pre-change values from `dentry->d_inode` and the requested new
 * values from `attr`. Userspace journals "old → new" so undo can
 * replay the inverse.
 *
 * `attr_valid` is a bitmask of SHIT_ATTR_* constants indicating which
 * of the new_* fields are valid for this syscall. For chmod only
 * MODE is set; for chown UID/GID; for utimes ATIME/MTIME; etc. */
struct shit_setattr_event {
    struct shit_event_hdr hdr;
    __u64 dev;
    __u64 inode;
    __u32 attr_valid;
    /* Old (pre-change) values, read from inode at hook time. */
    __u32 old_mode;
    __u32 old_uid;
    __u32 old_gid;
    /* New (requested) values, read from iattr. Only those whose bit
     * in `attr_valid` is set are meaningful. */
    __u32 new_mode;
    __u32 new_uid;
    __u32 new_gid;
    __u32 _pad3;
    __u64 old_size;
    __u64 new_size;
};

/* lsm/inode_mkdir — `mkdir(2)` / `mkdirat(2)`. The LSM hook fires
 * BEFORE the directory is actually created, so we don't yet have a
 * (dev, inode) for the new dir — userspace stats the resolved path
 * after the syscall completes to get those. We capture:
 *   - parent_inode of the containing directory (from `struct inode
 *     *dir`),
 *   - the basename of the new directory (from `struct dentry
 *     *dentry`'s `d_name`),
 *   - the umask-applied mode the kernel will assign to it. */
struct shit_mkdir_event {
    struct shit_event_hdr hdr;
    __u64 parent_dev;
    __u64 parent_inode;
    __u32 mode;
    __u32 name_len;
    char  name[SHIT_NAME_MAX + 1];
};

/* lsm/inode_create — `open(2)` with `O_CREAT` (and `creat(2)`,
 * `mknod(2)` for regular files). Same shape as `shit_mkdir_event`
 * (we keep them separate for wire clarity / userspace dispatch).
 * Userspace stats the resolved path post-syscall to fill in
 * (dev, inode) and also opens an `O_RDONLY` fd into the pre_opens
 * table — so a subsequent inode_unlink for the same file can
 * dup that fd and read pre-image content via the
 * open-fd-survives-unlink trick. */
struct shit_create_event {
    struct shit_event_hdr hdr;
    __u64 parent_dev;
    __u64 parent_inode;
    __u32 mode;
    __u32 name_len;
    char  name[SHIT_NAME_MAX + 1];
};

/* lsm/file_open — every `open(2)` / `openat(2)`. The BPF program
 * pre-filters to write-intent (FMODE_WRITE in `file->f_mode`) so
 * the ringbuf only carries opens that will mutate the file. We
 * carry both `f_mode` and `f_flags` so userspace can distinguish
 * O_TRUNC (will truncate, capture pre-image NOW) from O_APPEND
 * (will append, content blob still useful). */
struct shit_open_event {
    struct shit_event_hdr hdr;
    __u64 dev;
    __u64 inode;
    __u32 f_mode;
    __u32 f_flags;
};

/* lsm/inode_rename — `rename(2)` / `renameat2(2)`. Captures
 * (old_parent_inode, old_basename) -> (new_parent_inode,
 * new_basename) for both ends. (dev, inode) is invariant across
 * rename on the same filesystem. */
struct shit_rename_event {
    struct shit_event_hdr hdr;
    __u64 dev;
    __u64 inode;
    __u64 old_parent_inode;
    __u64 new_parent_inode;
    __u32 old_name_len;
    __u32 new_name_len;
    char  old_name[SHIT_NAME_MAX + 1];
    char  new_name[SHIT_NAME_MAX + 1];
};

#endif /* SHIT_BPF_COMMON_H */
