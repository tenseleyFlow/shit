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
    /* L04.2 — `lsm/file_release` event. Fires when the kernel's
     * struct-file refcount hits zero (last fd close + last mmap
     * unmap). Userspace re-hashes the inode's current content and
     * emits a CapturedPreImage iff it differs from the open-time
     * snapshot. Closes the in-place-write gap (open(O_RDWR) +
     * write/pwrite/mmap without rename/unlink/truncate). */
    SHIT_EVT_RELEASE = 8,
    /* AU29 — `lsm/inode_mknod` event. Fires on mkfifo(3) +
     * mknod(2) for FIFO/Socket/Block/Char kinds (inode_create
     * fires only for regular-file creation). Payload reuses
     * shit_create_event; the discriminator is the S_IF bits in
     * `e->mode`. Userspace routes through on_create →
     * handle_lsm_create (same handler — kind derivation from
     * mode is shared). AU22's mknod restore path consumes the
     * resulting RecreatePath{Fifo|...} when the dentry's later
     * removed and recreated. */
    SHIT_EVT_MKNOD = 9,
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
 * the race for any direct child of the tracked root.
 *
 * ancestors: the tgids above parent_pid, nearest first
 * (grandparent, great-grandparent, ...), read at hook-fire time like
 * parent_pid. `sh -c 'chmod ...'` on a shell that forks for the last
 * command puts chmod two levels below the tracked root; by the time
 * the reader consumes the event, chmod and often sh are gone and the
 * /proc walk fails (#209). Slots past the top of the tree read 0. */
#define SHIT_ANCESTRY_DEPTH 8

struct shit_event_hdr {
    __u8  kind;
    __u8  _pad[3];
    __u32 pid;
    __u32 tgid;
    __u32 parent_pid;
    __u64 ts_ns;
    char  comm[SHIT_COMM_LEN];
    __u32 ancestors[SHIT_ANCESTRY_DEPTH];
};

/* Fill parent_pid and ancestors from the current task's parent.
 *
 * The walk stops at init (tgid 1) or at a failed read (NULL link:
 * bpf_probe_read_kernel zero-fills, so tgid reads 0). Every slot from
 * there up is written 0 without further reads; the ringbuf reservation
 * is not zeroed, so each slot is written either way. Userspace treats
 * the first 0 as "the kernel saw the whole chain".
 *
 * Cost: two probe reads (real_parent, tgid) per level walked, plus one
 * for parent_pid. A shell command under a desktop or CI session is
 * typically 5 to 8 levels below init, so 11 to 17 reads per event, at
 * most 17. Each read is a bounded copy of a few bytes, so this adds well
 * under a microsecond to the hook. */
static __always_inline void shit_fill_ancestry(struct shit_event_hdr *h,
                                               struct task_struct *parent)
{
    __u32 tgid = BPF_CORE_READ(parent, tgid);
    struct task_struct *t = parent;
    h->parent_pid = tgid;
#pragma unroll
    for (int i = 0; i < SHIT_ANCESTRY_DEPTH; i++) {
        if (tgid > 1) {
            t = BPF_CORE_READ(t, real_parent);
            tgid = BPF_CORE_READ(t, tgid);
        } else {
            tgid = 0;
        }
        h->ancestors[i] = tgid;
    }
}

/* Max bytes captured for a file's basename. Matches kernel NAME_MAX.
 * Used as the buffer size in `shit_unlink_event::name`. We do NOT
 * include the trailing NUL count in NAME_MAX; the buffer carries one
 * extra byte so a NUL-terminated basename always fits. */
#define SHIT_NAME_MAX 255

/* Every BPF object that includes this header gets a private, one-element
 * loss counter.  The LSM programs deliberately allow the syscall when their
 * ring buffer is full, but a failed reserve must not be invisible: userspace
 * polls this map and counts every increase as dropped events (capture is
 * incomplete for the commands active at that time).
 *
 * This is an ARRAY rather than a ring-buffer "loss event" because a full
 * ringbuf could not carry that event either.  Atomic add is required because
 * the same hook can run concurrently on several CPUs.  Unsigned wrap is part
 * of the ABI; userspace computes deltas with wrapping subtraction. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_loss_count SEC(".maps");

/* #229: the same losses, keyed by the tgid whose event was dropped, with
 * that process's ancestry at the time of the drop. Userspace attributes
 * each tgid's increase to the command whose tree holds it, the same way
 * it attributes events, so an overflow caused by an unrelated process
 * does not count against every active command.
 *
 * LRU: under a storm of distinct tgids old entries are evicted and their
 * counts vanish. Userspace notices because the per-tgid increases then
 * fall short of `ringbuf_loss_count`, and charges the shortfall to every
 * active command, as before this map existed. The per-tgid update runs
 * before the total's, so a reader that reads the total first never sees
 * a total the per-tgid entries cannot cover yet. */
struct shit_loss_rec {
    __u64 count;
    __u32 parent_pid;
    __u32 _pad;
    __u32 ancestors[SHIT_ANCESTRY_DEPTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct shit_loss_rec);
} ringbuf_loss_by_tgid SEC(".maps");

static __always_inline void shit_note_ringbuf_loss(void)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct shit_loss_rec *rec = bpf_map_lookup_elem(&ringbuf_loss_by_tgid, &tgid);
    if (rec) {
        __sync_fetch_and_add(&rec->count, 1);
    } else {
        struct shit_event_hdr h = {};
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        shit_fill_ancestry(&h, BPF_CORE_READ(t, real_parent));
        struct shit_loss_rec fresh = {};
        fresh.count = 1;
        fresh.parent_pid = h.parent_pid;
#pragma unroll
        for (int i = 0; i < SHIT_ANCESTRY_DEPTH; i++) {
            fresh.ancestors[i] = h.ancestors[i];
        }
        if (bpf_map_update_elem(&ringbuf_loss_by_tgid, &tgid, &fresh, BPF_NOEXIST) != 0) {
            /* Another CPU inserted it first. */
            rec = bpf_map_lookup_elem(&ringbuf_loss_by_tgid, &tgid);
            if (rec) {
                __sync_fetch_and_add(&rec->count, 1);
            }
        }
    }

    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&ringbuf_loss_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

/* #233: inode numbers of the directories above a file's dentry, nearest
 * first, so userspace can tell a file outside the watched tree from one
 * in an unwalked part of it when the event carries no path. The walk
 * follows d_parent within the superblock and stops at its root
 * (d_parent == self); `dentry_depth` is the number of slots filled, and
 * `dentry_top` is 1 when the walk reached the superblock root. `nlink`
 * is the inode's link count: a file with more than one name may also
 * live inside the tree under another name, so userspace ignores the
 * walk for it. */
#define SHIT_DENTRY_DEPTH 16

struct shit_dentry_chain {
    __u32 nlink;
    __u16 dentry_depth;
    __u16 dentry_top;
    __u64 dentry_anc[SHIT_DENTRY_DEPTH];
};

static __always_inline void shit_fill_dentry_chain(struct shit_dentry_chain *c,
                                                   struct dentry *d)
{
    struct inode *ino = BPF_CORE_READ(d, d_inode);
    c->nlink = BPF_CORE_READ(ino, __i_nlink);
    __u16 depth = 0;
    __u16 top = 0;
#pragma unroll
    for (int i = 0; i < SHIT_DENTRY_DEPTH; i++) {
        struct dentry *p = 0;
        if (!top && d) {
            p = BPF_CORE_READ(d, d_parent);
            if (!p || p == d) {
                top = 1;
                p = 0;
            }
        }
        if (p) {
            c->dentry_anc[i] = BPF_CORE_READ(p, d_inode, i_ino);
            depth++;
        } else {
            c->dentry_anc[i] = 0;
        }
        d = p;
    }
    /* The loop may stop on the last slot without having looked one level
     * higher: check whether that ancestor is the root. */
    if (!top && d) {
        struct dentry *p = BPF_CORE_READ(d, d_parent);
        if (!p || p == d) {
            top = 1;
        }
    }
    c->dentry_depth = depth;
    c->dentry_top = top;
}

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
    struct shit_dentry_chain chain;
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
    struct shit_dentry_chain chain;
};

/* lsm/file_release — last-fd-close (incl. final mmap unmap).
 * Same body layout as shit_open_event for wire economy (the two
 * carry the same scalar set). Userspace dispatches by `kind`
 * tag, not struct identity. The release-handler re-hashes the
 * inode's content and emits CapturedPreImage iff it differs
 * from the pre-image stashed at pre_open_tree time. */
struct shit_release_event {
    struct shit_event_hdr hdr;
    __u64 dev;
    __u64 inode;
    __u32 f_mode;
    __u32 f_flags;
    struct shit_dentry_chain chain;
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
