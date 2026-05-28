// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux fanotify-perm-driven pre-image capture producer (L01).
//!
//! Mirrors the BSD producer at `capture/bsd.rs` but with two
//! event-source differences:
//!
//! 1. Events arrive from the fanotify reader thread already running
//!    in `fanotify/runtime.rs`, not from a kqueue drain loop. The
//!    runtime calls `LinuxCaptureRuntime::handle_event` synchronously
//!    inside `process_batch`'s `decide` closure.
//! 2. The fd we read the pre-image from is the kernel-provided fd
//!    inside `fanotify_event_metadata.fd`, not a subtree-tracked fd.
//!    fanotify opens a fresh fd per event; we close it after use.
//!
//! Dedupe model: identical to BSD. `BTreeMap<(dev, inode), DedupeEntry>`
//! per CommandId. First write per inode produces a CapturedPreImage.
//! Delete events flip `invalidated=true` so a subsequent open of the
//! same inode (the reuse-after-rm case) re-captures.
//!
//! Hot-path budget: capture-then-ALLOW must complete in ≤10ms p99 (the
//! `CAPTURE_TO_ALLOW` budget gate codified in
//! `benches/regression/src/lib.rs`). The fanotify-perm protocol allows
//! the kernel to back up perm events behind a slow userspace responder;
//! taking >50ms (`CAPTURE_KERNEL_DEADLINE`) creates queue overflow.
//! The staging-fd upload path (write blob to a temp file, send the fd
//! via SCM_RIGHTS, ALLOW immediately, daemon does its blake3 verify
//! asynchronously) is what keeps us under budget.
//!
//! Concurrency model: the runtime is owned by the helper's main task
//! and shared with the fanotify reader thread via `Arc<Mutex<...>>`.
//! The mutex critical section is the dedupe lookup + send_response_with_fd
//! — both microsecond-scale operations. Reader and request loops
//! never both hold this mutex for long enough to contend.

// Module is cfg-gated at the `pub mod linux;` declaration in
// `capture/mod.rs`; no inner `#![cfg(...)]` here so unit tests aren't
// accidentally filtered out on Linux.

// L01 chunk 2 — handle_event body is in. FanotifyCaptureKind +
// FanotifyEventView + path_for_kernel_fd stay dead until chunk 4
// wires fanotify/runtime.rs to construct views.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shit_planner::events::CommandId;
use shit_proto::HelperResponse;

use crate::ipc::Conn;

/// Bounded pre-image read size. Larger files ALLOW without capture
/// and log `partial=true` on the event (L04 may revisit). 256 MiB is
/// the open question default from L01 design notes — small enough to
/// avoid OOM under hostile inputs, large enough to catch real
/// user-edit-huge-file scenarios.
pub const MAX_PRE_IMAGE_BYTES: usize = 256 * 1024 * 1024;

/// Per-CommandId capture state. Lazy: created on the first event for
/// a tracked command and dropped when the command's
/// `HelperRequest::UnwatchTree` clears it.
#[derive(Debug, Default)]
struct WatchState {
    /// `(dev, inode) → DedupeEntry`. First-write-wins per inode.
    dedupe: BTreeMap<(u64, u64), DedupeEntry>,
    /// Pre-opened fds for files in the watched cwd. Populated by
    /// `pre_open_tree` at WatchTree time (L04 / Linux mirror of
    /// BSD `register_subtree`'s open-fd-survives-unlink trick). The
    /// LSM-unlink handler dups these to read the pre-image after the
    /// dentry is gone — the inode stays alive while the fd is open.
    pre_opens: BTreeMap<(u64, u64), OwnedFd>,
    /// L04.1 — Pre-image content + metadata snapshot, taken at
    /// `pre_open_tree` time (or `handle_lsm_create` time for files
    /// born mid-session). Unlike `pre_opens` (which races against
    /// `do_truncate` in the `file_open` LSM hook path), this is an
    /// in-memory copy taken BEFORE any LSM event fires. The
    /// file_open and inode_setattr handlers read from this snapshot
    /// instead of dup-and-reading the live fd — race-free.
    ///
    /// Sized cap per entry: [`MAX_PRE_IMAGE_BYTES`]. Files larger
    /// than the cap skip the snapshot (LSM events for them will be
    /// dropped at handler time — same fail-mode as fanotify's
    /// over-budget files).
    pre_snapshots: BTreeMap<(u64, u64), PreSnapshot>,
    /// Watch root absolute path, recorded at `pre_open_tree` time
    /// (the cwd that the shell's PreExec frame supplied). Used by
    /// every LSM event handler (unlink/create/mkdir/rename) to
    /// resolve `(parent_dir + basename)` into an absolute path WITHOUT
    /// going through `/proc/<pid>/cwd` -- that procfs symlink only
    /// lives as long as the mutating pid does, and the BPF→ringbuf→
    /// helper-handler hop is async wrt syscall completion + process
    /// exit. Issue #22: when the mutating process exited before the
    /// handler ran, the readlink fell back to a literal
    /// `/proc/<dead-pid>/cwd/...` string that was journaled and
    /// then ENOENT'd at undo time.
    cwd: Option<PathBuf>,
    /// AR01.1.fix-pre-open-tree-recursion — `(dev, inode) → absolute
    /// path` for every directory visited by `pre_open_tree` (including
    /// the watch root itself). LSM event handlers look up the
    /// parent inode here to reconstruct the full path for files
    /// in subdirectories. Pre-AR01.1 the handlers always joined
    /// `ws.cwd + basename`, which produced wrong paths like
    /// `repo/index.lock` for git's `.git/index.lock`.
    ///
    /// Populated lazily: `handle_lsm_mkdir` also inserts the new dir's
    /// (dev, inode) → path so subsequent nested events resolve.
    dir_paths: BTreeMap<(u64, u64), PathBuf>,
    /// AR01.3 follow-up: deferred create events whose parent dir
    /// wasn't yet in `dir_paths` when the handler ran. Per-program
    /// ringbuf readers run on separate threads serialized via
    /// `Mutex<runtime>` -- kernel-syscall ordering does NOT guarantee
    /// userspace dispatch ordering, so under bulk-create workloads
    /// (cp -r, etc.) handle_lsm_create can win the mutex before
    /// handle_lsm_mkdir for the same parent. Pre-AR01.3-fix this
    /// resulted in dropped TreeOpCreate events => files left on disk
    /// post-undo. The fix queues here, then drains in
    /// handle_lsm_mkdir's post-stat insert path once the parent
    /// becomes resolvable.
    ///
    /// Keyed by `(parent_dev_userspace, parent_inode)`. Bounded:
    /// each entry holds the basename + create mode + originating pid;
    /// max live entries == number of nested files in flight before
    /// their mkdir handler runs (typically <100 for real workloads).
    /// Drained at session-close as a safety net.
    pending_creates: BTreeMap<(u64, u64), Vec<PendingCreate>>,
    /// AR01.1.fix-rename-target-preimage — reverse of `dir_paths` +
    /// regular-file paths: `absolute_path → (dev, inode)`. Populated
    /// by `pre_open_tree` for every opened file and by
    /// `handle_lsm_create` for files born mid-session.
    ///
    /// The `inode_rename` LSM hook can clobber an existing destination
    /// (think `mv old new` where `new` already exists; or git's
    /// atomic `.git/index.lock → .git/index` swap). At handler time
    /// the rename has already completed, so stat'ing the destination
    /// path returns the NEW inode -- the OLD one is gone. To capture
    /// the about-to-be-clobbered content as a `FilePreImage`, we look
    /// up the destination path here PRE-rename-handler-update and find
    /// the OLD inode, then read its pre-snapshot.
    path_to_inode: BTreeMap<PathBuf, (u64, u64)>,
    /// AU17 — count of `send_response{_with_fd}` failures within this
    /// watch window. Every Err returning from a daemon-IPC send that
    /// would have shipped a CapturedPreImage / TreeMutation increments
    /// this. Logged loudly at `on_unwatch_tree` so the operator can
    /// see when capture events were lost mid-session (daemon socket
    /// disrupted, helper IPC saturated).
    ///
    /// AU17 ships VISIBILITY only — non-zero counts emit a WARN at
    /// session-close. Surfacing the degraded state on the wire so
    /// `shit undo` flags it to the user is a follow-up sprint.
    ///
    /// Counts only TRUE wire failures (daemon socket disconnected,
    /// write returned Err) — NOT dedupe-skips or other intentional
    /// short-circuits.
    silent_send_failures: u32,
}

impl WatchState {
    /// AU17 — increment the silent-send-failure counter (saturating
    /// at u32::MAX). Called from every `send_response{_with_fd}` Err
    /// path in this module.
    fn note_silent_send_failure(&mut self) {
        self.silent_send_failures = self.silent_send_failures.saturating_add(1);
    }
}

/// AR01.1.fix-pre-open-tree-recursion — bounded recursion depth for
/// `pre_open_tree`. Matches the BSD `register_subtree` and fanotify
/// `mark_dir_for_capture` defaults. Real-world load (a fresh
/// `git init` repo + a few commits): `.git/objects/XX/` is depth 3
/// from the repo root; depth 8 covers nested workloads (e.g.
/// `dst/sub1/sub2/.../file` in cp-r) with margin.
const PRE_OPEN_TREE_DEPTH_LIMIT: usize = 8;

/// AR01.1.fix-pre-open-tree-recursion — soft cap on how many files
/// `pre_open_tree` will open per command. Each open consumes one fd
/// plus an in-memory snapshot (up to MAX_PRE_IMAGE_BYTES each). The
/// process rlimit defaults to ~1024 fds on most distros; we leave
/// headroom for the daemon's own sockets, the BPF ringbuf fds, and
/// staging tmpfiles. If a tree is larger than this, we log a warning
/// and stop recursing. LSM handlers then fall back to live-fd capture
/// for unsnapshotted files (same fail-mode as a too-large pre-image).
const PRE_OPEN_TREE_MAX_FILES: usize = 512;

/// L04.1 — A snapshotted pre-image. Bytes + the stat-meta as it was
/// at snapshot time (mode/uid/gid/mtime/size). Both go on the wire
/// in [`HelperResponse::CapturedPreImage`].
#[derive(Debug, Clone)]
struct PreSnapshot {
    meta: StatMeta,
    bytes: Vec<u8>,
}

/// AR01.3 follow-up: queued create event waiting for its parent dir
/// to register in `dir_paths`. Owned-data flavor (basename is `String`)
/// because we may outlive the BPF ringbuf reader's borrowed buffer.
#[derive(Debug, Clone)]
struct PendingCreate {
    command: CommandId,
    pid: u32,
    parent_dev: u64,
    parent_inode: u64,
    basename: String,
    mode: u32,
}

#[derive(Debug, Clone, Copy)]
struct DedupeEntry {
    invalidated: bool,
}

/// Fanotify event class our handler cares about. The fanotify reader
/// thread maps from `Event.mask` to this enum so the producer doesn't
/// have to know the libc bit constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyCaptureKind {
    /// `FAN_OPEN_PERM` or `FAN_ACCESS_PERM` for a write-intent open.
    /// The pre-mutation moment we want to capture.
    OpenWrite,
    /// `FAN_OPEN_EXEC_PERM`. Not currently captured — the binary's
    /// pre-state is implicit. Reserved for future shim-stacking.
    OpenExec,
    /// Deletion observed via eBPF-LSM `inode_unlink` (L04). fanotify
    /// alone doesn't surface unlink as a perm event; L01 stubs this
    /// arm and L04 fills it in.
    Delete,
}

/// View struct passed from the fanotify reader to the capture runtime.
/// Constructed in `runtime.rs` from the raw `Event` plus the resolved
/// CommandId (looked up via the `TreeMap` already there).
#[derive(Debug)]
pub struct FanotifyEventView<'a> {
    pub command: CommandId,
    pub fd: RawFd,
    pub pid: i32,
    pub kind: FanotifyCaptureKind,
    pub _life: std::marker::PhantomData<&'a ()>,
}

/// Capture runtime. Owns dedupe state per CommandId, the IPC conn to
/// the daemon, and the staging dir for SCM_RIGHTS uploads.
pub struct LinuxCaptureRuntime {
    watches: BTreeMap<CommandId, WatchState>,
    conn: Arc<Conn>,
    staging_dir: PathBuf,
}

impl LinuxCaptureRuntime {
    pub fn new(staging_dir: PathBuf, conn: Arc<Conn>) -> std::io::Result<Self> {
        std::fs::create_dir_all(&staging_dir)?;
        Ok(Self {
            watches: BTreeMap::new(),
            conn,
            staging_dir,
        })
    }

    /// Begin watching for events from descendants of a command's
    /// tracked tree. The tree-pid resolution is done by the existing
    /// `fanotify::tree::TreeMap` — this method just sets up dedupe
    /// state.
    pub fn on_watch_tree(&mut self, command: CommandId) {
        self.watches.entry(command).or_default();
    }

    /// Stop watching. Drops the dedupe state and closes all
    /// pre-opened fds; subsequent events for this command's pids
    /// fall through `handle_event` without capture (the TreeMap will
    /// have already removed the pid).
    ///
    /// AR01.3 follow-up: any create events still in `pending_creates`
    /// at session-close never had their parent mkdir resolve. Log
    /// the unresolved count as a tracing breadcrumb (operator can
    /// investigate the lost mkdir) and drop them with the rest of
    /// the WatchState.
    pub fn on_unwatch_tree(&mut self, command: CommandId) {
        if let Some(ws) = self.watches.get(&command) {
            let pending = ws.pending_creates.values().map(|v| v.len()).sum::<usize>();
            if pending > 0 {
                tracing::warn!(
                    session = %command.session,
                    seq = command.seq,
                    pending,
                    "unwatch_tree: dropping unresolved pending creates (parent mkdir never landed)"
                );
            }
            // AU17 — surface the silent-send-failure count so the
            // operator can see when capture events were lost mid-
            // session (daemon socket disrupted, helper IPC saturated).
            // The counter is incremented every time
            // `send_response{_with_fd}` returns Err inside an LSM /
            // fanotify handler. Zero is the normal case; non-zero
            // means the journal is incomplete for this command.
            // Wire + CLI warning surface (so `shit undo` flags a
            // degraded session for the user) is deferred to a
            // follow-up sprint — this commit ships visibility.
            if ws.silent_send_failures > 0 {
                tracing::warn!(
                    session = %command.session,
                    seq = command.seq,
                    silent_send_failures = ws.silent_send_failures,
                    "unwatch_tree: session capture is DEGRADED — some events were silently dropped (daemon socket failures)"
                );
            }
        }
        self.watches.remove(&command);
    }

    /// L04 — open every regular file under `cwd` and stash the
    /// OwnedFds keyed by `(dev, inode)` in this command's WatchState.
    /// Mirror of `kqueue::register_subtree` — the open fd keeps the
    /// inode alive after `vfs_unlink` drops the dentry, so the LSM
    /// unlink handler can `read_pre_image(dup(fd))` after the file
    /// is "gone".
    ///
    /// AR01.1.fix-pre-open-tree-recursion — recurses up to
    /// [`PRE_OPEN_TREE_DEPTH_LIMIT`] levels, capped at
    /// [`PRE_OPEN_TREE_MAX_FILES`] opens per command. Stays on the
    /// same filesystem (same `dev`) as the watch root so we never
    /// cross a bind mount or a tmpfs sub-mount accidentally. Records
    /// every visited directory in `ws.dir_paths` so LSM event handlers
    /// can resolve `(parent_dev, parent_inode, basename)` into an
    /// absolute path for files in subdirectories.
    ///
    /// Best-effort: per-file open errors (EACCES on protected files,
    /// ELOOP on dangling symlinks) are skipped silently. The walker
    /// continues so a single denied entry doesn't disable capture
    /// for the rest.
    ///
    /// Caller invariant: must be called BEFORE the watched command's
    /// preexec returns userspace control. The L04 main.rs WatchTree
    /// handler does this synchronously between `tree.watch()` and
    /// returning the response.
    pub fn pre_open_tree(&mut self, command: CommandId, cwd: &Path) {
        let ws = self.watches.entry(command).or_default();
        // Record the watch root so LSM handlers can resolve
        // basename → absolute path without /proc/<pid>/cwd. See
        // WatchState::cwd docs for the why (Issue #22).
        ws.cwd = Some(cwd.to_path_buf());

        // Record the watch root itself in dir_paths so events whose
        // parent_inode == watch-root's inode resolve too.
        //
        // If stat fails we MUST NOT fall back to (0,0): a later event
        // with parent_inode == 0 (which BPF emits on root-of-mount
        // failures and a few other edge cases) would alias to this
        // bogus dir_paths entry and resolve to the wrong path. Skip
        // the insert AND the recursion so the watch surfaces zero
        // events for this command instead of wrong ones.
        let root_dev_inode = match std::fs::metadata(cwd) {
            Ok(m) => (m.dev(), m.ino()),
            Err(e) => {
                tracing::error!(
                    session = %command.session,
                    seq = command.seq,
                    cwd = %cwd.display(),
                    err = %e,
                    "pre_open_tree: stat(cwd) failed; skipping dir_paths root entry and recursion to avoid (0,0) aliasing"
                );
                return;
            }
        };
        ws.dir_paths.insert(root_dev_inode, cwd.to_path_buf());

        let mut opened = 0usize;
        let mut hit_cap = false;
        pre_open_recurse(ws, cwd, root_dev_inode.0, 0, &mut opened, &mut hit_cap);

        tracing::info!(
            session = %command.session,
            seq = command.seq,
            cwd = %cwd.display(),
            opened,
            dirs = ws.dir_paths.len(),
            hit_cap,
            "pre_open_tree complete"
        );
    }

    /// Called by the fanotify reader thread per event. Returns once
    /// the kernel-side ALLOW response is ready to send. Per L01's
    /// budget: best-effort capture, never block the kernel queue.
    /// All error paths log and continue — the producer's job is to
    /// keep the kernel moving.
    ///
    /// Flow (mirror of `capture/bsd.rs::PumpState::handle_vnode`):
    ///   1. fstat the kernel-provided fd → (dev, inode, kind)
    ///   2. Bail if non-regular file (directories, fifos, sockets —
    ///      pread is invalid on those; the fanotify mark may have
    ///      caught their parent dir's open).
    ///   3. Dedupe by (dev, inode). Delete bypasses dedupe — see the
    ///      S29 bug-fix lesson in bsd.rs: the paired Unlink TreeOp
    ///      depends on the daemon seeing the Delete event.
    ///   4. Read pre-image bytes from the kernel-provided fd (capped
    ///      at MAX_PRE_IMAGE_BYTES — huge files ALLOW without capture).
    ///   5. fstat for metadata (mode/uid/gid/mtime).
    ///   6. blake3 the bytes. Daemon verifies independently before
    ///      committing the blob.
    ///   7. Write bytes to staging file; pass the fd via SCM_RIGHTS.
    ///   8. Update dedupe state.
    pub fn handle_event(&mut self, ev: &FanotifyEventView<'_>) {
        // Lazy WatchState — first event for a command initializes its
        // dedupe map. `on_watch_tree` may have been called already, in
        // which case `or_default` is a cheap lookup.
        let ws = self.watches.entry(ev.command).or_default();

        let (dev, inode, file_type) = match fstat_dev_inode_kind(ev.fd) {
            Some(t) => t,
            None => {
                tracing::warn!(fd = ev.fd, "fstat failed; skipping capture");
                return;
            }
        };

        // Directories and specials (fifo/socket/blk/chr) don't carry a
        // useful pre-image. The fanotify mark may have caught e.g. an
        // open on a directory itself (`open(O_DIRECTORY)`); ignore.
        if file_type != FileType::Regular {
            tracing::trace!(fd = ev.fd, ?file_type, "non-regular fd; skipping");
            return;
        }

        let is_delete = matches!(ev.kind, FanotifyCaptureKind::Delete);
        if !is_delete && !should_capture_dedupe(&ws.dedupe, (dev, inode)) {
            tracing::trace!(fd = ev.fd, dev, inode, "dedupe hit; skipping");
            return;
        }

        let bytes = match read_pre_image(ev.fd) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(fd = ev.fd, error = %e, "pre-image read failed");
                return;
            }
        };
        let meta = match fstat_meta(ev.fd) {
            Some(m) => m,
            None => {
                tracing::warn!(fd = ev.fd, "fstat_meta failed");
                return;
            }
        };
        let blob_hash = blake3_of(&bytes);
        let staging_fd = match write_to_staging(&self.staging_dir, &bytes) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::warn!(error = %e, "staging write failed");
                return;
            }
        };
        let path = path_for_kernel_fd(ev.fd);

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev,
            inode,
            path: path.as_deref().map(path_to_string),
            blob_hash,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            is_delete,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "send_response_with_fd failed");
            ws.note_silent_send_failure();
        }

        ws.dedupe.insert(
            (dev, inode),
            DedupeEntry {
                invalidated: is_delete,
            },
        );

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            dev,
            inode,
            kind = ?ev.kind,
            bytes = bytes.len(),
            "CapturedPreImage sent",
        );
    }

    /// L04 — handler for `lsm/inode_unlink` events delivered by the
    /// eBPF ringbuf reader. Unlike the fanotify producer, the LSM
    /// hook does NOT hand us a kernel-provided fd. We have:
    ///
    ///   * `(dev, inode)` of the about-to-be-unlinked file,
    ///   * `parent_inode` of its containing directory,
    ///   * the basename (NAME_MAX bytes max),
    ///   * the pid that issued the unlink.
    ///
    /// Race protocol: open `/proc/<pid>/cwd/<basename>` with O_RDONLY,
    /// fstat to verify (dev, inode) matches what BPF told us — defends
    /// against the cwd-moved-since-LSM-fire case. If win:
    ///
    ///   * Read pre-image bytes, blake3, write to staging, send
    ///     CapturedPreImage with the staging fd — same as fanotify.
    ///
    /// If loss (open returned ENOENT, or fstat (dev, inode) mismatch):
    ///
    ///   * Send a marker CapturedPreImage with `stored_bytes = 0` and
    ///     `fd_sent_via_scm = false`. The daemon journals the unlink
    ///     and looks for a prior pre-image blob for the same
    ///     (dev, inode) to use as the restoration source.
    ///
    /// Dedupe: this method bypasses the dedupe map's "already
    /// captured" gate (Delete events always emit) so the daemon sees
    /// the unlink. After emission the dedupe entry is marked
    /// `invalidated=true` so a subsequent reuse of the inode (e.g.
    /// rm-then-recreate) re-captures.
    pub fn handle_lsm_unlink(&mut self, ev: &LsmUnlinkView<'_>) {
        let ws = self.watches.entry(ev.command).or_default();

        // BPF reports `dev` in the kernel's `dev_t` encoding
        // (`(major << 20) | minor`). All userspace stat-derived
        // (dev, inode) keys in this runtime — including the
        // pre_opens table — use glibc's encoding (split-bits via
        // `__gnu_dev_makedev`). Convert before lookup.
        let ev_dev_userspace = kernel_dev_to_userspace(ev.dev);

        // Mark the dedupe entry invalidated up front, regardless of
        // whether we successfully journal the event below: the unlink
        // happened on the kernel side, so any future reuse of this
        // inode (rm-then-recreate within the same watch window) must
        // re-capture rather than dedupe against the now-stale entry.
        ws.dedupe.insert(
            (ev_dev_userspace, ev.inode),
            DedupeEntry { invalidated: true },
        );

        // AR01.1.fix-path-via-parent-inode — resolve strictly through
        // the dir-inode map (populated by pre_open_tree recursion + by
        // handle_lsm_mkdir as nested dirs are born). For unlink, the
        // parent's dev == the file's dev (unlink can't cross
        // filesystems), so reuse the converted file dev.
        //
        // AR01.4 forensics: the watch-root + basename fallback was
        // ACTIVELY WRONG for nested files when mkdir's userspace handler
        // raced behind the child's unlink (parent dir_paths entry
        // not yet populated). The fallback joined `repo/tmp_obj_X`
        // when the real path was `repo/.git/objects/XX/tmp_obj_X`,
        // and the planner emitted RecreatePath at the bogus location.
        // Dropping the event is correct: for top-level files the
        // resolve_via_parent path hits (the watch root IS in
        // dir_paths), and for nested files where the parent isn't
        // in dir_paths the event is unrecoverable. Losing one event
        // with a tracing breadcrumb beats journaling a corrupted path.
        let Some(resolved_path) = resolve_via_parent(
            &ws.dir_paths,
            ev_dev_userspace,
            ev.parent_inode,
            ev.basename,
        ) else {
            tracing::warn!(
                pid = ev.pid,
                parent_inode = ev.parent_inode,
                basename = ev.basename,
                "lsm unlink: parent_inode not in dir_paths; dropping event"
            );
            return;
        };

        // Look up pre-opened fd for this (dev, inode). The fd was
        // grabbed at WatchTree time by `pre_open_tree`. Even after
        // vfs_unlink completes, the inode stays alive while we hold
        // the fd — same trick BSD kqueue uses. This is the
        // deterministic capture path; race-to-open is a last-resort
        // fallback for files created mid-session.
        let (capture_fd_owned, fd_source) =
            if let Some(fd) = ws.pre_opens.remove(&(ev_dev_userspace, ev.inode)) {
                (Some(fd), "pre-opened")
            } else {
                // Fall back to race-to-open via the resolved absolute
                // path. Win window: microseconds between vfs_unlink
                // and the file's dentry being torn down -- if we
                // beat that, the inode is still accessible by path.
                // We use the already-resolved absolute path (not
                // /proc/<pid>/cwd/...) so the open works even when
                // the mutating pid has exited between hook fire and
                // handler dispatch -- same fix scope as the resolved
                // path used for the journal entry (Issue #22).
                let opened = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&resolved_path);
                match opened {
                    Ok(f) => (Some(OwnedFd::from(f)), "race"),
                    Err(_) => (None, "miss"),
                }
            };

        let (capture_dev, capture_inode, file_type) = match capture_fd_owned.as_ref() {
            Some(fd) => match fstat_dev_inode_kind(fd.as_raw_fd()) {
                Some(t) => t,
                None => (0, 0, FileType::Other),
            },
            None => (0, 0, FileType::Other),
        };

        // Validate the capture-fd matches what BPF told us.
        // Protects against:
        //   - cwd moved between LSM fire and userspace race
        //   - basename reused by a different inode in the same dir
        //   - O_NOFOLLOW caught a symlink (file_type != Regular)
        //   - pre_open_tree captured a stale (dev, inode) — guard
        //     against rare reuse.
        // `capture_dev` is glibc-encoded (from fstat); compare against
        // the converted ev_dev_userspace, not the raw kernel dev.
        //
        // G03 — directory variant. The inode_rmdir hook routes here
        // with `is_directory: true`. We treat file_type==Directory
        // as the validation target instead of Regular, AND we skip
        // content capture (dirs have no bytes). The `meta_wire`
        // still carries mode/uid/gid so the daemon's marker-only
        // path emits TreeOp::Unlink with the right kind+mode for
        // the planner's RecreatePath inverse.
        // AU29 — for non-dir unlinks we accept Regular, Fifo, and
        // Socket as valid kinds. Pre-AU29 the check hard-coded
        // Regular, so FIFO/Socket unlinks always race-lost (the
        // held fd's fstat returned Fifo/Socket which != Regular)
        // even when AU29's pre_open extension stashed an O_PATH
        // fd. (dev, inode) match is the strong identity gate;
        // kind-mismatch via inode reuse is a near-impossible race
        // and isn't load-bearing for correctness here.
        let race_won = capture_fd_owned.is_some()
            && capture_dev == ev_dev_userspace
            && capture_inode == ev.inode
            && (if ev.is_directory {
                file_type == FileType::Directory
            } else {
                matches!(
                    file_type,
                    FileType::Regular | FileType::Fifo | FileType::Socket
                )
            });
        let race_fd = capture_fd_owned;
        // Alias to keep the wire-build block below readable.
        let _ = (capture_dev, capture_inode);

        let (stored_bytes, blob_hash, staging_fd, meta_wire) = if race_won && ev.is_directory {
            // G03 — dir capture: fstat for metadata only, no bytes.
            let fd = race_fd.as_ref().unwrap().as_raw_fd();
            let meta = fstat_meta(fd);
            (0, [0u8; 32], None, meta)
        } else if race_won {
            let fd = race_fd.as_ref().unwrap().as_raw_fd();
            match (read_pre_image(fd), fstat_meta(fd)) {
                (Ok(bytes), Some(meta)) => {
                    let hash = blake3_of(&bytes);
                    match write_to_staging(&self.staging_dir, &bytes) {
                        Ok(staging) => (bytes.len() as u64, hash, Some(staging), Some(meta)),
                        Err(e) => {
                            tracing::warn!(error = %e, "lsm staging write failed");
                            (0, [0u8; 32], None, None)
                        }
                    }
                }
                (Err(e), _) => {
                    tracing::warn!(error = %e, "lsm pre-image read failed");
                    (0, [0u8; 32], None, None)
                }
                (Ok(_), None) => (0, [0u8; 32], None, None),
            }
        } else {
            tracing::info!(
                pid = ev.pid,
                dev = ev.dev,
                inode = ev.inode,
                basename = ev.basename,
                is_directory = ev.is_directory,
                "lsm unlink race lost — marker-only CapturedPreImage"
            );
            (0, [0u8; 32], None, None)
        };

        // Build wire. If we lost the race, `meta_wire` is None — set
        // mode/uid/gid/mtime to 0; the daemon's Delete-restore path
        // does not rely on these for marker-only events.
        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            // Daemon side compares against PreExec's cwd_dev which is
            // glibc-encoded; send the converted value.
            dev: ev_dev_userspace,
            inode: ev.inode,
            path: Some(resolved_path.clone()),
            blob_hash,
            stored_bytes,
            post_content_hash: None,
            mode: meta_wire.as_ref().map(|m| m.mode).unwrap_or(0),
            uid: meta_wire.as_ref().map(|m| m.uid).unwrap_or(0),
            gid: meta_wire.as_ref().map(|m| m.gid).unwrap_or(0),
            mtime_unix_nanos: meta_wire.as_ref().map(|m| m.mtime_unix_nanos).unwrap_or(0),
            xattrs: meta_wire
                .as_ref()
                .map(|m| m.xattrs.clone())
                .unwrap_or_default(),
            is_delete: true,
            fd_sent_via_scm: staging_fd.is_some(),
        };

        let send_result = if let Some(ref fd) = staging_fd {
            self.conn.send_response_with_fd(&resp, fd.as_raw_fd())
        } else {
            self.conn.send_response(&resp)
        };
        if let Err(e) = send_result {
            tracing::warn!(error = %e, "lsm send_response failed");
            ws.note_silent_send_failure();
        }

        // (Dedupe already invalidated up-front at handler entry, so
        // we don't need a second insert here -- both paths agree on
        // the same key + state.)

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev_kernel = ev.dev,
            dev_userspace = ev_dev_userspace,
            inode = ev.inode,
            race_won,
            fd_source,
            stored_bytes,
            basename = ev.basename,
            path = %resolved_path,
            "lsm-unlink CapturedPreImage sent",
        );
    }

    /// L04 phase 3 — handler for `lsm/inode_setattr` events. Captures
    /// the pre-change metadata (mode/uid/gid) reported by the BPF
    /// program. The file content is re-read from the pre-opened fd
    /// (the chmod doesn't touch content; we capture it for the
    /// CapturedPreImage wire so the daemon's blob/hash invariants
    /// hold).
    ///
    /// If no pre-opened fd exists for this (dev, inode) we drop the
    /// event — the daemon refuses CapturedPreImage without an
    /// SCM_RIGHTS fd, and a race-to-open after the change is too
    /// late to retrieve the OLD metadata (BPF gave it to us; the
    /// CONTENT race is what would fail). Future enhancement: send a
    /// metadata-only variant on the wire.
    pub fn handle_lsm_setattr(&mut self, ev: &LsmSetattrView) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev_userspace = kernel_dev_to_userspace(ev.dev);

        // Dedupe — first capture per (dev, inode) wins. Important
        // for the open(O_WRONLY|O_TRUNC) path: file_open LSM fires
        // first and captures the pre-truncate content, then
        // inode_setattr fires for the truncate. Without dedupe both
        // would journal CapturedPreImage, causing double-restore on
        // undo. The dedupe entry from file_open's handler suppresses
        // setattr's duplicate.
        if !should_capture_dedupe(&ws.dedupe, (ev_dev_userspace, ev.inode)) {
            tracing::trace!(
                dev = ev_dev_userspace,
                inode = ev.inode,
                "lsm setattr: dedupe hit; skipping (already captured this watch window)"
            );
            return;
        }

        // Read pre-change bytes from the in-memory SNAPSHOT, NOT
        // from the live fd.
        //
        // The previous code did `read_pre_image(pre_opens.get(&key))`
        // — which reads through the held fd, which sees the file's
        // CURRENT content. For chmod/chown/utimes that's fine
        // (content doesn't change). But security_inode_setattr ALSO
        // fires for O_TRUNC during open(O_WRONLY|O_TRUNC): the BPF
        // hook submits to the ringbuf, the kernel proceeds to
        // do_truncate, then the userspace handler runs and reads...
        // truncated bytes (often 0). file_open's handler would
        // produce the correct pre-image but it's deduped because
        // setattr fired first. End result: blob stores 0 bytes;
        // restore writes 0 bytes; edit-undo's sha256 mismatch.
        //
        // Use the pre_snapshot taken at pre_open_tree time — that's
        // unconditionally the pre-mutation state regardless of what
        // the setattr is doing. Matches handle_lsm_open's pattern.
        let Some(snap) = ws.pre_snapshots.get(&(ev_dev_userspace, ev.inode)).cloned() else {
            tracing::info!(
                pid = ev.pid,
                dev_kernel = ev.dev,
                dev_userspace = ev_dev_userspace,
                inode = ev.inode,
                "lsm setattr: no pre-snapshot; dropping (file not in WatchTree's cwd or too large)"
            );
            // Mark dedupe so reuse-after-event re-captures.
            ws.dedupe.insert(
                (ev_dev_userspace, ev.inode),
                DedupeEntry { invalidated: false },
            );
            return;
        };
        let bytes = snap.bytes;
        let blob_hash = blake3_of(&bytes);
        let staging_fd = match write_to_staging(&self.staging_dir, &bytes) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "lsm setattr staging write failed");
                return;
            }
        };

        // mtime: from the snapshot, taken at pre_open_tree time. Same
        // race rationale as the bytes -- the live fd sees CURRENT
        // mtime which can be post-truncate.
        let meta_mtime = snap.meta.mtime_unix_nanos;

        // Path: the pre_opens fd is still valid for path recovery
        // (the inode lives until ws is dropped). Use it if present;
        // fall back to the path_to_inode reverse lookup. AR01.1: never
        // emit an empty path -- the daemon journals path:"" which
        // becomes a ConflictMissing at undo time. Drop the event
        // instead so the operator gets a tracing breadcrumb naming
        // the (dev, inode) that escaped both lookups.
        let path = match resolve_inode_to_path(ws, ev_dev_userspace, ev.inode) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    dev = ev_dev_userspace,
                    inode = ev.inode,
                    "lsm setattr: path resolution failed (pre_opens fd + path_to_inode reverse both miss); dropping event"
                );
                return;
            }
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev_userspace,
            inode: ev.inode,
            path: Some(path_to_string(&path)),
            blob_hash,
            stored_bytes: bytes.len() as u64,
            // AU11 — `post_content_hash: None` is correct here. The
            // LSM `inode_setattr` hook is an AUTH event firing
            // pre-mutation; the kernel hasn't applied the change at
            // this point, so the held fd still shows pre-content
            // and we can't cheaply predict the post-state without
            // either (a) waiting for the corresponding `file_open`+
            // `inode_release` cycle, which `handle_lsm_release`
            // already covers with Some(post_hash), or (b) emulating
            // the kernel's setattr semantics (truncate-to-size etc.)
            // which duplicates VFS work for marginal benefit.
            post_content_hash: None,
            // Pre-change metadata from the BPF event — these are the
            // values undo restores to.
            mode: ev.old_mode,
            uid: ev.old_uid,
            gid: ev.old_gid,
            mtime_unix_nanos: meta_mtime,
            // BPF setattr view has no fd (kernel-event path);
            // chmod/chown don't change xattrs anyway, so empty.
            xattrs: std::collections::BTreeMap::new(),
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm setattr send_response_with_fd failed");
            ws.note_silent_send_failure();
        }

        ws.dedupe.insert(
            (ev_dev_userspace, ev.inode),
            DedupeEntry { invalidated: false },
        );

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev_userspace,
            inode = ev.inode,
            attr_valid = ev.attr_valid,
            old_mode = format_args!("{:o}", ev.old_mode),
            new_mode = format_args!("{:o}", ev.new_mode),
            stored_bytes = bytes.len(),
            "lsm-setattr CapturedPreImage sent",
        );
    }

    /// L04 phase 4 — handler for `lsm/inode_mkdir` events. The LSM
    /// hook fires BEFORE the dir is created, so we don't yet have a
    /// (dev, inode) for the new dir. We resolve via stat-after-the-
    /// syscall: by the time the userspace consumer drains the
    /// ringbuf (~µs after submit), the kernel has completed mkdir
    /// and the new dir exists at /proc/<pid>/cwd/<basename>.
    ///
    /// Wire: HelperResponse::TreeMutation { op: TreeOpWire::Create
    /// { kind: Directory, .. } }. No SCM_RIGHTS fd needed — dir
    /// creation has no content blob.
    pub fn handle_lsm_mkdir(&mut self, ev: &LsmMkdirView<'_>) {
        let ws = self.watches.entry(ev.command).or_default();

        // AR01.1.fix-path-via-parent-inode — resolve strictly via the
        // dir map. Parent_dev arrives in BPF kernel encoding; convert
        // before lookup. The watch-root + basename fallback was
        // ACTIVELY WRONG for nested mkdirs (see AR01.4 forensics in
        // handle_lsm_unlink); drop the event on miss instead.
        let parent_dev_userspace = kernel_dev_to_userspace(ev.parent_dev);
        let Some(resolved_dir_str) = resolve_via_parent(
            &ws.dir_paths,
            parent_dev_userspace,
            ev.parent_inode,
            ev.basename,
        ) else {
            tracing::warn!(
                pid = ev.pid,
                parent_dev = parent_dev_userspace,
                parent_inode = ev.parent_inode,
                basename = ev.basename,
                "lsm mkdir: parent_inode not in dir_paths; dropping event"
            );
            return;
        };
        let resolved_dir = PathBuf::from(&resolved_dir_str);

        // Stat to grab the (dev, inode) of the freshly-created dir.
        //
        // `security_inode_mkdir` is a PRE-creation LSM hook: it fires
        // during the permission-check phase of `do_mkdirat`, BEFORE
        // `vfs_mkdir` publishes the dentry. The userspace ringbuf
        // reader runs async wrt the syscall, so when the handler
        // hits `symlink_metadata` the dentry may or may not yet be
        // visible. The kernel work between hook fire and dentry
        // visible is bounded (microseconds in the typical path);
        // retry with a small budget rather than dropping the event.
        //
        // If the stat still fails after the retry budget, emit a
        // marker-only TreeMutation (dev=0, inode=0). The daemon's
        // undo path resolves the dir via `path` -- it doesn't strictly
        // need the (dev, inode) tuple, that's only for invariant
        // checking. Marker-only beats dropping silently.
        use std::os::unix::fs::MetadataExt;
        let stat_result = (|| {
            // Up to 10 ms total: 20 iterations at 0.5 ms each. The
            // happy path resolves on the first iteration.
            for _ in 0..20 {
                match std::fs::symlink_metadata(&resolved_dir) {
                    Ok(meta) if meta.is_dir() => return Some((meta.dev(), meta.ino())),
                    Ok(_) => return None, // exists but not a dir; surface
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        std::thread::sleep(std::time::Duration::from_micros(500));
                    }
                    Err(_) => return None,
                }
            }
            None
        })();
        let (dev, inode) = match stat_result {
            Some(t) => t,
            None => {
                tracing::warn!(
                    path = %resolved_dir.display(),
                    "lsm mkdir: post-stat not visible within 10ms retry budget; \
                     emitting marker-only (dev=0, inode=0)"
                );
                (0, 0)
            }
        };

        // AR01.1.fix-path-via-parent-inode — register the new dir's
        // (dev, inode) → path so subsequent nested events (e.g. git's
        // `.git/objects/02/abc...` create-then-write into the just-
        // -mkdir'd `02`) resolve correctly. Skip the marker-only case
        // (dev=0, inode=0); without a real (dev, inode) we can't key
        // the lookup anyway.
        //
        // AR01.3 follow-up: after registering, drain any pending
        // create events whose parent_inode just became resolvable.
        // The per-program ringbuf reader race means create handlers
        // can arrive before their parent's mkdir handler; queue +
        // drain here ensures every create still gets a TreeOpCreate
        // journaled.
        let drained = if dev != 0 {
            ws.dir_paths.insert((dev, inode), resolved_dir.clone());
            ws.pending_creates.remove(&(dev, inode)).unwrap_or_default()
        } else {
            Vec::new()
        };

        let resp = HelperResponse::TreeMutation {
            session: ev.command.session,
            seq: ev.command.seq,
            op: shit_proto::TreeOpWire::Create {
                dev,
                inode,
                path: path_to_string(&resolved_dir),
                kind: shit_proto::FileKindWire::Directory,
                mode: ev.mode,
            },
            ts_unix_nanos: now_unix_nanos(),
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "lsm mkdir send_response failed");
            ws.note_silent_send_failure();
        }

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev,
            inode,
            mode = format_args!("{:o}", ev.mode),
            path = %resolved_dir.display(),
            drained_pending = drained.len(),
            "lsm-mkdir TreeMutation sent",
        );

        // AR01.3 follow-up: drain any create events that arrived
        // before this mkdir registered the parent. Each gets a fresh
        // resolve_via_parent attempt (now guaranteed to hit) and
        // takes the standard process_lsm_create_resolved path.
        for pc in drained {
            let resolved_child = resolved_dir.join(&pc.basename);
            self.process_lsm_create_resolved(pc.command, pc.pid, resolved_child, pc.mode);
        }
    }

    /// L04 phase 5 — handler for `lsm/inode_create` events.
    ///
    /// Two-fold purpose:
    ///   1. Emits `HelperResponse::TreeMutation { op: Create {
    ///      kind: Regular, ... } }` so the daemon can journal the
    ///      file's birth and reverse it on undo (unlink the file).
    ///   2. Opens an `O_RDONLY` fd into the freshly-created file
    ///      and stashes it in `pre_opens` keyed by (dev, inode).
    ///      This extends the WatchTree-time `pre_open_tree`
    ///      coverage to files born mid-session — so a subsequent
    ///      `inode_unlink` for this file can dup the fd and read
    ///      pre-image content via the open-fd-survives-unlink
    ///      trick. Without this, `touch foo; rm foo` would lose
    ///      foo's content because race-to-open is unreliable.
    pub fn handle_lsm_create(&mut self, ev: &LsmCreateView<'_>) {
        let ws = self.watches.entry(ev.command).or_default();

        // AR01.1.fix-path-via-parent-inode — resolve strictly via the
        // dir map. AR01.4 forensics: the watch-root + basename fallback
        // for parent-miss cases produced wrong paths for nested files
        // (see handle_lsm_unlink for the full incident). Drop on miss
        // -- the inode + basename are unrecoverable to a real path
        // without the parent context.
        let parent_dev_userspace = kernel_dev_to_userspace(ev.parent_dev);
        let resolved_path_str = match resolve_via_parent(
            &ws.dir_paths,
            parent_dev_userspace,
            ev.parent_inode,
            ev.basename,
        ) {
            Some(p) => p,
            None => {
                // AR01.3 follow-up: per-program ringbuf reader race --
                // handle_lsm_mkdir for the parent hasn't run yet, so
                // dir_paths doesn't have the entry. Queue this event;
                // handle_lsm_mkdir will drain the queue after its
                // post-stat dir_paths insert. Drop is a last-resort
                // failure mode (parent mkdir never lands -- session
                // close drains for safety).
                tracing::debug!(
                    pid = ev.pid,
                    parent_dev = parent_dev_userspace,
                    parent_inode = ev.parent_inode,
                    basename = ev.basename,
                    "lsm create: parent_inode not in dir_paths; queuing for retry"
                );
                ws.pending_creates
                    .entry((parent_dev_userspace, ev.parent_inode))
                    .or_default()
                    .push(PendingCreate {
                        command: ev.command,
                        pid: ev.pid,
                        parent_dev: parent_dev_userspace,
                        parent_inode: ev.parent_inode,
                        basename: ev.basename.to_string(),
                        mode: ev.mode,
                    });
                return;
            }
        };
        let resolved_path = PathBuf::from(&resolved_path_str);

        // Note: the `ws` borrow from above goes out of scope at the
        // call below -- process_lsm_create_resolved re-borrows.
        self.process_lsm_create_resolved(ev.command, ev.pid, resolved_path, ev.mode);
    }

    /// AR01.3 follow-up: post-resolve body of `handle_lsm_create`,
    /// extracted so the `handle_lsm_mkdir` drain path can re-invoke
    /// it for queued create events whose parent has just registered
    /// in `dir_paths`.
    ///
    /// Open + stat the resolved path (race-loss tolerated via marker-
    /// only TreeOpCreate), journal the Create event, and on open
    /// success stash the fd + snapshot + reverse indices + dedupe
    /// entry. Same semantics as the inline body that lived in
    /// handle_lsm_create pre-AR01.3.
    fn process_lsm_create_resolved(
        &mut self,
        command: CommandId,
        pid: u32,
        resolved_path: PathBuf,
        mode: u32,
    ) {
        // AR01.2 race: for `touch foo; rm foo` style workloads the
        // userspace handler may race against an immediate unlink --
        // by the time we open(O_NOFOLLOW), the dentry is gone and
        // we get ENOENT. We MUST still journal a TreeOpCreate so the
        // planner can emit an Unlink inverse; otherwise touch-edit
        // round-trips leave the freshly-created file on disk
        // post-undo. Marker-only (dev=0, inode=0) for the race-lost
        // path; same shape `handle_lsm_mkdir` already uses for its
        // PRE-creation hook visibility race.
        //
        // AU29 — add O_NONBLOCK so a FIFO open (mknod-routed
        // creation) doesn't block waiting for a writer. No-op for
        // regular files; gives O_RDONLY-style fd for FIFOs that
        // can be fstat'd. Sockets return ENXIO and fall to the
        // marker-only path (which still journals the TreeOpCreate
        // wire above).
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&resolved_path)
            .ok();

        let (dev, inode, file_type) = match opened
            .as_ref()
            .and_then(|f| fstat_dev_inode_kind(f.as_raw_fd()))
        {
            Some(t) => t,
            None => {
                tracing::warn!(
                    path = %resolved_path.display(),
                    "lsm create: post-open/fstat race lost; emitting marker TreeOpCreate (dev=0, inode=0)"
                );
                (0, 0, FileType::Regular)
            }
        };
        // AU29 — accept Fifo / Socket here (mknod routes through
        // this same handler via on_create). Pre-AU29 the
        // hard-coded `!= Regular` check skipped FIFOs/Sockets
        // even when their birth was captured, so the planner
        // never got a TreeOpCreate to invert.
        let wire_kind = match file_type {
            FileType::Regular => shit_proto::FileKindWire::Regular,
            FileType::Fifo => shit_proto::FileKindWire::Fifo,
            FileType::Socket => shit_proto::FileKindWire::Socket,
            _ => {
                // O_NOFOLLOW caught a symlink, dir (impossible here
                // since process_lsm_mkdir handles that), or Other
                // (Block/Char device, marker-only race-lost).
                tracing::trace!(
                    path = %resolved_path.display(),
                    ?file_type,
                    "lsm create: unsupported post-stat kind; skipping"
                );
                return;
            }
        };

        let path_str = path_to_string(&resolved_path);
        let resp = HelperResponse::TreeMutation {
            session: command.session,
            seq: command.seq,
            op: shit_proto::TreeOpWire::Create {
                dev,
                inode,
                path: path_str.clone(),
                kind: wire_kind,
                mode,
            },
            ts_unix_nanos: now_unix_nanos(),
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "lsm create send_response failed");
            // AU17 — `ws` from handle_lsm_create's scope is gone;
            // re-borrow here. Best-effort (the watch may have been
            // unwatched mid-flight, in which case the counter has
            // nowhere to go and we just log the warn above).
            if let Some(ws) = self.watches.get_mut(&command) {
                ws.note_silent_send_failure();
            }
            return;
        }

        // If we won the open race, do the L04.1 snapshot + fd-stash.
        // If we lost (marker-only above), skip — there's no fd to
        // stash, no bytes to snapshot, and subsequent open/setattr
        // handlers for inode=0 won't hit the snapshot cache anyway.
        if let Some(f) = opened {
            let ws = self.watches.entry(command).or_default();
            let fd_raw = f.as_raw_fd();
            // AU29 — only read content bytes for regular files.
            // FIFOs/Sockets have no bytes; read_pre_image would
            // return an empty Vec or fail. Skip the snapshot but
            // still stash the fd in pre_opens for the unlink
            // race-win path.
            if file_type == FileType::Regular
                && let (Ok(bytes), Some(meta)) = (read_pre_image(fd_raw), fstat_meta(fd_raw))
            {
                ws.pre_snapshots
                    .insert((dev, inode), PreSnapshot { meta, bytes });
            }
            ws.pre_opens.insert((dev, inode), OwnedFd::from(f));
            // AR01.1.fix-rename-target-preimage — reverse-index so a
            // later rename-over-this-path resolves the (dev, inode).
            ws.path_to_inode.insert(resolved_path.clone(), (dev, inode));
            // AR01.1 follow-up: mark this inode dedupe-captured so the
            // subsequent file_open (for the first write into this newly-
            // created file) is suppressed.
            ws.dedupe
                .insert((dev, inode), DedupeEntry { invalidated: false });
        }

        tracing::info!(
            session = %command.session,
            seq = command.seq,
            pid,
            dev,
            inode,
            mode = format_args!("{:o}", mode),
            path = path_str,
            "lsm-create TreeMutation sent + fd stashed in pre_opens",
        );
    }

    /// L04.1 — handler for `lsm/file_open` events (write-intent
    /// opens only; BPF pre-filtered). Mirrors fanotify-perm's
    /// OpenWrite path:
    ///   1. Look up `(dev, inode)` in `pre_opens` (the fd held since
    ///      WatchTree, or inserted by `handle_lsm_create` for files
    ///      born mid-session). dup it.
    ///   2. Read pre-image content from the dup'd fd (the kernel
    ///      hasn't applied O_TRUNC yet at LSM-hook-fire time, so
    ///      the file's content is still the pre-overwrite state).
    ///   3. Dedupe on `(dev, inode)` — first write-open per inode
    ///      wins, identical to fanotify's policy.
    ///   4. Emit `CapturedPreImage` (is_delete=false) via
    ///      SCM_RIGHTS, same wire as the fanotify path.
    ///
    /// Files never seen before (not in pre_opens) are dropped
    /// silently — they were opened without a pre-WatchTree
    /// existence and no `inode_create` saw their birth. This is the
    /// race-lost case; future enhancement could race-to-open via
    /// /proc/<pid>/fd/<n>, but that requires resolving the fd's
    /// path which BPF doesn't capture in this hook.
    pub fn handle_lsm_open(&mut self, ev: &LsmOpenView) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev = kernel_dev_to_userspace(ev.dev);

        // Dedupe: first write-open per (dev, inode) per watch window.
        if !should_capture_dedupe(&ws.dedupe, (ev_dev, ev.inode)) {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm open: dedupe hit; skipping"
            );
            return;
        }

        // L04.1 — read pre-image from the in-memory SNAPSHOT, NOT
        // from the live fd. The live fd would race against
        // `do_truncate` (which fires immediately after our LSM
        // hook returns 0) and read zero bytes. The snapshot was
        // taken at pre_open_tree time, before any LSM event fired.
        let Some(snap) = ws.pre_snapshots.get(&(ev_dev, ev.inode)).cloned() else {
            tracing::trace!(
                dev_kernel = ev.dev,
                dev_userspace = ev_dev,
                inode = ev.inode,
                "lsm open: no pre-snapshot; dropping (file not in WatchTree's cwd or too large)"
            );
            return;
        };
        let bytes = snap.bytes;
        let meta = snap.meta;
        let blob_hash = blake3_of(&bytes);
        let staging_fd = match write_to_staging(&self.staging_dir, &bytes) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "lsm open staging write failed");
                return;
            }
        };
        // Path resolution. AR01.1: never emit an empty path -- see
        // handle_lsm_setattr for the rationale.
        let path = match resolve_inode_to_path(ws, ev_dev, ev.inode) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    dev = ev_dev,
                    inode = ev.inode,
                    "lsm open: path resolution failed; dropping event"
                );
                return;
            }
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev,
            inode: ev.inode,
            path: Some(path_to_string(&path)),
            blob_hash,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm open send_response_with_fd failed");
            ws.note_silent_send_failure();
        }

        ws.dedupe
            .insert((ev_dev, ev.inode), DedupeEntry { invalidated: false });

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev,
            inode = ev.inode,
            f_flags = format_args!("{:#x}", ev.f_flags),
            bytes = bytes.len(),
            "lsm-open CapturedPreImage sent",
        );
    }

    /// L04.2 — handler for `lsm/file_release` events. Closes the
    /// in-place-write capture gap.
    ///
    /// Fires once per writable last-fd-close (incl. final mmap
    /// unmap). Flow:
    ///
    /// 1. Look up `pre_snapshots[(dev, inode)]`. Miss → drop. The
    ///    file wasn't in the watch tree at PreExec; outside our
    ///    undo surface.
    /// 2. Check dedupe. If another handler (unlink, setattr, open)
    ///    already captured for this inode in the watch window,
    ///    skip — that handler's bytes are authoritative.
    /// 3. Re-hash the file's current bytes via the held
    ///    `pre_opens` fd. Compare to the snapshot's hash.
    /// 4. Match → no actual mutation (writable open with no
    ///    committed changes, common case for tools that probe
    ///    + don't write). Drop the event silently.
    /// 5. Differ → emit CapturedPreImage with snapshot bytes +
    ///    `post_content_hash = Some(current_hash)` for daemon-side
    ///    conflict detection. Mark dedupe to suppress later
    ///    releases for the same inode in this watch window.
    pub fn handle_lsm_release(&mut self, ev: &LsmReleaseView) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev = kernel_dev_to_userspace(ev.dev);

        // Dedupe: another LSM handler may have already captured
        // for this (dev, inode) in this watch window. First handler
        // wins; release defers.
        if !should_capture_dedupe(&ws.dedupe, (ev_dev, ev.inode)) {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm release: dedupe hit; skipping"
            );
            return;
        }

        // Snapshot lookup. Miss means the file wasn't in the tree
        // at pre_open_tree (created mid-session, outside the cwd
        // tree, or too large for the cap). Either way, nothing to
        // diff against — drop silently.
        let Some(snap) = ws.pre_snapshots.get(&(ev_dev, ev.inode)).cloned() else {
            tracing::trace!(
                dev_kernel = ev.dev,
                dev_userspace = ev_dev,
                inode = ev.inode,
                "lsm release: no pre-snapshot; dropping"
            );
            return;
        };

        // Need the held fd to re-read the post-state. pre_opens
        // owns it for the watch window; we borrow.
        let Some(held_fd) = ws.pre_opens.get(&(ev_dev, ev.inode)) else {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm release: pre-snapshot present but no held fd; dropping"
            );
            return;
        };
        let raw_fd = held_fd.as_raw_fd();

        // Read current content. read_pre_image dups + seeks, so
        // we don't disturb the shared file offset.
        let current_bytes = match read_pre_image(raw_fd) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    dev = ev_dev,
                    inode = ev.inode,
                    error = %e,
                    "lsm release: read_pre_image failed; dropping"
                );
                return;
            }
        };
        let pre_hash = blake3_of(&snap.bytes);
        let post_hash = blake3_of(&current_bytes);
        if pre_hash == post_hash {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm release: content unchanged; no event"
            );
            return;
        }

        // Content changed. Emit pre-image with the open-time
        // snapshot bytes and the post-state hash.
        let pre_bytes = snap.bytes;
        let meta = snap.meta;
        let staging_fd = match write_to_staging(&self.staging_dir, &pre_bytes) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "lsm release staging write failed");
                return;
            }
        };
        let path = match resolve_inode_to_path(ws, ev_dev, ev.inode) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    dev = ev_dev,
                    inode = ev.inode,
                    "lsm release: path resolution failed; dropping event"
                );
                return;
            }
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev,
            inode: ev.inode,
            path: Some(path_to_string(&path)),
            blob_hash: pre_hash,
            stored_bytes: pre_bytes.len() as u64,
            post_content_hash: Some(post_hash),
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm release send_response_with_fd failed");
            ws.note_silent_send_failure();
        }

        ws.dedupe
            .insert((ev_dev, ev.inode), DedupeEntry { invalidated: false });

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev,
            inode = ev.inode,
            f_flags = format_args!("{:#x}", ev.f_flags),
            pre_bytes = pre_bytes.len(),
            post_bytes = current_bytes.len(),
            "lsm-release CapturedPreImage sent (content diff)",
        );
    }

    /// L04.1 — handler for `lsm/inode_rename` events. Emits
    /// `HelperResponse::TreeMutation { op: Rename { from, to, ... } }`.
    /// Both paths resolved post-syscall via /proc/<pid>/cwd for the
    /// flat-tree case; the smoke + L02/L03 don't exercise nested
    /// renames in v1.
    pub fn handle_lsm_rename(&mut self, ev: &LsmRenameView<'_>) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev = kernel_dev_to_userspace(ev.dev);

        // AR01.1.fix-path-via-parent-inode — resolve strictly via the
        // dir map. Rename can't cross filesystems, so both parents
        // share ev_dev. AR01.4 forensics: the watch-root + basename
        // fallback produced wrong paths for nested files; drop on miss.
        let Some(from_path) =
            resolve_via_parent(&ws.dir_paths, ev_dev, ev.old_parent_inode, ev.old_basename)
        else {
            tracing::warn!(
                pid = ev.pid,
                old_parent_inode = ev.old_parent_inode,
                basename = ev.old_basename,
                "lsm rename: old_parent_inode not in dir_paths; dropping event"
            );
            return;
        };
        let Some(to_path) =
            resolve_via_parent(&ws.dir_paths, ev_dev, ev.new_parent_inode, ev.new_basename)
        else {
            tracing::warn!(
                pid = ev.pid,
                new_parent_inode = ev.new_parent_inode,
                basename = ev.new_basename,
                "lsm rename: new_parent_inode not in dir_paths; dropping event"
            );
            return;
        };

        // AR01.1.fix-rename-target-preimage — if the rename is going
        // to clobber an existing file (e.g. git's atomic
        // `.git/index.lock → .git/index`), the OLD destination's
        // content is destroyed in the swap. Look up the destination
        // path in our reverse index BEFORE the rename completes (the
        // lookup uses path_to_inode populated at pre_open_tree time
        // and on inode_create), find the OLD (dev, inode), and emit a
        // CapturedPreImage so the daemon journals a FilePreImage +
        // paired Unlink. Without this step the rename-over loses the
        // OLD destination's pre-image silently and undo can't restore
        // the prior content.
        //
        // No-clobber renames (creating a fresh name) miss in
        // path_to_inode; that's the correct behavior -- nothing to
        // capture.
        let to_path_buf = PathBuf::from(&to_path);
        if let Some(&(old_dev, old_inode)) = ws.path_to_inode.get(&to_path_buf)
            && let Some(snap) = ws.pre_snapshots.get(&(old_dev, old_inode)).cloned()
        {
            let bytes = snap.bytes;
            let meta = snap.meta;
            let blob_hash = blake3_of(&bytes);
            match write_to_staging(&self.staging_dir, &bytes) {
                Ok(staging_fd) => {
                    let resp = HelperResponse::CapturedPreImage {
                        session: ev.command.session,
                        seq: ev.command.seq,
                        dev: old_dev,
                        inode: old_inode,
                        path: Some(to_path.clone()),
                        blob_hash,
                        stored_bytes: bytes.len() as u64,
                        post_content_hash: None,
                        mode: meta.mode,
                        uid: meta.uid,
                        gid: meta.gid,
                        mtime_unix_nanos: meta.mtime_unix_nanos,
                        xattrs: meta.xattrs.clone(),
                        is_delete: true,
                        fd_sent_via_scm: true,
                    };
                    if let Err(e) = self
                        .conn
                        .send_response_with_fd(&resp, staging_fd.as_raw_fd())
                    {
                        tracing::warn!(error = %e, "lsm rename target-pre-image send_response_with_fd failed");
                        ws.note_silent_send_failure();
                    } else {
                        tracing::info!(
                            session = %ev.command.session,
                            seq = ev.command.seq,
                            pid = ev.pid,
                            old_dev,
                            old_inode,
                            bytes = bytes.len(),
                            path = %to_path,
                            "lsm-rename target pre-image CapturedPreImage sent"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "lsm rename target staging write failed");
                }
            }
        }

        let resp = HelperResponse::TreeMutation {
            session: ev.command.session,
            seq: ev.command.seq,
            op: shit_proto::TreeOpWire::Rename {
                from: from_path.clone(),
                to: to_path.clone(),
                dev: ev_dev,
                inode: ev.inode,
            },
            ts_unix_nanos: now_unix_nanos(),
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "lsm rename send_response failed");
            ws.note_silent_send_failure();
        }

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev,
            inode = ev.inode,
            from = %from_path,
            to = %to_path,
            "lsm-rename TreeMutation sent",
        );
    }
}

/// AR01.1.fix-pre-open-tree-recursion — recurse `pre_open_tree` into
/// subdirectories. Caller passes the root's `dev` and we refuse to
/// descend into entries on a different filesystem (cross-fs traversal
/// would let us open files outside the user's intent on a watched
/// repo containing a submodule's tmpfs mount). Symlinks are never
/// followed; `O_NOFOLLOW` on the open ensures the file we snapshot
/// is the one we statted.
fn pre_open_recurse(
    ws: &mut WatchState,
    dir: &Path,
    root_dev: u64,
    depth: usize,
    opened: &mut usize,
    hit_cap: &mut bool,
) {
    if depth >= PRE_OPEN_TREE_DEPTH_LIMIT {
        return;
    }
    if *opened >= PRE_OPEN_TREE_MAX_FILES {
        *hit_cap = true;
        return;
    }
    let read = match std::fs::read_dir(dir) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), err = %e, "pre_open_tree: read_dir failed");
            return;
        }
    };
    for ent in read.flatten() {
        if *opened >= PRE_OPEN_TREE_MAX_FILES {
            *hit_cap = true;
            return;
        }
        let path = ent.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            // Cross-fs guard: don't recurse into a submount.
            if meta.dev() != root_dev {
                continue;
            }
            ws.dir_paths.insert((meta.dev(), meta.ino()), path.clone());
            // G03 — also stash an O_PATH fd for the dir in pre_opens
            // so a subsequent inode_rmdir can race-win via the held
            // fd (the dentry vanishes post-rmdir; without a pinned
            // fd, fstat-by-path returns ENOENT and we lose the
            // captured mode). O_PATH doesn't require read perm and
            // works with fstat for metadata. We deliberately do NOT
            // bump `opened` here — that counter tracks regular-file
            // snapshots against PRE_OPEN_TREE_MAX_FILES; the depth
            // cap (PRE_OPEN_TREE_DEPTH_LIMIT=8) already bounds the
            // dir-fd count.
            if let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(&path)
            {
                ws.pre_opens
                    .insert((meta.dev(), meta.ino()), OwnedFd::from(f));
                ws.path_to_inode
                    .insert(path.clone(), (meta.dev(), meta.ino()));
            }
            pre_open_recurse(ws, &path, root_dev, depth + 1, opened, hit_cap);
            continue;
        }
        // AU29 — capture FIFOs and sockets with an O_PATH fd so
        // the inode_unlink LSM handler can race-win when one is
        // removed mid-session. Without this, the helper has no
        // held fd, race_won=false, and the marker-only path emits
        // meta_wire=None → wire mode=0 → daemon's
        // kind_from_mode_bits falls through to Regular → executor
        // recreates the path as a regular empty file instead of
        // dispatching mknod via the AU22 helper-IPC route.
        //
        // O_PATH works on FIFO/Socket inodes without opening for
        // I/O (no blocking write side, no socket connect). Same
        // shape as the dir branch above; fstat returns the right
        // mode bits via the held fd.
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() || ft.is_socket() {
            if let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(&path)
            {
                ws.pre_opens
                    .insert((meta.dev(), meta.ino()), OwnedFd::from(f));
                ws.path_to_inode
                    .insert(path.clone(), (meta.dev(), meta.ino()));
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(f) => f,
            Err(_) => continue,
        };
        let fd = f.as_raw_fd();
        let Some((dev, inode, FileType::Regular)) = fstat_dev_inode_kind(fd) else {
            continue;
        };
        if let (Ok(bytes), Some(meta)) = (read_pre_image(fd), fstat_meta(fd)) {
            ws.pre_snapshots
                .insert((dev, inode), PreSnapshot { meta, bytes });
        } else {
            tracing::trace!(
                dev,
                inode,
                "pre_open_tree: snapshot skipped (too large or read failed)"
            );
        }
        ws.pre_opens.insert((dev, inode), OwnedFd::from(f));
        // AR01.1.fix-rename-target-preimage — reverse-index so a
        // later rename-over-this-path can find the OLD inode.
        ws.path_to_inode.insert(path.clone(), (dev, inode));
        *opened += 1;
    }
}

/// Convert the kernel's `dev_t` encoding (`(major << 20) | minor`)
/// to glibc's userspace encoding (split-bits per `__gnu_dev_makedev`).
/// All userspace stat() values use the latter; BPF CO-RE reads of
/// `i_sb->s_dev` produce the former. Without the conversion, the
/// dedupe map and pre_opens table key mismatch with values fstat
/// returns elsewhere in the runtime.
fn kernel_dev_to_userspace(kdev: u64) -> u64 {
    let major: u64 = kdev >> 20;
    let minor: u64 = kdev & 0xfffff;
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

/// AR01.1.fix-path-via-parent-inode + AR01.4 — resolve `(parent_dev,
/// parent_inode, basename)` to an absolute path via the dir map
/// populated by `pre_open_tree` (and `handle_lsm_mkdir` for dirs born
/// mid-session). This is the ONLY path resolver for LSM events --
/// the pre-AR01.4 fallback that joined `ws.cwd + basename` when the
/// parent missed produced ACTIVELY WRONG paths for nested-dir
/// workloads (sed/git tmp objects under `.git/objects/XX/` came out
/// as `repo/tmp_obj_X`, and the planner happily emitted RecreatePath
/// at the bogus location).
///
/// Returns `None` when the parent isn't in the dir map. Callers
/// MUST drop the event in that case -- emitting at the wrong path
/// corrupts the journal and causes spurious untracked files post-undo.
/// The drop is recoverable for transient-lock-pattern workloads (no
/// inverse needed) and surfaces as a tracing warning for the rest.
///
/// `parent_dev` must already be in glibc encoding -- the same
/// encoding `pre_open_tree` keyed dir_paths with. BPF callers must
/// pass `kernel_dev_to_userspace(ev.parent_dev)` (or use the file's
/// own dev for unlink/rename, since those can't cross filesystems).
fn resolve_via_parent(
    ws_dir_paths: &BTreeMap<(u64, u64), PathBuf>,
    parent_dev: u64,
    parent_inode: u64,
    basename: &str,
) -> Option<String> {
    let parent = ws_dir_paths.get(&(parent_dev, parent_inode))?;
    Some(path_to_string(&parent.join(basename)))
}

/// View into an `lsm/inode_unlink` event as the BPF ringbuf reader
/// sees it. Borrows the basename from the decoded record; the
/// reader thread holds the storage for the duration of the dispatch.
#[derive(Debug, Clone, Copy)]
pub struct LsmUnlinkView<'a> {
    pub command: CommandId,
    pub pid: u32,
    pub dev: u64,
    pub inode: u64,
    pub parent_inode: u64,
    pub basename: &'a str,
    /// G03 — set when this event came from the `inode_rmdir` LSM
    /// hook rather than `inode_unlink`. The handler skips bytes-
    /// capture (directories have no content) and emits a marker
    /// CapturedPreImage with the dir's mode so the daemon's
    /// kind_from_mode_bits derives `Directory` and the planner's
    /// RecreatePath emits the right inverse.
    pub is_directory: bool,
}

/// View into an `lsm/inode_setattr` event as the BPF ringbuf reader
/// sees it. Old values are pre-change (read from the live inode at
/// BPF hook time); new values are what the syscall is requesting.
#[derive(Debug, Clone, Copy)]
pub struct LsmSetattrView {
    pub command: CommandId,
    pub pid: u32,
    pub dev: u64,
    pub inode: u64,
    pub attr_valid: u32,
    pub old_mode: u32,
    pub old_uid: u32,
    pub old_gid: u32,
    pub old_size: u64,
    pub new_mode: u32,
    pub new_uid: u32,
    pub new_gid: u32,
    pub new_size: u64,
}

/// View into an `lsm/inode_mkdir` event. The new directory's own
/// (dev, inode) is unknown at hook time (it doesn't exist yet);
/// userspace stats the resolved path post-syscall to fill them in.
#[derive(Debug, Clone, Copy)]
pub struct LsmMkdirView<'a> {
    pub command: CommandId,
    pub pid: u32,
    pub parent_dev: u64,
    pub parent_inode: u64,
    pub mode: u32,
    pub basename: &'a str,
}

/// View into an `lsm/inode_create` event. Same shape as
/// [`LsmMkdirView`] but for regular files — emitted via TreeMutation
/// with `FileKindWire::Regular` and additionally registers the new
/// file's `O_RDONLY` fd into `pre_opens` so a subsequent unlink can
/// capture its pre-image content.
#[derive(Debug, Clone, Copy)]
pub struct LsmCreateView<'a> {
    pub command: CommandId,
    pub pid: u32,
    pub parent_dev: u64,
    pub parent_inode: u64,
    pub mode: u32,
    pub basename: &'a str,
}

/// L04.1 — View into an `lsm/file_open` event. BPF already filtered
/// to write-intent (FMODE_WRITE set in `f_mode`); userspace's job is
/// to look up the file in `pre_opens` and stream its pre-image via
/// the same wire as fanotify-perm's OpenWrite path.
#[derive(Debug, Clone, Copy)]
pub struct LsmOpenView {
    pub command: CommandId,
    pub pid: u32,
    pub dev: u64,
    pub inode: u64,
    pub f_mode: u32,
    pub f_flags: u32,
}

/// L04.2 — View into an `lsm/file_release` event. Fires at
/// last-fd-close of a writable file; the handler diffs current
/// content against the open-time `pre_snapshot` and emits a
/// CapturedPreImage iff they differ.
#[derive(Debug, Clone, Copy)]
pub struct LsmReleaseView {
    pub command: CommandId,
    pub pid: u32,
    pub dev: u64,
    pub inode: u64,
    pub f_mode: u32,
    pub f_flags: u32,
}

/// L04.1 — View into an `lsm/inode_rename` event. Carries both
/// ends of the rename; the (dev, inode) is invariant.
#[derive(Debug, Clone, Copy)]
pub struct LsmRenameView<'a> {
    pub command: CommandId,
    pub pid: u32,
    pub dev: u64,
    pub inode: u64,
    pub old_parent_inode: u64,
    pub new_parent_inode: u64,
    pub old_basename: &'a str,
    pub new_basename: &'a str,
}

/// Decide whether the producer should emit a pre-image capture for
/// the given `(dev, inode)` given the current dedupe map state.
///
/// First-write-wins per (dev, inode) within a watch window. A delete
/// flips `invalidated=true`, which lets the *next* write re-capture —
/// handles inode reuse and the rm-then-recreate pattern.
///
/// Factored out as a pure function so the dedupe logic is testable
/// without spinning up a real fanotify event source.
fn should_capture_dedupe(map: &BTreeMap<(u64, u64), DedupeEntry>, key: (u64, u64)) -> bool {
    match map.get(&key) {
        None => true,
        Some(e) if e.invalidated => true,
        Some(_) => false,
    }
}

/// fstat that also returns the file kind. Mirror of BSD helper —
/// fanotify hands us a kernel-opened fd per event; we use it for
/// dedupe (dev, inode) and for the pre-image read.
fn fstat_dev_inode_kind(fd: RawFd) -> Option<(u64, u64, FileType)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return None;
    }
    let kind = match (st.st_mode as libc::mode_t) & libc::S_IFMT {
        libc::S_IFREG => FileType::Regular,
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFIFO => FileType::Fifo,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::Other,
    };
    Some((st.st_dev, st.st_ino, kind))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Regular,
    Directory,
    Fifo,
    Socket,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatMeta {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_unix_nanos: i128,
    xattrs: std::collections::BTreeMap<String, Vec<u8>>,
}

impl StatMeta {
    #[allow(dead_code)] // currently unused on linux — kept for symmetry with bsd
    fn to_wire(&self) -> shit_proto::FileMetadataWire {
        shit_proto::FileMetadataWire {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime_unix_nanos: self.mtime_unix_nanos,
            xattrs: self.xattrs.clone(),
        }
    }
}

fn fstat_meta(fd: RawFd) -> Option<StatMeta> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return None;
    }
    let mtime = (st.st_mtime as i128)
        .saturating_mul(1_000_000_000)
        .saturating_add(st.st_mtime_nsec as i128);
    Some(StatMeta {
        mode: st.st_mode,
        uid: st.st_uid,
        gid: st.st_gid,
        size: st.st_size as u64,
        mtime_unix_nanos: mtime,
        xattrs: crate::capture::xattr::read_user_xattrs(fd),
    })
}

/// Resolve the kernel-provided fd to a path via `/proc/self/fd/<fd>`.
/// Best-effort: returns `None` if the symlink read fails (e.g. the
/// file was already unlinked and `/proc` cleared the link).
fn path_for_kernel_fd(fd: RawFd) -> Option<PathBuf> {
    let link = format!("/proc/self/fd/{fd}");
    std::fs::read_link(&link).ok()
}

/// AR01.1 — resolve a known `(dev, inode)` to an absolute path. Tries
/// the procfs fd-symlink first (instant lookup via the still-held
/// pre_opened fd) and falls back to a reverse iteration over
/// `ws.path_to_inode` (slower, but path_to_inode is small per
/// command -- typically <500 entries -- and only one event per
/// inode hits this fallback per watch window).
///
/// Returns `None` only if both lookups miss. Callers should drop the
/// event in that case -- emitting `CapturedPreImage` with `path=None`
/// makes the daemon journal an empty-string path which ConflictMissings
/// at undo time. Better to lose one event with a tracing breadcrumb
/// than to journal a corrupted one.
fn resolve_inode_to_path(ws: &WatchState, dev: u64, inode: u64) -> Option<PathBuf> {
    if let Some(p) = ws
        .pre_opens
        .get(&(dev, inode))
        .and_then(|f| path_for_kernel_fd(f.as_raw_fd()))
    {
        // procfs returns paths suffixed with " (deleted)" for unlinked
        // files. Trim that so the journal stores a real path; the file
        // may have been re-created at the same path or we may be
        // capturing a rename-source whose name we want intact.
        let s = p.to_string_lossy();
        if let Some(stripped) = s.strip_suffix(" (deleted)") {
            return Some(PathBuf::from(stripped));
        }
        return Some(p);
    }
    ws.path_to_inode
        .iter()
        .find(|&(_, &v)| v == (dev, inode))
        .map(|(k, _)| k.clone())
}

/// Read pre-image bytes from the kernel-provided fd. fanotify hands
/// us an fd pre-opened at the moment of the syscall — pread(2) on it
/// returns the bytes as they existed before the about-to-happen
/// mutation, even after the file is unlinked.
///
/// **Caveat for held fds (L04.1):** `dup(2)` shares the file offset
/// with the source fd. If the same source fd is used for repeated
/// `read_pre_image` calls (which is the L04 pre_opens pattern), the
/// second call would start at EOF and return zero bytes. We `lseek`
/// the dup back to 0 before reading — the share-the-offset semantic
/// of dup means this resets the original fd's offset too, which is
/// what we want for repeated reads.
fn read_pre_image(fd: RawFd) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    // Stat to size-cap; refuse to capture huge files (the kernel
    // budget cliff is 50ms — reading 4GB at ~1GB/s overshoots).
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let size = st.st_size as usize;
    if size > MAX_PRE_IMAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("pre-image size {size} exceeds cap {MAX_PRE_IMAGE_BYTES}"),
        ));
    }
    // Use a fresh File handle bound to the fd so we don't move
    // ownership — the caller owns the fd.
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Rewind to start before reading. dup shares the offset with the
    // source — without this, a held fd that's already been read once
    // (e.g. by pre_open_tree's snapshot pass) returns zero bytes on
    // subsequent reads.
    if unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(err);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
    let mut f = std::fs::File::from(owned);
    let mut buf = Vec::with_capacity(size.min(MAX_PRE_IMAGE_BYTES));
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// blake3 the bytes — same hasher the daemon side verifies against.
fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Write the captured bytes to a uniquely-named staging file under
/// `staging_dir`, return an OwnedFd suitable for SCM_RIGHTS. The
/// daemon ingests + unlinks; if it fails the file lingers and the
/// helper's GC pass cleans on the next boot.
fn write_to_staging(dir: &Path, bytes: &[u8]) -> std::io::Result<OwnedFd> {
    use std::io::Write;
    let name = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    let path = dir.join(&name);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        f.write_all(bytes)?;
        // No fsync — staging files don't need durability. The
        // SCM_RIGHTS fd is pinned by the kernel until the daemon
        // closes it; if we crash before the daemon reads, the
        // staging file is dropped by GC.
    }
    let f = std::fs::OpenOptions::new().read(true).open(&path)?;
    Ok(f.into())
}

fn path_to_string(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    String::from_utf8_lossy(p.as_os_str().as_bytes()).to_string()
}

fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// Wire-builder helper is folded into handle_event in chunk 3 — kept
// out of the skeleton to avoid an 8-arg-clippy-lint dead helper.

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use uuid::Uuid;

    fn fresh_runtime() -> (LinuxCaptureRuntime, tempfile::TempDir, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (a, _b) = crate::ipc::socketpair().expect("socketpair");
        let rt = LinuxCaptureRuntime::new(staging.path().to_path_buf(), Arc::new(a)).unwrap();
        (rt, dir, staging)
    }

    fn ghost_cmd() -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq: 0,
        }
    }

    #[test]
    fn fstat_returns_regular_for_open_file_and_directory_for_open_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe");
        std::fs::write(&path, b"x").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let (dev, inode, kind) = fstat_dev_inode_kind(f.as_raw_fd()).expect("fstat ok");
        assert!(dev > 0 || inode > 0);
        assert_eq!(kind, FileType::Regular);
        let d = std::fs::File::open(dir.path()).unwrap();
        let (_, _, dir_kind) = fstat_dev_inode_kind(d.as_raw_fd()).expect("fstat ok");
        assert_eq!(dir_kind, FileType::Directory);
    }

    #[test]
    fn read_pre_image_returns_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe");
        let expected = b"hello world".repeat(100);
        std::fs::write(&path, &expected).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let got = read_pre_image(f.as_raw_fd()).expect("pre-image read");
        assert_eq!(got, expected);
    }

    #[test]
    fn write_to_staging_round_trips_bytes() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"staging-round-trip-linux";
        let fd = write_to_staging(dir.path(), bytes).unwrap();
        let mut f = std::fs::File::from(fd);
        let mut out = Vec::new();
        f.read_to_end(&mut out).unwrap();
        assert_eq!(out.as_slice(), bytes);
    }

    #[test]
    fn blake3_of_matches_known_vector() {
        let got = blake3_of(b"");
        assert_eq!(got[..4], [0xAF, 0x13, 0x49, 0xB9]);
    }

    #[test]
    fn on_watch_tree_then_unwatch_clears_state() {
        let (mut rt, _dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        assert!(rt.watches.contains_key(&cmd));
        rt.on_unwatch_tree(cmd);
        assert!(!rt.watches.contains_key(&cmd));
    }

    /// First write per inode captures; the second is dedupe-suppressed
    /// within the same watch window. A different inode in the same
    /// watch captures independently.
    #[test]
    fn dedupe_first_write_wins() {
        let mut map: BTreeMap<(u64, u64), DedupeEntry> = BTreeMap::new();
        let key = (1u64, 42u64);
        assert!(should_capture_dedupe(&map, key));
        map.insert(key, DedupeEntry { invalidated: false });
        assert!(!should_capture_dedupe(&map, key));
        assert!(should_capture_dedupe(&map, (1, 43)));
    }

    /// `Delete` flips `invalidated=true`. The next write to the same
    /// (dev, inode) re-captures — handles the rm-then-recreate /
    /// inode-reuse cases.
    #[test]
    fn delete_invalidates_then_recaptures() {
        let mut map: BTreeMap<(u64, u64), DedupeEntry> = BTreeMap::new();
        let key = (2u64, 100u64);
        assert!(should_capture_dedupe(&map, key));
        map.insert(key, DedupeEntry { invalidated: false });
        assert!(!should_capture_dedupe(&map, key));
        // Simulate the post-Delete bookkeeping that handle_event
        // performs after a Delete-kind capture.
        map.insert(key, DedupeEntry { invalidated: true });
        assert!(should_capture_dedupe(&map, key));
    }

    /// After `on_unwatch_tree`, the WatchState is gone. A late event
    /// arriving with the same CommandId initializes a *fresh* state
    /// via `entry().or_default()` rather than panicking — the
    /// fanotify reader can race the unwatch and we must tolerate it.
    /// This test verifies the lazy-init path doesn't crash; capture
    /// still works (the late event behaves as a first event for a
    /// new window).
    #[test]
    fn late_event_after_unwatch_dropped() {
        let (mut rt, _dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        rt.on_unwatch_tree(cmd);
        assert!(!rt.watches.contains_key(&cmd));
        // Drive handle_event with a synthetic view. fd=-1 means
        // fstat will fail at step 1 and the handler returns cleanly
        // without panicking. The new WatchState lazy-inited by
        // entry().or_default() is left in place — the next real
        // unwatch will clear it.
        let view = FanotifyEventView {
            command: cmd,
            fd: -1,
            pid: 0,
            kind: FanotifyCaptureKind::OpenWrite,
            _life: std::marker::PhantomData,
        };
        rt.handle_event(&view);
        // Lazy-init left an empty WatchState; this is correctness, not a leak.
        assert!(rt.watches.contains_key(&cmd));
        assert!(rt.watches.get(&cmd).unwrap().dedupe.is_empty());
    }

    /// L04 — `handle_lsm_unlink` with a real-on-disk file (not yet
    /// unlinked at call time, simulating the "race won" case where the
    /// LSM hook fires before vfs_unlink completes). The handler should:
    ///   * open `/proc/<self>/cwd/<basename>`,
    ///   * confirm (dev, inode) match what the BPF event reported,
    ///   * read pre-image bytes,
    ///   * stage them and try to send the response.
    ///
    /// We can't easily assert the send (no daemon listening), but we
    /// CAN assert the dedupe map flipped to `invalidated=true` —
    /// proof the unlink path executed end-to-end.
    #[test]
    fn lsm_unlink_race_win_invalidates_dedupe() {
        let (mut rt, dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();

        // Create a real file in the test cwd so /proc/<self>/cwd/<name>
        // resolves. Use tempdir and chdir for hermetic isolation.
        let basename = "race-win-probe.txt";
        let path = dir.path().join(basename);
        std::fs::write(&path, b"pre-image-contents").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let (dev, inode, _) = fstat_dev_inode_kind(f.as_raw_fd()).unwrap();
        drop(f);

        // Change cwd to dir so /proc/<self>/cwd/<basename> resolves
        // to our probe file. Restore on drop via a guard.
        struct CwdGuard(PathBuf);
        impl Drop for CwdGuard {
            fn drop(&mut self) {
                if let Err(e) = std::env::set_current_dir(&self.0) {
                    tracing::warn!(
                        original = %self.0.display(),
                        err = %e,
                        "CwdGuard: failed to restore cwd on drop; subsequent tests may misbehave"
                    );
                }
            }
        }
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let _guard = CwdGuard(original);

        let view = LsmUnlinkView {
            command: cmd,
            pid: std::process::id(),
            dev,
            inode,
            parent_inode: 0,
            basename,
            is_directory: false,
        };

        rt.handle_lsm_unlink(&view);

        // Dedupe is keyed in glibc-encoded dev; the handler converts
        // from the view's kernel-encoded dev. Don't bind the test to
        // a specific encoding — just assert exactly one entry exists
        // and it's invalidated.
        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.dedupe.len(), 1, "exactly one dedupe entry");
        let entry = ws.dedupe.values().next().unwrap();
        assert!(entry.invalidated, "dedupe entry must be invalidated");
    }

    /// L04 — Race-lost path: pass a basename that doesn't exist under
    /// /proc/<self>/cwd. Handler should not panic, should mark the
    /// dedupe entry invalidated all the same, and should still attempt
    /// to send a marker (which silently fails since no daemon listens
    /// — that's the warn!() path, not an error to surface).
    #[test]
    fn lsm_unlink_race_loss_still_invalidates_dedupe() {
        let (mut rt, _dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();

        let view = LsmUnlinkView {
            command: cmd,
            pid: std::process::id(),
            dev: 0xdead_beef,
            inode: 0xcafe_babe,
            parent_inode: 0,
            basename: "this-file-does-not-exist-anywhere.xyz",
            is_directory: false,
        };

        rt.handle_lsm_unlink(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.dedupe.len(), 1, "exactly one dedupe entry");
        let entry = ws.dedupe.values().next().unwrap();
        assert!(entry.invalidated);
    }

    /// AU17 — counter mechanism: `note_silent_send_failure` is
    /// idempotent + saturating, and `on_unwatch_tree` reads the
    /// final value. Each `send_response{_with_fd}` Err branch in
    /// the handlers calls this; integration paths are mechanical
    /// line-by-line additions, validated end-to-end by smoke
    /// runners.
    #[test]
    fn silent_send_failure_counter_increments_and_saturates() {
        let mut ws = WatchState::default();
        assert_eq!(ws.silent_send_failures, 0);
        ws.note_silent_send_failure();
        ws.note_silent_send_failure();
        ws.note_silent_send_failure();
        assert_eq!(ws.silent_send_failures, 3);
        // Saturate doesn't wrap.
        ws.silent_send_failures = u32::MAX - 1;
        ws.note_silent_send_failure();
        ws.note_silent_send_failure();
        ws.note_silent_send_failure();
        assert_eq!(ws.silent_send_failures, u32::MAX);
    }

    /// AU17 — `on_unwatch_tree` logs (at warn) when the counter is
    /// non-zero. We can't easily intercept the tracing macro in
    /// unit tests, but we CAN verify the unwatch correctly clears
    /// the watch state regardless of the counter.
    #[test]
    fn on_unwatch_tree_with_silent_failures_still_clears_state() {
        let (mut rt, _dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();
        // Populate watch state + a synthetic counter value.
        rt.on_watch_tree(cmd);
        {
            let ws = rt.watches.get_mut(&cmd).expect("watch state");
            ws.silent_send_failures = 7;
        }
        rt.on_unwatch_tree(cmd);
        assert!(
            !rt.watches.contains_key(&cmd),
            "on_unwatch_tree should clear the WatchState"
        );
    }

    /// L04 — kernel→glibc dev_t conversion vector. Picked from a real
    /// hasu observation: kernel `0x800002` (major=8 minor=2) maps to
    /// glibc `0x802` (== `2050` decimal, as seen on PreExec's cwd_dev
    /// in the smoke harness log).
    #[test]
    fn kernel_dev_to_userspace_matches_observed_vector() {
        assert_eq!(kernel_dev_to_userspace(0x800002), 0x802);
        // Identity at major=0: encodings agree.
        assert_eq!(kernel_dev_to_userspace(42), 42);
    }

    /// AR01.1.fix-pre-open-tree-recursion — `pre_open_tree` must
    /// recurse into subdirectories so files like `.git/index` get a
    /// pre-snapshot. Pre-AR01.1 only depth-1 was walked, and every
    /// nested-dir workload (git, cp -r, etc.) silently lost capture
    /// for files in subdirs.
    #[test]
    fn pre_open_tree_recurses_into_subdirs_and_records_dir_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Mimic a fresh git repo layout.
        let git = root.join(".git");
        let objects = git.join("objects");
        let xx = objects.join("02");
        std::fs::create_dir_all(&xx).unwrap();
        std::fs::write(root.join("README.md"), b"top-level").unwrap();
        std::fs::write(git.join("HEAD"), b"ref: refs/heads/main").unwrap();
        std::fs::write(git.join("index"), b"index-bytes").unwrap();
        std::fs::write(xx.join("abc123"), b"blob-bytes").unwrap();

        let mut ws = WatchState {
            cwd: Some(root.to_path_buf()),
            ..Default::default()
        };
        let root_dev = std::fs::metadata(root).unwrap().dev();
        let root_ino = std::fs::metadata(root).unwrap().ino();
        ws.dir_paths
            .insert((root_dev, root_ino), root.to_path_buf());

        let mut opened = 0usize;
        let mut hit_cap = false;
        pre_open_recurse(&mut ws, root, root_dev, 0, &mut opened, &mut hit_cap);

        assert!(!hit_cap, "should not have hit max-files cap");
        // 4 regular files were created; all should be snapshotted.
        assert_eq!(opened, 4, "expected 4 files snapshotted, got {opened}");
        assert_eq!(
            ws.pre_snapshots.len(),
            4,
            "all files should have pre-snapshots"
        );
        // G03: pre_opens holds fds for both files (O_RDONLY) and dirs
        // (O_PATH) — 4 files + 3 nested dirs (.git, objects, 02).
        assert_eq!(
            ws.pre_opens.len(),
            7,
            "expected 4 file fds + 3 dir fds, got {}",
            ws.pre_opens.len()
        );
        // 4 dirs: root, .git, .git/objects, .git/objects/02.
        // (root was inserted by the caller; pre_open_recurse adds the 3 below.)
        assert_eq!(
            ws.dir_paths.len(),
            4,
            "expected 4 dirs in dir_paths (root + .git + objects + 02), got {}",
            ws.dir_paths.len()
        );
        // Spot-check: .git/objects/02 should be reachable by (dev, inode).
        let xx_md = std::fs::metadata(&xx).unwrap();
        assert_eq!(
            ws.dir_paths.get(&(xx_md.dev(), xx_md.ino())),
            Some(&xx),
            "deepest dir should be registered with its full path"
        );

        // AR01.1.fix-rename-target-preimage — every regular file must
        // be in path_to_inode so a future rename-over-this-path
        // resolves the OLD (dev, inode). G03 — dirs are also indexed
        // for the same reason (rename-over-dir uses the same map).
        assert_eq!(
            ws.path_to_inode.len(),
            7,
            "expected 4 file + 3 dir entries in path_to_inode, got {:?}",
            ws.path_to_inode
        );
        let index_md = std::fs::metadata(git.join("index")).unwrap();
        assert_eq!(
            ws.path_to_inode.get(&git.join("index")),
            Some(&(index_md.dev(), index_md.ino())),
            ".git/index should be reverse-indexed for rename-target lookup"
        );
    }

    /// AR01.1.fix-path-via-parent-inode — `resolve_via_parent` produces
    /// the correct nested-dir absolute path, where the prior
    /// flat-join resolver would have produced `repo/index.lock` for
    /// git's actual `repo/.git/index.lock`.
    #[test]
    fn resolve_via_parent_uses_dir_map() {
        let mut dir_paths: BTreeMap<(u64, u64), PathBuf> = BTreeMap::new();
        dir_paths.insert((64, 100), "/tmp/repo".into());
        dir_paths.insert((64, 200), "/tmp/repo/.git".into());
        dir_paths.insert((64, 300), "/tmp/repo/.git/objects/02".into());

        // Top-level file: parent is the watch root.
        assert_eq!(
            resolve_via_parent(&dir_paths, 64, 100, "README.md").as_deref(),
            Some("/tmp/repo/README.md")
        );
        // Nested under .git/.
        assert_eq!(
            resolve_via_parent(&dir_paths, 64, 200, "index.lock").as_deref(),
            Some("/tmp/repo/.git/index.lock")
        );
        // Deeply nested.
        assert_eq!(
            resolve_via_parent(&dir_paths, 64, 300, "abc123").as_deref(),
            Some("/tmp/repo/.git/objects/02/abc123")
        );
        // Unknown parent inode → None (caller falls back).
        assert_eq!(resolve_via_parent(&dir_paths, 64, 999, "missing"), None);
        // Wrong dev (e.g. submount) → None.
        assert_eq!(resolve_via_parent(&dir_paths, 65, 100, "README.md"), None);
    }

    /// AR01.1.fix-pre-open-tree-recursion — depth cap is enforced.
    /// Files at depth N+1 should NOT be snapshotted when the cap is N.
    #[test]
    fn pre_open_tree_honors_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Build a chain root/d1/d2/d3/.../d10/leaf.txt
        let mut p = root.to_path_buf();
        for i in 1..=10 {
            p.push(format!("d{i}"));
        }
        std::fs::create_dir_all(&p).unwrap();
        let leaf = p.join("leaf.txt");
        std::fs::write(&leaf, b"deep").unwrap();

        let mut ws = WatchState {
            cwd: Some(root.to_path_buf()),
            ..Default::default()
        };
        let root_dev = std::fs::metadata(root).unwrap().dev();

        let mut opened = 0usize;
        let mut hit_cap = false;
        pre_open_recurse(&mut ws, root, root_dev, 0, &mut opened, &mut hit_cap);

        // Depth limit is 8; leaf.txt is at depth 10. Should not be opened.
        assert_eq!(
            opened, 0,
            "leaf at depth 10 must not be opened under depth-8 cap"
        );
        // But the chain of dirs up to depth-8 should be registered.
        assert!(
            ws.dir_paths.len() >= 7,
            "expected at least 7 nested dirs in dir_paths, got {}",
            ws.dir_paths.len()
        );
        assert!(
            ws.dir_paths.len() <= 9,
            "must not exceed depth limit; got {} dirs",
            ws.dir_paths.len()
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // L04.2 — handle_lsm_release unit tests
    // ─────────────────────────────────────────────────────────────────

    /// Helper: set up a runtime with a pre_snapshot + pre_opens fd
    /// for a tempdir-resident file. Returns (rt, dir, staging,
    /// path, dev_userspace, inode). The view's `dev` field MUST be
    /// the kernel-encoded form so the handler's
    /// `kernel_dev_to_userspace` conversion reproduces the key the
    /// WatchState maps use; the returned `dev_userspace` is for
    /// asserting against the same map.
    fn release_test_setup(
        cmd: CommandId,
        pre_bytes: &[u8],
    ) -> (
        LinuxCaptureRuntime,
        tempfile::TempDir,
        tempfile::TempDir,
        PathBuf,
        u64,
        u64,
    ) {
        let (mut rt, dir, staging) = fresh_runtime();
        let path = dir.path().join("probe.txt");
        std::fs::write(&path, pre_bytes).unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        let (dev_userspace, inode, _) = fstat_dev_inode_kind(f.as_raw_fd()).unwrap();
        let meta = fstat_meta(f.as_raw_fd()).unwrap();
        let ws = rt.watches.entry(cmd).or_default();
        ws.cwd = Some(dir.path().to_path_buf());
        let root_md = std::fs::metadata(dir.path()).unwrap();
        ws.dir_paths
            .insert((root_md.dev(), root_md.ino()), dir.path().to_path_buf());
        ws.pre_snapshots.insert(
            (dev_userspace, inode),
            PreSnapshot {
                meta,
                bytes: pre_bytes.to_vec(),
            },
        );
        ws.pre_opens
            .insert((dev_userspace, inode), OwnedFd::from(f));
        ws.path_to_inode
            .insert(path.clone(), (dev_userspace, inode));
        (rt, dir, staging, path, dev_userspace, inode)
    }

    /// Re-encode a userspace dev as the kernel `(major<<20)|minor`
    /// form so a LsmReleaseView submitted to `handle_lsm_release`
    /// round-trips through `kernel_dev_to_userspace` back to the
    /// userspace key used by WatchState maps.
    fn userspace_to_kernel_dev(udev: u64) -> u64 {
        // glibc's encoding: bits 0..7 = minor low, 8..19 = major,
        // 20..31 = minor high. Recompose major/minor then re-encode
        // as (major<<20)|minor.
        let minor = (udev & 0xff) | ((udev >> 12) & 0xffff_ff00);
        let major = (udev >> 8) & 0xfff;
        (major << 20) | (minor & 0xfffff)
    }

    /// L04.2 — happy path: pre-snapshot present, post-write content
    /// differs → handler runs to completion, marks dedupe entry.
    #[test]
    fn handle_lsm_release_emits_on_content_diff() {
        let cmd = ghost_cmd();
        let (mut rt, _dir, _staging, path, dev_userspace, inode) =
            release_test_setup(cmd, b"before-bytes");

        // Mutate in place — no rename, no truncate.
        std::fs::write(&path, b"after-bytes!").unwrap();

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,    // FMODE_WRITE
            f_flags: 0o002, // O_RDWR
        };
        rt.handle_lsm_release(&view);

        let ws = rt.watches.get(&cmd).expect("watch state");
        // Dedupe entry inserted, NOT invalidated (it's a content
        // capture, not a delete).
        let entry = ws
            .dedupe
            .get(&(dev_userspace, inode))
            .expect("dedupe entry inserted");
        assert!(
            !entry.invalidated,
            "release dedupe entry must not be invalidated"
        );
    }

    /// L04.2 — no-change path: pre-snapshot present, content
    /// unchanged → no dedupe entry, no event.
    #[test]
    fn handle_lsm_release_skips_when_unchanged() {
        let cmd = ghost_cmd();
        let (mut rt, _dir, _staging, _path, dev_userspace, inode) =
            release_test_setup(cmd, b"identical-bytes");

        // No write — content matches snapshot.

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,
            f_flags: 0o002,
        };
        rt.handle_lsm_release(&view);

        let ws = rt.watches.get(&cmd).expect("watch state");
        assert!(
            !ws.dedupe.contains_key(&(dev_userspace, inode)),
            "unchanged content must not insert a dedupe entry"
        );
    }

    /// L04.2 — dedupe-hit path: another handler already captured for
    /// this inode → release skips without re-reading.
    #[test]
    fn handle_lsm_release_skips_when_already_captured() {
        let cmd = ghost_cmd();
        let (mut rt, _dir, _staging, path, dev_userspace, inode) =
            release_test_setup(cmd, b"original");

        // Mark dedupe as if an earlier handler captured.
        {
            let ws = rt.watches.get_mut(&cmd).unwrap();
            ws.dedupe
                .insert((dev_userspace, inode), DedupeEntry { invalidated: false });
        }

        // Mutate content to make sure the early-return is the only
        // reason no work happens.
        std::fs::write(&path, b"mutated-but-deduped").unwrap();

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,
            f_flags: 0o002,
        };
        rt.handle_lsm_release(&view);

        let ws = rt.watches.get(&cmd).expect("watch state");
        // Still exactly one entry; release didn't add a duplicate.
        assert_eq!(ws.dedupe.len(), 1, "exactly one dedupe entry");
    }

    /// L04.2 — miss path: file wasn't in pre_open_tree's snapshot
    /// (created mid-session, outside cwd tree, or oversized) →
    /// silent drop, no dedupe entry.
    #[test]
    fn handle_lsm_release_drops_when_no_snapshot() {
        let (mut rt, _dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            dev: 0xdead_beef,
            inode: 0xcafe_babe,
            f_mode: 0x2,
            f_flags: 0o002,
        };
        rt.handle_lsm_release(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert!(
            ws.dedupe.is_empty(),
            "no pre-snapshot must produce no dedupe entry"
        );
    }
}
