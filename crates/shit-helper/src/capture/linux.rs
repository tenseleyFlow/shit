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
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shit_planner::events::CommandId;
use shit_proto::HelperResponse;

use crate::capture::streaming::{
    STREAM_COPY_CAP, StreamError, hash_fd_contents, inode_size, stream_copy_to_staging_path,
};
use crate::fanotify::event_loop::Decision;
use crate::ipc::Conn;

/// Bounded pre-image read size. Larger files ALLOW without capture
/// and log `partial=true` on the event.
///
/// AU25 — bumped from 256 MiB to 1 GiB (= [`STREAM_COPY_CAP`]) now
/// that the LSM capture path streams through a 64 KiB buffer
/// instead of materializing the whole file into `Vec<u8>`. The cap
/// is a wall-clock + disk-budget guard, not a memory guard.
pub const MAX_PRE_IMAGE_BYTES: usize = STREAM_COPY_CAP as usize;

/// Total immutable pre-command bytes retained for one command. The baseline
/// walker may visit up to 512 regular files, but it must never turn that count
/// limit into hundreds of GiB of helper memory or staging-disk pressure. A
/// complete baseline above 1 GiB is refused before `WatchTreeReady`; there is
/// no partial-ready mode.
const MAX_STAGED_BYTES_PER_COMMAND: u64 = 1024 * 1024 * 1024;

/// Maximum number of writable-file close observations held while a matching
/// `inode_create` callback catches up on its independent ring-buffer reader.
/// A full map is fail-closed: additional distinct inodes increment
/// `pending_release_overflows` and make the command non-undoable at close.
const MAX_PENDING_RELEASES: usize = 512;

/// Same bounded cross-reader correlation window for `file_open` events that
/// can beat their authoritative `inode_create` callback in userspace.
const MAX_PENDING_OPENS: usize = 512;

/// Same bounded correlation window for `inode_setattr` observations whose
/// inode may be awaiting its authoritative `inode_create` callback.
const MAX_PENDING_SETATTRS: usize = 512;

/// Maximum number of create records waiting for a parent-directory reader to
/// catch up. Overflow is remembered and refused at command close.
const MAX_PENDING_CREATES: usize = 512;

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
    /// L04.1 — Immutable pre-image staging fd + metadata/hash, taken at
    /// `pre_open_tree` time (or `handle_lsm_create` time for files
    /// born mid-session). Unlike `pre_opens` (which races against
    /// `do_truncate` in the `file_open` LSM hook path), this is an
    /// unlinked staging copy taken BEFORE any LSM event fires. The
    /// file_open and inode_setattr handlers read from this snapshot
    /// instead of dup-and-reading the live fd — race-free.
    ///
    /// Sized cap per entry: [`MAX_PRE_IMAGE_BYTES`]. Files larger
    /// than the cap skip the snapshot (LSM events for them will be
    /// dropped at handler time — same fail-mode as fanotify's
    /// over-budget files).
    pre_snapshots: BTreeMap<(u64, u64), PreSnapshot>,
    /// Aggregate bytes retained by `pre_snapshots`. This is bounded by
    /// [`MAX_STAGED_BYTES_PER_COMMAND`] and decremented when inode reuse
    /// replaces an older snapshot.
    staged_bytes: u64,
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
    /// Total records across every `pending_creates` bucket.
    pending_create_count: usize,
    /// Create records rejected at [`MAX_PENDING_CREATES`].
    pending_create_overflows: u32,
    /// Writable-file closes that arrived before the matching `inode_create`
    /// callback installed its snapshot. Each BPF program has an independent
    /// ring-buffer reader, so userspace mutex acquisition can invert those
    /// callbacks even though the kernel create happened first.
    ///
    /// Keyed by userspace `(dev, inode)` and bounded by
    /// [`MAX_PENDING_RELEASES`]. A late create removes and retries the close.
    /// After the v9 close barrier has flushed every reader, any entries still
    /// present are genuine snapshot misses and are converted to a command-wide
    /// refusal in `on_unwatch_tree`.
    pending_releases: BTreeMap<(u64, u64), LsmReleaseView>,
    /// Number of distinct release observations that could not be queued due
    /// to [`MAX_PENDING_RELEASES`]. Saturating and surfaced as capture loss at
    /// command close; capacity pressure must never silently lose evidence.
    pending_release_overflows: u32,
    /// Write-intent opens waiting to learn whether the inode was born during
    /// this command. A matching authoritative Create is the complete inverse
    /// for such a file, so the create handler suppresses rather than retries
    /// these observations after its TreeMutation reaches the wire.
    pending_opens: BTreeMap<(u64, u64), LsmOpenView>,
    /// Distinct open observations dropped at [`MAX_PENDING_OPENS`]. Surfaced
    /// as capture loss at command close.
    pending_open_overflows: u32,
    /// Metadata mutations awaiting proof that the inode was born during this
    /// command. If Create reaches the wire, unlinking that new inode is the
    /// complete inverse and these observations are suppressed. Otherwise they
    /// fail closed after the reader-flush barrier.
    pending_setattrs: BTreeMap<(u64, u64), LsmSetattrView>,
    /// Distinct setattr observations dropped at [`MAX_PENDING_SETATTRS`].
    pending_setattr_overflows: u32,
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
    /// At session-close a non-zero count is emitted as a command-scoped
    /// `CaptureRefused` in addition to the warning. If the link is
    /// permanently gone that final refusal cannot be delivered; the error
    /// is logged and daemon-side helper liveness remains the backstop.
    ///
    /// Counts only TRUE wire failures (daemon socket disconnected,
    /// write returned Err) — NOT dedupe-skips or other intentional
    /// short-circuits.
    silent_send_failures: u32,
    /// Last post-mutation content hash successfully emitted by
    /// `file_release` for each inode. This is deliberately separate
    /// from `dedupe`: `file_open` records the pre-image in `dedupe`,
    /// but release must still enrich that capture with the final hash.
    /// Repeated closes with unchanged bytes do not need duplicate wire
    /// events; a later distinct hash is emitted again.
    last_post_hash: BTreeMap<(u64, u64), [u8; 32]>,
}

#[derive(Debug, Default)]
struct BaselineWalkReport {
    issues: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Default)]
struct BaselineWalkProgress {
    opened: usize,
    visited: usize,
    hit_cap: bool,
    report: BaselineWalkReport,
}

impl BaselineWalkReport {
    fn note(&mut self, issue: &'static str) {
        *self.issues.entry(issue).or_default() += 1;
    }

    fn into_result(self) -> Result<(), String> {
        if self.issues.is_empty() {
            return Ok(());
        }
        let detail = self
            .issues
            .into_iter()
            .map(|(issue, count)| format!("{issue} ({count})"))
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!("watch baseline incomplete: {detail}"))
    }
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

/// Hard cap on every directory entry visited by `pre_open_tree` per command.
/// Regular files, directories, and special files can each retain descriptors
/// or index entries; bounding only regular files leaves a wide directory tree
/// able to exhaust both fds and memory. Crossing this cap makes the baseline
/// incomplete and readiness is withheld.
const PRE_OPEN_TREE_MAX_ENTRIES: usize = 512;

/// L04.1 — A snapshotted pre-image. `staging_fd` names an immutable,
/// already-unlinked file, so held live source fds are never mistaken for a
/// snapshot after truncate or in-place write. Hash and size are computed in
/// the same fixed-buffer pass that creates it.
#[derive(Debug, Clone)]
struct PreSnapshot {
    meta: StatMeta,
    staging_fd: Arc<OwnedFd>,
    blob_hash: [u8; 32],
    stored_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
enum SnapshotStageError {
    #[error("pre-image metadata was unavailable")]
    MetadataUnavailable,
    #[error("pre-image metadata changed while its content was staged")]
    MetadataChanged,
    #[error(
        "pre-image size {size} would exceed the per-command staged-byte budget of {limit} bytes (already staged {used})"
    )]
    AggregateBudget { size: u64, used: u64, limit: u64 },
    #[error(transparent)]
    Stream(#[from] StreamError),
}

fn install_pre_snapshot(
    ws: &mut WatchState,
    key: (u64, u64),
    src_fd: RawFd,
    staging_dir: &Path,
) -> Result<PreSnapshot, SnapshotStageError> {
    let replaced_bytes = ws
        .pre_snapshots
        .get(&key)
        .map_or(0, |snapshot| snapshot.stored_bytes);
    let used_without_replaced = ws.staged_bytes.saturating_sub(replaced_bytes);
    let size = inode_size(src_fd)?;
    if size > MAX_PRE_IMAGE_BYTES as u64 {
        return Err(StreamError::TooLargeForBuffer(size).into());
    }
    if used_without_replaced.saturating_add(size) > MAX_STAGED_BYTES_PER_COMMAND {
        return Err(SnapshotStageError::AggregateBudget {
            size,
            used: used_without_replaced,
            limit: MAX_STAGED_BYTES_PER_COMMAND,
        });
    }

    let before_meta = fstat_meta(src_fd).ok_or(SnapshotStageError::MetadataUnavailable)?;
    let (staging_fd, blob_hash, stored_bytes) =
        stream_copy_to_staging_path(src_fd, staging_dir, MAX_PRE_IMAGE_BYTES as u64)?;
    let after_meta = fstat_meta(src_fd).ok_or(SnapshotStageError::MetadataUnavailable)?;
    if before_meta != after_meta || stored_bytes != size {
        return Err(SnapshotStageError::MetadataChanged);
    }

    let snapshot = PreSnapshot {
        meta: before_meta,
        staging_fd: Arc::new(staging_fd),
        blob_hash,
        stored_bytes,
    };
    ws.staged_bytes = used_without_replaced.saturating_add(stored_bytes);
    ws.pre_snapshots.insert(key, snapshot.clone());
    Ok(snapshot)
}

/// AR01.3 follow-up: queued create event waiting for its parent dir
/// to register in `dir_paths`. Owned-data flavor (basename is `OsString`)
/// because we may outlive the BPF ringbuf reader's borrowed buffer.
#[derive(Debug, Clone)]
struct PendingCreate {
    command: CommandId,
    pid: u32,
    /// Monotonic kernel timestamp from the common BPF event header.  This is
    /// preserved while the parent directory reader catches up so later
    /// cross-reader correlation cannot confuse inode reuse with reordering.
    ts_ns: u64,
    parent_dev: u64,
    parent_inode: u64,
    basename: OsString,
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

    /// Roll back a WatchTree setup that never became ready. Unlike
    /// `on_unwatch_tree`, this does not diagnose pending runtime events:
    /// the caller already emits the attach/baseline refusal that explains
    /// why this command was never safely watched.
    pub fn cancel_watch_tree(&mut self, command: CommandId) {
        self.watches.remove(&command);
    }

    /// Stop watching. Drops the dedupe state and closes all
    /// pre-opened fds; subsequent events for this command's pids
    /// fall through `handle_event` without capture (the TreeMap will
    /// have already removed the pid).
    ///
    /// AR01.3 follow-up: any create events still in `pending_creates`
    /// at session-close never had their parent mkdir resolve. Likewise,
    /// pending open/release/setattr observations that remain after the
    /// caller's v9 reader-flush barrier never acquired either a trustworthy
    /// snapshot or proof that the inode was born in-command. Surface either
    /// condition as capture loss before dropping the WatchState.
    pub fn on_unwatch_tree(&mut self, command: CommandId) {
        if let Some(ws) = self.watches.get_mut(&command) {
            let pending = ws.pending_create_count;
            let create_overflows = ws.pending_create_overflows;
            if pending > 0 || create_overflows > 0 {
                tracing::warn!(
                    session = %command.session,
                    seq = command.seq,
                    pending,
                    create_overflows,
                    "unwatch_tree: dropping unresolved pending creates (parent mkdir never landed)"
                );
                let overflow_detail = if create_overflows == 0 {
                    String::new()
                } else {
                    format!("; pending-create capacity was exceeded by {create_overflows} event(s)")
                };
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    None,
                    format!(
                        "capture incomplete: {pending} create event(s) could not be resolved by parent inode before command close{overflow_detail}"
                    ),
                ) {
                    tracing::error!(
                        %error,
                        session = %command.session,
                        seq = command.seq,
                        "unwatch_tree: permanent IPC failure prevented pending-create refusal delivery"
                    );
                }
            }
            let pending_opens = ws.pending_opens.len();
            let open_overflows = ws.pending_open_overflows;
            let pending_releases = ws.pending_releases.len();
            let release_overflows = ws.pending_release_overflows;
            let pending_setattrs = ws.pending_setattrs.len();
            let setattr_overflows = ws.pending_setattr_overflows;
            if pending_opens > 0
                || pending_releases > 0
                || pending_setattrs > 0
                || open_overflows > 0
                || release_overflows > 0
                || setattr_overflows > 0
            {
                tracing::warn!(
                    session = %command.session,
                    seq = command.seq,
                    pending_opens,
                    pending_releases,
                    pending_setattrs,
                    open_overflows,
                    release_overflows,
                    setattr_overflows,
                    "unwatch_tree: unresolved inode observations after eBPF reader flush"
                );
                let mut issues = Vec::new();
                if pending_opens > 0 {
                    issues.push(format!(
                        "{pending_opens} writable-file open observation(s) had no authoritative create or trustworthy pre-mutation snapshot"
                    ));
                }
                if pending_releases > 0 {
                    issues.push(format!(
                        "{pending_releases} writable-file close observation(s) had no trustworthy pre-mutation snapshot"
                    ));
                }
                if pending_setattrs > 0 {
                    issues.push(format!(
                        "{pending_setattrs} setattr observation(s) had no authoritative create or trustworthy pre-mutation snapshot"
                    ));
                }
                if open_overflows > 0 {
                    issues.push(format!(
                        "pending-open capacity was exceeded by {open_overflows} observation(s)"
                    ));
                }
                if release_overflows > 0 {
                    issues.push(format!(
                        "pending-release capacity was exceeded by {release_overflows} observation(s)"
                    ));
                }
                if setattr_overflows > 0 {
                    issues.push(format!(
                        "pending-setattr capacity was exceeded by {setattr_overflows} observation(s)"
                    ));
                }
                let detail = format!(
                    "capture incomplete after all eBPF readers drained: {}",
                    issues.join("; ")
                );
                if let Err(error) = send_capture_refused(&self.conn, command, None, detail) {
                    tracing::error!(
                        %error,
                        session = %command.session,
                        seq = command.seq,
                        "unwatch_tree: permanent IPC failure prevented pending-observation refusal delivery"
                    );
                }
            }
            // AU17 — surface the silent-send-failure count so the
            // operator can see when capture events were lost mid-
            // session (daemon socket disrupted, helper IPC saturated).
            // The counter is incremented every time
            // `send_response{_with_fd}` returns Err inside an LSM /
            // fanotify handler. Zero is the normal case; non-zero
            // means the journal is incomplete for this command.
            if ws.silent_send_failures > 0 {
                let failures = ws.silent_send_failures;
                tracing::warn!(
                    session = %command.session,
                    seq = command.seq,
                    silent_send_failures = failures,
                    "unwatch_tree: session capture is DEGRADED — some events were silently dropped (daemon socket failures)"
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    None,
                    format!(
                        "capture transport lost {failures} event(s) before command close; undo evidence is incomplete"
                    ),
                ) {
                    tracing::error!(
                        %error,
                        session = %command.session,
                        seq = command.seq,
                        "unwatch_tree: permanent IPC failure prevented transport-loss refusal delivery"
                    );
                }
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
    /// [`PRE_OPEN_TREE_MAX_ENTRIES`] entries per command. Stays on the
    /// same filesystem (same `dev`) as the watch root so we never
    /// cross a bind mount or a tmpfs sub-mount accidentally. Records
    /// every visited directory in `ws.dir_paths` so LSM event handlers
    /// can resolve `(parent_dev, parent_inode, basename)` into an
    /// absolute path for files in subdirectories.
    ///
    /// The walker continues after per-entry errors to collect as much
    /// baseline state as possible, but records every truncation. Any
    /// depth/file cap, cross-filesystem omission, permission error, or
    /// unavailable snapshot makes the returned result incomplete; the
    /// caller journals a refusal and withholds readiness.
    ///
    /// Caller invariant: must be called BEFORE the watched command's
    /// preexec returns userspace control. The L04 main.rs WatchTree
    /// handler does this synchronously between `tree.watch()` and
    /// returning the response.
    pub fn pre_open_tree(&mut self, command: CommandId, cwd: &Path) -> Result<(), String> {
        let staging_dir = self.staging_dir.clone();
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
        let root_metadata = match std::fs::metadata(cwd) {
            Ok(metadata) => metadata,
            Err(e) => {
                tracing::error!(
                    session = %command.session,
                    seq = command.seq,
                    cwd = %cwd.display(),
                    err = %e,
                    "pre_open_tree: stat(cwd) failed; skipping dir_paths root entry and recursion to avoid (0,0) aliasing"
                );
                return Err(format!("watch baseline root stat failed: {e}"));
            }
        };
        if !root_metadata.is_dir() {
            return Err("watch baseline root is not a directory".to_string());
        }
        let root_dev_inode = (root_metadata.dev(), root_metadata.ino());
        ws.dir_paths.insert(root_dev_inode, cwd.to_path_buf());

        let mut progress = BaselineWalkProgress::default();
        pre_open_recurse(ws, cwd, &staging_dir, root_dev_inode.0, 0, &mut progress);

        tracing::info!(
            session = %command.session,
            seq = command.seq,
            cwd = %cwd.display(),
            opened = progress.opened,
            visited = progress.visited,
            dirs = ws.dir_paths.len(),
            hit_cap = progress.hit_cap,
            "pre_open_tree complete"
        );
        progress.report.into_result()
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
    pub fn handle_event(&mut self, ev: &FanotifyEventView<'_>) -> Decision {
        // Lazy WatchState — first event for a command initializes its
        // dedupe map. `on_watch_tree` may have been called already, in
        // which case `or_default` is a cheap lookup.
        let ws = self.watches.entry(ev.command).or_default();

        let (dev, inode, file_type) = match fstat_dev_inode_kind(ev.fd) {
            Some(t) => t,
            None => {
                tracing::warn!(fd = ev.fd, "fstat failed; denying mutation");
                return Decision::Deny;
            }
        };

        // Directories and specials (fifo/socket/blk/chr) don't carry a
        // useful pre-image. The fanotify mark may have caught e.g. an
        // open on a directory itself (`open(O_DIRECTORY)`); ignore.
        if file_type != FileType::Regular {
            tracing::trace!(fd = ev.fd, ?file_type, "non-regular fd; skipping");
            return Decision::Allow;
        }
        if matches!(ev.kind, FanotifyCaptureKind::OpenExec) {
            return Decision::Allow;
        }

        let is_delete = matches!(ev.kind, FanotifyCaptureKind::Delete);
        if !is_delete && !should_capture_dedupe(&ws.dedupe, (dev, inode)) {
            tracing::trace!(fd = ev.fd, dev, inode, "dedupe hit; skipping");
            return Decision::Allow;
        }

        let Some(path) = path_for_kernel_fd(ev.fd) else {
            if let Err(error) = send_capture_refused(
                &self.conn,
                ev.command,
                None,
                "kernel-provided fd could not be resolved to an undo path",
            ) {
                tracing::warn!(%error, "fanotify path-resolution refusal send failed");
                ws.note_silent_send_failure();
            }
            return Decision::Deny;
        };
        let Some(path_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &path) else {
            return Decision::Deny;
        };

        let before_meta = match fstat_meta(ev.fd) {
            Some(meta) => meta,
            None => {
                tracing::warn!(fd = ev.fd, "fanotify pre-capture metadata unavailable");
                if let Err(send_error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    Some(path_wire.clone()),
                    "regular-file metadata became unavailable before capture",
                ) {
                    tracing::warn!(error = %send_error, "fanotify capture refusal send failed");
                    ws.note_silent_send_failure();
                }
                return Decision::Deny;
            }
        };
        let (staging_fd, blob_hash, stored_bytes) =
            match stream_copy_to_staging_path(ev.fd, &self.staging_dir, MAX_PRE_IMAGE_BYTES as u64)
            {
                Ok(staged) => staged,
                Err(error) => {
                    tracing::warn!(fd = ev.fd, %error, "fanotify pre-image stream failed");
                    if let Err(send_error) = send_capture_refused(
                        &self.conn,
                        ev.command,
                        Some(path_wire.clone()),
                        format!("regular-file pre-image stream failed: {error}"),
                    ) {
                        tracing::warn!(error = %send_error, "fanotify capture refusal send failed");
                        ws.note_silent_send_failure();
                    }
                    return Decision::Deny;
                }
            };
        let meta = match fstat_meta(ev.fd) {
            Some(meta) if meta == before_meta && meta.size == stored_bytes => meta,
            Some(_) => {
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    Some(path_wire.clone()),
                    "regular-file identity, size, or metadata changed during pre-image capture",
                ) {
                    tracing::warn!(%error, "fanotify metadata refusal send failed");
                    ws.note_silent_send_failure();
                }
                return Decision::Deny;
            }
            None => {
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    Some(path_wire.clone()),
                    "regular-file metadata became unavailable after pre-image capture",
                ) {
                    tracing::warn!(%error, "fanotify metadata refusal send failed");
                    ws.note_silent_send_failure();
                }
                return Decision::Deny;
            }
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev,
            inode,
            path: Some(path_wire),
            blob_hash,
            stored_bytes,
            // AU11 — None is correct on the fanotify path. We mark
            // with `FAN_OPEN_PERM | FAN_ACCESS_PERM` (see
            // fanotify/mark.rs), both of which fire BEFORE the
            // kernel commits the syscall. `bytes` is therefore the
            // pre-image; the post-mutation content lives on the
            // LSM-release path (handle_lsm_release sets Some).
            post_content_hash: None,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            flags: 0,
            is_delete,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "send_response_with_fd failed");
            ws.note_silent_send_failure();
            return Decision::Deny;
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
            bytes = stored_bytes,
            "CapturedPreImage sent",
        );
        Decision::Allow
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
    /// If loss (open returned ENOENT, fstat identity mismatch, content is
    /// unreadable, or the blob exceeds the cap), send `CaptureRefused`.
    /// A failed regular-file capture must never be represented as an empty
    /// pre-image. Directories and FIFOs use the distinct typed
    /// `CapturedDeletionMarker` variant so the daemon can refuse explicitly
    /// until complete directory/FIFO metadata replay is modeled.
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
                basename = ?ev.basename,
                "lsm unlink: parent_inode not in dir_paths; dropping event"
            );
            if let Err(error) = send_capture_refused(
                &self.conn,
                ev.command,
                None,
                "deleted path could not be resolved from its parent inode",
            ) {
                tracing::warn!(%error, "lsm unlink unresolved-path refusal send failed");
                ws.note_silent_send_failure();
            }
            return;
        };
        let Some(resolved_path_wire) =
            path_to_wire_or_refuse(&self.conn, ev.command, &resolved_path)
        else {
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

        enum DeleteEvidence {
            Content {
                stored_bytes: u64,
                blob_hash: [u8; 32],
                staging_fd: OwnedFd,
                metadata: StatMeta,
            },
            MetadataOnly(StatMeta),
            Refused(String),
        }

        let evidence = if race_won && ev.is_directory {
            // G03 — dir capture: fstat for metadata only, no bytes.
            let fd = race_fd.as_ref().unwrap().as_raw_fd();
            match fstat_meta(fd) {
                Some(meta) => DeleteEvidence::MetadataOnly(meta),
                None => DeleteEvidence::Refused(
                    "directory metadata became unavailable before deletion capture".into(),
                ),
            }
        } else if race_won && file_type == FileType::Fifo {
            // FIFOs have no content bytes to restore. The held O_PATH fd is
            // authoritative for identity and metadata, so this is a genuine
            // metadata-only marker rather than a failed content capture.
            let fd = race_fd.as_ref().unwrap().as_raw_fd();
            match fstat_meta(fd) {
                Some(meta) => DeleteEvidence::MetadataOnly(meta),
                None => DeleteEvidence::Refused(
                    "FIFO metadata became unavailable before deletion capture".into(),
                ),
            }
        } else if race_won && file_type == FileType::Socket {
            // A pathname socket cannot be reconstructed safely from stat
            // metadata alone (there is no peer/bind state on the wire).
            DeleteEvidence::Refused(
                "Unix-domain socket deletion has no safe metadata-only inverse".into(),
            )
        } else if race_won {
            // AU25 — single-pass streaming capture. Pre-AU25 this
            // three-stepped through `read_pre_image` (materialize
            // file into Vec<u8>) → `blake3_of` → `write_to_staging`
            // (write same Vec to disk). For >32 MiB files that
            // round-tripped 32–256 MiB through userspace memory per
            // event; >256 MiB files hit the cap and skipped
            // capture entirely. Now: src_fd → 64 KiB chunked
            // pread + in-flight blake3 + write directly to staging.
            let fd = race_fd.as_ref().unwrap().as_raw_fd();
            let meta = fstat_meta(fd);
            match (
                stream_copy_to_staging_path(fd, &self.staging_dir, MAX_PRE_IMAGE_BYTES as u64),
                meta,
            ) {
                (Ok((staging_fd, blob_hash, stored_bytes)), Some(metadata)) => {
                    DeleteEvidence::Content {
                        stored_bytes,
                        blob_hash,
                        staging_fd,
                        metadata,
                    }
                }
                (Err(StreamError::TooLargeForBuffer(n)), _) => {
                    tracing::warn!(
                        size = n,
                        cap = MAX_PRE_IMAGE_BYTES,
                        "lsm pre-image exceeds cap; refusing capture"
                    );
                    DeleteEvidence::Refused(format!(
                        "regular-file pre-image size {n} exceeds capture cap {MAX_PRE_IMAGE_BYTES}"
                    ))
                }
                (Err(e), _) => {
                    tracing::warn!(error = %e, "lsm pre-image stream failed");
                    DeleteEvidence::Refused(format!("regular-file pre-image stream failed: {e}"))
                }
                (Ok(_), None) => DeleteEvidence::Refused(
                    "regular-file metadata became unavailable during capture".into(),
                ),
            }
        } else {
            tracing::info!(
                pid = ev.pid,
                dev = ev.dev,
                inode = ev.inode,
                basename = ?ev.basename,
                is_directory = ev.is_directory,
                "lsm unlink race lost — refusing capture"
            );
            DeleteEvidence::Refused(
                "pre-image fd was unavailable or no longer matched the deleted inode".into(),
            )
        };

        let (send_result, stored_bytes, evidence_kind) = match evidence {
            DeleteEvidence::Content {
                stored_bytes,
                blob_hash,
                staging_fd,
                metadata,
            } => {
                let resp = HelperResponse::CapturedPreImage {
                    session: ev.command.session,
                    seq: ev.command.seq,
                    // Daemon side compares against PreExec's cwd_dev which is
                    // glibc-encoded; send the converted value.
                    dev: ev_dev_userspace,
                    inode: ev.inode,
                    path: Some(resolved_path_wire.clone()),
                    blob_hash,
                    stored_bytes,
                    post_content_hash: None,
                    mode: metadata.mode,
                    uid: metadata.uid,
                    gid: metadata.gid,
                    mtime_unix_nanos: metadata.mtime_unix_nanos,
                    xattrs: metadata.xattrs,
                    flags: 0,
                    is_delete: true,
                    fd_sent_via_scm: true,
                };
                (
                    self.conn
                        .send_response_with_fd(&resp, staging_fd.as_raw_fd()),
                    stored_bytes,
                    "content",
                )
            }
            DeleteEvidence::MetadataOnly(metadata) => {
                let resp = HelperResponse::CapturedDeletionMarker {
                    session: ev.command.session,
                    seq: ev.command.seq,
                    dev: ev_dev_userspace,
                    inode: ev.inode,
                    path: resolved_path_wire.clone(),
                    metadata: shit_proto::FileMetadataWire {
                        mode: metadata.mode,
                        uid: metadata.uid,
                        gid: metadata.gid,
                        size: metadata.size,
                        mtime_unix_nanos: metadata.mtime_unix_nanos,
                        xattrs: metadata.xattrs,
                        flags: 0,
                    },
                };
                (self.conn.send_response(&resp), 0, "metadata-only")
            }
            DeleteEvidence::Refused(detail) => {
                let resp = HelperResponse::CaptureRefused {
                    session: ev.command.session,
                    seq: ev.command.seq,
                    path: Some(resolved_path_wire.clone()),
                    detail,
                };
                (self.conn.send_response(&resp), 0, "refused")
            }
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
            evidence_kind,
            basename = ?ev.basename,
            path = %resolved_path.display(),
            "lsm-unlink deletion evidence sent",
        );
        remove_path_identity(ws, &resolved_path, (ev_dev_userspace, ev.inode));
    }

    /// L04 phase 3 — handler for `lsm/inode_setattr` events. Captures
    /// the pre-change metadata (mode/uid/gid) reported by the BPF
    /// program. The file content is re-read from the pre-opened fd
    /// (the chmod doesn't touch content; we capture it for the
    /// CapturedPreImage wire so the daemon's blob/hash invariants
    /// hold).
    ///
    /// A missing pre-command snapshot is held in a bounded map until the
    /// independent `inode_create` reader either proves the inode was born in
    /// this command or the command-close barrier proves no such Create
    /// exists. The former is fully inverted by unlinking the born inode; the
    /// latter is refused atomically rather than guessing at old content.
    pub fn handle_lsm_setattr(&mut self, ev: &LsmSetattrView) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev_userspace = kernel_dev_to_userspace(ev.dev);

        let key = (ev_dev_userspace, ev.inode);

        // Dedupe — first capture per (dev, inode) wins. Important
        // for the open(O_WRONLY|O_TRUNC) path: file_open LSM fires
        // first and captures the pre-truncate content, then
        // inode_setattr fires for the truncate. Without dedupe both
        // would journal CapturedPreImage, causing double-restore on
        // undo. The dedupe entry from file_open's handler suppresses
        // setattr's duplicate.
        if !should_capture_dedupe(&ws.dedupe, key) {
            tracing::trace!(
                dev = ev_dev_userspace,
                inode = ev.inode,
                "lsm setattr: dedupe hit; skipping (already captured this watch window)"
            );
            return;
        }

        // inode_setattr and inode_create have independent ring-buffer
        // readers. A newly-created inode can therefore reach this handler
        // before its authoritative Create even though the kernel callbacks
        // occurred in the opposite order. Do not interpret that dispatch
        // inversion as an existing file whose baseline was lost. Defer it;
        // process_lsm_create_resolved suppresses it only after successfully
        // sending the exact-identity Create, and on_unwatch_tree refuses any
        // observation still unresolved after every reader has drained.
        let Some(snap) = ws.pre_snapshots.get(&key).cloned() else {
            if let Some(pending) = ws.pending_setattrs.get_mut(&key) {
                // Preserve the earliest kernel observation. A later Create
                // may suppress this key only if it predates *every* missing-
                // snapshot mutation, not merely the most recently dispatched
                // one. An unknown timestamp (zero) stays conservative.
                if ev.ts_ns == 0 || (pending.ts_ns != 0 && ev.ts_ns < pending.ts_ns) {
                    *pending = *ev;
                }
                tracing::trace!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev_userspace,
                    inode = ev.inode,
                    "lsm setattr: refreshed deferred observation awaiting create"
                );
            } else if ws.pending_setattrs.len() < MAX_PENDING_SETATTRS {
                ws.pending_setattrs.insert(key, *ev);
                tracing::trace!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev_userspace,
                    inode = ev.inode,
                    pending_setattrs = ws.pending_setattrs.len(),
                    "lsm setattr: deferred observation awaiting create"
                );
            } else {
                ws.pending_setattr_overflows = ws.pending_setattr_overflows.saturating_add(1);
                tracing::warn!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev_userspace,
                    inode = ev.inode,
                    pending_setattr_cap = MAX_PENDING_SETATTRS,
                    pending_setattr_overflows = ws.pending_setattr_overflows,
                    "lsm setattr: pending-setattr capacity exceeded; command will be refused"
                );
            }
            return;
        };

        // `FileMetadataWire` has no atime field. A touch/utimens operation
        // on an existing inode therefore cannot be represented exactly; do
        // not silently journal a metadata inverse that restores only mtime.
        // This check intentionally follows snapshot lookup: for an inode born
        // in-command, a late authoritative Create makes unlink the complete
        // inverse, including the unrepresentable timestamp update.
        if ev.attr_valid & crate::ebpf::ringbuf_reader::attr::ATIME != 0 {
            let native_path = resolve_inode_to_path(ws, ev_dev_userspace, ev.inode);
            let wire_path = native_path.as_deref().and_then(path_to_string);
            let detail = if native_path.is_some() && wire_path.is_none() {
                "timestamp mutation changes atime, which is not captured; native path is also not representable as UTF-8"
            } else {
                "timestamp mutation changes atime, which is not captured by FileMetadataWire"
            };
            if let Err(error) = send_capture_refused(&self.conn, ev.command, wire_path, detail) {
                tracing::warn!(%error, "lsm setattr atime refusal send failed");
                ws.note_silent_send_failure();
            }
            ws.dedupe.insert(key, DedupeEntry { invalidated: false });
            return;
        }

        // Use the immutable, unlinked staging snapshot, NOT the live fd.
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
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    None,
                    "pre-image was captured but its replay path could not be resolved",
                ) {
                    tracing::warn!(%error, "lsm setattr unresolved-path refusal send failed");
                    ws.note_silent_send_failure();
                }
                return;
            }
        };
        let Some(path_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &path) else {
            return;
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev_userspace,
            inode: ev.inode,
            path: Some(path_wire),
            blob_hash: snap.blob_hash,
            stored_bytes: snap.stored_bytes,
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
            flags: 0,
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, snap.staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm setattr send_response_with_fd failed");
            ws.note_silent_send_failure();
        }

        ws.dedupe.insert(key, DedupeEntry { invalidated: false });

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev_userspace,
            inode = ev.inode,
            attr_valid = ev.attr_valid,
            old_mode = format_args!("{:o}", ev.old_mode),
            new_mode = format_args!("{:o}", ev.new_mode),
            stored_bytes = snap.stored_bytes,
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
        let Some(resolved_dir) = resolve_via_parent(
            &ws.dir_paths,
            parent_dev_userspace,
            ev.parent_inode,
            ev.basename,
        ) else {
            tracing::warn!(
                pid = ev.pid,
                parent_dev = parent_dev_userspace,
                parent_inode = ev.parent_inode,
                basename = ?ev.basename,
                "lsm mkdir: parent_inode not in dir_paths; dropping event"
            );
            if let Err(error) = send_capture_refused(
                &self.conn,
                ev.command,
                None,
                "mkdir path could not be resolved from its parent inode",
            ) {
                tracing::warn!(%error, "lsm mkdir unresolved-path refusal send failed");
                ws.note_silent_send_failure();
            }
            return;
        };
        let Some(resolved_dir_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &resolved_dir)
        else {
            return;
        };

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
        // If the stat still fails after the retry budget, the directory
        // may already have been removed. A path-only Create would be an
        // unsafe guess: it could cancel an unrelated Unlink at the same
        // pathname. Refuse explicitly instead.
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
                     refusing path-only create evidence"
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    Some(resolved_dir_wire),
                    "mkdir completed but its kernel identity was unavailable before the path disappeared",
                ) {
                    tracing::warn!(%error, "lsm mkdir identity refusal send failed");
                    ws.note_silent_send_failure();
                }
                return;
            }
        };

        // AR01.1.fix-path-via-parent-inode — register the new dir's
        // (dev, inode) → path so subsequent nested events (e.g. git's
        // `.git/objects/02/abc...` create-then-write into the just-
        // -mkdir'd `02`) resolve correctly. Identity-unavailable cases
        // returned a refusal above and never reach this map.
        //
        // AR01.3 follow-up: after registering, drain any pending
        // create events whose parent_inode just became resolvable.
        // The per-program ringbuf reader race means create handlers
        // can arrive before their parent's mkdir handler; queue +
        // drain here ensures every create still gets a TreeOpCreate
        // journaled.
        ws.dir_paths.insert((dev, inode), resolved_dir.clone());
        let drained = ws.pending_creates.remove(&(dev, inode)).unwrap_or_default();
        ws.pending_create_count = ws.pending_create_count.saturating_sub(drained.len());

        let resp = HelperResponse::TreeMutation {
            session: ev.command.session,
            seq: ev.command.seq,
            op: shit_proto::TreeOpWire::Create {
                dev,
                inode,
                path: resolved_dir_wire,
                kind: shit_proto::FileKindWire::Directory,
                mode: ev.mode,
            },
            ts_unix_nanos: now_unix_nanos(),
            partial: false,
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
            self.process_lsm_create_resolved(pc.command, pc.pid, pc.ts_ns, resolved_child, pc.mode);
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
        let resolved_path = match resolve_via_parent(
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
                    basename = ?ev.basename,
                    "lsm create: parent_inode not in dir_paths; queuing for retry"
                );
                if ws.pending_create_count < MAX_PENDING_CREATES {
                    ws.pending_creates
                        .entry((parent_dev_userspace, ev.parent_inode))
                        .or_default()
                        .push(PendingCreate {
                            command: ev.command,
                            pid: ev.pid,
                            ts_ns: ev.ts_ns,
                            parent_dev: parent_dev_userspace,
                            parent_inode: ev.parent_inode,
                            basename: ev.basename.to_os_string(),
                            mode: ev.mode,
                        });
                    ws.pending_create_count += 1;
                } else {
                    ws.pending_create_overflows = ws.pending_create_overflows.saturating_add(1);
                    tracing::warn!(
                        parent_dev = parent_dev_userspace,
                        parent_inode = ev.parent_inode,
                        pending_create_cap = MAX_PENDING_CREATES,
                        pending_create_overflows = ws.pending_create_overflows,
                        "lsm create: pending-create capacity exceeded; command will be refused"
                    );
                }
                return;
            }
        };
        // Note: the `ws` borrow from above goes out of scope at the
        // call below -- process_lsm_create_resolved re-borrows.
        self.process_lsm_create_resolved(ev.command, ev.pid, ev.ts_ns, resolved_path, ev.mode);
    }

    /// AR01.3 follow-up: post-resolve body of `handle_lsm_create`,
    /// extracted so the `handle_lsm_mkdir` drain path can re-invoke
    /// it for queued create events whose parent has just registered
    /// in `dir_paths`.
    ///
    /// Open + stat the resolved path, journal an exact-identity Create,
    /// and on open success stash the fd + snapshot + reverse indices +
    /// dedupe entry. If the entry disappears before identity capture,
    /// emit `CaptureRefused` instead of a path-only marker.
    fn process_lsm_create_resolved(
        &mut self,
        command: CommandId,
        pid: u32,
        create_ts_ns: u64,
        resolved_path: PathBuf,
        mode: u32,
    ) {
        // AR01.2 race: for `touch foo; rm foo` style workloads the
        // userspace handler may race against an immediate unlink --
        // by the time we open(O_NOFOLLOW), the dentry is gone and
        // we get ENOENT. Never journal a `(0, 0)` path-only Create:
        // it can be paired with an unrelated deletion at the same path.
        // The event is explicitly refused when no kernel identity can
        // be recovered.
        //
        // AU29 — add O_NONBLOCK so a FIFO open (mknod-routed
        // creation) doesn't block waiting for a writer. No-op for
        // regular files; gives O_RDONLY-style fd for FIFOs that
        // can be fstat'd. Sockets return ENXIO and fall to the
        // identity-only path when a readable fd is unavailable.
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&resolved_path)
            .ok();

        let Some(path_str) = path_to_wire_or_refuse(&self.conn, command, &resolved_path) else {
            return;
        };
        let observed_identity = opened
            .as_ref()
            .and_then(|f| fstat_dev_inode_kind(f.as_raw_fd()))
            .or_else(|| {
                let metadata = std::fs::symlink_metadata(&resolved_path).ok()?;
                let file_type = metadata.file_type();
                let kind = if file_type.is_file() {
                    FileType::Regular
                } else if file_type.is_dir() {
                    FileType::Directory
                } else if file_type.is_symlink() {
                    FileType::Symlink
                } else if file_type.is_fifo() {
                    FileType::Fifo
                } else if file_type.is_socket() {
                    FileType::Socket
                } else if file_type.is_block_device() {
                    FileType::BlockDevice
                } else if file_type.is_char_device() {
                    FileType::CharDevice
                } else {
                    FileType::Other
                };
                Some((metadata.dev(), metadata.ino(), kind))
            });
        let (dev, inode, file_type) = match observed_identity {
            Some(t) => t,
            None => {
                tracing::warn!(
                    path = %resolved_path.display(),
                    "lsm create: post-open/fstat race lost; refusing path-only create evidence"
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    Some(path_str),
                    "created entry disappeared before its kernel identity could be captured",
                ) {
                    tracing::warn!(%error, "lsm create identity refusal send failed");
                    if let Some(ws) = self.watches.get_mut(&command) {
                        ws.note_silent_send_failure();
                    }
                }
                return;
            }
        };
        // AU29 — accept Fifo / Socket here (mknod routes through
        // this same handler via on_create). Pre-AU29 the
        // hard-coded `!= Regular` check skipped FIFOs/Sockets
        // even when their birth was captured, so the planner
        // never got a TreeOpCreate to invert.
        let wire_kind = match file_type {
            FileType::Regular => shit_proto::FileKindWire::Regular,
            FileType::Directory => shit_proto::FileKindWire::Directory,
            FileType::Symlink => shit_proto::FileKindWire::Symlink,
            FileType::Fifo => shit_proto::FileKindWire::Fifo,
            FileType::Socket => shit_proto::FileKindWire::Socket,
            FileType::BlockDevice => shit_proto::FileKindWire::BlockDevice,
            FileType::CharDevice => shit_proto::FileKindWire::CharDevice,
            _ => {
                tracing::warn!(
                    path = %resolved_path.display(),
                    ?file_type,
                    "lsm create: unsupported post-stat kind; refusing"
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    Some(path_str),
                    "created entry has an unsupported filesystem kind",
                ) {
                    tracing::warn!(%error, "lsm create unsupported-kind refusal send failed");
                    if let Some(ws) = self.watches.get_mut(&command) {
                        ws.note_silent_send_failure();
                    }
                }
                return;
            }
        };

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
            partial: false,
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

        // A write-open or setattr for this exact inode may have reached its
        // independent userspace reader before this create callback. Now that
        // the authoritative Create is on the wire, its inverse (unlink) fully
        // covers the born-mid-command inode, so suppress those observations.
        // Never clear them on the send-failure path above: transport loss
        // must remain visible at command close.
        let (pending_open, pending_setattr) =
            {
                let ws = self.watches.entry(command).or_default();
                let pending_open = if file_type == FileType::Regular
                    && ws.pending_opens.get(&(dev, inode)).is_some_and(|pending| {
                        create_precedes_observation(create_ts_ns, pending.ts_ns)
                    }) {
                    ws.pending_opens.remove(&(dev, inode))
                } else {
                    None
                };
                let pending_setattr = if ws
                    .pending_setattrs
                    .get(&(dev, inode))
                    .is_some_and(|pending| create_precedes_observation(create_ts_ns, pending.ts_ns))
                {
                    ws.pending_setattrs.remove(&(dev, inode))
                } else {
                    None
                };
                (pending_open, pending_setattr)
            };
        if let Some(pending_open) = pending_open {
            tracing::trace!(
                dev,
                inode,
                pending_pid = pending_open.pid,
                "lsm create: suppressing write-open deferred before authoritative create"
            );
        }
        if let Some(pending_setattr) = pending_setattr {
            tracing::trace!(
                dev,
                inode,
                pending_pid = pending_setattr.pid,
                pending_attr_valid = pending_setattr.attr_valid,
                "lsm create: suppressing setattr deferred before authoritative create"
            );
        }

        // If we won the open race, do the L04.1 snapshot + fd-stash.
        // A metadata-only identity observation still journals the exact
        // Create above but has no fd to retain.
        let mut pending_release = None;
        let mut snapshot_error = None;
        if let Some(f) = opened {
            let ws = self.watches.entry(command).or_default();
            let fd_raw = f.as_raw_fd();
            // AU29 — only read content bytes for regular files.
            // FIFOs/Sockets have no bytes. Regular files are copied into a
            // new immutable staging inode; the held live fd remains only for
            // path identity and release-time post-state hashing.
            if file_type == FileType::Regular {
                match install_pre_snapshot(ws, (dev, inode), fd_raw, &self.staging_dir) {
                    Ok(_) => {
                        // file_release and inode_create use independent
                        // ring-buffer readers. If release won the userspace
                        // dispatch race, retry it after installing snapshot.
                        if ws
                            .pending_releases
                            .get(&(dev, inode))
                            .is_some_and(|pending| {
                                create_precedes_observation(create_ts_ns, pending.ts_ns)
                            })
                        {
                            pending_release = ws.pending_releases.remove(&(dev, inode));
                        }
                    }
                    Err(error) => snapshot_error = Some(error.to_string()),
                }
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

        if let Some(detail) = snapshot_error {
            let detail = format!("new regular-file snapshot could not be staged safely: {detail}");
            if let Err(error) =
                send_capture_refused(&self.conn, command, Some(path_str.clone()), detail)
            {
                tracing::warn!(%error, "lsm create snapshot refusal send failed");
                if let Some(ws) = self.watches.get_mut(&command) {
                    ws.note_silent_send_failure();
                }
            }
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

        if let Some(pending_release) = pending_release {
            tracing::trace!(
                dev,
                inode,
                "lsm create: retrying writable-file close deferred before snapshot"
            );
            self.handle_lsm_release(&pending_release);
        }
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
    /// A missing snapshot is deferred because an `inode_create` callback on
    /// its independent reader may still prove the file was born during this
    /// command. Once that authoritative Create is sent, its inverse (unlink)
    /// fully covers the new file and the pending open is suppressed. A miss
    /// still unresolved after every reader flushes is refused at close.
    pub fn handle_lsm_open(&mut self, ev: &LsmOpenView) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev = kernel_dev_to_userspace(ev.dev);
        let key = (ev_dev, ev.inode);

        // Dedupe: first write-open per (dev, inode) per watch window.
        if !should_capture_dedupe(&ws.dedupe, key) {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm open: dedupe hit; skipping"
            );
            return;
        }

        // L04.1 — use the immutable staged snapshot, NOT the live fd. The
        // live fd would race against
        // `do_truncate` (which fires immediately after our LSM
        // hook returns 0) and read zero bytes. The snapshot was
        // taken at pre_open_tree time, before any LSM event fired.
        let Some(snap) = ws.pre_snapshots.get(&key).cloned() else {
            if let Some(pending) = ws.pending_opens.get_mut(&key) {
                if ev.ts_ns == 0 || (pending.ts_ns != 0 && ev.ts_ns < pending.ts_ns) {
                    *pending = *ev;
                }
                tracing::trace!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev,
                    inode = ev.inode,
                    "lsm open: refreshed deferred write-open awaiting create"
                );
            } else if ws.pending_opens.len() < MAX_PENDING_OPENS {
                ws.pending_opens.insert(key, *ev);
                tracing::trace!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev,
                    inode = ev.inode,
                    pending_opens = ws.pending_opens.len(),
                    "lsm open: deferred write-open awaiting create"
                );
            } else {
                ws.pending_open_overflows = ws.pending_open_overflows.saturating_add(1);
                tracing::warn!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev,
                    inode = ev.inode,
                    pending_open_cap = MAX_PENDING_OPENS,
                    pending_open_overflows = ws.pending_open_overflows,
                    "lsm open: pending-open capacity exceeded; command will be refused"
                );
            }
            return;
        };
        let meta = snap.meta;
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
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    None,
                    "pre-image was captured but its replay path could not be resolved",
                ) {
                    tracing::warn!(%error, "lsm open unresolved-path refusal send failed");
                    ws.note_silent_send_failure();
                }
                return;
            }
        };
        let Some(path_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &path) else {
            return;
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev,
            inode: ev.inode,
            path: Some(path_wire),
            blob_hash: snap.blob_hash,
            stored_bytes: snap.stored_bytes,
            // AU11 — None is correct. The LSM `file_open` hook is
            // a pre-mutation AUTH event; `bytes` come from the
            // pre-snapshot taken at WatchTree setup, not from
            // post-mutation content. The matching post-content
            // hash is set on the `handle_lsm_release` path when
            // the writer closes the fd.
            post_content_hash: None,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            flags: 0,
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, snap.staging_fd.as_raw_fd())
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
            bytes = snap.stored_bytes,
            "lsm-open CapturedPreImage sent",
        );
    }

    /// L04.2 — handler for `lsm/file_release` events. Closes the
    /// in-place-write capture gap.
    ///
    /// Fires once per writable last-fd-close (incl. final mmap
    /// unmap). Flow:
    ///
    /// 1. Look up `pre_snapshots[(dev, inode)]`. A miss may be a userspace
    ///    dispatch inversion with `inode_create`, whose independent reader
    ///    has not installed the snapshot yet. Defer it in a bounded map. A
    ///    matching create retries it; unresolved/overflowed observations are
    ///    refused after the v9 close barrier drains every reader.
    /// 2. Do not use pre-image dedupe here. `file_open` normally
    ///    captured the same inode first, but its event necessarily has
    ///    no post hash. Release enriches that evidence for conflict
    ///    detection and only suppresses an identical post hash.
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

        // Snapshot lookup. A miss can mean inode_create ran first in the
        // kernel but lost the userspace mutex race to this program's reader.
        // Hold the close briefly and let the create handler retry it. If no
        // create ever supplies a snapshot, on_unwatch_tree converts the
        // still-pending observation to a fail-closed refusal only after the
        // caller has flushed every BPF reader.
        let key = (ev_dev, ev.inode);
        let Some(snap) = ws.pre_snapshots.get(&key).cloned() else {
            if let Some(pending) = ws.pending_releases.get_mut(&key) {
                if ev.ts_ns == 0 || (pending.ts_ns != 0 && ev.ts_ns < pending.ts_ns) {
                    *pending = *ev;
                }
                tracing::trace!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev,
                    inode = ev.inode,
                    "lsm release: refreshed deferred close awaiting snapshot"
                );
            } else if ws.pending_releases.len() < MAX_PENDING_RELEASES {
                ws.pending_releases.insert(key, *ev);
                tracing::trace!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev,
                    inode = ev.inode,
                    pending_releases = ws.pending_releases.len(),
                    "lsm release: deferred close awaiting snapshot"
                );
            } else {
                ws.pending_release_overflows = ws.pending_release_overflows.saturating_add(1);
                tracing::warn!(
                    dev_kernel = ev.dev,
                    dev_userspace = ev_dev,
                    inode = ev.inode,
                    pending_release_cap = MAX_PENDING_RELEASES,
                    pending_release_overflows = ws.pending_release_overflows,
                    "lsm release: pending-close capacity exceeded; command will be refused"
                );
            }
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
            let native_path = resolve_inode_to_path(ws, ev_dev, ev.inode);
            let wire_path = native_path.as_deref().and_then(path_to_string);
            if let Err(error) = send_capture_refused(
                &self.conn,
                ev.command,
                wire_path,
                "post-state fd unavailable; capture completeness cannot be verified",
            ) {
                tracing::warn!(%error, "lsm release missing-fd refusal send failed");
                ws.note_silent_send_failure();
            }
            return;
        };
        let raw_fd = held_fd.as_raw_fd();

        // Hash the current content through the same fixed-size streaming
        // buffer used by baseline staging. This keeps release-time memory
        // bounded even for files near the capture cap and verifies that the
        // inode did not change identity, size, or timestamps while hashing.
        let (post_hash, post_bytes) = match hash_fd_contents(raw_fd, MAX_PRE_IMAGE_BYTES as u64) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(
                    dev = ev_dev,
                    inode = ev.inode,
                    error = %e,
                    "lsm release: post-state hash failed; dropping"
                );
                let native_path = resolve_inode_to_path(ws, ev_dev, ev.inode);
                let wire_path = native_path.as_deref().and_then(path_to_string);
                if let Err(send_error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    wire_path,
                    format!("post-state content hash failed: {e}"),
                ) {
                    tracing::warn!(error = %send_error, "lsm release hash refusal send failed");
                    ws.note_silent_send_failure();
                }
                return;
            }
        };
        let pre_hash = snap.blob_hash;
        if pre_hash == post_hash {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm release: content unchanged; no event"
            );
            return;
        }
        if ws.last_post_hash.get(&(ev_dev, ev.inode)) == Some(&post_hash) {
            tracing::trace!(
                dev = ev_dev,
                inode = ev.inode,
                "lsm release: identical post hash already emitted"
            );
            return;
        }

        // Content changed. Emit the already-staged immutable pre-image with
        // the release-time post-state hash. Reusing the unlinked read-only fd
        // avoids a second source read, allocation, and staging write.
        let meta = snap.meta;
        let path = match resolve_inode_to_path(ws, ev_dev, ev.inode) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    dev = ev_dev,
                    inode = ev.inode,
                    "lsm release: path resolution failed; dropping event"
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    None,
                    "pre-image was captured but its replay path could not be resolved",
                ) {
                    tracing::warn!(%error, "lsm release unresolved-path refusal send failed");
                    ws.note_silent_send_failure();
                }
                return;
            }
        };
        let Some(path_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &path) else {
            return;
        };

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev,
            inode: ev.inode,
            path: Some(path_wire),
            blob_hash: pre_hash,
            stored_bytes: snap.stored_bytes,
            post_content_hash: Some(post_hash),
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            flags: 0,
            is_delete: false,
            fd_sent_via_scm: true,
        };
        let sent = if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, snap.staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm release send_response_with_fd failed");
            ws.note_silent_send_failure();
            false
        } else {
            true
        };

        ws.dedupe
            .insert((ev_dev, ev.inode), DedupeEntry { invalidated: false });
        if sent {
            ws.last_post_hash.insert((ev_dev, ev.inode), post_hash);
        }

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev,
            inode = ev.inode,
            f_flags = format_args!("{:#x}", ev.f_flags),
            pre_bytes = snap.stored_bytes,
            post_bytes,
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
                basename = ?ev.old_basename,
                "lsm rename: old_parent_inode not in dir_paths; dropping event"
            );
            if let Err(error) = send_capture_refused(
                &self.conn,
                ev.command,
                None,
                "rename source path could not be resolved from its parent inode",
            ) {
                tracing::warn!(%error, "lsm rename source-path refusal send failed");
                ws.note_silent_send_failure();
            }
            return;
        };
        let Some(to_path) =
            resolve_via_parent(&ws.dir_paths, ev_dev, ev.new_parent_inode, ev.new_basename)
        else {
            tracing::warn!(
                pid = ev.pid,
                new_parent_inode = ev.new_parent_inode,
                basename = ?ev.new_basename,
                "lsm rename: new_parent_inode not in dir_paths; dropping event"
            );
            if let Err(error) = send_capture_refused(
                &self.conn,
                ev.command,
                None,
                "rename destination path could not be resolved from its parent inode",
            ) {
                tracing::warn!(%error, "lsm rename destination-path refusal send failed");
                ws.note_silent_send_failure();
            }
            return;
        };
        let Some(from_path_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &from_path)
        else {
            return;
        };
        let Some(to_path_wire) = path_to_wire_or_refuse(&self.conn, ev.command, &to_path) else {
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
        if let Some(&(old_dev, old_inode)) = ws.path_to_inode.get(&to_path) {
            let Some(snap) = ws.pre_snapshots.get(&(old_dev, old_inode)).cloned() else {
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    ev.command,
                    Some(to_path_wire.clone()),
                    "rename would replace a destination whose pre-image snapshot is unavailable",
                ) {
                    tracing::warn!(%error, "lsm rename missing-snapshot refusal send failed");
                    ws.note_silent_send_failure();
                }
                return;
            };
            let meta = snap.meta;
            let resp = HelperResponse::CapturedPreImage {
                session: ev.command.session,
                seq: ev.command.seq,
                dev: old_dev,
                inode: old_inode,
                path: Some(to_path_wire.clone()),
                blob_hash: snap.blob_hash,
                stored_bytes: snap.stored_bytes,
                // AU11 — None is correct: `is_delete: true`
                // below marks the rename target's prior
                // contents as deleted by the rename. No
                // post-mutation content exists for a Delete.
                post_content_hash: None,
                mode: meta.mode,
                uid: meta.uid,
                gid: meta.gid,
                mtime_unix_nanos: meta.mtime_unix_nanos,
                xattrs: meta.xattrs.clone(),
                flags: 0,
                is_delete: true,
                fd_sent_via_scm: true,
            };
            if let Err(e) = self
                .conn
                .send_response_with_fd(&resp, snap.staging_fd.as_raw_fd())
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
                    bytes = snap.stored_bytes,
                    path = %to_path.display(),
                    "lsm-rename target pre-image CapturedPreImage sent"
                );
            }
        }

        let resp = HelperResponse::TreeMutation {
            session: ev.command.session,
            seq: ev.command.seq,
            op: shit_proto::TreeOpWire::Rename {
                from: from_path_wire,
                to: to_path_wire,
                dev: ev_dev,
                inode: ev.inode,
            },
            ts_unix_nanos: now_unix_nanos(),
            partial: false,
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "lsm rename send_response failed");
            ws.note_silent_send_failure();
        }

        // Keep the resolver's model aligned with the namespace mutation.
        // Without this, a later rename into `from_path` is mistaken for a
        // clobber of the inode that already moved away, and directory moves
        // leave every descendant resolving through the stale prefix.
        rebase_path_indices(ws, ev_dev, ev.inode, &from_path, &to_path);

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev = ev_dev,
            inode = ev.inode,
            from = %from_path.display(),
            to = %to_path.display(),
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
    staging_dir: &Path,
    root_dev: u64,
    depth: usize,
    progress: &mut BaselineWalkProgress,
) {
    if depth >= PRE_OPEN_TREE_DEPTH_LIMIT {
        progress.report.note("directory depth limit reached");
        return;
    }
    if progress.visited >= PRE_OPEN_TREE_MAX_ENTRIES {
        progress.hit_cap = true;
        progress.report.note("filesystem entry count limit reached");
        return;
    }
    let read = match std::fs::read_dir(dir) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), err = %e, "pre_open_tree: read_dir failed");
            progress.report.note("directory could not be read");
            return;
        }
    };
    for ent in read {
        let ent = match ent {
            Ok(ent) => ent,
            Err(_) => {
                progress.report.note("directory entry could not be read");
                continue;
            }
        };
        if progress.visited >= PRE_OPEN_TREE_MAX_ENTRIES {
            progress.hit_cap = true;
            progress.report.note("filesystem entry count limit reached");
            return;
        }
        progress.visited += 1;
        let path = ent.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                progress.report.note("directory entry metadata unavailable");
                continue;
            }
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            // Cross-fs guard: don't recurse into a submount.
            if meta.dev() != root_dev {
                progress.report.note("cross-filesystem subtree skipped");
                continue;
            }
            ws.dir_paths.insert((meta.dev(), meta.ino()), path.clone());
            // G03 — also stash an O_PATH fd for the dir in pre_opens
            // so a subsequent inode_rmdir can race-win via the held
            // fd (the dentry vanishes post-rmdir; without a pinned
            // fd, fstat-by-path returns ENOENT and we lose the
            // captured mode). O_PATH doesn't require read perm and
            // works with fstat for metadata. `opened` remains a regular-file
            // diagnostic; `visited` is the command-wide resource bound.
            if let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(&path)
            {
                ws.pre_opens
                    .insert((meta.dev(), meta.ino()), OwnedFd::from(f));
                ws.path_to_inode
                    .insert(path.clone(), (meta.dev(), meta.ino()));
            } else {
                progress.report.note("directory fd could not be opened");
            }
            pre_open_recurse(ws, &path, staging_dir, root_dev, depth + 1, progress);
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
            } else {
                progress.report.note("special-file fd could not be opened");
            }
            continue;
        }
        if !ft.is_file() {
            progress.report.note("unsupported filesystem entry skipped");
            continue;
        }
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(f) => f,
            Err(_) => {
                progress.report.note("regular file could not be opened");
                continue;
            }
        };
        let fd = f.as_raw_fd();
        let Some((dev, inode, FileType::Regular)) = fstat_dev_inode_kind(fd) else {
            progress.report.note("regular-file identity unavailable");
            continue;
        };
        if let Err(error) = install_pre_snapshot(ws, (dev, inode), fd, staging_dir) {
            progress.report.note("regular-file snapshot unavailable");
            tracing::trace!(
                dev,
                inode,
                %error,
                "pre_open_tree: snapshot skipped (too large or read failed)"
            );
        }
        ws.pre_opens.insert((dev, inode), OwnedFd::from(f));
        // AR01.1.fix-rename-target-preimage — reverse-index so a
        // later rename-over-this-path can find the OLD inode.
        ws.path_to_inode.insert(path.clone(), (dev, inode));
        progress.opened += 1;
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
    basename: &OsStr,
) -> Option<PathBuf> {
    let parent = ws_dir_paths.get(&(parent_dev, parent_inode))?;
    Some(parent.join(basename))
}

/// Remove an exact path from the forward/reverse resolver indices after its
/// inode is unlinked. Identity matching prevents an out-of-order event from
/// deleting a newer inode's mapping at the same pathname.
fn remove_path_identity(ws: &mut WatchState, path: &Path, identity: (u64, u64)) {
    if ws.path_to_inode.get(path) == Some(&identity) {
        ws.path_to_inode.remove(path);
    }
    if ws
        .dir_paths
        .get(&identity)
        .is_some_and(|mapped| mapped == path)
    {
        ws.dir_paths.remove(&identity);
    }
}

/// Apply a successful rename to every path-based resolver index. Directory
/// renames rebase descendants as well as the directory itself. Any mapping at
/// the destination belongs to the clobbered pre-rename inode and is removed,
/// while its held snapshot/fd remains available for undo evidence.
fn rebase_path_indices(
    ws: &mut WatchState,
    dev: u64,
    inode: u64,
    from_path: &Path,
    to_path: &Path,
) {
    let identity = (dev, inode);
    let source_is_directory = ws.dir_paths.contains_key(&identity);

    let stale_destination_paths = ws
        .path_to_inode
        .keys()
        .filter(|path| path.strip_prefix(to_path).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    for path in stale_destination_paths {
        ws.path_to_inode.remove(&path);
    }
    ws.dir_paths
        .retain(|_, path| path.strip_prefix(to_path).is_err());

    if source_is_directory {
        let moved_paths = ws
            .path_to_inode
            .iter()
            .filter_map(|(path, mapped_identity)| {
                path.strip_prefix(from_path)
                    .ok()
                    .map(|suffix| (path.clone(), to_path.join(suffix), *mapped_identity))
            })
            .collect::<Vec<_>>();
        for (old_path, _, _) in &moved_paths {
            ws.path_to_inode.remove(old_path);
        }
        for (_, new_path, mapped_identity) in moved_paths {
            ws.path_to_inode.insert(new_path, mapped_identity);
        }
        for path in ws.dir_paths.values_mut() {
            if let Ok(suffix) = path.strip_prefix(from_path) {
                *path = to_path.join(suffix);
            }
        }
    } else {
        ws.path_to_inode.remove(from_path);
        ws.path_to_inode.insert(to_path.to_path_buf(), identity);
    }
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
    pub basename: &'a OsStr,
    /// G03 — set when this event came from the `inode_rmdir` LSM
    /// hook rather than `inode_unlink`. The handler skips bytes-
    /// capture (directories have no content) and emits a typed deletion
    /// marker. The daemon currently turns that marker into an explicit
    /// refusal rather than pretending mode-only reconstruction is complete.
    pub is_directory: bool,
}

/// View into an `lsm/inode_setattr` event as the BPF ringbuf reader
/// sees it. Old values are pre-change (read from the live inode at
/// BPF hook time); new values are what the syscall is requesting.
#[derive(Debug, Clone, Copy)]
pub struct LsmSetattrView {
    pub command: CommandId,
    pub pid: u32,
    pub ts_ns: u64,
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
    pub basename: &'a OsStr,
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
    pub ts_ns: u64,
    pub parent_dev: u64,
    pub parent_inode: u64,
    pub mode: u32,
    pub basename: &'a OsStr,
}

/// L04.1 — View into an `lsm/file_open` event. BPF already filtered
/// to write-intent (FMODE_WRITE set in `f_mode`); userspace's job is
/// to look up the file in `pre_opens` and stream its pre-image via
/// the same wire as fanotify-perm's OpenWrite path.
#[derive(Debug, Clone, Copy)]
pub struct LsmOpenView {
    pub command: CommandId,
    pub pid: u32,
    pub ts_ns: u64,
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
    pub ts_ns: u64,
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
    pub old_basename: &'a OsStr,
    pub new_basename: &'a OsStr,
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

/// Whether an asynchronously-dispatched Create can authoritatively explain a
/// missing-snapshot observation for the same `(dev, inode)`.
///
/// Device/inode alone is insufficient because Linux may reuse an inode after
/// deletion within the same command window. Every BPF program stamps records
/// from the same monotonic `bpf_ktime_get_ns()` clock, so only a Create that
/// happened no later than the open/release/setattr may suppress that pending
/// observation. Zero is treated as unknown and therefore cannot prove the
/// ordering.
fn create_precedes_observation(create_ts_ns: u64, observation_ts_ns: u64) -> bool {
    create_ts_ns != 0 && observation_ts_ns != 0 && create_ts_ns <= observation_ts_ns
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
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::Fifo,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFCHR => FileType::CharDevice,
        _ => FileType::Other,
    };
    Some((st.st_dev, st.st_ino, kind))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
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
            // Linux has no BSD-style st_flags; M03.x.SETATTR is a
            // macOS/BSD concept (chflags). Always 0 here.
            flags: 0,
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
        xattrs: crate::capture::xattr::try_read_user_xattrs(fd).ok()?,
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
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let bytes = p.as_os_str().as_bytes();
        if let Some(stripped) = bytes.strip_suffix(b" (deleted)") {
            return Some(std::ffi::OsString::from_vec(stripped.to_vec()).into());
        }
        return Some(p);
    }
    ws.path_to_inode
        .iter()
        .find(|&(_, &v)| v == (dev, inode))
        .map(|(k, _)| k.clone())
}

fn path_to_string(p: &Path) -> Option<String> {
    p.to_str().map(ToOwned::to_owned)
}

fn send_capture_refused(
    conn: &Conn,
    command: CommandId,
    path: Option<String>,
    detail: impl Into<String>,
) -> Result<(), crate::ipc::ConnError> {
    conn.send_response(&HelperResponse::CaptureRefused {
        session: command.session,
        seq: command.seq,
        path,
        detail: detail.into(),
    })
}

/// Convert a native POSIX path for the UTF-8 helper wire. Lossy conversion is
/// forbidden because an inverse aimed at a U+FFFD-substituted pathname can
/// mutate a different file. Emit an explicit, non-actionable refusal instead.
fn path_to_wire_or_refuse(conn: &Conn, command: CommandId, path: &Path) -> Option<String> {
    if let Some(path) = path_to_string(path) {
        return Some(path);
    }
    if let Err(error) = send_capture_refused(
        conn,
        command,
        None,
        "native path is not representable as UTF-8",
    ) {
        tracing::warn!(%error, "failed to send non-UTF-8-path CaptureRefused");
    }
    None
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

    fn runtime_with_peer() -> (
        LinuxCaptureRuntime,
        crate::ipc::Conn,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (a, b) = crate::ipc::socketpair().expect("socketpair");
        let rt = LinuxCaptureRuntime::new(staging.path().to_path_buf(), Arc::new(a)).unwrap();
        (rt, b, dir, staging)
    }

    fn conn_readable(conn: &crate::ipc::Conn) -> bool {
        let mut pollfd = libc::pollfd {
            fd: conn.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized element for the duration
        // of this non-blocking poll.
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        assert!(
            result >= 0,
            "poll failed: {}",
            std::io::Error::last_os_error()
        );
        result > 0
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
            basename: OsStr::new(basename),
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
            basename: OsStr::new("this-file-does-not-exist-anywhere.xyz"),
            is_directory: false,
        };

        rt.handle_lsm_unlink(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.dedupe.len(), 1, "exactly one dedupe entry");
        let entry = ws.dedupe.values().next().unwrap();
        assert!(entry.invalidated);
    }

    #[test]
    fn lsm_regular_unlink_race_loss_emits_capture_refused() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        let root = std::fs::metadata(dir.path()).unwrap();
        rt.watches
            .entry(cmd)
            .or_default()
            .dir_paths
            .insert((root.dev(), root.ino()), dir.path().to_path_buf());

        rt.handle_lsm_unlink(&LsmUnlinkView {
            command: cmd,
            pid: std::process::id(),
            dev: userspace_to_kernel_dev(root.dev()),
            inode: u64::MAX - 1,
            parent_inode: root.ino(),
            basename: OsStr::new("already-gone.bin"),
            is_directory: false,
        });

        let response = peer.recv_response().unwrap();
        assert!(matches!(
            response,
            HelperResponse::CaptureRefused { path: Some(path), .. }
                if path.ends_with("/already-gone.bin")
        ));
    }

    #[test]
    fn lsm_directory_unlink_emits_typed_deletion_marker() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        let child = dir.path().join("empty-dir");
        std::fs::create_dir(&child).unwrap();
        let root = std::fs::metadata(dir.path()).unwrap();
        let child_meta = std::fs::metadata(&child).unwrap();
        let child_fd = std::fs::File::open(&child).unwrap();
        let ws = rt.watches.entry(cmd).or_default();
        ws.dir_paths
            .insert((root.dev(), root.ino()), dir.path().to_path_buf());
        ws.pre_opens
            .insert((child_meta.dev(), child_meta.ino()), child_fd.into());

        rt.handle_lsm_unlink(&LsmUnlinkView {
            command: cmd,
            pid: std::process::id(),
            dev: userspace_to_kernel_dev(child_meta.dev()),
            inode: child_meta.ino(),
            parent_inode: root.ino(),
            basename: OsStr::new("empty-dir"),
            is_directory: true,
        });

        let response = peer.recv_response().unwrap();
        assert!(matches!(
            response,
            HelperResponse::CapturedDeletionMarker { metadata, .. }
                if metadata.mode & libc::S_IFMT == libc::S_IFDIR
        ));
    }

    #[test]
    fn non_utf8_native_path_emits_refusal_without_replacement_target() {
        use std::os::unix::ffi::OsStringExt;

        let (a, peer) = crate::ipc::socketpair().expect("socketpair");
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/bad-\xff".to_vec()));
        assert_eq!(path_to_wire_or_refuse(&a, ghost_cmd(), &path), None);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { path: None, detail, .. }
                if detail.contains("not representable as UTF-8")
        ));
    }

    #[test]
    fn create_race_loss_refuses_instead_of_path_only_marker() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        let vanished = dir.path().join("already-vanished");

        rt.process_lsm_create_resolved(cmd, std::process::id(), 10, vanished.clone(), 0o100644);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused {
                path: Some(path),
                detail,
                ..
            } if path == vanished.to_str().unwrap()
                && detail.contains("kernel identity")
        ));
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

    #[test]
    fn on_unwatch_tree_surfaces_silent_failures_as_refusal() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        rt.watches.get_mut(&cmd).unwrap().silent_send_failures = 3;

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused {
                session,
                seq,
                path: None,
                detail,
            } if session == cmd.session && seq == cmd.seq && detail.contains("lost 3 event")
        ));
        assert!(!rt.watches.contains_key(&cmd));
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
        let staging = tempfile::tempdir().unwrap();
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

        let mut progress = BaselineWalkProgress::default();
        pre_open_recurse(&mut ws, root, staging.path(), root_dev, 0, &mut progress);

        assert!(!progress.hit_cap, "should not have hit max-entry cap");
        assert_eq!(
            progress.visited, 7,
            "expected four files plus three directories"
        );
        let report = &progress.report;
        assert!(report.issues.is_empty(), "unexpected issues: {report:?}");
        // 4 regular files were created; all should be snapshotted.
        let opened = progress.opened;
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
            resolve_via_parent(&dir_paths, 64, 100, OsStr::new("README.md")).as_deref(),
            Some(Path::new("/tmp/repo/README.md"))
        );
        // Nested under .git/.
        assert_eq!(
            resolve_via_parent(&dir_paths, 64, 200, OsStr::new("index.lock")).as_deref(),
            Some(Path::new("/tmp/repo/.git/index.lock"))
        );
        // Deeply nested.
        assert_eq!(
            resolve_via_parent(&dir_paths, 64, 300, OsStr::new("abc123")).as_deref(),
            Some(Path::new("/tmp/repo/.git/objects/02/abc123"))
        );
        // Unknown parent inode → None (caller falls back).
        assert_eq!(
            resolve_via_parent(&dir_paths, 64, 999, OsStr::new("missing")),
            None
        );
        // Wrong dev (e.g. submount) → None.
        assert_eq!(
            resolve_via_parent(&dir_paths, 65, 100, OsStr::new("README.md")),
            None
        );
    }

    #[test]
    fn rename_indices_rebase_directory_descendants_and_forget_target() {
        let mut ws = WatchState::default();
        let root = PathBuf::from("/tmp/repo");
        let from = root.join("old");
        let to = root.join("new");
        let nested = from.join("nested");
        let file = nested.join("file.txt");
        let source = (7, 10);
        let nested_identity = (7, 11);
        let file_identity = (7, 12);
        let old_target = (7, 20);

        ws.dir_paths.insert((7, 1), root.clone());
        ws.dir_paths.insert(source, from.clone());
        ws.dir_paths.insert(nested_identity, nested.clone());
        ws.path_to_inode.insert(from.clone(), source);
        ws.path_to_inode.insert(nested, nested_identity);
        ws.path_to_inode.insert(file, file_identity);
        ws.path_to_inode.insert(to.clone(), old_target);

        rebase_path_indices(&mut ws, source.0, source.1, &from, &to);

        assert_eq!(ws.path_to_inode.get(&to), Some(&source));
        assert_eq!(
            ws.path_to_inode.get(&to.join("nested")),
            Some(&nested_identity)
        );
        assert_eq!(
            ws.path_to_inode.get(&to.join("nested/file.txt")),
            Some(&file_identity)
        );
        assert!(!ws.path_to_inode.values().any(|value| *value == old_target));
        assert_eq!(ws.dir_paths.get(&source), Some(&to));
        assert_eq!(ws.dir_paths.get(&nested_identity), Some(&to.join("nested")));
        assert_eq!(ws.dir_paths.get(&(7, 1)), Some(&root));
    }

    #[test]
    fn unlink_index_removal_is_identity_guarded() {
        let mut ws = WatchState::default();
        let path = PathBuf::from("/tmp/repo/entry");
        let identity = (9, 99);
        ws.path_to_inode.insert(path.clone(), identity);
        ws.dir_paths.insert(identity, path.clone());

        remove_path_identity(&mut ws, &path, (9, 100));
        assert_eq!(ws.path_to_inode.get(&path), Some(&identity));
        assert_eq!(ws.dir_paths.get(&identity), Some(&path));

        remove_path_identity(&mut ws, &path, identity);
        assert!(!ws.path_to_inode.contains_key(&path));
        assert!(!ws.dir_paths.contains_key(&identity));
    }

    /// AR01.1.fix-pre-open-tree-recursion — depth cap is enforced.
    /// Files at depth N+1 should NOT be snapshotted when the cap is N.
    #[test]
    fn pre_open_tree_honors_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
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

        let mut progress = BaselineWalkProgress::default();
        pre_open_recurse(&mut ws, root, staging.path(), root_dev, 0, &mut progress);

        // Depth limit is 8; leaf.txt is at depth 10. Should not be opened.
        assert_eq!(
            progress.opened, 0,
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
        let report = &progress.report;
        assert!(
            report.issues.contains_key("directory depth limit reached"),
            "depth truncation must make readiness incomplete: {report:?}"
        );
    }

    #[test]
    fn pre_open_tree_bounds_wide_directory_resources() {
        let dir = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        for index in 0..=PRE_OPEN_TREE_MAX_ENTRIES {
            std::fs::create_dir(dir.path().join(format!("dir-{index:04}"))).unwrap();
        }

        let mut ws = WatchState::default();
        let root_dev = std::fs::metadata(dir.path()).unwrap().dev();
        let mut progress = BaselineWalkProgress::default();
        pre_open_recurse(
            &mut ws,
            dir.path(),
            staging.path(),
            root_dev,
            0,
            &mut progress,
        );

        assert!(progress.hit_cap);
        assert_eq!(progress.visited, PRE_OPEN_TREE_MAX_ENTRIES);
        assert_eq!(progress.opened, 0);
        assert!(ws.pre_opens.len() <= PRE_OPEN_TREE_MAX_ENTRIES);
        assert!(ws.dir_paths.len() <= PRE_OPEN_TREE_MAX_ENTRIES);
        let report = &progress.report;
        assert!(
            report
                .issues
                .contains_key("filesystem entry count limit reached"),
            "entry truncation must make readiness incomplete: {report:?}"
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
        crate::ipc::Conn,
        tempfile::TempDir,
        tempfile::TempDir,
        PathBuf,
        u64,
        u64,
    ) {
        let (mut rt, peer, dir, staging) = runtime_with_peer();
        let path = dir.path().join("probe.txt");
        std::fs::write(&path, pre_bytes).unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        let (dev_userspace, inode, _) = fstat_dev_inode_kind(f.as_raw_fd()).unwrap();
        let ws = rt.watches.entry(cmd).or_default();
        ws.cwd = Some(dir.path().to_path_buf());
        let root_md = std::fs::metadata(dir.path()).unwrap();
        ws.dir_paths
            .insert((root_md.dev(), root_md.ino()), dir.path().to_path_buf());
        install_pre_snapshot(ws, (dev_userspace, inode), f.as_raw_fd(), staging.path())
            .expect("stage release-test pre-image");
        ws.pre_opens
            .insert((dev_userspace, inode), OwnedFd::from(f));
        ws.path_to_inode
            .insert(path.clone(), (dev_userspace, inode));
        (rt, peer, dir, staging, path, dev_userspace, inode)
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

    fn setattr_view(command: CommandId, dev: u64, inode: u64, attr_valid: u32) -> LsmSetattrView {
        LsmSetattrView {
            command,
            pid: std::process::id(),
            ts_ns: 20,
            dev,
            inode,
            attr_valid,
            old_mode: 0o100644,
            old_uid: 1000,
            old_gid: 1000,
            old_size: 0,
            new_mode: 0o100644,
            new_uid: 1000,
            new_gid: 1000,
            new_size: 0,
        }
    }

    /// L04.2 — happy path: pre-snapshot present, post-write content
    /// differs → handler runs to completion, marks dedupe entry.
    #[test]
    fn handle_lsm_release_emits_on_content_diff() {
        let cmd = ghost_cmd();
        let (mut rt, peer, _dir, _staging, path, dev_userspace, inode) =
            release_test_setup(cmd, b"before-bytes");

        // Mutate in place — no rename, no truncate.
        std::fs::write(&path, b"after-bytes!").unwrap();

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,    // FMODE_WRITE
            f_flags: 0o002, // O_RDWR
        };
        rt.handle_lsm_release(&view);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CapturedPreImage {
                post_content_hash: Some(_),
                ..
            }
        ));

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
        let (mut rt, _peer, _dir, _staging, _path, dev_userspace, inode) =
            release_test_setup(cmd, b"identical-bytes");

        // No write — content matches snapshot.

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
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

    /// L04.2 — an open-time pre-image must not suppress the
    /// release-time post hash. The test runtime intentionally has a
    /// closed peer; observing a send failure proves release reached
    /// the wire path instead of returning at the pre-image dedupe gate.
    #[test]
    fn handle_lsm_release_bypasses_preimage_dedupe() {
        let cmd = ghost_cmd();
        let (mut rt, peer, _dir, _staging, path, dev_userspace, inode) =
            release_test_setup(cmd, b"original");

        // Mark dedupe as if an earlier handler captured.
        {
            let ws = rt.watches.get_mut(&cmd).unwrap();
            ws.dedupe
                .insert((dev_userspace, inode), DedupeEntry { invalidated: false });
        }

        // Mutate content so release must emit the enriched event.
        std::fs::write(&path, b"mutated-but-deduped").unwrap();

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,
            f_flags: 0o002,
        };
        rt.handle_lsm_release(&view);

        let ws = rt.watches.get(&cmd).expect("watch state");
        assert_eq!(ws.dedupe.len(), 1, "exactly one dedupe entry");
        assert_eq!(ws.silent_send_failures, 0);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CapturedPreImage {
                post_content_hash: Some(_),
                ..
            }
        ));
    }

    /// Even an ATTR_ATIME event must wait for the create reader before being
    /// judged unrepresentable: a born-in-command inode is exactly undone by
    /// unlink, while a genuinely missing baseline is refused at close.
    #[test]
    fn setattr_without_snapshot_is_deferred_then_refused_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        let view = setattr_view(
            cmd,
            0xdead_beef,
            0xcafe_babe,
            crate::ebpf::ringbuf_reader::attr::ATIME,
        );

        rt.handle_lsm_setattr(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_setattrs.len(), 1);
        assert!(ws.dedupe.is_empty());
        assert!(
            !conn_readable(&peer),
            "missing snapshot must not trigger a premature atime refusal"
        );

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("setattr observation")
                    && detail.contains("after all eBPF readers drained")
        ));
    }

    /// If the Create reader catches up, its successfully emitted inverse
    /// covers every metadata mutation on the newly-born inode, including
    /// ATTR_ATIME which FileMetadataWire cannot otherwise represent.
    #[test]
    fn setattr_before_create_is_suppressed_by_authoritative_create() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        let path = dir.path().join("setattr-before-create.txt");
        std::fs::write(&path, b"").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let dev_userspace = metadata.dev();
        let inode = metadata.ino();

        rt.handle_lsm_setattr(&setattr_view(
            cmd,
            userspace_to_kernel_dev(dev_userspace),
            inode,
            crate::ebpf::ringbuf_reader::attr::ATIME,
        ));
        assert_eq!(rt.watches[&cmd].pending_setattrs.len(), 1);
        assert!(!conn_readable(&peer));

        rt.process_lsm_create_resolved(cmd, std::process::id(), 10, path, libc::S_IFREG | 0o644);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::TreeMutation {
                op: shit_proto::TreeOpWire::Create { dev, inode: ino, .. },
                ..
            } if dev == dev_userspace && ino == inode
        ));
        assert!(rt.watches[&cmd].pending_setattrs.is_empty());

        rt.on_unwatch_tree(cmd);
        assert!(!conn_readable(&peer));
    }

    /// A later Create with a recycled `(dev, inode)` is not evidence that an
    /// earlier missing-snapshot mutation belonged to a born-in-command file.
    /// Cross-reader correlation must use the common kernel clock as well as
    /// identity or it can suppress genuine loss after inode reuse.
    #[test]
    fn later_create_cannot_suppress_earlier_pending_setattr() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        let path = dir.path().join("reused-inode.txt");
        std::fs::write(&path, b"").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let dev_userspace = metadata.dev();
        let inode = metadata.ino();
        let mut pending = setattr_view(
            cmd,
            userspace_to_kernel_dev(dev_userspace),
            inode,
            crate::ebpf::ringbuf_reader::attr::ATIME,
        );
        pending.ts_ns = 10;
        rt.handle_lsm_setattr(&pending);

        // The same numeric inode appears in a Create only later. The Create
        // itself is journaled, but it must not consume the older refusal.
        rt.process_lsm_create_resolved(cmd, std::process::id(), 20, path, libc::S_IFREG | 0o644);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::TreeMutation {
                op: shit_proto::TreeOpWire::Create { .. },
                ..
            }
        ));
        assert_eq!(rt.watches[&cmd].pending_setattrs.len(), 1);

        rt.on_unwatch_tree(cmd);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("setattr observation")
        ));
    }

    /// A failed Create publication is not proof available to the daemon, so
    /// it must leave the deferred setattr pending rather than suppressing it.
    #[test]
    fn failed_create_send_does_not_suppress_pending_setattr() {
        let (mut rt, dir, _staging) = fresh_runtime();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        let path = dir.path().join("failed-create-send.txt");
        std::fs::write(&path, b"").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let dev_userspace = metadata.dev();
        let inode = metadata.ino();

        rt.handle_lsm_setattr(&setattr_view(
            cmd,
            userspace_to_kernel_dev(dev_userspace),
            inode,
            0,
        ));
        rt.process_lsm_create_resolved(cmd, std::process::id(), 10, path, libc::S_IFREG | 0o644);

        let ws = &rt.watches[&cmd];
        assert_eq!(ws.pending_setattrs.len(), 1);
        assert_eq!(ws.silent_send_failures, 1);
    }

    /// Existing-file ATTR_ATIME remains an immediate refusal because a valid
    /// baseline proves no late Create can supply the unlink inverse.
    #[test]
    fn existing_file_atime_setattr_is_immediately_refused() {
        let cmd = ghost_cmd();
        let (mut rt, peer, _dir, _staging, _path, dev_userspace, inode) =
            release_test_setup(cmd, b"existing");

        rt.handle_lsm_setattr(&setattr_view(
            cmd,
            userspace_to_kernel_dev(dev_userspace),
            inode,
            crate::ebpf::ringbuf_reader::attr::ATIME,
        ));

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("atime") && detail.contains("not captured")
        ));
        let ws = &rt.watches[&cmd];
        assert!(ws.pending_setattrs.is_empty());
        assert!(ws.dedupe.contains_key(&(dev_userspace, inode)));
    }

    /// A missing open snapshot waits for a possible authoritative Create and
    /// becomes a refusal only after the reader-flush barrier proves none came.
    #[test]
    fn open_without_snapshot_is_deferred_then_refused_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        let view = LsmOpenView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
            dev: 0xdead_beef,
            inode: 0xcafe_babe,
            f_mode: 0x2,
            f_flags: 0o002,
        };

        rt.handle_lsm_open(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_opens.len(), 1);
        assert!(ws.dedupe.is_empty());
        assert!(!conn_readable(&peer));

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("writable-file open observation")
                    && detail.contains("after all eBPF readers drained")
        ));
    }

    /// A new inode's Create is the authoritative inverse. If its write-open
    /// reader wins dispatch first, successful Create delivery suppresses the
    /// pending open without fabricating a pre-command pre-image.
    #[test]
    fn open_before_create_is_suppressed_by_authoritative_create() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);
        let path = dir.path().join("open-before-create.txt");
        std::fs::write(&path, b"").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let dev_userspace = metadata.dev();
        let inode = metadata.ino();

        rt.handle_lsm_open(&LsmOpenView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,
            f_flags: 0o002,
        });
        assert_eq!(rt.watches[&cmd].pending_opens.len(), 1);
        assert!(!conn_readable(&peer));

        rt.process_lsm_create_resolved(cmd, std::process::id(), 10, path, libc::S_IFREG | 0o644);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::TreeMutation {
                op: shit_proto::TreeOpWire::Create { dev, inode: ino, .. },
                ..
            } if dev == dev_userspace && ino == inode
        ));
        assert!(rt.watches[&cmd].pending_opens.is_empty());

        rt.on_unwatch_tree(cmd);
        assert!(!conn_readable(&peer));
    }

    /// L04.2 — a snapshot miss is held until the command-close barrier has
    /// drained all eBPF readers, then converted to a fail-closed refusal.
    #[test]
    fn release_without_snapshot_is_deferred_then_refused_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();

        let view = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
            dev: 0xdead_beef,
            inode: 0xcafe_babe,
            f_mode: 0x2,
            f_flags: 0o002,
        };
        rt.handle_lsm_release(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_releases.len(), 1);
        assert!(ws.dedupe.is_empty());
        assert!(
            !conn_readable(&peer),
            "snapshot miss must not refuse before the reader-flush barrier"
        );

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused {
                session,
                seq,
                path: None,
                detail,
            } if session == cmd.session
                && seq == cmd.seq
                && detail.contains("after all eBPF readers drained")
        ));
        assert!(!rt.watches.contains_key(&cmd));
    }

    /// Each LSM program has an independent reader. Production command-close
    /// flushes every reader before calling `on_unwatch_tree`; model the worst
    /// ordering here: release dispatches first, create dispatches second, and
    /// only then does close convert unresolved observations. The late create
    /// must drain the deferred release, leaving no spurious refusal.
    #[test]
    fn open_and_release_before_create_are_resolved_before_close_refusal() {
        let (mut rt, peer, dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();
        rt.on_watch_tree(cmd);

        let path = dir.path().join("created-then-closed.txt");
        std::fs::write(&path, b"").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let dev_userspace = metadata.dev();
        let inode = metadata.ino();
        let open = LsmOpenView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 20,
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,
            f_flags: 0o002,
        };
        let release = LsmReleaseView {
            command: cmd,
            pid: std::process::id(),
            ts_ns: 30,
            dev: userspace_to_kernel_dev(dev_userspace),
            inode,
            f_mode: 0x2,
            f_flags: 0o002,
        };

        // file_open and file_release readers both win the userspace mutex
        // race against inode_create.
        rt.handle_lsm_open(&open);
        rt.handle_lsm_release(&release);
        assert_eq!(rt.watches[&cmd].pending_opens.len(), 1);
        assert_eq!(rt.watches[&cmd].pending_releases.len(), 1);
        assert!(!conn_readable(&peer));

        // inode_create reader catches up while the close barrier is draining.
        rt.process_lsm_create_resolved(
            cmd,
            std::process::id(),
            10,
            path.clone(),
            libc::S_IFREG | 0o644,
        );
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::TreeMutation {
                op: shit_proto::TreeOpWire::Create { dev, inode: ino, .. },
                ..
            } if dev == dev_userspace && ino == inode
        ));
        assert!(rt.watches[&cmd].pending_opens.is_empty());
        assert!(rt.watches[&cmd].pending_releases.is_empty());

        // The release retried against the create snapshot and found unchanged
        // bytes. Closing now must not manufacture a missing-snapshot refusal.
        rt.on_unwatch_tree(cmd);
        assert!(!conn_readable(&peer));
    }

    #[test]
    fn pending_create_capacity_overflow_refuses_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();

        for index in 0..=MAX_PENDING_CREATES {
            let basename = format!("pending-{index}");
            rt.handle_lsm_create(&LsmCreateView {
                command: cmd,
                pid: std::process::id(),
                ts_ns: index as u64 + 1,
                parent_dev: 0x0080_0002,
                parent_inode: 0xdead_beef,
                mode: libc::S_IFREG | 0o644,
                basename: OsStr::new(&basename),
            });
        }

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_create_count, MAX_PENDING_CREATES);
        assert_eq!(ws.pending_create_overflows, 1);
        assert!(!conn_readable(&peer));

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("pending-create capacity was exceeded by 1")
        ));
    }

    /// Capacity pressure is itself loss of close evidence and therefore must
    /// make the command non-undoable rather than silently evicting an inode.
    #[test]
    fn pending_release_capacity_overflow_refuses_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();

        for inode in 1..=(MAX_PENDING_RELEASES as u64 + 1) {
            rt.handle_lsm_release(&LsmReleaseView {
                command: cmd,
                pid: std::process::id(),
                ts_ns: inode + 1,
                dev: 0x0080_0002,
                inode,
                f_mode: 0x2,
                f_flags: 0o002,
            });
        }

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_releases.len(), MAX_PENDING_RELEASES);
        assert_eq!(ws.pending_release_overflows, 1);
        assert!(!conn_readable(&peer));

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("pending-release capacity was exceeded by 1")
        ));
    }

    #[test]
    fn pending_open_capacity_overflow_refuses_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();

        for inode in 1..=(MAX_PENDING_OPENS as u64 + 1) {
            rt.handle_lsm_open(&LsmOpenView {
                command: cmd,
                pid: std::process::id(),
                ts_ns: inode + 1,
                dev: 0x0080_0002,
                inode,
                f_mode: 0x2,
                f_flags: 0o002,
            });
        }

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_opens.len(), MAX_PENDING_OPENS);
        assert_eq!(ws.pending_open_overflows, 1);
        assert!(!conn_readable(&peer));

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("pending-open capacity was exceeded by 1")
        ));
    }

    #[test]
    fn pending_setattr_capacity_overflow_refuses_at_close() {
        let (mut rt, peer, _dir, _staging) = runtime_with_peer();
        let cmd = ghost_cmd();

        for inode in 1..=(MAX_PENDING_SETATTRS as u64 + 1) {
            rt.handle_lsm_setattr(&setattr_view(cmd, 0x0080_0002, inode, 0));
        }

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.pending_setattrs.len(), MAX_PENDING_SETATTRS);
        assert_eq!(ws.pending_setattr_overflows, 1);
        assert!(!conn_readable(&peer));

        rt.on_unwatch_tree(cmd);

        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { detail, .. }
                if detail.contains("pending-setattr capacity was exceeded by 1")
        ));
    }
}
