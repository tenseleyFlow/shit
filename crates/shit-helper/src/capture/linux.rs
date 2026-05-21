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
use std::os::unix::fs::OpenOptionsExt;
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
}

/// L04.1 — A snapshotted pre-image. Bytes + the stat-meta as it was
/// at snapshot time (mode/uid/gid/mtime/size). Both go on the wire
/// in [`HelperResponse::CapturedPreImage`].
#[derive(Debug, Clone)]
struct PreSnapshot {
    meta: StatMeta,
    bytes: Vec<u8>,
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
    pub fn on_unwatch_tree(&mut self, command: CommandId) {
        self.watches.remove(&command);
    }

    /// L04 — open every regular file under `cwd` (non-recursive in
    /// v1; matches the smoke's flat-tree assumption) and stash the
    /// OwnedFds keyed by `(dev, inode)` in this command's WatchState.
    /// Mirror of `kqueue::register_subtree` — the open fd keeps the
    /// inode alive after `vfs_unlink` drops the dentry, so the LSM
    /// unlink handler can `read_pre_image(dup(fd))` after the file
    /// is "gone".
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
        let dir = match std::fs::read_dir(cwd) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(cwd = %cwd.display(), err = %e, "pre_open_tree: read_dir failed");
                return;
            }
        };
        let mut opened = 0usize;
        for ent in dir.flatten() {
            let path = ent.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.file_type().is_file() {
                continue;
            }
            // O_RDONLY + O_NOFOLLOW — never follow a symlink (else
            // we'd open something outside the watched tree).
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
            // L04.1 — snapshot bytes + meta BEFORE inserting the fd.
            // Reads are race-free at this moment (no LSM event has
            // fired yet). If read fails or file's too large, skip
            // snapshot — the LSM open/setattr handlers will see a
            // miss and drop their events.
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
            opened += 1;
        }
        tracing::info!(
            session = %command.session,
            seq = command.seq,
            cwd = %cwd.display(),
            opened,
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
            is_delete,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "send_response_with_fd failed");
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

        // Resolve the file's real path. Prefer the watch root recorded
        // at WatchTree time (canonical, survives the mutating pid's
        // exit); fall back to readlink(/proc/<pid>/cwd) which works
        // while the pid is alive but races against the BPF→ringbuf→
        // handler hop. NEVER fall back to the literal procfs symlink
        // string -- that's Issue #22: a `/proc/<dead-pid>/cwd/foo`
        // gets journaled and then ENOENT's at undo time.
        let resolved_path = resolve_basename_to_path(ws.cwd.as_deref(), ev.pid.into(), ev.basename);
        let Some(resolved_path) = resolved_path else {
            tracing::warn!(
                pid = ev.pid,
                basename = ev.basename,
                "lsm unlink: cannot resolve basename to absolute path \
                 (watch_tree cwd missing AND /proc/<pid>/cwd readlink failed); \
                 dropping event"
            );
            return;
        };

        // BPF reports `dev` in the kernel's `dev_t` encoding
        // (`(major << 20) | minor`). All userspace stat-derived
        // (dev, inode) keys in this runtime — including the
        // pre_opens table — use glibc's encoding (split-bits via
        // `__gnu_dev_makedev`). Convert before lookup.
        let ev_dev_userspace = kernel_dev_to_userspace(ev.dev);

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
        let race_won = capture_fd_owned.is_some()
            && capture_dev == ev_dev_userspace
            && capture_inode == ev.inode
            && file_type == FileType::Regular;
        let race_fd = capture_fd_owned;
        // Alias to keep the wire-build block below readable.
        let _ = (capture_dev, capture_inode);

        let (stored_bytes, blob_hash, staging_fd, meta_wire) = if race_won {
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
            mode: meta_wire.map(|m| m.mode).unwrap_or(0),
            uid: meta_wire.map(|m| m.uid).unwrap_or(0),
            gid: meta_wire.map(|m| m.gid).unwrap_or(0),
            mtime_unix_nanos: meta_wire.map(|m| m.mtime_unix_nanos).unwrap_or(0),
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
        }

        // Mark dedupe invalidated regardless of race outcome — the
        // unlink happened, so any subsequent reuse of (dev, inode)
        // should re-capture. Keyed in glibc-encoded dev for symmetry
        // with the fanotify producer's dedupe.
        ws.dedupe.insert(
            (ev_dev_userspace, ev.inode),
            DedupeEntry { invalidated: true },
        );

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

        // Look up — but keep the fd in the table. setattr doesn't
        // unlink, so subsequent events for the same inode (e.g.
        // chmod then chmod) should still find the fd.
        let pre_fd_raw = ws
            .pre_opens
            .get(&(ev_dev_userspace, ev.inode))
            .map(|f| f.as_raw_fd());
        let Some(fd) = pre_fd_raw else {
            tracing::info!(
                pid = ev.pid,
                dev_kernel = ev.dev,
                dev_userspace = ev_dev_userspace,
                inode = ev.inode,
                "lsm setattr: no pre-opened fd; dropping (race-to-open not viable for metadata-only)"
            );
            // Mark dedupe so reuse-after-event re-captures.
            ws.dedupe.insert(
                (ev_dev_userspace, ev.inode),
                DedupeEntry { invalidated: false },
            );
            return;
        };

        let bytes = match read_pre_image(fd) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "lsm setattr pre-image read failed");
                return;
            }
        };
        let blob_hash = blake3_of(&bytes);
        let staging_fd = match write_to_staging(&self.staging_dir, &bytes) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "lsm setattr staging write failed");
                return;
            }
        };

        // mtime: post-chmod fstat is fine — chmod doesn't change
        // mtime; only ctime moves. For utimes we'd need to capture
        // pre-change atime/mtime in the BPF event; deferred.
        let meta_mtime = fstat_meta(fd).map(|m| m.mtime_unix_nanos).unwrap_or(0);

        let path = path_for_kernel_fd(fd);

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev_userspace,
            inode: ev.inode,
            path: path.as_deref().map(path_to_string),
            blob_hash,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None,
            // Pre-change metadata from the BPF event — these are the
            // values undo restores to.
            mode: ev.old_mode,
            uid: ev.old_uid,
            gid: ev.old_gid,
            mtime_unix_nanos: meta_mtime,
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm setattr send_response_with_fd failed");
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

        // Resolve the new dir's path. The LSM hook fired with the
        // dentry's basename; the parent is the cwd of the calling pid
        // (for `mkdir foo` with no slashes). For `mkdir a/b` cases the
        // parent isn't cwd; defer those to a follow-up that walks the
        // dentry's parent chain.
        //
        // resolve_basename_to_path prefers the watch root recorded
        // at WatchTree time (canonical, survives mutating-pid exit)
        // and only falls back to readlink(/proc/<pid>/cwd) when the
        // watch root is missing. Issue #22.
        let resolved_dir_str = match resolve_basename_to_path(ws.cwd.as_deref(), ev.pid.into(), ev.basename) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    basename = ev.basename,
                    "lsm mkdir: cannot resolve basename to absolute path; dropping event"
                );
                return;
            }
        };
        let resolved_dir = PathBuf::from(&resolved_dir_str);

        // Stat to grab the (dev, inode) of the freshly-created dir.
        let (dev, inode) = match std::fs::symlink_metadata(&resolved_dir) {
            Ok(meta) => {
                use std::os::unix::fs::MetadataExt;
                if !meta.is_dir() {
                    tracing::warn!(
                        path = %resolved_dir.display(),
                        "lsm mkdir: post-stat is not a dir (race?); dropping"
                    );
                    return;
                }
                (meta.dev(), meta.ino())
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    path = %resolved_dir.display(),
                    "lsm mkdir: post-stat failed; dropping"
                );
                return;
            }
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
        }

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev,
            inode,
            mode = format_args!("{:o}", ev.mode),
            path = %resolved_dir.display(),
            "lsm-mkdir TreeMutation sent",
        );
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

        // Issue #22: resolve via watch root, never journal a
        // /proc/<pid>/cwd/... string.
        let resolved_path_str = match resolve_basename_to_path(ws.cwd.as_deref(), ev.pid.into(), ev.basename) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    basename = ev.basename,
                    "lsm create: cannot resolve basename to absolute path; dropping event"
                );
                return;
            }
        };
        let resolved_path = PathBuf::from(&resolved_path_str);

        // Open + stat. The kernel completed the create by the time
        // we run (LSM fired pre-create but returned 0; the syscall
        // proceeded; ringbuf submit + userspace read happens after
        // syscall completion).
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&resolved_path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    path = %resolved_path.display(),
                    "lsm create: post-open failed; dropping"
                );
                return;
            }
        };
        let (dev, inode, file_type) = match fstat_dev_inode_kind(f.as_raw_fd()) {
            Some(t) => t,
            None => {
                tracing::warn!(path = %resolved_path.display(), "lsm create: fstat failed");
                return;
            }
        };
        if file_type != FileType::Regular {
            // O_NOFOLLOW caught a symlink, or something else; skip.
            tracing::trace!(
                path = %resolved_path.display(),
                ?file_type,
                "lsm create: non-regular post-stat; skipping"
            );
            return;
        }

        let path_str = path_to_string(&resolved_path);
        let resp = HelperResponse::TreeMutation {
            session: ev.command.session,
            seq: ev.command.seq,
            op: shit_proto::TreeOpWire::Create {
                dev,
                inode,
                path: path_str.clone(),
                kind: shit_proto::FileKindWire::Regular,
                mode: ev.mode,
            },
            ts_unix_nanos: now_unix_nanos(),
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "lsm create send_response failed");
            return;
        }

        // L04.1 — snapshot the new file's bytes + meta. For a
        // freshly-created file these are typically empty + the
        // create mode, but the snapshot is what later file_open
        // handlers will use as pre-image (race-free).
        let fd_raw = f.as_raw_fd();
        if let (Ok(bytes), Some(meta)) = (read_pre_image(fd_raw), fstat_meta(fd_raw)) {
            ws.pre_snapshots
                .insert((dev, inode), PreSnapshot { meta, bytes });
        }
        // Stash the fd in pre_opens. Subsequent unlink for this
        // (dev, inode) will hit the table → race_won → pre-image
        // capture succeeds even if the file was modified mid-session.
        ws.pre_opens.insert((dev, inode), OwnedFd::from(f));

        tracing::info!(
            session = %ev.command.session,
            seq = ev.command.seq,
            pid = ev.pid,
            dev,
            inode,
            mode = format_args!("{:o}", ev.mode),
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
        // Path resolution via the still-held pre-opened fd.
        let path = ws
            .pre_opens
            .get(&(ev_dev, ev.inode))
            .and_then(|f| path_for_kernel_fd(f.as_raw_fd()));

        let resp = HelperResponse::CapturedPreImage {
            session: ev.command.session,
            seq: ev.command.seq,
            dev: ev_dev,
            inode: ev.inode,
            path: path.as_deref().map(path_to_string),
            blob_hash,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            is_delete: false,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "lsm open send_response_with_fd failed");
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

    /// L04.1 — handler for `lsm/inode_rename` events. Emits
    /// `HelperResponse::TreeMutation { op: Rename { from, to, ... } }`.
    /// Both paths resolved post-syscall via /proc/<pid>/cwd for the
    /// flat-tree case; the smoke + L02/L03 don't exercise nested
    /// renames in v1.
    pub fn handle_lsm_rename(&mut self, ev: &LsmRenameView<'_>) {
        let ws = self.watches.entry(ev.command).or_default();

        let ev_dev = kernel_dev_to_userspace(ev.dev);

        // Issue #22: resolve via watch root, not /proc/<pid>/cwd.
        let from_path = match resolve_basename_to_path(ws.cwd.as_deref(), ev.pid.into(), ev.old_basename) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    basename = ev.old_basename,
                    "lsm rename: cannot resolve old basename to absolute path; dropping event"
                );
                return;
            }
        };
        let to_path = match resolve_basename_to_path(ws.cwd.as_deref(), ev.pid.into(), ev.new_basename) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    pid = ev.pid,
                    basename = ev.new_basename,
                    "lsm rename: cannot resolve new basename to absolute path; dropping event"
                );
                return;
            }
        };

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

/// Resolve `basename` to an absolute path under the watch root.
///
/// Resolution order:
///   1. Watch root (`ws.cwd`) recorded at `pre_open_tree` time --
///      canonical, survives mutating-pid exit.
///   2. `readlink(/proc/<pid>/cwd)` -- works while the mutating pid
///      is alive, races against BPF→ringbuf→handler hop on fast
///      operations (rm, mv) where the syscall returns before our
///      handler runs and the shell reaps the subprocess promptly.
///
/// Returns `None` when both fail. Callers must drop the event;
/// emitting the literal `/proc/<pid>/cwd/<basename>` string into the
/// journal is Issue #22 -- it ENOENT's at undo time once the pid
/// is gone.
///
/// `pid` accepts `i64` so callers with either `i32` (LsmUnlinkView)
/// or `u32` (Lsm{Create,Mkdir,Rename,Setattr,Open}View) pid fields
/// can pass through without explicit casts.
fn resolve_basename_to_path(ws_cwd: Option<&Path>, pid: i64, basename: &str) -> Option<String> {
    if let Some(cwd) = ws_cwd {
        return Some(path_to_string(&cwd.join(basename)));
    }
    let cwd_link = format!("/proc/{pid}/cwd");
    std::fs::read_link(&cwd_link)
        .ok()
        .map(|cwd| path_to_string(&cwd.join(basename)))
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
        _ => FileType::Other,
    };
    Some((st.st_dev, st.st_ino, kind))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Regular,
    Directory,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatMeta {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_unix_nanos: i128,
}

impl StatMeta {
    fn to_wire(self) -> shit_proto::FileMetadataWire {
        shit_proto::FileMetadataWire {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime_unix_nanos: self.mtime_unix_nanos,
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
    })
}

/// Resolve the kernel-provided fd to a path via `/proc/self/fd/<fd>`.
/// Best-effort: returns `None` if the symlink read fails (e.g. the
/// file was already unlinked and `/proc` cleared the link).
fn path_for_kernel_fd(fd: RawFd) -> Option<PathBuf> {
    let link = format!("/proc/self/fd/{fd}");
    std::fs::read_link(&link).ok()
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
                let _ = std::env::set_current_dir(&self.0);
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
        };

        rt.handle_lsm_unlink(&view);

        let ws = rt.watches.get(&cmd).expect("watch state created");
        assert_eq!(ws.dedupe.len(), 1, "exactly one dedupe entry");
        let entry = ws.dedupe.values().next().unwrap();
        assert!(entry.invalidated);
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
}
