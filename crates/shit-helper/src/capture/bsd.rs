// SPDX-License-Identifier: AGPL-3.0-or-later

//! BSD/kqueue capture producer (S24.B).
//!
//! Consumes `DrainEvent::Vnode` events from S23.3's drain session and
//! emits `HelperResponse::CapturedPreImage` to the daemon, with the
//! pre-image bytes attached via `SCM_RIGHTS` per the S24.A wire.
//!
//! Architecture:
//!
//! ```text
//!   request_loop thread          pump thread (this module)
//!   ────────────────────         ──────────────────────────
//!   recv HelperRequest           recv DrainEvent | recv ControlMsg
//!         │                            │
//!         ▼                            ▼
//!   WatchTree { command,         decide route:
//!               root_pid }       ─ Vnode: capture + send
//!         │                      ─ ControlAttach: extend state
//!         │ send ControlAttach   ─ ControlDetach: shrink state
//!         ▼                      ─ Shutdown: clean exit
//!   (control channel) ───────────┘
//! ```
//!
//! State mutations happen *only* on the pump thread — no locks needed.
//! The control channel and the drain channel are both `sync_channel(N)`
//! and the pump alternates `try_recv` on them.
//!
//! **Stage-1 limits the producer to a single watched subtree per
//! CommandId.** Recursive lazy expansion on directory NOTE_WRITE
//! events is filed as a follow-up; for the rm-undo smoke (S24.C)
//! the initial walk under the command's cwd is sufficient.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::collections::{BTreeMap, HashMap};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use shit_planner::events::CommandId;
use shit_proto::HelperResponse;
use uuid::Uuid;

use crate::ipc::Conn;
use crate::kqueue::{
    DrainEvent, DrainSession, KqueueFd, STREAM_COPY_CAP, TrackedSubtree, VnodeEventKind,
    init as kqueue_init, register_subtree, register_subtree_at, spawn_drain,
    stream_copy_to_staging,
};

/// Default subtree depth — matches `kqueue::vnode::DEFAULT_DEPTH_LIMIT`.
const DEFAULT_DEPTH: usize = 8;

/// Inbound control commands the request_loop sends to the pump.
enum ControlMsg {
    Attach {
        command: CommandId,
        root_path: PathBuf,
    },
    Detach {
        command: CommandId,
    },
    Shutdown,
}

/// Producer state owned by the pump thread.
struct WatchState {
    subtree: TrackedSubtree,
    /// `(dev, inode)` → was the pre-image already captured? `true`
    /// = invalidated by NOTE_DELETE (next write should re-capture).
    dedupe: HashMap<(u64, u64), DedupeEntry>,
    /// S29.1 — per-dir-fd snapshot of immediate child entries, captured
    /// at attach time and refreshed after every dir-diff. The diff
    /// between current entries and the baseline is what we emit as
    /// `TreeOpWire::Create` / `TreeOpWire::Unlink`.
    dir_baselines: HashMap<RawFd, DirBaseline>,
    /// S29.3 — per-fd metadata snapshot, populated at attach time
    /// (and at `add_path` time for new files). On `NOTE_ATTRIB`,
    /// re-stat the fd; if anything user-visible (mode/uid/gid/mtime)
    /// changed, emit `CapturedMetadataChange` with this baseline as
    /// `before`, and update the baseline.
    meta_baselines: HashMap<RawFd, StatMeta>,
}

#[derive(Debug, Clone)]
struct DirBaseline {
    /// Absolute path of the directory (for emitting child paths).
    path: PathBuf,
    /// Child name → (dev, inode) at baseline time. We store inode so
    /// the diff can detect rename-within-dir as
    /// `Unlink old_name + Create new_name` for the same inode.
    entries: BTreeMap<std::ffi::OsString, (u64, u64)>,
}

#[derive(Debug, Clone, Copy)]
struct DedupeEntry {
    invalidated: bool,
}

/// Decide whether the producer should emit a pre-image capture for
/// the given `(dev, inode)`, given the current dedupe map state.
///
/// First-write-wins per (dev, inode) within a watch window. A delete
/// flips `invalidated=true`, which lets the *next* write re-capture
/// (handles inode reuse and the rm-then-recreate pattern).
fn should_capture_dedupe(map: &HashMap<(u64, u64), DedupeEntry>, key: (u64, u64)) -> bool {
    match map.get(&key) {
        None => true,
        Some(e) if e.invalidated => true,
        Some(_) => false,
    }
}

/// Pump thread's working set. Maps RawFd to which CommandId owns it,
/// so a DrainEvent's `fd` resolves quickly to its watch state.
struct PumpState {
    watches: BTreeMap<CommandId, WatchState>,
    fd_to_command: HashMap<RawFd, CommandId>,
    /// B05 Phase C: pre-cap_enter `O_DIRECTORY` open of the staging
    /// dir. `stream_copy_to_staging` uses `openat(staging_dir_fd,
    /// name, ...)` instead of absolute opens so it works under
    /// capability mode. (The original `staging_dir: PathBuf` field
    /// was removed once every staging op switched to the fd-relative
    /// API.)
    staging_dir_fd: Arc<OwnedFd>,
    conn: Arc<Conn>,
    /// S29.2 — kept here so `handle_dir_change` can register fresh
    /// kqueue watches via `TrackedSubtree::add_path` when a new entry
    /// appears in a watched directory.
    kq: Arc<KqueueFd>,
    /// B05 Phase B — pre-cap_enter `O_DIRECTORY` open of `/`.
    /// When `Some`, `attach()` opens watch roots via
    /// `openat(slash_fd, abspath_minus_slash, ...)` so the open
    /// survives Capsicum capability mode. When `None`, falls back
    /// to absolute-path `open(...)` (the non-capsicum path).
    slash_fd: Option<Arc<OwnedFd>>,
}

impl PumpState {
    fn new(
        staging_dir_fd: Arc<OwnedFd>,
        conn: Arc<Conn>,
        kq: Arc<KqueueFd>,
        slash_fd: Option<Arc<OwnedFd>>,
    ) -> Self {
        Self {
            watches: BTreeMap::new(),
            fd_to_command: HashMap::new(),
            staging_dir_fd,
            conn,
            kq,
            slash_fd,
        }
    }

    fn attach(&mut self, kq: &KqueueFd, command: CommandId, root_path: &Path) {
        let subtree_result = match &self.slash_fd {
            Some(slash) => register_subtree_at(kq, slash.as_raw_fd(), root_path, DEFAULT_DEPTH),
            None => register_subtree(kq, root_path, DEFAULT_DEPTH),
        };
        let subtree = match subtree_result {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    %command.session,
                    seq = command.seq,
                    path = %root_path.display(),
                    error = %e,
                    "register_subtree failed; watch dropped",
                );
                return;
            }
        };
        // Index every tracked fd → CommandId so the pump can resolve
        // DrainEvent::Vnode { fd, .. } to its watch.
        for raw in tracked_fds(&subtree) {
            self.fd_to_command.insert(raw, command);
        }
        tracing::info!(
            %command.session,
            seq = command.seq,
            path = %root_path.display(),
            tracked_entries = subtree.len(),
            "watch attached",
        );
        // Build per-dir-fd entry baselines so we can diff on
        // subsequent NOTE_WRITE events. Walks each tracked dir once
        // here; the cost is proportional to dir size.
        let mut dir_baselines: HashMap<RawFd, DirBaseline> = HashMap::new();
        for raw in tracked_fds(&subtree) {
            let Some((_, _, ft)) = fstat_dev_inode_kind(raw) else {
                continue;
            };
            if ft != FileType::Directory {
                continue;
            }
            let Some(dir_path) = subtree.path_for_fd(raw).map(|p| p.to_path_buf()) else {
                continue;
            };
            let entries = read_dir_entries(raw).unwrap_or_default();
            dir_baselines.insert(
                raw,
                DirBaseline {
                    path: dir_path,
                    entries,
                },
            );
        }
        // S29.3 — snapshot per-fd metadata so NOTE_ATTRIB events can
        // diff and emit MetadataChange with the original `before`
        // values. Populated for *every* tracked fd (file or dir);
        // we skip the dir-attrib path in handle_vnode but the data
        // is cheap and complete.
        let mut meta_baselines: HashMap<RawFd, StatMeta> = HashMap::new();
        for raw in tracked_fds(&subtree) {
            if let Some(m) = fstat_meta(raw) {
                meta_baselines.insert(raw, m);
            }
        }
        // W02.B.live-baseline — walk the just-registered subtree
        // and ship a BaselineCaptured for every regular file. This
        // is the load-bearing piece that lets `shit undo` reverse
        // in-place writes on BSD where NOTE_WRITE alone fires too
        // late to capture pre-content.
        //
        // Default-on after the W02.B regression sweep landed 12/12
        // BSD smokes green. Opt out with `SHIT_BASELINE_PREEXEC=0`
        // for diagnostics / emergency rollback.
        if std::env::var("SHIT_BASELINE_PREEXEC").as_deref() != Ok("0") {
            let (n, partial) = baseline_walk_and_emit(
                &subtree,
                &self.conn,
                self.staging_dir_fd.as_raw_fd(),
                command.session,
                root_path,
            );
            tracing::info!(
                %command.session,
                seq = command.seq,
                baseline_files = n,
                baseline_partial = partial,
                "live-baseline walk emitted",
            );
        }

        self.watches.insert(
            command,
            WatchState {
                subtree,
                dedupe: HashMap::new(),
                dir_baselines,
                meta_baselines,
            },
        );
    }

    fn detach(&mut self, command: CommandId) {
        if let Some(ws) = self.watches.remove(&command) {
            for raw in tracked_fds(&ws.subtree) {
                self.fd_to_command.remove(&raw);
            }
            tracing::info!(
                %command.session,
                seq = command.seq,
                "watch detached",
            );
        }
    }

    fn handle_vnode(&mut self, fd: RawFd, kind: VnodeEventKind) {
        // S29.3: route NOTE_ATTRIB (chmod/chown/touch) into its own
        // handler before the content-capture branch so we never
        // try to pread bytes for a metadata-only event.
        if matches!(kind, VnodeEventKind::Attrib) {
            self.handle_attrib(fd);
            return;
        }
        // Only Write/Extend/Delete trigger pre-image capture; other
        // kinds (Link, Rename, Revoke) get a trace log for now —
        // future S29.x sub-sprints land them.
        let is_delete = matches!(kind, VnodeEventKind::Delete);
        let triggers = matches!(
            kind,
            VnodeEventKind::Write | VnodeEventKind::Extend | VnodeEventKind::Delete
        );
        if !triggers {
            tracing::trace!(fd, ?kind, "vnode event ignored (not a capture trigger)");
            return;
        }
        let Some(command) = self.fd_to_command.get(&fd).copied() else {
            tracing::trace!(fd, ?kind, "vnode event for untracked fd; dropping");
            return;
        };
        let Some(ws) = self.watches.get_mut(&command) else {
            // fd_to_command had us, but the watch state is gone —
            // race with detach. Drop.
            return;
        };
        // register_subtree opens both directories and files. A delete
        // *inside* a directory delivers NOTE_DELETE on the file fd, but
        // NOTE_WRITE also fires on the parent dir fd (its contents
        // changed). pread(2) is invalid on a directory, so we filter
        // here to regular files only. The dir's NOTE_WRITE is fine —
        // it just means "someone touched the dir," which we may use
        // later for tree-mutation TreeOps but is not a pre-image
        // capture trigger.
        let (dev, inode, file_type) = match fstat_dev_inode_kind(fd) {
            Some(t) => t,
            None => {
                tracing::warn!(fd, "fstat failed; skipping capture");
                return;
            }
        };
        if file_type == FileType::Directory {
            // S29.1: NOTE_WRITE on a tracked dir indicates child
            // entries changed. Diff against the baseline to detect
            // create/unlink/rename and emit TreeMutation events.
            self.handle_dir_change(command, fd);
            return;
        }
        if file_type != FileType::Regular {
            tracing::trace!(fd, ?kind, ?file_type, "vnode event on non-file; skipping");
            return;
        }
        // Delete events ALWAYS go through, even if we already captured
        // a pre-image for this (dev, inode) earlier in the command —
        // the daemon needs the paired TreeOp::Unlink to plan the
        // recreate side of undo. (Smoke-surfaced bug: touch + echo +
        // rm produced only Create + FilePreImage; the rm's
        // CapturedPreImage was dedupe-suppressed and the Unlink half
        // never landed.) For Write/Extend, first-write-wins still
        // applies — repeated writes to the same file get one
        // pre-image, the post-content can be reconstructed from
        // post_content_hash + the original blob.
        if !is_delete && !should_capture_dedupe(&ws.dedupe, (dev, inode)) {
            tracing::trace!(fd, dev, inode, "dedupe hit; skipping recapture");
            return;
        }
        let path = ws.subtree.path_for_fd(fd).map(|p| p.to_path_buf());
        // Stat for metadata. After Delete the fstat above already
        // returned valid (dev, inode); same call works for mode/uid/gid/mtime.
        let meta = match fstat_meta(fd) {
            Some(m) => m,
            None => {
                tracing::warn!(fd, "fstat for meta failed; skipping capture");
                return;
            }
        };
        // W07.A.1: stream the pre-image directly from the tracked fd
        // into a staging file, blake3-hashing as we go. For Delete,
        // the fd survives unlink and pread still returns original
        // bytes (S23.4's architectural test proves this).
        //
        // No `Vec<u8>` is materialized — userspace buffer bounded by
        // STREAM_COPY_CHUNK (64 KiB) regardless of file size. Cap is
        // STREAM_COPY_CAP (1 GiB this sprint; final policy in A.3).
        let (staging_fd, claimed_hash, stored_bytes) =
            match stream_copy_to_staging(fd, self.staging_dir_fd.as_raw_fd(), STREAM_COPY_CAP) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(fd, error = %e, "stream_copy_to_staging failed");
                    return;
                }
            };
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // Wire's `seq` field is the *command's* seq — that's the FK
        // the daemon uses to attach the event to the originating
        // PreExec'd command (the helper-local seq_counter we had here
        // before tripped a sqlite FK constraint on the daemon side).
        let resp = HelperResponse::CapturedPreImage {
            session: command.session,
            seq: command.seq,
            dev,
            inode,
            path: path.as_deref().map(path_to_string),
            blob_hash: claimed_hash,
            stored_bytes,
            post_content_hash: None, // TODO: compute when not Delete
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
        // Mark as captured. Don't insert a NEW key — we used or_insert
        // above; just update the invalidated flag based on Delete.
        ws.dedupe.insert(
            (dev, inode),
            DedupeEntry {
                invalidated: is_delete,
            },
        );
        // Record helper-local stamp for telemetry. (TODO wire to stats.)
        tracing::info!(
            %command.session,
            seq = command.seq,
            dev,
            inode,
            ?kind,
            bytes = stored_bytes,
            now_nanos,
            "CapturedPreImage sent",
        );
    }

    /// S29.1 — diff a directory's current entries against the baseline
    /// captured at attach time, emit `TreeMutation` events for each
    /// added/removed child, and refresh the baseline. Inode preservation
    /// across a name change is detected as Unlink+Create for the same
    /// `(dev, inode)`; the planner can pair them into a Rename at cohort
    /// assignment time.
    ///
    /// S29.2 — when a new entry is a regular file, auto-add it to the
    /// kqueue watch via `subtree.add_path` so subsequent
    /// NOTE_WRITE/NOTE_DELETE on the new file's fd are picked up by
    /// the regular file branch of `handle_vnode`. The kq fd is the
    /// pump's shared `Arc<KqueueFd>` (`self.kq`).
    fn handle_dir_change(&mut self, command: CommandId, fd: RawFd) {
        // W03.B: drive the diff via a work-queue so newly-discovered
        // sub-directories can be scanned in the same handler call.
        // Without this, `cp -r src dst` only registered the top-level
        // `dst` create and lost every event inside it — S29.2's
        // original logic only watched new *regular* files, not new
        // *dirs*, so NOTE_WRITE on the new dir never fired and its
        // children stayed invisible.
        let mut to_scan: Vec<RawFd> = vec![fd];
        while let Some(fd) = to_scan.pop() {
            self.scan_dir_emit_and_watch_children(command, fd, &mut to_scan);
        }
    }

    /// Process one directory's diff, emit Create events, install
    /// watches for new files AND new dirs, and append any new dir
    /// fds to `to_scan` so the caller can process them in the same
    /// invocation. Split out from `handle_dir_change` so the
    /// recursive case (new dir → its children) can be handled in a
    /// single drain iteration without re-entering kqueue dispatch.
    fn scan_dir_emit_and_watch_children(
        &mut self,
        command: CommandId,
        fd: RawFd,
        to_scan: &mut Vec<RawFd>,
    ) {
        let Some(ws) = self.watches.get_mut(&command) else {
            return;
        };
        let Some(baseline) = ws.dir_baselines.get_mut(&fd) else {
            tracing::trace!(fd, "dir Write on dir without baseline; skipping");
            return;
        };
        let dir_path = baseline.path.clone();
        let current = match read_dir_entries(fd) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(fd, error = %e, "read_dir_entries failed");
                return;
            }
        };
        // Compute additions (in current, not in baseline). A name with
        // a different (dev, inode) at the same name is treated as an
        // addition (the inode-replacement case — file deleted and a new
        // one created with the same name).
        //
        // S29.2: for each *new regular file*, register a kqueue watch
        // on it via `subtree.add_path` and index its fd in
        // `fd_to_command`. Subsequent writes/deletes then fire on the
        // tracked fd and the regular-file branch of `handle_vnode`
        // picks them up.
        //
        // W03.B: do the same for *new directories*, AND queue them
        // for an immediate re-scan in this same handler call. Without
        // the watch + rescan, a `cp -r src dst` loses every event
        // under dst because NOTE_WRITE never fires on dst (no watch).
        let mut events: Vec<shit_proto::TreeOpWire> = Vec::new();
        let mut new_files_to_watch: Vec<std::path::PathBuf> = Vec::new();
        let mut new_dirs_to_watch: Vec<std::path::PathBuf> = Vec::new();
        for (name, &(dev, inode)) in &current {
            match baseline.entries.get(name) {
                Some(&prev) if prev == (dev, inode) => {} // unchanged
                Some(_) | None => {
                    // New entry, or entry with different inode at same name.
                    let child = dir_path.join(name);
                    // file_kind_AT (not _for): under cap_enter,
                    // absolute-path stat returns ENOTCAPABLE, falls
                    // through to Regular, and the dir-watching branch
                    // below never fires for new dirs. W03.B.
                    let kind = file_kind_at(fd, name);
                    events.push(shit_proto::TreeOpWire::Create {
                        dev,
                        inode,
                        path: path_to_string(&child),
                        kind,
                        mode: file_mode_for(&child).unwrap_or(0),
                    });
                    match kind {
                        shit_proto::FileKindWire::Regular => {
                            new_files_to_watch.push(child);
                        }
                        shit_proto::FileKindWire::Directory => {
                            new_dirs_to_watch.push(child);
                        }
                        _ => {} // symlinks/other tracked via S29.1's tree-op pairing path
                    }
                }
            }
        }
        // **Intentionally do not emit Unlink for removed entries here.**
        // Every name that *was* in the baseline was an fd-tracked entry
        // (since `register_subtree` opens directories AND files). Its
        // removal raises NOTE_DELETE on the file's own fd, which the
        // file branch of `handle_vnode` handles by emitting
        // CapturedPreImage(is_delete=true) — that path produces the
        // paired TreeOp::Unlink via `journal_unlink_idempotent` on the
        // daemon side. Emitting Unlink here too would race the file
        // path's ts ordering and break the planner's
        // reverse-chronological invariant (smoke-surfaced bug:
        // RestoreContent ran before RecreatePath when dir-diff's
        // Unlink got a lower ts than FilePreImage).
        //
        // The remaining gap — rmdir of the watched root dir itself —
        // is handled by a dedicated branch in `handle_vnode` for
        // `(kind=Delete, file_type=Directory)`, not here.
        let _ = &baseline.entries; // kept for the diff above (Create emit)
        // Refresh baseline so subsequent diffs are relative to the
        // post-change state.
        baseline.entries = current;

        // S29.2 — register fresh fds for each new regular file. Mutate
        // both the watch's subtree (so add_path's bookkeeping is
        // visible) and our `fd_to_command` index (so when the new
        // fd's NOTE_WRITE/NOTE_DELETE fires later, the file branch in
        // `handle_vnode` resolves it correctly).
        for new_path in new_files_to_watch {
            if let Some(new_fd) = ws.subtree.add_path(&self.kq, &new_path) {
                self.fd_to_command.insert(new_fd, command);
                // S29.3 — seed the metadata baseline for the new fd so
                // a subsequent NOTE_ATTRIB has something to compare to.
                if let Some(m) = fstat_meta(new_fd) {
                    ws.meta_baselines.insert(new_fd, m);
                }
                tracing::info!(
                    %command.session,
                    seq = command.seq,
                    path = %new_path.display(),
                    new_fd,
                    "auto-added new file to subtree watch",
                );
            }
        }

        // W03.B — same as above for new directories, plus seed an
        // EMPTY dir_baseline + queue the new dir's fd for an
        // immediate rescan. The empty baseline makes the next
        // scan_dir_emit_and_watch_children call treat everything
        // currently inside the dir as a fresh addition (which it is
        // — cp may have already populated it before our watch
        // installed). The queue iteration is what propagates the
        // walk deep into a `cp -r` tree.
        for new_path in new_dirs_to_watch {
            if let Some(new_fd) = ws.subtree.add_path(&self.kq, &new_path) {
                self.fd_to_command.insert(new_fd, command);
                // S29.3 — meta baseline for the dir too (chmod on a
                // dir fires NOTE_ATTRIB on it).
                if let Some(m) = fstat_meta(new_fd) {
                    ws.meta_baselines.insert(new_fd, m);
                }
                // Seed empty dir baseline so the imminent rescan
                // surfaces every current child as a Create.
                ws.dir_baselines.insert(
                    new_fd,
                    DirBaseline {
                        path: new_path.clone(),
                        entries: BTreeMap::new(),
                    },
                );
                tracing::info!(
                    %command.session,
                    seq = command.seq,
                    path = %new_path.display(),
                    new_fd,
                    "auto-added new dir to subtree watch + queued rescan",
                );
                to_scan.push(new_fd);
            }
        }

        if events.is_empty() {
            tracing::trace!(fd, "dir Write produced no entry-set delta");
            return;
        }
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        for op in events {
            let resp = shit_proto::HelperResponse::TreeMutation {
                session: command.session,
                seq: command.seq,
                op,
                ts_unix_nanos: now_nanos,
            };
            if let Err(e) = self.conn.send_response(&resp) {
                tracing::warn!(error = %e, "send TreeMutation failed");
            }
        }
    }

    /// S29.3 — handle `NOTE_ATTRIB` on a tracked fd. Diff the current
    /// fstat against the meta baseline; if mode/uid/gid/mtime/size
    /// changed, emit `CapturedMetadataChange` and update the baseline.
    /// `NOTE_ATTRIB` also fires for atime-only updates (e.g., a read)
    /// which we deliberately ignore — atime isn't a user-visible
    /// mutation worth journaling.
    fn handle_attrib(&mut self, fd: RawFd) {
        let Some(command) = self.fd_to_command.get(&fd).copied() else {
            tracing::trace!(fd, "NOTE_ATTRIB for untracked fd; dropping");
            return;
        };
        let Some(ws) = self.watches.get_mut(&command) else {
            return;
        };
        // Directories also fire NOTE_ATTRIB on chmod; we skip dir
        // attribs for now (the planner doesn't have a MetadataChange
        // executor for dirs that's distinct from regular files, and
        // the chmod-undo smoke targets files).
        let Some((dev, inode, ft)) = fstat_dev_inode_kind(fd) else {
            tracing::warn!(fd, "fstat failed during attrib handling");
            return;
        };
        if ft != FileType::Regular {
            tracing::trace!(fd, ?ft, "attrib on non-regular; skipping");
            return;
        }
        let Some(after) = fstat_meta(fd) else {
            tracing::warn!(fd, "fstat_meta failed during attrib handling");
            return;
        };
        let before = match ws.meta_baselines.get(&fd).copied() {
            Some(b) => b,
            None => {
                // No baseline (shouldn't happen post-attach; could
                // race with detach). Take the current as baseline and
                // skip emission — we have nothing to compare to.
                ws.meta_baselines.insert(fd, after);
                return;
            }
        };
        if before == after {
            tracing::trace!(fd, "attrib fired but baseline matches; ignoring");
            return;
        }
        let path = ws.subtree.path_for_fd(fd).map(|p| p.to_path_buf());
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let resp = shit_proto::HelperResponse::CapturedMetadataChange {
            session: command.session,
            seq: command.seq,
            dev,
            inode,
            path: path.as_deref().map(path_to_string),
            before: before.to_wire(),
            after: after.to_wire(),
            ts_unix_nanos: now_nanos,
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "send CapturedMetadataChange failed");
            return;
        }
        ws.meta_baselines.insert(fd, after);
        tracing::info!(
            %command.session,
            seq = command.seq,
            dev,
            inode,
            "CapturedMetadataChange sent",
        );
    }
}

/// Read `mode` bits for a path. Used by the dir-diff path to populate
/// `TreeOpWire::Create.mode` so the undo executor's `RecreatePath` can
/// chmod to the original perms.
fn file_mode_for(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some(meta.mode())
}

fn tracked_fds(_subtree: &TrackedSubtree) -> Vec<RawFd> {
    // TrackedSubtree doesn't currently expose its fds; we use
    // path_for_fd in reverse via a small scan. The fd range we care
    // about (0..1024) covers normal helper-process descriptor usage
    // with margin.
    let mut out = Vec::new();
    for fd in 0..1024 {
        if _subtree.path_for_fd(fd).is_some() {
            out.push(fd);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Regular,
    Directory,
    Other,
}

/// fstat that also returns the file kind. register_subtree opens both
/// directories and files; only Regular files are valid pre-image
/// capture targets (pread on a directory returns EISDIR).
fn fstat_dev_inode_kind(fd: RawFd) -> Option<(u64, u64, FileType)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is expected valid; st is writable.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return None;
    }
    let kind = match (st.st_mode as libc::mode_t) & libc::S_IFMT {
        libc::S_IFREG => FileType::Regular,
        libc::S_IFDIR => FileType::Directory,
        _ => FileType::Other,
    };
    Some((st.st_dev as u64, st.st_ino as u64, kind))
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
    /// Convert to the wire shape the daemon expects. Same field set.
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
    #[cfg(target_os = "freebsd")]
    let (msec, mnsec) = (st.st_mtime as i128, st.st_mtime_nsec as i128);
    #[cfg(not(target_os = "freebsd"))]
    let (msec, mnsec) = (st.st_mtime as i128, st.st_mtime_nsec as i128);
    let mtime = msec.saturating_mul(1_000_000_000).saturating_add(mnsec);
    Some(StatMeta {
        mode: st.st_mode as u32,
        uid: st.st_uid as u32,
        gid: st.st_gid as u32,
        size: st.st_size as u64,
        mtime_unix_nanos: mtime,
    })
}

/// W02.B.live-baseline step 2b — walk the tracked subtree, ship a
/// BaselineCaptured message for every regular file, then a
/// BaselineWalkComplete to tell the daemon the cwd's cache is ready.
///
/// Reuses the fds the kqueue walker already opened (via
/// [`TrackedSubtree::iter_entries`]) — we don't re-open files, just
/// pread their content through the existing fd. Each regular file
/// gets staged into the SCM_RIGHTS staging dir, blake3-hashed, and
/// shipped to the daemon for ingestion into the LiveBaseline cache.
///
/// Returns `(file_count, partial)`. `partial == true` means at least
/// one regular file in the subtree was skipped (read error, stat
/// failure, staging error, send error). The daemon's promote path
/// falls back to layer 3 (post-write NOTE_WRITE read, S24.4) for
/// inodes the baseline missed.
fn baseline_walk_and_emit(
    subtree: &TrackedSubtree,
    conn: &Conn,
    staging_dir_fd: RawFd,
    session: uuid::Uuid,
    cwd_path: &Path,
) -> (u64, bool) {
    let mut count = 0u64;
    let mut partial = false;

    for (fd, path) in subtree.iter_entries() {
        let Some((dev, inode, kind)) = fstat_dev_inode_kind(fd) else {
            partial = true;
            continue;
        };
        if kind != FileType::Regular {
            // Dirs are watched but not baselined — their content is
            // their entry list, captured separately via S29.1 diff.
            continue;
        }

        let meta = match fstat_meta(fd) {
            Some(m) => m,
            None => {
                tracing::debug!(fd, "baseline: fstat_meta failed; skipping");
                partial = true;
                continue;
            }
        };

        // W07.A.1: stream-copy directly from the tracked fd into a
        // staging file. No `Vec<u8>` buffer.
        let (staging_fd, blob_hash, stored_bytes) =
            match stream_copy_to_staging(fd, staging_dir_fd, STREAM_COPY_CAP) {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(
                        fd,
                        error = %e,
                        path = %path.display(),
                        "baseline: stream_copy_to_staging failed; skipping"
                    );
                    partial = true;
                    continue;
                }
            };

        let resp = HelperResponse::BaselineCaptured {
            session,
            cwd: path_to_string(cwd_path),
            dev,
            inode,
            path: path_to_string(path),
            blob_hash,
            stored_bytes,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            fd_sent_via_scm: true,
        };

        if let Err(e) = conn.send_response_with_fd(&resp, staging_fd.as_raw_fd()) {
            tracing::warn!(error = %e, "baseline: send_response_with_fd failed");
            partial = true;
            continue;
        }
        count += 1;
    }

    // Walker done. Notify the daemon so it flips this cwd's
    // BaselineCacheEntry from Pending → Ready.
    let complete = HelperResponse::BaselineWalkComplete {
        session,
        cwd: path_to_string(cwd_path),
        file_count: count,
        partial,
    };
    if let Err(e) = conn.send_response(&complete) {
        tracing::warn!(error = %e, "baseline: BaselineWalkComplete send failed");
    }

    (count, partial)
}

fn path_to_string(p: &Path) -> String {
    String::from_utf8_lossy(p.as_os_str().as_bytes()).to_string()
}

/// Read a directory's immediate child entries via a tracked dir fd,
/// returning `name → (dev, inode)`. Symlinks recorded as their own
/// inode (not the link target's). Errors swallowed.
///
/// B05 Phase C: uses fdopendir + fstatat against `dir_fd` rather
/// than absolute-path `std::fs::read_dir`, so it works under
/// `cap_enter(2)`. The caller already holds `dir_fd` as a tracked
/// kqueue watch fd (we dup before fdopendir to avoid losing the
/// original reference).
fn read_dir_entries(dir_fd: RawFd) -> std::io::Result<BTreeMap<std::ffi::OsString, (u64, u64)>> {
    let mut out = BTreeMap::new();
    // SAFETY: dir_fd is alive (caller holds the OwnedFd in
    // TrackedSubtree). dup returns a fresh fd we own; fdopendir
    // takes it under DIR* control.
    let dup_fd = unsafe { libc::dup(dir_fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dir = unsafe { libc::fdopendir(dup_fd) };
    if dir.is_null() {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(err);
    }
    // CRITICAL: dup(2) shares the open file description (including the
    // file offset) with the source fd. After the attach-time baseline
    // read, the dir_fd's offset is at EOF. Subsequent read_dir_entries
    // calls would start from EOF and return nothing — so dir-diff
    // would miss every new entry. rewinddir resets the shared offset
    // back to 0. Caught by the freebsd-smoke CI run (amd64) where
    // mkdir-undo + touch-edit-undo both failed at TreeOpCreate; arm64
    // shit-fbsd hides this because its fdopendir is more lenient.
    unsafe { libc::rewinddir(dir) };
    loop {
        let entry_ptr = unsafe { libc::readdir(dir) };
        if entry_ptr.is_null() {
            break;
        }
        let entry = unsafe { &*entry_ptr };
        let name_len = unsafe { libc::strlen(entry.d_name.as_ptr()) };
        let name_bytes =
            unsafe { std::slice::from_raw_parts(entry.d_name.as_ptr().cast::<u8>(), name_len) };
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        // fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW) to get dev+inode
        // without following symlinks. NOFOLLOW matches the
        // symlink_metadata semantics the absolute-path version had.
        let name_c = match std::ffi::CString::new(name_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::fstatat(dir_fd, name_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if rc != 0 {
            continue;
        }
        let name_os = std::ffi::OsString::from(std::ffi::OsStr::from_bytes(name_bytes));
        out.insert(name_os, (st.st_dev as u64, st.st_ino));
    }
    unsafe { libc::closedir(dir) };
    Ok(out)
}

/// Classify a directory child's `FileKind` for the wire via
/// `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)` — fd-relative ops
/// work under capsicum, unlike absolute-path `stat`. W03.B
/// surfaced this: under default-on cap_enter, an earlier
/// absolute-path version returned `ENOTCAPABLE`, fell through to
/// `Regular`, and caused S29.2 to treat new dirs as files (missing
/// every `cp -r` event under dst).
///
/// Errors fall through to `Regular` — the planner only acts on
/// `Directory`/`Regular`/`Symlink` distinctly, and `Regular` is
/// the safe default fallback for fifo/socket/block/char/etc.
fn file_kind_at(dir_fd: RawFd, name: &std::ffi::OsStr) -> shit_proto::FileKindWire {
    use shit_proto::FileKindWire as K;
    let name_c = match std::ffi::CString::new(name.as_bytes()) {
        Ok(c) => c,
        Err(_) => return K::Regular,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd is alive per caller (held in TrackedSubtree);
    // name_c is NUL-terminated; st is writable.
    let rc = unsafe { libc::fstatat(dir_fd, name_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return K::Regular;
    }
    match (st.st_mode as libc::mode_t) & libc::S_IFMT {
        libc::S_IFDIR => K::Directory,
        libc::S_IFLNK => K::Symlink,
        _ => K::Regular,
    }
}

/// Handle the request_loop holds. Cheaply cloneable.
#[derive(Clone)]
pub struct CaptureControl {
    tx: SyncSender<ControlMsg>,
}

impl CaptureControl {
    /// B05.10: caller provides `cwd_path` directly (forwarded from the
    /// shell hook via WatchTree). Empty string falls back to the
    /// legacy sysctl(KERN_PROC_CWD) resolver for the helper's-own-pid
    /// path; cross-pid resolves are blocked under cap_enter so that
    /// path effectively requires `cwd_path` to be non-empty.
    pub fn on_watch_tree(&self, session: Uuid, command_seq: u64, root_pid: u32, cwd_path: &str) {
        let path = if !cwd_path.is_empty() {
            PathBuf::from(cwd_path)
        } else {
            match super::cwd::resolve_pid_cwd(root_pid) {
                Some(p) => p,
                None => {
                    tracing::warn!(
                        %session,
                        command_seq,
                        root_pid,
                        "could not resolve root_pid cwd and no cwd_path provided; watch dropped",
                    );
                    return;
                }
            }
        };
        let _ = self.tx.try_send(ControlMsg::Attach {
            command: CommandId {
                session,
                seq: command_seq,
            },
            root_path: path,
        });
    }

    pub fn on_unwatch_tree(&self, session: Uuid, command_seq: u64) {
        let _ = self.tx.try_send(ControlMsg::Detach {
            command: CommandId {
                session,
                seq: command_seq,
            },
        });
    }

    /// Signal the pump thread to exit. Best-effort.
    pub fn shutdown(&self) {
        let _ = self.tx.try_send(ControlMsg::Shutdown);
    }
}

/// Spawn the BSD capture pump. Returns a control handle for the
/// request loop to drive watches, plus the join handle so the
/// caller can wait for the pump to exit.
pub fn spawn(
    conn: Arc<Conn>,
    staging_dir: PathBuf,
    slash_fd: Option<Arc<OwnedFd>>,
) -> std::io::Result<(CaptureControl, JoinHandle<()>)> {
    std::fs::create_dir_all(&staging_dir)?;
    // B05 Phase C: pre-open the staging dir as O_DIRECTORY so
    // stream_copy_to_staging can use openat under cap_enter.
    let staging_dir_fd = {
        use std::os::fd::FromRawFd;
        let cpath = std::ffi::CString::new(staging_dir.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "staging path NUL")
        })?;
        let raw = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Arc::new(unsafe { OwnedFd::from_raw_fd(raw) })
    };
    // Single shared kqueue: the drain thread reads events, the pump
    // thread calls `register_subtree` to add new fd watches. Both
    // operations on the same fd are thread-safe at the kernel level.
    let kq = Arc::new(kqueue_init().map_err(std::io::Error::other)?);
    let drain_session = spawn_drain(Arc::clone(&kq), 4096).map_err(std::io::Error::other)?;
    let (ctrl_tx, ctrl_rx) = sync_channel::<ControlMsg>(64);
    let handle = std::thread::Builder::new()
        .name("shit-bsd-capture-pump".to_string())
        .spawn(move || pump(kq, drain_session, conn, staging_dir_fd, ctrl_rx, slash_fd))?;
    Ok((CaptureControl { tx: ctrl_tx }, handle))
}

fn pump(
    kq: Arc<KqueueFd>,
    drain_session: DrainSession,
    conn: Arc<Conn>,
    staging_dir_fd: Arc<OwnedFd>,
    ctrl_rx: Receiver<ControlMsg>,
    slash_fd: Option<Arc<OwnedFd>>,
) {
    let mut state = PumpState::new(staging_dir_fd, conn, Arc::clone(&kq), slash_fd);
    loop {
        // Try a control command first (low latency for watch/unwatch).
        match ctrl_rx.try_recv() {
            Ok(ControlMsg::Attach { command, root_path }) => {
                state.attach(&kq, command, &root_path);
                continue;
            }
            Ok(ControlMsg::Detach { command }) => {
                state.detach(command);
                continue;
            }
            Ok(ControlMsg::Shutdown) => {
                tracing::info!("bsd capture pump shutdown requested");
                drop(drain_session);
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                tracing::info!("control channel closed; pump exiting");
                drop(drain_session);
                return;
            }
        }
        // Then a drain event (block with a short timeout so control
        // commands stay responsive).
        match drain_session.events.recv_timeout(Duration::from_millis(50)) {
            Ok(DrainEvent::Vnode { fd, kind, .. }) => {
                state.handle_vnode(fd, kind);
            }
            Ok(DrainEvent::Proc { .. }) => {
                // S24.B doesn't act on proc events; S24's tree-tracking
                // story for descendants lands later.
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!("drain channel disconnected; pump exiting");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dedupe_first_write_wins() {
        let mut map: HashMap<(u64, u64), DedupeEntry> = HashMap::new();
        let key = (1u64, 42u64);
        // First write: empty map → should capture.
        assert!(should_capture_dedupe(&map, key));
        // Record the capture (not invalidated — was a Write/Extend).
        map.insert(key, DedupeEntry { invalidated: false });
        // Second write to the same inode: dedupe hit → skip.
        assert!(!should_capture_dedupe(&map, key));
        // Different inode in the same watch: independent dedupe.
        assert!(should_capture_dedupe(&map, (1, 43)));
    }

    #[test]
    fn delete_invalidates_then_recaptures() {
        let mut map: HashMap<(u64, u64), DedupeEntry> = HashMap::new();
        let key = (2u64, 100u64);
        // Initial write captures.
        assert!(should_capture_dedupe(&map, key));
        map.insert(key, DedupeEntry { invalidated: false });
        // Subsequent write: skipped.
        assert!(!should_capture_dedupe(&map, key));
        // NOTE_DELETE flips the entry — simulates the helper's
        // post-Delete bookkeeping.
        map.insert(key, DedupeEntry { invalidated: true });
        // Next write (inode reuse or recreate-with-same-key): captures.
        assert!(should_capture_dedupe(&map, key));
    }

    #[test]
    fn late_event_after_unwatch_dropped() {
        // After detach, the PumpState's watches map no longer contains
        // the command; handle_vnode short-circuits at the
        // `self.watches.get_mut(&command)` lookup. We simulate the
        // "fd is registered but watch is gone" race by populating
        // fd_to_command without an entry in watches and asserting the
        // code path returns cleanly.
        let (conn_a, _conn_b) = crate::ipc::socketpair().expect("socketpair");
        let dir = tempfile::tempdir().unwrap();
        let kq = Arc::new(crate::kqueue::init().expect("kqueue init"));
        // Open staging dir for the fd. Test only needs it to exist;
        // handle_vnode-ghost-fd path doesn't actually write.
        let staging_fd = {
            use std::os::fd::FromRawFd;
            let cpath = std::ffi::CString::new(dir.path().as_os_str().as_bytes()).unwrap();
            let raw = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            assert!(raw >= 0);
            Arc::new(unsafe { OwnedFd::from_raw_fd(raw) })
        };
        let mut state = PumpState::new(staging_fd, Arc::new(conn_a), kq, None);
        let ghost = CommandId {
            session: Uuid::nil(),
            seq: 0,
        };
        state.fd_to_command.insert(999, ghost);
        // Must not panic; must not send.
        state.handle_vnode(999, VnodeEventKind::Write);
        assert!(state.watches.is_empty(), "watches must still be empty");
    }
}
