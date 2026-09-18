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
//!         ▲                            │
//!         └── attach + baseline result ───┘
//! ```
//!
//! State mutations happen *only* on the pump thread — no locks needed.
//! The control channel and the drain channel are both `sync_channel(N)`
//! and the pump alternates `try_recv` on them. A `WatchTree` caller waits
//! on a per-attach completion channel before it may emit `WatchTreeReady`.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, channel, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use shit_planner::events::CommandId;
use shit_proto::HelperResponse;
use uuid::Uuid;

use crate::ipc::Conn;
use crate::kqueue::{
    DrainEvent, DrainSession, KqueueError, KqueueFd, STREAM_COPY_CAP, TrackedSubtree,
    VnodeEventKind, init as kqueue_init, register_subtree, register_subtree_at, spawn_drain,
    stream_copy_to_staging,
};

/// Default subtree depth — matches `kqueue::vnode::DEFAULT_DEPTH_LIMIT`.
const DEFAULT_DEPTH: usize = 8;

/// Leaves time inside the daemon's five-second readiness deadline to persist
/// a refusal and answer the shell even when registration or baseline capture
/// stalls. A timed-out request is fenced so a late attach cannot stay live.
const ATTACH_COMPLETION_TIMEOUT: Duration = Duration::from_secs(3);

/// Once the pump advertises a prepared watch, the request loop immediately
/// commits it over an in-process channel. Bounding that handshake protects the
/// pump if its requester exits between receiving readiness and committing it.
const ATTACH_COMMIT_TIMEOUT: Duration = Duration::from_secs(1);

/// Must expire before the daemon's five-second outer UnwatchTree deadline so
/// the helper still has time to deliver a final CaptureRefused.
const DETACH_COMPLETION_TIMEOUT: Duration = Duration::from_secs(3);

/// Inbound control commands the request_loop sends to the pump.
enum ControlMsg {
    Attach {
        command: CommandId,
        root_path: PathBuf,
        /// Set by the request loop when its bounded wait expires. The pump
        /// checks it both before and after the potentially expensive baseline
        /// walk and removes any watch that completed after cancellation.
        cancelled: Arc<AtomicBool>,
        /// One-shot completion sent only after the subtree is registered,
        /// its metadata maps are populated, and the live-baseline walk has
        /// finished. The request loop must not emit WatchTreeReady before
        /// receiving this result.
        completion: std::sync::mpsc::Sender<Result<(), CaptureAttachError>>,
        /// Second half of the readiness handshake. A prepared watch remains
        /// live only if the request loop received `Ok(())` and commits it.
        commit: Receiver<()>,
    },
    Detach {
        command: CommandId,
        /// Completed only after the kqueue drain has emitted an ordered flush
        /// marker and the pump has processed every event before that marker.
        completion: std::sync::mpsc::Sender<Result<(), CaptureDetachError>>,
    },
    Shutdown,
}

/// Failure to make a BSD command watch capture-ready.
///
/// Kept attach-specific so the readiness fix does not silently broaden
/// AU16 into changing detach/shutdown semantics in the same patch.
#[derive(Debug, thiserror::Error)]
pub enum CaptureAttachError {
    #[error("could not resolve cwd for root pid {root_pid}")]
    CwdUnavailable { root_pid: u32 },
    #[error("BSD capture control channel is closed")]
    ControlChannelClosed,
    #[error("BSD capture pump dropped the attach completion channel")]
    CompletionChannelClosed,
    #[error("BSD capture pump did not complete attach within {timeout:?}")]
    Timeout { timeout: Duration },
    #[error("BSD capture attach was cancelled before readiness commit")]
    ReadinessCancelled,
    #[error("watch cwd is not representable as UTF-8 on the helper wire")]
    CwdUnrepresentable,
    #[error("register kqueue subtree at {root_path:?}: {source}")]
    RegisterSubtree {
        root_path: PathBuf,
        #[source]
        source: KqueueError,
    },
    #[error("watch snapshot at {root_path:?} was incomplete: {detail}")]
    SnapshotIncomplete { root_path: PathBuf, detail: String },
    #[error("pre-command baseline at {root_path:?} was incomplete ({file_count} files emitted)")]
    BaselineIncomplete { root_path: PathBuf, file_count: u64 },
    #[error("pre-command baseline is disabled for {root_path:?}; refusing an unsafe BSD watch")]
    BaselineDisabled { root_path: PathBuf },
    #[error(
        "watch root {root_path:?} overlaps active BSD watch {active_root:?} for {active_command:?}"
    )]
    OverlappingWatch {
        root_path: PathBuf,
        active_root: PathBuf,
        active_command: CommandId,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureDetachError {
    #[error("BSD capture control channel is closed")]
    ControlChannelClosed,
    #[error("BSD capture pump dropped the detach completion channel")]
    CompletionChannelClosed,
    #[error("BSD capture pump did not complete detach within {timeout:?}")]
    Timeout { timeout: Duration },
    #[error("kqueue drain flush failed: {0}")]
    DrainFlush(String),
    #[error("BSD capture was incomplete at command close: {detail}")]
    CaptureUnsafe { detail: String },
}

/// Producer state owned by the pump thread.
struct WatchState {
    subtree: TrackedSubtree,
    /// Root spelling paired with the descriptor-identity overlap check. BSD
    /// baselines are keyed by cwd in the daemon today, so two live watches
    /// whose roots are equal or nested must be refused until that cache is
    /// command-keyed.
    root_path: PathBuf,
    root_identity: (u64, u64),
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
    /// First loss of required evidence or delivery. Sticky for the complete
    /// command window; later successful observations cannot repair a missing
    /// earlier mutation.
    capture_failure: Option<String>,
}

impl WatchState {
    fn mark_unsafe(&mut self, detail: impl Into<String>) {
        mark_capture_unsafe(&mut self.capture_failure, detail);
    }
}

fn mark_capture_unsafe(slot: &mut Option<String>, detail: impl Into<String>) {
    if slot.is_none() {
        *slot = Some(detail.into());
    }
}

#[derive(Debug, Clone)]
struct DirBaseline {
    /// Absolute path of the directory (for emitting child paths).
    path: PathBuf,
    /// Child name → per-entry baseline. We store inode so the diff
    /// can detect rename-within-dir; the optional symlink_target
    /// (captured via readlinkat at scan time) lets the diff detect
    /// `ln -sf newtarget link` and emit a SymlinkRemoved event
    /// carrying the OLD target so undo can restore it.
    entries: BTreeMap<std::ffi::OsString, DirEntryBaseline>,
}

/// W09.16.1 — per-directory-entry baseline. The (dev, inode) pair
/// detects entry replacement at the same name; `symlink_target`
/// (populated for symlink entries via readlinkat) lets the dir-diff
/// emit a `SymlinkRemoved` event carrying the OLD target so undo
/// can restore it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirEntryBaseline {
    dev: u64,
    inode: u64,
    /// `Some(readlink_value)` if this entry was a symlink at scan
    /// time. `None` for regular files, dirs, FIFOs, sockets, etc.
    symlink_target: Option<std::ffi::OsString>,
    /// True when this entry was a symlink but readlinkat failed or could have
    /// truncated the target. A later removal/replacement must be refused.
    symlink_target_unavailable: bool,
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

    fn attach(
        &mut self,
        kq: &KqueueFd,
        command: CommandId,
        root_path: &Path,
    ) -> Result<(), CaptureAttachError> {
        // Every baseline and mutation response keys the watch by this cwd on
        // the UTF-8 helper wire. Accepting a native non-UTF-8 cwd would make
        // it impossible to emit BaselineWalkComplete while the request loop
        // could still advertise WatchTreeReady. Fail the attach instead.
        if root_path.to_str().is_none() {
            return Err(CaptureAttachError::CwdUnrepresentable);
        }
        let subtree_result = match &self.slash_fd {
            Some(slash) => register_subtree_at(kq, slash.as_raw_fd(), root_path, DEFAULT_DEPTH),
            None => register_subtree(kq, root_path, DEFAULT_DEPTH),
        };
        let subtree = subtree_result.map_err(|source| CaptureAttachError::RegisterSubtree {
            root_path: root_path.to_path_buf(),
            source,
        })?;
        let root_identity = subtree_root_identity(&subtree).ok_or_else(|| {
            CaptureAttachError::SnapshotIncomplete {
                root_path: root_path.to_path_buf(),
                detail: "could not stat the newly registered watch root".into(),
            }
        })?;
        for (active_command, active_watch) in &self.watches {
            let new_contains_active = subtree_contains_identity(
                &subtree,
                active_watch.root_identity,
            )
            .map_err(|fd| CaptureAttachError::SnapshotIncomplete {
                root_path: root_path.to_path_buf(),
                detail: format!(
                    "could not stat newly registered watch fd {fd} while checking root overlap"
                ),
            })?;
            let active_contains_new =
                subtree_contains_identity(&active_watch.subtree, root_identity).map_err(|fd| {
                    CaptureAttachError::SnapshotIncomplete {
                        root_path: root_path.to_path_buf(),
                        detail: format!(
                            "could not stat active watch fd {fd} while checking root overlap"
                        ),
                    }
                })?;
            if new_contains_active || active_contains_new {
                return Err(CaptureAttachError::OverlappingWatch {
                    root_path: root_path.to_path_buf(),
                    active_root: active_watch.root_path.clone(),
                    active_command: *active_command,
                });
            }
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
                return Err(CaptureAttachError::SnapshotIncomplete {
                    root_path: root_path.to_path_buf(),
                    detail: format!("file-type snapshot failed for tracked fd {raw}"),
                });
            };
            if ft != FileType::Directory {
                continue;
            }
            let Some(dir_path) = subtree.path_for_fd(raw).map(|p| p.to_path_buf()) else {
                return Err(CaptureAttachError::SnapshotIncomplete {
                    root_path: root_path.to_path_buf(),
                    detail: format!("tracked directory fd {raw} had no registered path"),
                });
            };
            let entries =
                read_dir_entries(raw).map_err(|error| CaptureAttachError::SnapshotIncomplete {
                    root_path: root_path.to_path_buf(),
                    detail: format!(
                        "could not snapshot directory {}: {error}",
                        dir_path.display()
                    ),
                })?;
            // W09.16.1 CI diag — dump baseline dir entries with
            // their symlink_target so we know if `config` is in
            // the map at attach time.
            for (name, e) in &entries {
                tracing::info!(
                    fd = raw,
                    name = %name.to_string_lossy(),
                    dev = e.dev,
                    inode = e.inode,
                    symlink_target = ?e.symlink_target,
                    "W09.16.1 baseline entry"
                );
            }
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
            let Some(meta) = fstat_meta(raw) else {
                return Err(CaptureAttachError::SnapshotIncomplete {
                    root_path: root_path.to_path_buf(),
                    detail: format!("metadata snapshot failed for tracked fd {raw}"),
                });
            };
            meta_baselines.insert(raw, meta);
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
                command,
                root_path,
            );
            tracing::info!(
                %command.session,
                seq = command.seq,
                baseline_files = n,
                baseline_partial = partial,
                "live-baseline walk emitted",
            );
            if partial {
                return Err(CaptureAttachError::BaselineIncomplete {
                    root_path: root_path.to_path_buf(),
                    file_count: n,
                });
            }
        } else {
            return Err(CaptureAttachError::BaselineDisabled {
                root_path: root_path.to_path_buf(),
            });
        }

        // Publish fd routing only after every snapshot is complete. A failed
        // attach drops the subtree without leaving stale fd ownership behind.
        for raw in tracked_fds(&subtree) {
            self.fd_to_command.insert(raw, command);
        }
        self.watches.insert(
            command,
            WatchState {
                subtree,
                root_path: root_path.to_path_buf(),
                root_identity,
                dedupe: HashMap::new(),
                dir_baselines,
                meta_baselines,
                capture_failure: None,
            },
        );
        Ok(())
    }

    /// Remove every fd route before reporting command health. Returning the
    /// sticky failure lets the flush-completion path send one final refusal
    /// only after cleanup is complete.
    fn detach(&mut self, command: CommandId) -> Option<String> {
        if let Some(ws) = self.watches.remove(&command) {
            for raw in tracked_fds(&ws.subtree) {
                self.fd_to_command.remove(&raw);
            }
            tracing::info!(
                %command.session,
                seq = command.seq,
                "watch detached",
            );
            ws.capture_failure
        } else {
            Some("no active BSD watch existed at command detach".into())
        }
    }

    fn mark_all_active_unsafe(&mut self, detail: &str) {
        for watch in self.watches.values_mut() {
            watch.mark_unsafe(detail.to_owned());
        }
    }

    fn refuse_all_active(&mut self, detail: &str) {
        self.mark_all_active_unsafe(detail);
        send_capture_refusals(
            &self.conn,
            self.watches.keys().copied().collect::<Vec<_>>(),
            detail,
        );
    }

    /// Called only after `DrainEvent::FlushComplete`. Cleanup happens before
    /// the final refusal attempt, and any unsafe command returns Err whether
    /// or not that refusal can still reach the daemon. The request loop then
    /// withholds the shared v9 completion acknowledgement.
    fn finish_detach_after_flush(&mut self, command: CommandId) -> Result<(), CaptureDetachError> {
        let Some(capture_failure) = self.detach(command) else {
            return Ok(());
        };
        let refusal_detail =
            format!("BSD capture became incomplete before command close: {capture_failure}");
        let detail = match send_capture_refused(&self.conn, command, None, refusal_detail.clone()) {
            Ok(()) => refusal_detail,
            Err(error) => {
                tracing::error!(
                    %command.session,
                    seq = command.seq,
                    %error,
                    "final unsafe-command CaptureRefused could not be delivered"
                );
                format!("{refusal_detail}; final CaptureRefused delivery failed: {error}")
            }
        };
        Err(CaptureDetachError::CaptureUnsafe { detail })
    }

    fn handle_vnode(&mut self, fd: RawFd, kind: VnodeEventKind) {
        // W09.16.1 CI diag — log EVERY vnode event entry so we
        // can confirm whether kqueue is firing at all for the
        // symlink-replace case on 14.2 ZFS.
        tracing::info!(fd, ?kind, "W09.16.1 handle_vnode entry");
        let Some(command) = self.fd_to_command.get(&fd).copied() else {
            let detail = format!(
                "kqueue delivered {kind:?} for untracked fd {fd}; command attribution was impossible"
            );
            tracing::warn!(fd, ?kind, "vnode event for untracked fd");
            self.mark_all_active_unsafe(&detail);
            return;
        };
        // S29.3: route NOTE_ATTRIB (chmod/chown/touch) into its own
        // handler before the content-capture branch so we never
        // try to pread bytes for a metadata-only event.
        if matches!(kind, VnodeEventKind::Attrib) {
            self.handle_attrib(command, fd);
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
            if let Some(ws) = self.watches.get_mut(&command) {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("BSD kqueue event {kind:?} has no authoritative capture handler"),
                );
            }
            tracing::warn!(fd, ?kind, %command, "unsupported vnode mutation made capture unsafe");
            return;
        }
        let Some(ws) = self.watches.get_mut(&command) else {
            // A live fd route without its command state is an invariant
            // violation. Attribution is still exact, so refuse that command
            // instead of silently dropping a potentially mutating event.
            let detail = format!(
                "kqueue delivered {kind:?} for fd {fd} after its command watch state disappeared"
            );
            if let Err(error) = send_capture_refused(&self.conn, command, None, detail.clone()) {
                tracing::error!(
                    %command.session,
                    seq = command.seq,
                    %error,
                    "orphaned BSD vnode-event refusal could not be delivered"
                );
            }
            tracing::warn!(fd, ?kind, %command, %detail, "orphaned BSD vnode event");
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
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("fstat failed for tracked fd {fd} while handling {kind:?}"),
                );
                return;
            }
        };
        if file_type == FileType::Directory {
            // S29.1: NOTE_WRITE on a tracked dir indicates child
            // entries changed. Diff against the baseline to detect
            // create/unlink/rename and emit TreeMutation events.
            if is_delete {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!(
                        "directory deletion on tracked fd {fd} has no complete metadata pre-image"
                    ),
                );
                tracing::warn!(fd, %command, "directory delete made BSD capture unsafe");
                return;
            }
            self.handle_dir_change(command, fd);
            return;
        }
        if file_type != FileType::Regular {
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("{kind:?} on unsupported tracked {file_type:?} fd {fd}"),
            );
            tracing::warn!(fd, ?kind, ?file_type, "vnode event on unsupported type");
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
        let Some(path) = ws.subtree.path_for_fd(fd).map(|p| p.to_path_buf()) else {
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("tracked vnode fd {fd} could not be resolved to an undo path"),
            );
            if let Err(error) = send_capture_refused(
                &self.conn,
                command,
                None,
                "tracked vnode fd could not be resolved to an undo path",
            ) {
                tracing::warn!(%error, "BSD unresolved-path refusal send failed");
            }
            return;
        };
        let Some(path_wire) = path_to_wire_or_refuse(&self.conn, command, &path) else {
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!(
                    "tracked vnode path {} is not representable on the helper wire",
                    path.display()
                ),
            );
            return;
        };
        // Stat for metadata. After Delete the fstat above already
        // returned valid (dev, inode); same call works for mode/uid/gid/mtime.
        let meta = match fstat_meta(fd) {
            Some(m) => m,
            None => {
                tracing::warn!(fd, "fstat for meta failed; skipping capture");
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("regular-file metadata became unavailable for tracked fd {fd}"),
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    Some(path_wire.clone()),
                    "regular-file metadata became unavailable during capture",
                ) {
                    tracing::warn!(%error, "BSD metadata refusal send failed");
                }
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
                    mark_capture_unsafe(
                        &mut ws.capture_failure,
                        format!(
                            "regular-file pre-image capture failed for {}: {e}",
                            path.display()
                        ),
                    );
                    if let Err(send_error) = send_capture_refused(
                        &self.conn,
                        command,
                        Some(path_wire.clone()),
                        format!("regular-file pre-image capture failed: {e}"),
                    ) {
                        tracing::warn!(error = %send_error, "BSD pre-image refusal send failed");
                    }
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
        // AU11 — `post_content_hash` for non-Delete events. On BSD
        // kqueue fires AFTER the syscall commits, so the held fd
        // points to the inode's POST-mutation content. The
        // `stream_copy_to_staging` call above hashed exactly those
        // bytes, so `claimed_hash` IS the post-content hash for
        // non-Delete events.
        //
        // The blob bytes the daemon ultimately journals come from
        // the LiveBaseline cache (`handle_baseline_promoted_pre_image`
        // in shitd::helper_link) — that's the pre-command snapshot.
        // So the wire's `blob_hash` gets overridden daemon-side to
        // the real pre-image hash, while `post_content_hash` we set
        // here carries the helper's view of "what's at the fd now"
        // for the planner's drift-detection at undo time.
        //
        // For Delete events the fd survives unlink (per S23.4's
        // architectural test) and `claimed_hash` IS the pre-image
        // hash — there's no "post-content" because the file is
        // gone, so keep None.
        let post_content_hash = if is_delete { None } else { Some(claimed_hash) };
        let resp = HelperResponse::CapturedPreImage {
            session: command.session,
            seq: command.seq,
            dev,
            inode,
            path: Some(path_wire),
            blob_hash: claimed_hash,
            stored_bytes,
            post_content_hash,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            xattrs: meta.xattrs.clone(),
            // M03.x.SETATTR — BSD st_flags from the pre-mutation
            // StatMeta. 0 if the file had no chflags set.
            flags: meta.flags,
            is_delete,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, staging_fd.as_raw_fd())
        {
            tracing::warn!(error = %e, "send_response_with_fd failed");
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!(
                    "CapturedPreImage delivery failed for {}: {e}",
                    path.display()
                ),
            );
            return;
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
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("directory change on tracked fd {fd} had no entry baseline"),
            );
            tracing::warn!(fd, "dir Write on dir without baseline");
            return;
        };
        let dir_path = baseline.path.clone();
        let current = match read_dir_entries(fd) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(fd, error = %e, "read_dir_entries failed");
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("directory rescan failed for {}: {e}", dir_path.display()),
                );
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
        // W09.16.1 CI diag — dump current entries pre-diff.
        for (name, e) in &current {
            tracing::info!(
                fd,
                name = %name.to_string_lossy(),
                dev = e.dev,
                inode = e.inode,
                symlink_target = ?e.symlink_target,
                "W09.16.1 dir-diff current entry"
            );
        }
        for (name, cur_entry) in &current {
            let prev = baseline.entries.get(name);
            tracing::info!(
                fd,
                name = %name.to_string_lossy(),
                prev_some = prev.is_some(),
                "W09.16.1 dir-diff per-iter (pre check)"
            );
            // Unchanged entry: same (dev, inode) AND (for symlinks)
            // same target. Symlink target equality is checked because
            // `ln -sf newtarget link` allocates a NEW inode for the
            // new symlink, so (dev, inode) already detects the
            // replacement — but we want to ALSO catch the degenerate
            // case where the inode happens to land back on the old
            // one (filesystem reuse with same st_ino under heavy
            // churn). Cheap to compare.
            if let Some(p) = prev
                && p.dev == cur_entry.dev
                && p.inode == cur_entry.inode
                && p.symlink_target == cur_entry.symlink_target
                && p.symlink_target_unavailable == cur_entry.symlink_target_unavailable
            {
                continue;
            }
            let child = dir_path.join(name);
            let Some(child_wire) = path_to_wire_or_refuse(&self.conn, command, &child) else {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!(
                        "directory entry path {} is not representable on the helper wire",
                        child.display()
                    ),
                );
                continue;
            };
            // W09.16.1 — `ln -sf newtarget existing_link`: the OLD
            // symlink got unlinked and a new symlink took its place
            // at the same name. The OS may or may not reuse the
            // freed st_ino for the new symlink; we can't depend on
            // inode change to detect the replacement (FreeBSD 14.2's
            // ZFS reuses the freed inode in tight succession,
            // leaving the entry's (dev, inode) identical pre- and
            // post-replacement — surfaced via CI on the W09.16.1 PR).
            // Emit `SymlinkRemoved` whenever the old entry was a
            // symlink AND its target differs from the new one — the
            // target string is the load-bearing signal, not the
            // inode. The planner inverts SymlinkRemoved as
            // `CreateSymlink { target: old_target, path }` and the
            // paired Create's inverse (Unlink) runs first in
            // reverse-event-order; net effect restores the OLD
            // target.
            if let Some(p) = prev {
                tracing::info!(
                    name = %name.to_string_lossy(),
                    prev_inode = p.inode,
                    cur_inode = cur_entry.inode,
                    prev_target = ?p.symlink_target,
                    cur_target = ?cur_entry.symlink_target,
                    "W09.16.1 dir-diff: same-name-changed entry"
                );
                if p.symlink_target_unavailable {
                    mark_capture_unsafe(
                        &mut ws.capture_failure,
                        format!("old symlink target was unavailable for {}", child.display()),
                    );
                    if let Err(error) = send_capture_refused(
                        &self.conn,
                        command,
                        Some(child_wire.clone()),
                        "old symlink target was unavailable or truncated during baseline capture",
                    ) {
                        tracing::warn!(%error, "BSD unavailable-symlink-target refusal send failed");
                    }
                    continue;
                }
                if let Some(old_target) = &p.symlink_target
                    && p.symlink_target != cur_entry.symlink_target
                {
                    let Some(old_target_wire) = old_target.to_str().map(ToOwned::to_owned) else {
                        mark_capture_unsafe(
                            &mut ws.capture_failure,
                            format!(
                                "symlink target for {} is not representable as UTF-8",
                                child.display()
                            ),
                        );
                        if let Err(error) = send_capture_refused(
                            &self.conn,
                            command,
                            Some(child_wire.clone()),
                            "symlink target is not representable as UTF-8",
                        ) {
                            tracing::warn!(%error, "BSD symlink-target refusal send failed");
                        }
                        continue;
                    };
                    events.push(shit_proto::TreeOpWire::SymlinkRemovedIdentified {
                        dev: p.dev,
                        inode: p.inode,
                        target: old_target_wire,
                        path: child_wire.clone(),
                    });
                }
            }
            // New entry, or entry with different inode at same name.
            // file_kind_AT (not _for): under cap_enter,
            // absolute-path stat returns ENOTCAPABLE, falls
            // through to Regular, and the dir-watching branch
            // below never fires for new dirs. W03.B.
            let (kind, mode) = match file_kind_and_mode_at(fd, name) {
                Ok(observation) => observation,
                Err(error) => {
                    mark_capture_unsafe(
                        &mut ws.capture_failure,
                        format!(
                            "could not classify new directory entry {}: {error}",
                            child.display()
                        ),
                    );
                    tracing::warn!(fd, path = %child.display(), %error, "new directory entry classification failed");
                    continue;
                }
            };
            events.push(shit_proto::TreeOpWire::Create {
                dev: cur_entry.dev,
                inode: cur_entry.inode,
                path: child_wire,
                kind,
                mode,
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
        // W08: cross-dir `rename(2)` doesn't fire NOTE_DELETE on the
        // file's fd (the inode isn't unlinked, just reparented) and
        // NOTE_RENAME is currently a no-op in `handle_vnode`. The
        // source half of an intra-watch `mv` is therefore silent,
        // and the planner cannot pair it with the destination Create
        // to emit a Rename inverse. Documented as W06 territory —
        // the same cwd-watch-scope expansion that closes `make
        // install` closes the rename-source-half capture too.
        // W09.16.1.ci-fix — emit SymlinkRemoved for symlinks that
        // were in baseline but disappeared from current. Symlinks
        // aren't fd-tracked entries (register_subtree's open follows
        // the symlink target, not the symlink itself), so their
        // unlink does not raise NOTE_DELETE on a tracked fd. The dir's
        // NOTE_WRITE is the only signal we get.
        //
        // On FreeBSD 14.2 ZFS, `ln -sf newtarget link` produces TWO
        // NOTE_WRITE events: one when the old link is unlinked
        // (current has no `link` entry), one when the new link is
        // created (current has `link` with a new inode + new target).
        // Without this branch, the first event clobbered baseline.entries
        // with the entry-missing snapshot, so the second event saw
        // prev=None for `link` and emitted only a Create (no
        // SymlinkRemoved), losing the OLD target. On 14.4 the two
        // operations apparently coalesce into one event so the gap
        // never showed; 14.2 surfaced it.
        for (name, prev_entry) in &baseline.entries {
            if current.contains_key(name) {
                continue;
            }
            if prev_entry.symlink_target_unavailable {
                let child = dir_path.join(name);
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("old symlink target was unavailable for {}", child.display()),
                );
                let wire_path = path_to_string(&child);
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    wire_path,
                    "old symlink target was unavailable or truncated during baseline capture",
                ) {
                    tracing::warn!(%error, "BSD unavailable-symlink-target refusal send failed");
                }
                continue;
            }
            let Some(old_target) = &prev_entry.symlink_target else {
                continue;
            };
            let child = dir_path.join(name);
            let Some(child_wire) = path_to_wire_or_refuse(&self.conn, command, &child) else {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!(
                        "removed symlink path {} is not representable on the helper wire",
                        child.display()
                    ),
                );
                continue;
            };
            let Some(old_target_wire) = old_target.to_str().map(ToOwned::to_owned) else {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!(
                        "removed symlink target for {} is not representable as UTF-8",
                        child.display()
                    ),
                );
                if let Err(error) = send_capture_refused(
                    &self.conn,
                    command,
                    Some(child_wire),
                    "symlink target is not representable as UTF-8",
                ) {
                    tracing::warn!(%error, "BSD symlink-target refusal send failed");
                }
                continue;
            };
            events.push(shit_proto::TreeOpWire::SymlinkRemovedIdentified {
                dev: prev_entry.dev,
                inode: prev_entry.inode,
                target: old_target_wire,
                path: child_wire,
            });
        }
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
                } else {
                    mark_capture_unsafe(
                        &mut ws.capture_failure,
                        format!(
                            "metadata baseline failed for newly watched file {}",
                            new_path.display()
                        ),
                    );
                }
                tracing::info!(
                    %command.session,
                    seq = command.seq,
                    path = %new_path.display(),
                    new_fd,
                    "auto-added new file to subtree watch",
                );
            } else {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!(
                        "could not install kqueue watch for new file {}",
                        new_path.display()
                    ),
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
                } else {
                    mark_capture_unsafe(
                        &mut ws.capture_failure,
                        format!(
                            "metadata baseline failed for newly watched directory {}",
                            new_path.display()
                        ),
                    );
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
            } else {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!(
                        "could not install kqueue watch for new directory {}",
                        new_path.display()
                    ),
                );
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
                partial: false,
            };
            if let Err(e) = self.conn.send_response(&resp) {
                tracing::warn!(error = %e, "send TreeMutation failed");
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("TreeMutation delivery failed: {e}"),
                );
            }
        }
    }

    /// S29.3 — handle `NOTE_ATTRIB` on a tracked fd. Diff the current
    /// fstat against the meta baseline; if mode/uid/gid/mtime/size
    /// changed, emit `CapturedMetadataChange` and update the baseline.
    /// `NOTE_ATTRIB` also fires for atime-only updates (e.g., a read)
    /// which we deliberately ignore — atime isn't a user-visible
    /// mutation worth journaling.
    fn handle_attrib(&mut self, command: CommandId, fd: RawFd) {
        let Some(ws) = self.watches.get_mut(&command) else {
            let detail = format!(
                "kqueue delivered NOTE_ATTRIB for fd {fd} after its command watch state disappeared"
            );
            if let Err(error) = send_capture_refused(&self.conn, command, None, detail.clone()) {
                tracing::error!(
                    %command.session,
                    seq = command.seq,
                    %error,
                    "orphaned BSD metadata-event refusal could not be delivered"
                );
            }
            tracing::warn!(fd, %command, %detail, "orphaned BSD metadata event");
            return;
        };
        // Directories also fire NOTE_ATTRIB on chmod; we skip dir
        // attribs for now (the planner doesn't have a MetadataChange
        // executor for dirs that's distinct from regular files, and
        // the chmod-undo smoke targets files).
        let Some((dev, inode, ft)) = fstat_dev_inode_kind(fd) else {
            tracing::warn!(fd, "fstat failed during attrib handling");
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("fstat failed for tracked fd {fd} during metadata capture"),
            );
            return;
        };
        if ft != FileType::Regular {
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("metadata change on unsupported tracked {ft:?} fd {fd}"),
            );
            tracing::warn!(fd, ?ft, "attrib on unsupported file type");
            return;
        }
        let Some(after) = fstat_meta(fd) else {
            tracing::warn!(fd, "fstat_meta failed during attrib handling");
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("metadata snapshot failed for tracked fd {fd} after NOTE_ATTRIB"),
            );
            return;
        };
        let before = match ws.meta_baselines.get(&fd).cloned() {
            Some(b) => b,
            None => {
                mark_capture_unsafe(
                    &mut ws.capture_failure,
                    format!("NOTE_ATTRIB on tracked fd {fd} had no pre-change metadata baseline"),
                );
                return;
            }
        };
        if before == after {
            tracing::trace!(fd, "attrib fired but baseline matches; ignoring");
            return;
        }
        let Some(path) = ws.subtree.path_for_fd(fd).map(|p| p.to_path_buf()) else {
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!("metadata-change fd {fd} could not be resolved to an undo path"),
            );
            if let Err(error) = send_capture_refused(
                &self.conn,
                command,
                None,
                "metadata-change fd could not be resolved to an undo path",
            ) {
                tracing::warn!(%error, "BSD metadata unresolved-path refusal send failed");
            }
            return;
        };
        let Some(path_wire) = path_to_wire_or_refuse(&self.conn, command, &path) else {
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!(
                    "metadata-change path {} is not representable on the helper wire",
                    path.display()
                ),
            );
            return;
        };
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let resp = shit_proto::HelperResponse::CapturedMetadataChange {
            session: command.session,
            seq: command.seq,
            dev,
            inode,
            path: Some(path_wire),
            before: before.to_wire(),
            after: after.to_wire(),
            ts_unix_nanos: now_nanos,
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(error = %e, "send CapturedMetadataChange failed");
            mark_capture_unsafe(
                &mut ws.capture_failure,
                format!(
                    "CapturedMetadataChange delivery failed for {}: {e}",
                    path.display()
                ),
            );
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

fn tracked_fds(subtree: &TrackedSubtree) -> Vec<RawFd> {
    // Iterate the owned entries directly. Scanning an assumed fd range
    // lost every watch whose kernel-assigned descriptor was >= 1024,
    // making readiness untruthful for large trees or helpers that
    // already held many descriptors.
    subtree.iter_entries().map(|(fd, _)| fd).collect()
}

fn subtree_root_identity(subtree: &TrackedSubtree) -> Option<(u64, u64)> {
    let (fd, _) = subtree.iter_entries().next()?;
    let (dev, inode, _) = fstat_dev_inode_kind(fd)?;
    Some((dev, inode))
}

/// Descriptor identities make this an alias-safe ancestry check: roots reached
/// through different symlink spellings still overlap when either registered
/// subtree contains the other root inode.
fn subtree_contains_identity(
    subtree: &TrackedSubtree,
    identity: (u64, u64),
) -> Result<bool, RawFd> {
    for (fd, _) in subtree.iter_entries() {
        let Some((dev, inode, _)) = fstat_dev_inode_kind(fd) else {
            return Err(fd);
        };
        if (dev, inode) == identity {
            return Ok(true);
        }
    }
    Ok(false)
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatMeta {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_unix_nanos: i128,
    /// User-namespace xattrs read at the same point as the stat. Empty
    /// when the filesystem has none or the read failed. (W09.21)
    xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    /// BSD `st_flags` (chflags bitmap). 0 means no flags set.
    flags: u32,
}

impl StatMeta {
    /// Convert to the wire shape the daemon expects.
    fn to_wire(&self) -> shit_proto::FileMetadataWire {
        shit_proto::FileMetadataWire {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime_unix_nanos: self.mtime_unix_nanos,
            xattrs: self.xattrs.clone(),
            flags: self.flags,
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
        // FreeBSD cap_enter blocks extattr_*_fd even for pre-opened fds.
        // Keep this best-effort field for wire compatibility; replay must not
        // interpret an empty/incomplete map as authority to delete attrs.
        xattrs: crate::capture::xattr::read_user_xattrs(fd),
        // M03.x.SETATTR — BSD st_flags (chflags bitmap). libc::stat on
        // FreeBSD exposes st_flags directly.
        flags: st.st_flags as u32,
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
    command: CommandId,
    cwd_path: &Path,
) -> (u64, bool) {
    let mut count = 0u64;
    let mut partial = false;
    // PumpState::attach rejects an unrepresentable cwd before registering the
    // subtree, so reaching the walk without a wire key is an internal bug.
    let cwd_wire = path_to_string(cwd_path).expect("attach validated UTF-8 cwd");

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
        let Some(after_meta) = fstat_meta(fd) else {
            tracing::warn!(fd, path = %path.display(), "baseline: post-copy metadata unavailable");
            partial = true;
            continue;
        };
        if after_meta != meta || stored_bytes != meta.size {
            tracing::warn!(
                fd,
                path = %path.display(),
                before = ?meta,
                after = ?after_meta,
                stored_bytes,
                "baseline: file changed while its pre-command snapshot was captured"
            );
            partial = true;
            continue;
        }

        let Some(path_wire) = path_to_string(path) else {
            tracing::warn!(fd, "baseline path is not representable as UTF-8; skipping");
            partial = true;
            continue;
        };
        let resp = HelperResponse::BaselineCaptured {
            session: command.session,
            command_seq: command.seq,
            cwd: cwd_wire.clone(),
            dev,
            inode,
            path: path_wire,
            blob_hash,
            stored_bytes,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            flags: meta.flags,
            // FreeBSD capability mode intentionally blocks extattr_*_fd.
            // The daemon replaces this placeholder with an identity-checked
            // path-based snapshot before it marks the baseline Ready.
            xattrs: std::collections::BTreeMap::new(),
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
        session: command.session,
        command_seq: command.seq,
        cwd: cwd_wire,
        file_count: count,
        partial,
    };
    if let Err(e) = conn.send_response(&complete) {
        tracing::warn!(error = %e, "baseline: BaselineWalkComplete send failed");
        partial = true;
    }

    (count, partial)
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

fn send_capture_refusals(conn: &Conn, commands: impl IntoIterator<Item = CommandId>, detail: &str) {
    for command in commands {
        if let Err(error) = send_capture_refused(conn, command, None, detail.to_owned()) {
            tracing::error!(
                %command.session,
                seq = command.seq,
                %error,
                "failed to send command-level BSD capture refusal"
            );
        }
    }
}

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

#[cfg(target_os = "freebsd")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: libc returns this thread's errno slot.
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: libc returns this thread's errno slot.
    unsafe { libc::__errno() }
}

#[cfg(target_os = "dragonfly")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: libc returns this thread's errno slot.
    unsafe { libc::__errno_location() }
}

fn clear_errno() {
    // SAFETY: `errno_location` returns a valid thread-local c_int pointer.
    unsafe { *errno_location() = 0 };
}

fn current_errno() -> libc::c_int {
    // SAFETY: `errno_location` returns a valid thread-local c_int pointer.
    unsafe { *errno_location() }
}

/// Read a directory's immediate child entries via a tracked dir fd,
/// returning `name → (dev, inode)`. Symlinks are recorded as their own
/// inode (not the link target's). Any incomplete observation is an error.
///
/// B05 Phase C: uses fdopendir + fstatat against `dir_fd` rather
/// than absolute-path `std::fs::read_dir`, so it works under
/// `cap_enter(2)`. The caller already holds `dir_fd` as a tracked
/// kqueue watch fd (we dup before fdopendir to avoid losing the
/// original reference).
fn read_dir_entries(
    dir_fd: RawFd,
) -> std::io::Result<BTreeMap<std::ffi::OsString, DirEntryBaseline>> {
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
        // POSIX reports readdir failure as NULL with errno set, while EOF is
        // NULL with errno unchanged. Clear it first so a partial scan cannot
        // be mistaken for a complete directory baseline.
        clear_errno();
        let entry_ptr = unsafe { libc::readdir(dir) };
        if entry_ptr.is_null() {
            let errno = current_errno();
            if errno != 0 {
                unsafe { libc::closedir(dir) };
                return Err(std::io::Error::from_raw_os_error(errno));
            }
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
            Err(_) => {
                unsafe { libc::closedir(dir) };
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "directory entry name contains NUL",
                ));
            }
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::fstatat(dir_fd, name_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::closedir(dir) };
            return Err(error);
        }
        let name_os = std::ffi::OsString::from(std::ffi::OsStr::from_bytes(name_bytes));
        // W09.16.1 — for symlinks, capture readlink target so dir-diff
        // can later detect `ln -sf newtarget link` (same-name +
        // different-inode + old-kind-was-symlink) and emit
        // SymlinkRemoved with the OLD target.
        let is_symlink = (st.st_mode as libc::mode_t) & libc::S_IFMT == libc::S_IFLNK;
        let symlink_target = if is_symlink {
            readlink_at(dir_fd, &name_c)
        } else {
            None
        };
        if is_symlink && symlink_target.is_none() {
            unsafe { libc::closedir(dir) };
            return Err(std::io::Error::other(
                "symlink target was unavailable or may have been truncated",
            ));
        }
        let symlink_target_unavailable = is_symlink && symlink_target.is_none();
        out.insert(
            name_os,
            DirEntryBaseline {
                dev: st.st_dev as u64,
                inode: st.st_ino,
                symlink_target,
                symlink_target_unavailable,
            },
        );
    }
    unsafe { libc::closedir(dir) };
    Ok(out)
}

/// W09.16.1 — read a symlink target via `readlinkat(2)`, which is
/// the fd-relative form (capsicum-compatible). Returns the target
/// string as the kernel returned it (no canonicalization or symlink
/// chasing), or `None` if the entry isn't a symlink or readlink
/// fails. Buffer sized to PATH_MAX (1024 on FreeBSD). A return equal to
/// the buffer capacity is ambiguous truncation and is treated as unavailable;
/// callers preserve that state and refuse a later destructive inverse.
fn readlink_at(dir_fd: RawFd, name: &std::ffi::CStr) -> Option<std::ffi::OsString> {
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        libc::readlinkat(
            dir_fd,
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    readlink_bytes_to_os_string(&buf, n as usize)
}

fn readlink_bytes_to_os_string(buf: &[u8], n: usize) -> Option<std::ffi::OsString> {
    if n == 0 || n >= buf.len() {
        return None;
    }
    // readlinkat doesn't NUL-terminate; the n bytes are the target.
    use std::os::unix::ffi::OsStringExt;
    Some(std::ffi::OsString::from_vec(buf[..n].to_vec()))
}

/// Classify a directory child's `FileKind` for the wire via
/// `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)` — fd-relative ops
/// work under capsicum, unlike absolute-path `stat`. W03.B
/// surfaced this: under default-on cap_enter, an earlier
/// absolute-path version returned `ENOTCAPABLE`, fell through to
/// `Regular`, and caused S29.2 to treat new dirs as files (missing
/// every `cp -r` event under dst).
///
/// Classification and mode are one identity-bound observation. Any failure is
/// returned to the caller; inventing a regular-file fallback would turn an
/// incomplete scan into authoritative undo evidence.
fn file_kind_and_mode_at(
    dir_fd: RawFd,
    name: &std::ffi::OsStr,
) -> std::io::Result<(shit_proto::FileKindWire, u32)> {
    use shit_proto::FileKindWire as K;
    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "directory entry name contains NUL",
        )
    })?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd is alive per caller (held in TrackedSubtree);
    // name_c is NUL-terminated; st is writable.
    let rc = unsafe { libc::fstatat(dir_fd, name_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let kind = match (st.st_mode as libc::mode_t) & libc::S_IFMT {
        libc::S_IFREG => K::Regular,
        libc::S_IFDIR => K::Directory,
        libc::S_IFLNK => K::Symlink,
        libc::S_IFIFO => K::Fifo,
        libc::S_IFSOCK => K::Socket,
        libc::S_IFBLK => K::BlockDevice,
        libc::S_IFCHR => K::CharDevice,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported directory entry file type bits {other:#o}"),
            ));
        }
    };
    Ok((kind, st.st_mode as u32))
}

/// Handle the request_loop holds. Cheaply cloneable.
#[derive(Clone)]
pub struct CaptureControl {
    tx: SyncSender<ControlMsg>,
    conn: Arc<Conn>,
}

impl CaptureControl {
    /// B05.10: caller provides `cwd_path` directly (forwarded from the
    /// shell hook via WatchTree). Empty string falls back to the
    /// legacy sysctl(KERN_PROC_CWD) resolver for the helper's-own-pid
    /// path; cross-pid resolves are blocked under cap_enter so that
    /// path effectively requires `cwd_path` to be non-empty.
    pub fn on_watch_tree(
        &self,
        session: Uuid,
        command_seq: u64,
        root_pid: u32,
        cwd_path: &str,
    ) -> Result<(), CaptureAttachError> {
        self.on_watch_tree_with_timeout(
            session,
            command_seq,
            root_pid,
            cwd_path,
            ATTACH_COMPLETION_TIMEOUT,
        )
    }

    fn on_watch_tree_with_timeout(
        &self,
        session: Uuid,
        command_seq: u64,
        root_pid: u32,
        cwd_path: &str,
        timeout: Duration,
    ) -> Result<(), CaptureAttachError> {
        let command = CommandId {
            session,
            seq: command_seq,
        };
        let path = if !cwd_path.is_empty() {
            PathBuf::from(cwd_path)
        } else {
            match super::cwd::resolve_pid_cwd(root_pid) {
                Some(p) => p,
                None => {
                    let error = CaptureAttachError::CwdUnavailable { root_pid };
                    let _ = send_capture_refused(
                        &self.conn,
                        command,
                        None,
                        format!("BSD watch attach failed: {error}"),
                    );
                    return Err(error);
                }
            }
        };
        let refusal_path = path_to_string(&path);
        let (completion_tx, completion_rx) = channel();
        let (commit_tx, commit_rx) = channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut pending = ControlMsg::Attach {
            command,
            root_path: path,
            cancelled: Arc::clone(&cancelled),
            completion: completion_tx,
            commit: commit_rx,
        };
        let deadline = Instant::now() + timeout;
        loop {
            match self.tx.try_send(pending) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => {
                    let error = CaptureAttachError::ControlChannelClosed;
                    let _ = send_capture_refused(
                        &self.conn,
                        command,
                        refusal_path.clone(),
                        format!("BSD watch attach control failed: {error}"),
                    );
                    return Err(error);
                }
                Err(TrySendError::Full(returned)) => {
                    pending = returned;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        cancelled.store(true, Ordering::Release);
                        let error = CaptureAttachError::Timeout { timeout };
                        let _ = send_capture_refused(
                            &self.conn,
                            command,
                            refusal_path.clone(),
                            format!("BSD watch attach enqueue failed: {error}"),
                        );
                        return Err(error);
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        }

        // The pump sends this only after registration, baseline emission,
        // and insertion into its live watch map. A second commit channel closes
        // the timeout race: if this receiver expires just as the pump sends,
        // no commit arrives and the pump removes the late watch.
        let remaining = deadline.saturating_duration_since(Instant::now());
        match completion_rx.recv_timeout(remaining) {
            Ok(Ok(())) => {
                if commit_tx.send(()).is_ok() {
                    Ok(())
                } else {
                    cancelled.store(true, Ordering::Release);
                    let error = CaptureAttachError::CompletionChannelClosed;
                    let _ = send_capture_refused(
                        &self.conn,
                        command,
                        refusal_path,
                        format!("BSD watch attach commit failed: {error}"),
                    );
                    Err(error)
                }
            }
            Ok(Err(error)) => {
                let _ = send_capture_refused(
                    &self.conn,
                    command,
                    refusal_path,
                    format!("BSD watch attach failed: {error}"),
                );
                Err(error)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                let error = CaptureAttachError::Timeout { timeout };
                let _ = send_capture_refused(
                    &self.conn,
                    command,
                    refusal_path,
                    format!("BSD watch attach completion failed: {error}"),
                );
                Err(error)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                cancelled.store(true, Ordering::Release);
                let error = CaptureAttachError::CompletionChannelClosed;
                let _ = send_capture_refused(
                    &self.conn,
                    command,
                    refusal_path,
                    format!("BSD watch attach completion failed: {error}"),
                );
                Err(error)
            }
        }
    }

    pub fn on_unwatch_tree(
        &self,
        session: Uuid,
        command_seq: u64,
    ) -> Result<(), CaptureDetachError> {
        self.on_unwatch_tree_with_timeout(session, command_seq, DETACH_COMPLETION_TIMEOUT)
    }

    fn on_unwatch_tree_with_timeout(
        &self,
        session: Uuid,
        command_seq: u64,
        timeout: Duration,
    ) -> Result<(), CaptureDetachError> {
        let command = CommandId {
            session,
            seq: command_seq,
        };
        let (completion_tx, completion_rx) = channel();
        let deadline = Instant::now() + timeout;
        let mut pending = ControlMsg::Detach {
            command,
            completion: completion_tx,
        };
        loop {
            match self.tx.try_send(pending) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => {
                    let error = CaptureDetachError::ControlChannelClosed;
                    if let Err(refusal_error) = send_capture_refused(
                        &self.conn,
                        command,
                        None,
                        format!("BSD watch detach control failed: {error}"),
                    ) {
                        tracing::error!(
                            %session,
                            command_seq,
                            %refusal_error,
                            "BSD detach control refusal could not be delivered"
                        );
                    }
                    tracing::warn!(
                        %session,
                        command_seq,
                        %error,
                        "BSD UnwatchTree could not reach the capture pump"
                    );
                    return Err(error);
                }
                Err(TrySendError::Full(returned)) => {
                    pending = returned;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        let error = CaptureDetachError::Timeout { timeout };
                        if let Err(refusal_error) = send_capture_refused(
                            &self.conn,
                            command,
                            None,
                            format!("BSD watch detach enqueue failed: {error}"),
                        ) {
                            tracing::error!(
                                %session,
                                command_seq,
                                %refusal_error,
                                "BSD detach enqueue-timeout refusal could not be delivered"
                            );
                        }
                        tracing::warn!(
                            %session,
                            command_seq,
                            %error,
                            "BSD UnwatchTree control queue timed out"
                        );
                        return Err(error);
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        }

        // This is synchronous inside the helper: its request loop does not
        // accept another message until the drain barrier completes. The daemon
        // protocol's shared UnwatchTreeFlushed response is emitted by the
        // request loop only when this method returns Ok.
        let remaining = deadline.saturating_duration_since(Instant::now());
        match completion_rx.recv_timeout(remaining) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(
                    %session,
                    command_seq,
                    %error,
                    "BSD UnwatchTree drain failed"
                );
                Err(error)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let error = CaptureDetachError::Timeout { timeout };
                let _ = send_capture_refused(
                    &self.conn,
                    command,
                    None,
                    format!("BSD watch detach completion failed: {error}"),
                );
                tracing::warn!(%session, command_seq, %error, "BSD UnwatchTree completion timed out");
                Err(error)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let error = CaptureDetachError::CompletionChannelClosed;
                let _ = send_capture_refused(
                    &self.conn,
                    command,
                    None,
                    format!("BSD watch detach completion failed: {error}"),
                );
                tracing::warn!(%session, command_seq, %error, "BSD UnwatchTree completion lost");
                Err(error)
            }
        }
    }

    /// Signal the pump thread to exit. Best-effort: shutdown is
    /// called during teardown where the pump may already be gone;
    /// a silent drop here is the right semantics (matches the
    /// macOS sibling at capture/macos.rs:150-152).
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
    let control_conn = Arc::clone(&conn);
    let handle = std::thread::Builder::new()
        .name("shit-bsd-capture-pump".to_string())
        .spawn(move || pump(kq, drain_session, conn, staging_dir_fd, ctrl_rx, slash_fd))?;
    Ok((
        CaptureControl {
            tx: ctrl_tx,
            conn: control_conn,
        },
        handle,
    ))
}

fn send_attach_refusal(state: &PumpState, command: CommandId, root_path: &Path, detail: String) {
    if let Err(error) =
        send_capture_refused(&state.conn, command, path_to_string(root_path), detail)
    {
        tracing::error!(
            %command.session,
            seq = command.seq,
            %error,
            "failed to send durable BSD attach refusal"
        );
    }
}

/// Complete the two-phase attach handshake. Registration and baseline capture
/// may outlive the request loop's deadline, so cancellation is checked on both
/// sides of `attach`. Even if the completion send races with the deadline, the
/// watch is retained only after the request loop explicitly commits it.
fn process_attach_control(
    state: &mut PumpState,
    kq: &KqueueFd,
    command: CommandId,
    root_path: PathBuf,
    cancelled: Arc<AtomicBool>,
    completion: std::sync::mpsc::Sender<Result<(), CaptureAttachError>>,
    commit: Receiver<()>,
) {
    let mut result = if cancelled.load(Ordering::Acquire) {
        Err(CaptureAttachError::ReadinessCancelled)
    } else {
        state.attach(kq, command, &root_path)
    };

    if result.is_ok() && cancelled.load(Ordering::Acquire) {
        let _ = state.detach(command);
        result = Err(CaptureAttachError::ReadinessCancelled);
    }

    if let Err(error) = result {
        send_attach_refusal(
            state,
            command,
            &root_path,
            format!("BSD watch attach failed: {error}"),
        );
        let _ = completion.send(Err(error));
        return;
    }

    if completion.send(Ok(())).is_err() {
        let _ = state.detach(command);
        send_attach_refusal(
            state,
            command,
            &root_path,
            "BSD watch attach readiness delivery failed".into(),
        );
        return;
    }

    let commit_failure = match commit.recv_timeout(ATTACH_COMMIT_TIMEOUT) {
        Ok(()) if !cancelled.load(Ordering::Acquire) => None,
        Ok(()) => Some("BSD watch attach was cancelled during readiness commit"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Some("BSD watch attach readiness commit timed out")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Some("BSD watch attach requester disappeared before readiness commit")
        }
    };
    if let Some(detail) = commit_failure {
        let _ = state.detach(command);
        send_attach_refusal(state, command, &root_path, detail.into());
    }
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
    let mut next_flush_token = 1u64;
    let mut pending_detaches: HashMap<
        u64,
        (
            CommandId,
            std::sync::mpsc::Sender<Result<(), CaptureDetachError>>,
        ),
    > = HashMap::new();
    loop {
        // Try a control command first (low latency for watch/unwatch).
        match ctrl_rx.try_recv() {
            Ok(ControlMsg::Attach {
                command,
                root_path,
                cancelled,
                completion,
                commit,
            }) => {
                process_attach_control(
                    &mut state, &kq, command, root_path, cancelled, completion, commit,
                );
                continue;
            }
            Ok(ControlMsg::Detach {
                command,
                completion,
            }) => {
                let token = next_flush_token;
                next_flush_token = next_flush_token.wrapping_add(1).max(1);
                match drain_session.request_flush(token) {
                    Ok(()) => {
                        pending_detaches.insert(token, (command, completion));
                    }
                    Err(error) => {
                        let detail = format!("kqueue drain flush failed before detach: {error}");
                        let _ = state.detach(command);
                        if let Err(send_error) =
                            send_capture_refused(&state.conn, command, None, detail.clone())
                        {
                            tracing::error!(
                                %command.session,
                                seq = command.seq,
                                error = %send_error,
                                "BSD pre-flush detach refusal could not be delivered"
                            );
                        }
                        let _ = completion.send(Err(CaptureDetachError::DrainFlush(detail)));
                    }
                }
            }
            Ok(ControlMsg::Shutdown) => {
                tracing::info!("bsd capture pump shutdown requested");
                state.refuse_all_active(
                    "BSD capture pump shut down while command watches were active",
                );
                for (_, (_, completion)) in pending_detaches.drain() {
                    let _ = completion.send(Err(CaptureDetachError::DrainFlush(
                        "capture pump shut down before flush completion".into(),
                    )));
                }
                drop(drain_session);
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                tracing::info!("control channel closed; pump exiting");
                state.refuse_all_active(
                    "BSD capture control channel disconnected while watches were active",
                );
                for (_, (_, completion)) in pending_detaches.drain() {
                    let _ = completion.send(Err(CaptureDetachError::DrainFlush(
                        "capture pump control channel disconnected before flush completion".into(),
                    )));
                }
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
            Ok(DrainEvent::Proc { pid, kind, .. }) => {
                // There is no pid→command routing in the BSD producer yet.
                // Silently dropping a process-boundary event could omit
                // descendant mutations, so conservatively poison every live
                // command until exact attribution is implemented.
                state.mark_all_active_unsafe(&format!(
                    "unattributed BSD process event {kind:?} for pid {pid}"
                ));
            }
            Ok(DrainEvent::FlushComplete { token }) => {
                if let Some((command, completion)) = pending_detaches.remove(&token) {
                    let result = state.finish_detach_after_flush(command);
                    if completion.send(result).is_err() {
                        tracing::warn!(
                            %command.session,
                            seq = command.seq,
                            "BSD detach flush completed after requester disappeared"
                        );
                    }
                } else {
                    tracing::warn!(token, "unexpected BSD drain flush completion marker");
                    state.mark_all_active_unsafe(&format!(
                        "unexpected kqueue drain flush marker {token}"
                    ));
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let detail = "kqueue drain channel disconnected (overflow, kevent failure, or consumer loss) while watches were active";
                tracing::error!(
                    detail,
                    "drain channel disconnected; refusing active watches"
                );
                state.refuse_all_active(detail);
                for (_, (_, completion)) in pending_detaches.drain() {
                    let _ = completion.send(Err(CaptureDetachError::DrainFlush(detail.into())));
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    fn test_control(tx: SyncSender<ControlMsg>) -> (CaptureControl, Conn) {
        let (conn, peer) = crate::ipc::socketpair().expect("socketpair");
        (
            CaptureControl {
                tx,
                conn: Arc::new(conn),
            },
            peer,
        )
    }

    fn test_pump_state(staging_dir: &Path) -> (PumpState, Arc<KqueueFd>, Conn) {
        use std::os::fd::FromRawFd;

        let (sender, peer) = crate::ipc::socketpair().expect("socketpair");
        let staging_path = std::ffi::CString::new(staging_dir.as_os_str().as_bytes()).unwrap();
        let staging_raw = unsafe {
            libc::open(
                staging_path.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        assert!(staging_raw >= 0, "open staging directory");
        let staging_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(staging_raw) });
        let kq = Arc::new(crate::kqueue::init().expect("kqueue init"));
        (
            PumpState::new(staging_fd, Arc::new(sender), Arc::clone(&kq), None),
            kq,
            peer,
        )
    }

    fn consume_empty_baseline(peer: &Conn, expected: CommandId) {
        assert!(matches!(
            peer.recv_response().expect("baseline completion"),
            HelperResponse::BaselineWalkComplete {
                session,
                command_seq,
                file_count: 0,
                partial: false,
                ..
            } if session == expected.session && command_seq == expected.seq
        ));
    }

    fn consume_single_file_baseline(peer: &Conn, expected: CommandId) {
        let (response, staged_fd) = peer
            .recv_response_with_fd()
            .expect("file baseline response");
        assert!(
            staged_fd.is_some(),
            "file baseline must carry its staged fd"
        );
        assert!(matches!(
            response,
            HelperResponse::BaselineCaptured {
                session,
                command_seq,
                ..
            } if session == expected.session && command_seq == expected.seq
        ));
        assert!(matches!(
            peer.recv_response().expect("baseline completion"),
            HelperResponse::BaselineWalkComplete {
                session,
                command_seq,
                file_count: 1,
                partial: false,
                ..
            } if session == expected.session && command_seq == expected.seq
        ));
    }

    #[test]
    fn same_root_attach_is_refused_while_first_watch_remains_active() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, _peer) = test_pump_state(staging.path());
        let first = command(1);
        let second = command(2);

        state.attach(&kq, first, root.path()).unwrap();
        let error = state.attach(&kq, second, root.path()).unwrap_err();

        assert!(matches!(
            error,
            CaptureAttachError::OverlappingWatch {
                active_command,
                ..
            } if active_command == first
        ));
        assert!(state.watches.contains_key(&first));
        assert!(!state.watches.contains_key(&second));
    }

    #[test]
    fn nested_root_attach_is_refused_in_both_directions() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, _peer) = test_pump_state(staging.path());

        state.attach(&kq, command(3), root.path()).unwrap();
        assert!(matches!(
            state.attach(&kq, command(4), &child),
            Err(CaptureAttachError::OverlappingWatch { .. })
        ));

        let _ = state.detach(command(3));
        state.attach(&kq, command(5), &child).unwrap();
        assert!(matches!(
            state.attach(&kq, command(6), root.path()),
            Err(CaptureAttachError::OverlappingWatch { .. })
        ));
    }

    #[test]
    fn detach_then_reattach_same_root_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, _peer) = test_pump_state(staging.path());
        let first = command(7);
        let second = command(8);

        state.attach(&kq, first, root.path()).unwrap();
        let _ = state.detach(first);
        state.attach(&kq, second, root.path()).unwrap();

        assert!(!state.watches.contains_key(&first));
        assert!(state.watches.contains_key(&second));
    }

    #[test]
    fn watch_tree_waits_until_the_pump_reports_capture_ready() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let (control, _peer) = test_control(tx);
        let session = Uuid::nil();

        let waiter = std::thread::spawn(move || {
            control.on_watch_tree(session, 17, 4242, "/tmp/capture-root")
        });

        let ControlMsg::Attach {
            command,
            root_path,
            cancelled,
            completion,
            commit,
        } = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("capture pump should receive attach")
        else {
            panic!("expected attach control message");
        };
        assert_eq!(command.session, session);
        assert_eq!(command.seq, 17);
        assert_eq!(root_path, PathBuf::from("/tmp/capture-root"));
        assert!(!cancelled.load(Ordering::Acquire));

        // Receiving the Attach is not readiness: the caller remains
        // blocked until registration and the baseline have both ended.
        assert!(!waiter.is_finished());
        completion
            .send(Ok(()))
            .expect("watch request should still be waiting");
        commit
            .recv_timeout(Duration::from_secs(1))
            .expect("request loop should commit received readiness");
        assert!(waiter.join().expect("watch request panicked").is_ok());
    }

    #[test]
    fn watch_tree_timeout_fences_late_attach_and_refuses_exact_command() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let (control, peer) = test_control(tx);
        let command = command(18);

        let result = control.on_watch_tree_with_timeout(
            command.session,
            command.seq,
            4242,
            "/tmp/capture-root",
            Duration::from_millis(10),
        );

        assert!(matches!(result, Err(CaptureAttachError::Timeout { .. })));
        let ControlMsg::Attach {
            command: queued,
            cancelled,
            ..
        } = rx.recv().expect("queued attach")
        else {
            panic!("expected attach control message");
        };
        assert_eq!(queued, command);
        assert!(
            cancelled.load(Ordering::Acquire),
            "late pump work must observe the timeout fence"
        );
        assert!(matches!(
            peer.recv_response().expect("timeout refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("did not complete attach")
        ));
    }

    #[test]
    fn watch_tree_timeout_also_bounds_a_full_control_queue() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        tx.send(ControlMsg::Shutdown).unwrap();
        let (control, peer) = test_control(tx);
        let command = command(181);

        let result = control.on_watch_tree_with_timeout(
            command.session,
            command.seq,
            4242,
            "/tmp/capture-root",
            Duration::from_millis(10),
        );

        assert!(matches!(result, Err(CaptureAttachError::Timeout { .. })));
        assert!(matches!(rx.recv().unwrap(), ControlMsg::Shutdown));
        assert!(
            rx.try_recv().is_err(),
            "timed-out attach must not enqueue late"
        );
        assert!(matches!(
            peer.recv_response().expect("enqueue-timeout refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("attach enqueue")
        ));
    }

    #[test]
    fn prepared_attach_is_cleaned_if_readiness_delivery_is_lost() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(19);
        let (completion_tx, completion_rx) = channel();
        let (_commit_tx, commit_rx) = channel();
        drop(completion_rx);

        process_attach_control(
            &mut state,
            &kq,
            command,
            root.path().to_path_buf(),
            Arc::new(AtomicBool::new(false)),
            completion_tx,
            commit_rx,
        );

        consume_empty_baseline(&peer, command);
        assert!(matches!(
            peer.recv_response().expect("delivery-loss refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("readiness delivery failed")
        ));
        assert!(!state.watches.contains_key(&command));
        assert!(state.fd_to_command.values().all(|owner| *owner != command));
    }

    #[test]
    fn cancelled_queued_attach_never_registers_a_watch() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(20);
        let (completion_tx, completion_rx) = channel();
        let (_commit_tx, commit_rx) = channel();

        process_attach_control(
            &mut state,
            &kq,
            command,
            root.path().to_path_buf(),
            Arc::new(AtomicBool::new(true)),
            completion_tx,
            commit_rx,
        );

        assert!(matches!(
            completion_rx.recv().expect("cancelled completion"),
            Err(CaptureAttachError::ReadinessCancelled)
        ));
        assert!(matches!(
            peer.recv_response().expect("cancelled-attach refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("cancelled before readiness commit")
        ));
        assert!(!state.watches.contains_key(&command));
        assert!(state.fd_to_command.is_empty());
    }

    #[test]
    fn watch_tree_propagates_the_pump_attach_failure() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let (control, _peer) = test_control(tx);
        let failed_root = PathBuf::from("/missing/capture-root");

        let waiter = std::thread::spawn(move || {
            control.on_watch_tree(Uuid::nil(), 23, 5252, "/missing/capture-root")
        });

        let ControlMsg::Attach { completion, .. } = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("capture pump should receive attach")
        else {
            panic!("expected attach control message");
        };
        completion
            .send(Err(CaptureAttachError::RegisterSubtree {
                root_path: failed_root.clone(),
                source: KqueueError::NotImplemented("test attach failure"),
            }))
            .expect("watch request should still be waiting");

        match waiter.join().expect("watch request panicked") {
            Err(CaptureAttachError::RegisterSubtree { root_path, source }) => {
                assert_eq!(root_path, failed_root);
                assert!(matches!(
                    source,
                    KqueueError::NotImplemented("test attach failure")
                ));
            }
            other => panic!("unexpected watch result: {other:?}"),
        }
    }

    #[test]
    fn watch_tree_reports_a_closed_control_channel() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        drop(rx);
        let (control, _peer) = test_control(tx);

        let result = control.on_watch_tree(Uuid::nil(), 29, 6262, "/tmp/capture-root");
        assert!(matches!(
            result,
            Err(CaptureAttachError::ControlChannelClosed)
        ));
    }

    #[test]
    fn unwatch_waits_for_pump_flush_completion() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let (control, _peer) = test_control(tx);
        let session = Uuid::nil();
        let waiter = std::thread::spawn(move || control.on_unwatch_tree(session, 31));

        let ControlMsg::Detach {
            command,
            completion,
        } = rx.recv().expect("detach request")
        else {
            panic!("expected detach control message");
        };
        assert_eq!(command, CommandId { session, seq: 31 });
        assert!(!waiter.is_finished(), "unwatch returned before flush ack");
        completion.send(Ok(())).expect("detach waiter alive");
        assert!(waiter.join().expect("unwatch waiter").is_ok());
    }

    #[test]
    fn unwatch_completion_has_a_bounded_timeout_and_refuses_the_exact_command() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let (control, peer) = test_control(tx);
        let command = command(32);

        let result = control.on_unwatch_tree_with_timeout(
            command.session,
            command.seq,
            Duration::from_millis(10),
        );
        assert!(matches!(result, Err(CaptureDetachError::Timeout { .. })));
        let ControlMsg::Detach {
            command: queued, ..
        } = rx.recv().expect("queued detach")
        else {
            panic!("expected detach request");
        };
        assert_eq!(queued, command);
        assert!(matches!(
            peer.recv_response().expect("timeout refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("did not complete detach")
        ));
    }

    #[test]
    fn unwatch_timeout_bounds_a_full_control_queue_and_never_enqueues_detach() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        tx.send(ControlMsg::Shutdown).unwrap();
        let (control, peer) = test_control(tx);
        let command = command(321);
        let timeout = Duration::from_millis(10);
        let started = Instant::now();

        let result = control.on_unwatch_tree_with_timeout(command.session, command.seq, timeout);

        assert!(matches!(result, Err(CaptureDetachError::Timeout { .. })));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "saturated detach queue exceeded its aggregate deadline"
        );
        assert!(matches!(rx.recv().unwrap(), ControlMsg::Shutdown));
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(
            peer.recv_response().expect("enqueue-timeout refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("detach enqueue")
        ));
    }

    #[test]
    fn unwatch_disconnected_control_queue_refuses_the_exact_command() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        drop(rx);
        let (control, peer) = test_control(tx);
        let command = command(322);

        let result = control.on_unwatch_tree_with_timeout(
            command.session,
            command.seq,
            Duration::from_millis(10),
        );

        assert!(matches!(
            result,
            Err(CaptureDetachError::ControlChannelClosed)
        ));
        assert!(matches!(
            peer.recv_response().expect("control-disconnect refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("detach control failed")
        ));
    }

    #[test]
    fn sticky_capture_failure_is_refused_after_cleanup_and_withholds_completion() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(33);
        state.attach(&kq, command, root.path()).unwrap();
        consume_empty_baseline(&peer, command);
        state
            .watches
            .get_mut(&command)
            .unwrap()
            .mark_unsafe("synthetic required capture loss");

        let result = state.finish_detach_after_flush(command);

        assert!(matches!(
            result,
            Err(CaptureDetachError::CaptureUnsafe { ref detail })
                if detail.contains("synthetic required capture loss")
        ));
        assert!(!state.watches.contains_key(&command));
        assert!(state.fd_to_command.values().all(|owner| *owner != command));
        assert!(matches!(
            peer.recv_response().expect("final refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == command.session
                    && seq == command.seq
                    && detail.contains("synthetic required capture loss")
        ));
    }

    #[test]
    fn final_refusal_delivery_failure_still_withholds_completion() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(34);
        state.attach(&kq, command, root.path()).unwrap();
        consume_empty_baseline(&peer, command);
        state
            .watches
            .get_mut(&command)
            .unwrap()
            .mark_unsafe("synthetic loss before peer close");
        drop(peer);

        let result = state.finish_detach_after_flush(command);

        assert!(matches!(
            result,
            Err(CaptureDetachError::CaptureUnsafe { ref detail })
                if detail.contains("final CaptureRefused delivery failed")
        ));
        assert!(!state.watches.contains_key(&command));
    }

    #[test]
    fn fstat_and_directory_rescan_failures_poison_the_exact_command() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(35);
        state.attach(&kq, command, root.path()).unwrap();
        consume_empty_baseline(&peer, command);

        state.fd_to_command.insert(-1, command);
        state.handle_vnode(-1, VnodeEventKind::Write);
        let first = state.watches[&command]
            .capture_failure
            .as_deref()
            .expect("fstat failure must be sticky")
            .to_owned();
        assert!(first.contains("fstat failed"), "{first}");

        // Sticky means a later failure cannot erase the first missing event.
        state
            .watches
            .get_mut(&command)
            .unwrap()
            .dir_baselines
            .insert(
                -2,
                DirBaseline {
                    path: root.path().to_path_buf(),
                    entries: BTreeMap::new(),
                },
            );
        state.scan_dir_emit_and_watch_children(command, -2, &mut Vec::new());
        assert_eq!(
            state.watches[&command].capture_failure.as_deref(),
            Some(first.as_str())
        );
    }

    #[test]
    fn required_tree_response_delivery_failure_poison_exact_command() {
        let root = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(36);
        state.attach(&kq, command, root.path()).unwrap();
        consume_empty_baseline(&peer, command);
        let root_fd = state.watches[&command]
            .dir_baselines
            .iter()
            .find_map(|(fd, baseline)| (baseline.path == root.path()).then_some(*fd))
            .expect("root directory baseline");
        std::fs::write(root.path().join("created"), b"new").unwrap();
        drop(peer);

        state.handle_dir_change(command, root_fd);

        let detail = state.watches[&command]
            .capture_failure
            .as_deref()
            .expect("failed TreeMutation delivery must be sticky");
        assert!(detail.contains("TreeMutation delivery failed"), "{detail}");
    }

    #[test]
    fn required_preimage_response_delivery_failure_poison_exact_command() {
        let root = tempfile::tempdir().unwrap();
        let file_path = root.path().join("tracked");
        std::fs::write(&file_path, b"before").unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(361);
        state.attach(&kq, command, root.path()).unwrap();
        consume_single_file_baseline(&peer, command);
        let file_fd = state.watches[&command]
            .subtree
            .iter_entries()
            .find_map(|(fd, path)| (path == file_path).then_some(fd))
            .expect("tracked file fd");
        drop(peer);

        state.handle_vnode(file_fd, VnodeEventKind::Write);

        let detail = state.watches[&command]
            .capture_failure
            .as_deref()
            .expect("failed CapturedPreImage delivery must be sticky");
        assert!(
            detail.contains("CapturedPreImage delivery failed"),
            "{detail}"
        );
    }

    #[test]
    fn required_metadata_response_delivery_failure_poison_exact_command() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let file_path = root.path().join("tracked");
        std::fs::write(&file_path, b"content").unwrap();
        let staging = tempfile::tempdir().unwrap();
        let (mut state, kq, peer) = test_pump_state(staging.path());
        let command = command(362);
        state.attach(&kq, command, root.path()).unwrap();
        consume_single_file_baseline(&peer, command);
        let file_fd = state.watches[&command]
            .subtree
            .iter_entries()
            .find_map(|(fd, path)| (path == file_path).then_some(fd))
            .expect("tracked file fd");
        let original_mode = std::fs::metadata(&file_path).unwrap().permissions().mode();
        std::fs::set_permissions(
            &file_path,
            std::fs::Permissions::from_mode(original_mode ^ 0o100),
        )
        .unwrap();
        drop(peer);

        state.handle_attrib(command, file_fd);

        let detail = state.watches[&command]
            .capture_failure
            .as_deref()
            .expect("failed CapturedMetadataChange delivery must be sticky");
        assert!(
            detail.contains("CapturedMetadataChange delivery failed"),
            "{detail}"
        );
    }

    #[test]
    fn attach_is_not_dropped_when_control_queue_is_temporarily_full() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        tx.send(ControlMsg::Shutdown).unwrap();
        let (control, _peer) = test_control(tx);
        let waiter = std::thread::spawn(move || {
            control.on_watch_tree(Uuid::nil(), 37, 7373, "/tmp/capture-root")
        });

        assert!(!waiter.is_finished(), "full queue must apply backpressure");
        assert!(matches!(rx.recv().unwrap(), ControlMsg::Shutdown));
        let ControlMsg::Attach {
            completion, commit, ..
        } = rx.recv().expect("queued attach")
        else {
            panic!("expected attach after queue space became available");
        };
        completion.send(Ok(())).unwrap();
        commit
            .recv_timeout(Duration::from_secs(1))
            .expect("request loop should commit received readiness");
        assert!(waiter.join().unwrap().is_ok());
    }

    #[test]
    fn drain_failure_refuses_every_active_command() {
        let (sender, peer) = crate::ipc::socketpair().expect("socketpair");
        let session = Uuid::nil();
        let commands = [
            CommandId { session, seq: 51 },
            CommandId { session, seq: 52 },
        ];
        send_capture_refusals(&sender, commands, "synthetic drain disconnect");

        let mut seen = Vec::new();
        for _ in commands {
            let HelperResponse::CaptureRefused { seq, detail, .. } =
                peer.recv_response().expect("refusal response")
            else {
                panic!("expected CaptureRefused");
            };
            assert_eq!(detail, "synthetic drain disconnect");
            seen.push(seq);
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![51, 52]);
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
    fn non_utf8_native_path_emits_refusal_without_replacement_target() {
        use std::os::unix::ffi::OsStringExt;

        let (sender, peer) = crate::ipc::socketpair().expect("socketpair");
        let command = CommandId {
            session: Uuid::nil(),
            seq: 41,
        };
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/bad-\xff".to_vec()));

        assert_eq!(path_to_wire_or_refuse(&sender, command, &path), None);
        assert!(matches!(
            peer.recv_response().unwrap(),
            HelperResponse::CaptureRefused { path: None, detail, .. }
                if detail == "native path is not representable as UTF-8"
        ));
    }

    #[test]
    fn readlink_decode_rejects_ambiguous_full_buffer_and_preserves_native_bytes() {
        use std::os::unix::ffi::OsStrExt;

        let full = [b'x'; 8];
        assert_eq!(readlink_bytes_to_os_string(&full, full.len()), None);

        let raw = b"target-\xff-tail";
        let mut roomy = [0u8; 32];
        roomy[..raw.len()].copy_from_slice(raw);
        let decoded = readlink_bytes_to_os_string(&roomy, raw.len()).expect("not truncated");
        assert_eq!(decoded.as_os_str().as_bytes(), raw);
    }

    #[test]
    fn orphaned_routed_event_refuses_the_exact_command() {
        // A stale route should be impossible after ordered detach cleanup,
        // but if the invariant breaks we still know the exact CommandId and
        // must not silently discard a potentially mutating event.
        let (conn_a, conn_b) = crate::ipc::socketpair().expect("socketpair");
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
        state.handle_vnode(999, VnodeEventKind::Write);
        assert!(state.watches.is_empty(), "watches must still be empty");
        assert!(matches!(
            conn_b.recv_response().expect("orphan-event refusal"),
            HelperResponse::CaptureRefused { session, seq, detail, .. }
                if session == ghost.session
                    && seq == ghost.seq
                    && detail.contains("watch state disappeared")
        ));
    }
}
