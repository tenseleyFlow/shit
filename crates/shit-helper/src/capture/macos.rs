// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS FSEvents capture producer (M01.A).
//!
//! Consumes [`FsEventRecord`]s from a [`FsEventsStream`] (M01.7) and
//! ships `HelperResponse::TreeMutation` events to the daemon for each
//! tree-shape change inside a tracked subtree.
//!
//! Structurally mirrors [`super::bsd`], but simpler: FSEvents is
//! post-hoc, so there's no pre-image content to capture and no need
//! for the bsd producer's dedupe / dir-baseline / metadata-baseline
//! machinery. Every event the daemon ingests here lands with
//! `partial = true` semantics on the planner side.
//!
//! Per-WatchTree subscription model: when the daemon registers a new
//! `(CommandId, root_path)`, the pump starts a replacement FSEvents
//! stream over all tracked roots, then drops the old stream only after
//! the replacement reports successful startup. Because FSEvents offers no
//! atomic queue handoff between those streams, commands already running on
//! the old stream are refused before a watch-set rebuild; otherwise events
//! queued on the old stream during replacement startup could be discarded.
//! This costs ~50–200ms per attach/detach (FSEvents kernel registration
//! latency) and is acceptable because attach happens at PreExec, not on the
//! per-event hot path. The request loop waits for that startup result before
//! it may emit `WatchTreeReady`.
//!
//! Wire-event mapping (Decision 1 in `.docs/sprints/macos/M01.A-…md`):
//!
//! | FSEvents flag       | Wire emit |
//! |---------------------|-----------|
//! | `is_created`        | `TreeOpWire::Create { dev, inode, path, kind, mode }` |
//! | `is_removed`        | `TreeOpWire::Unlink { dev: 0, inode: 0, path }` — inode lost when the file was removed before our stat |
//! | `is_renamed` (paired) | `TreeOpWire::Rename { from, to, dev, inode }` |
//! | `is_renamed` (timeout) | `CaptureRefused` — an unmatched half is ambiguous |
//! | `is_modified`       | **skipped** — no pre-image, no useful undo. Doctor surfaces the gap. |
//! | `is_meta_changed`   | **skipped for M01.A** — `CapturedMetadataChange` needs a before-state we don't have post-hoc. M03's ES path captures both. |
//! | `is_root_changed`   | `CaptureRefused` for every watch whose coverage is invalid |
//! | `must_scan_subdirs` | `CaptureRefused` for every active command; no partial op emitted |

// Module-level `#[cfg(target_os = "macos")]` lives on `pub mod macos;`
// in `super::mod`; the inner `#![cfg(...)]` is redundant and trips
// `clippy::duplicated_attributes` on newer rustc.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, channel, sync_channel,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use shit_planner::events::CommandId;
use shit_proto::{FileKindWire, HelperResponse, TreeOpWire};
use uuid::Uuid;

use crate::fsevents::{FsEventRecord, FsEventsStream, StreamOptions};
use crate::ipc::Conn;

/// Treat two `is_renamed` events arriving within this window as one
/// rename pair. FSEvents typically delivers both halves of an atomic
/// rename inside the same callback invocation, so this is generous;
/// a longer window would let stale halves pair across unrelated
/// operations.
const PENDING_RENAME_TIMEOUT: Duration = Duration::from_millis(100);

/// Pump idle-sleep when both the control channel and the event
/// stream report `Empty`. Long enough to avoid burning CPU; short
/// enough that pending-rename flushes happen promptly.
const PUMP_IDLE_SLEEP: Duration = Duration::from_millis(50);

/// Channel capacity for control messages from the request loop.
/// Far in excess of the realistic attach/detach rate (one per
/// shell command). Overflow is returned to the request loop so attach/detach
/// cannot be acknowledged before the pump actually applies it.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Keep the helper-side wait below the daemon's five-second unwatch deadline,
/// leaving time to report a command-scoped refusal when the pump is wedged.
const CONTROL_COMPLETION_TIMEOUT: Duration = Duration::from_secs(4);

// ─────────────────────────────────────────────────────────────────────
// Control-channel messages
// ─────────────────────────────────────────────────────────────────────

enum ControlMsg {
    Attach {
        command: CommandId,
        root_path: PathBuf,
        /// One-shot completion sent only after canonicalization and
        /// successful startup of the replacement stream. The request
        /// loop must not emit WatchTreeReady before receiving it.
        completion: std::sync::mpsc::Sender<Result<(), CaptureAttachError>>,
        /// Set by the request thread when its bounded completion wait expires.
        /// The pump retains this token with a successful watch so even the
        /// send-success/recv-timeout boundary race is eventually cleaned up.
        cancelled: Arc<AtomicBool>,
    },
    Detach {
        command: CommandId,
        completion: std::sync::mpsc::Sender<Result<(), CaptureDetachError>>,
    },
    Shutdown,
}

/// Failure to make a macOS FSEvents watch capture-ready.
#[derive(Debug, thiserror::Error)]
pub enum CaptureAttachError {
    #[error("could not resolve cwd for root pid {root_pid}")]
    CwdUnavailable { root_pid: u32 },
    #[error("macOS FSEvents capture control channel is full")]
    ControlChannelFull,
    #[error("macOS FSEvents capture control channel is closed")]
    ControlChannelClosed,
    #[error("macOS FSEvents capture pump dropped the attach completion channel")]
    CompletionChannelClosed,
    #[error("macOS FSEvents capture pump timed out while attaching the watch")]
    CompletionTimeout,
    #[error("canonicalize FSEvents watch root {root_path:?}: {source}")]
    CanonicalizeRoot {
        root_path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("start FSEvents stream for watch root {root_path:?}: {source}")]
    StreamStart {
        root_path: PathBuf,
        #[source]
        source: crate::fsevents::FsEventsError,
    },
    #[error("refuse commands affected by an FSEvents stream rebuild: {source}")]
    RebuildCoverage {
        #[source]
        source: crate::ipc::ConnError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureDetachError {
    #[error("macOS FSEvents capture control channel is full")]
    ControlChannelFull,
    #[error("macOS FSEvents capture control channel is closed")]
    ControlChannelClosed,
    #[error("macOS FSEvents capture pump dropped the detach completion channel")]
    CompletionChannelClosed,
    #[error("macOS FSEvents capture pump timed out while detaching the watch")]
    CompletionTimeout,
    #[error("macOS FSEvents stream disconnected while draining command {command:?}")]
    StreamDisconnected { command: CommandId },
    #[error("flush FSEvents stream while detaching {command:?}: {source}")]
    StreamFlush {
        command: CommandId,
        #[source]
        source: std::io::Error,
    },
    #[error("restart FSEvents stream while detaching {command:?}: {source}")]
    StreamRestart {
        command: CommandId,
        #[source]
        source: crate::fsevents::FsEventsError,
    },
    #[error("emit final FSEvents state while detaching {command:?}: {source}")]
    Emit {
        command: CommandId,
        #[source]
        source: crate::ipc::ConnError,
    },
    #[error("macOS FSEvents capture became unsafe for {command:?}: {detail}")]
    CaptureUnhealthy { command: CommandId, detail: String },
}

// ─────────────────────────────────────────────────────────────────────
// Public surface
// ─────────────────────────────────────────────────────────────────────

/// Handle the request loop holds. Cheaply cloneable.
#[derive(Clone)]
pub struct CaptureControl {
    tx: SyncSender<ControlMsg>,
}

impl CaptureControl {
    /// Register a new tracked tree. Mirrors
    /// [`super::bsd::CaptureControl::on_watch_tree`].
    ///
    /// `cwd_path` is the shell hook's cwd as forwarded by the daemon.
    /// On macOS we always require it — there's no FreeBSD-style
    /// `sysctl(KERN_PROC_CWD)` fallback because libproc cross-PID
    /// queries are unreliable enough (TCC, dropped privileges) that
    /// requiring the path keeps the contract honest.
    pub fn on_watch_tree(
        &self,
        session: Uuid,
        command_seq: u64,
        root_pid: u32,
        cwd_path: &str,
    ) -> Result<(), CaptureAttachError> {
        if cwd_path.is_empty() {
            return Err(CaptureAttachError::CwdUnavailable { root_pid });
        }
        let path = PathBuf::from(cwd_path);
        let command = CommandId {
            session,
            seq: command_seq,
        };
        let (completion_tx, completion_rx) = channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        self.tx
            .try_send(ControlMsg::Attach {
                command,
                root_path: path,
                completion: completion_tx,
                cancelled: Arc::clone(&cancelled),
            })
            .map_err(|err| match err {
                TrySendError::Full(_) => CaptureAttachError::ControlChannelFull,
                TrySendError::Disconnected(_) => CaptureAttachError::ControlChannelClosed,
            })?;

        // FsEventsStream::start_with_options itself waits until
        // FSEventStreamStart succeeds. Waiting for the pump's result here
        // therefore makes the request loop's later WatchTreeReady truthful.
        recv_attach_completion(
            completion_rx,
            CONTROL_COMPLETION_TIMEOUT,
            cancelled.as_ref(),
        )
    }

    pub fn on_unwatch_tree(
        &self,
        session: Uuid,
        command_seq: u64,
    ) -> Result<(), CaptureDetachError> {
        let command = CommandId {
            session,
            seq: command_seq,
        };
        let (completion_tx, completion_rx) = channel();
        self.tx
            .try_send(ControlMsg::Detach {
                command,
                completion: completion_tx,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => CaptureDetachError::ControlChannelFull,
                TrySendError::Disconnected(_) => CaptureDetachError::ControlChannelClosed,
            })?;
        recv_detach_completion(completion_rx, CONTROL_COMPLETION_TIMEOUT)
    }

    /// Signal the pump thread to exit. Best-effort.
    pub fn shutdown(&self) {
        let _ = self.tx.try_send(ControlMsg::Shutdown);
    }
}

fn recv_attach_completion(
    completion: Receiver<Result<(), CaptureAttachError>>,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<(), CaptureAttachError> {
    match completion.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            cancelled.store(true, Ordering::Release);
            Err(CaptureAttachError::CompletionTimeout)
        }
        Err(RecvTimeoutError::Disconnected) => {
            cancelled.store(true, Ordering::Release);
            Err(CaptureAttachError::CompletionChannelClosed)
        }
    }
}

fn recv_detach_completion(
    completion: Receiver<Result<(), CaptureDetachError>>,
    timeout: Duration,
) -> Result<(), CaptureDetachError> {
    completion
        .recv_timeout(timeout)
        .map_err(|error| match error {
            RecvTimeoutError::Timeout => CaptureDetachError::CompletionTimeout,
            RecvTimeoutError::Disconnected => CaptureDetachError::CompletionChannelClosed,
        })?
}

/// Spawn the macOS FSEvents capture pump. Returns a control handle
/// for the request loop and the worker `JoinHandle`.
///
/// The pump runs until it receives `ControlMsg::Shutdown` or the
/// control channel is closed. It owns the `FsEventsStream` and
/// recreates it on every attach/detach.
pub fn spawn(conn: Arc<Conn>) -> std::io::Result<(CaptureControl, JoinHandle<()>)> {
    let (ctrl_tx, ctrl_rx) = sync_channel::<ControlMsg>(CONTROL_CHANNEL_CAPACITY);
    let handle = std::thread::Builder::new()
        .name("shit-macos-capture-pump".to_string())
        .spawn(move || pump(conn, ctrl_rx))?;
    Ok((CaptureControl { tx: ctrl_tx }, handle))
}

// ─────────────────────────────────────────────────────────────────────
// Pump
// ─────────────────────────────────────────────────────────────────────

/// Pending first half of a FSEvents rename pair. The "before" path
/// no longer exists by the time we see the event, so we can't stat
/// it; the second half's stat fills in the dev/inode for the pair.
struct PendingRename {
    command: CommandId,
    from_path: PathBuf,
    ts: Instant,
}

struct PumpState {
    conn: Arc<Conn>,
    /// Active tracked subtrees. Ordered for deterministic
    /// longest-prefix iteration.
    watches: BTreeMap<CommandId, PathBuf>,
    /// Active FSEvents stream + its event channel. `None` when no
    /// watches are registered. Recreated on every attach/detach
    /// because FSEvents has no add-path API.
    stream: Option<(FsEventsStream, Receiver<FsEventRecord>)>,
    /// Half-rename awaiting its pair within `PENDING_RENAME_TIMEOUT`.
    pending_rename: Option<PendingRename>,
    /// First capture/delivery failure for each live command. A transient IPC
    /// timeout must not disappear merely because the socket later accepts the
    /// detach barrier; detach consumes this entry and returns an error after
    /// cleaning up the watch.
    unsafe_commands: BTreeMap<CommandId, String>,
    /// Cancellation tokens for successful attaches. Retaining them until
    /// detach closes the narrow race where the completion send succeeds just
    /// as the request thread's `recv_timeout` expires.
    attach_cancellations: BTreeMap<CommandId, Arc<AtomicBool>>,
}

impl PumpState {
    fn new(conn: Arc<Conn>) -> Self {
        Self {
            conn,
            watches: BTreeMap::new(),
            stream: None,
            pending_rename: None,
            unsafe_commands: BTreeMap::new(),
            attach_cancellations: BTreeMap::new(),
        }
    }

    fn mark_unsafe(&mut self, command: CommandId, detail: impl Into<String>) {
        self.unsafe_commands
            .entry(command)
            .or_insert_with(|| detail.into());
    }

    fn cleanup_cancelled_attach(&mut self, command: CommandId) {
        if let Err(error) = self.detach(command) {
            // `detach` removes the watch before returning an error, so this is
            // a health report rather than an uncleaned late attachment.
            tracing::error!(
                %command.session,
                seq = command.seq,
                %error,
                "late FSEvents attach cleanup reported an error"
            );
        }
    }

    fn cleanup_cancelled_attaches(&mut self) {
        let cancelled = self
            .attach_cancellations
            .iter()
            .filter(|(_, token)| token.load(Ordering::Acquire))
            .map(|(command, _)| *command)
            .collect::<Vec<_>>();
        for command in cancelled {
            self.cleanup_cancelled_attach(command);
        }
    }

    fn attach(&mut self, command: CommandId, root_path: PathBuf) -> Result<(), CaptureAttachError> {
        // Canonicalize so subsequent path-prefix comparisons match
        // FSEvents-reported paths (which arrive realpath-resolved).
        let canonical = std::fs::canonicalize(&root_path).map_err(|source| {
            CaptureAttachError::CanonicalizeRoot {
                root_path: root_path.clone(),
                source,
            }
        })?;

        // FSEvents cannot atomically transfer the callback queue from the old
        // stream to a replacement. Any commands already executing could have
        // an event land in the old queue after replacement startup begins and
        // before the old stream is dropped. Refuse those commands before the
        // rebuild. The new command has not received WatchTreeReady yet, so it
        // is not part of the at-risk set.
        if !self.watches.is_empty() {
            self.refuse_all_active(
                "macOS FSEvents watch-set rebuild cannot prove a gap-free queue handoff; refusing commands already in flight",
            )
            .map_err(|source| CaptureAttachError::RebuildCoverage { source })?;
        }

        // Make the map change transactional. A failed replacement stream
        // leaves both the previous stream and its matching watch map intact.
        let previous = self.watches.insert(command, canonical.clone());
        if let Err(source) = self.rebuild_stream() {
            match previous {
                Some(previous) => {
                    self.watches.insert(command, previous);
                }
                None => {
                    self.watches.remove(&command);
                }
            }
            return Err(CaptureAttachError::StreamStart {
                root_path: canonical,
                source,
            });
        }

        tracing::info!(
            %command.session,
            seq = command.seq,
            path = %canonical.display(),
            "fsevents watch attached"
        );
        Ok(())
    }

    fn detach(&mut self, command: CommandId) -> Result<(), CaptureDetachError> {
        self.attach_cancellations.remove(&command);
        let mut first_error = self
            .unsafe_commands
            .get(&command)
            .cloned()
            .map(|detail| CaptureDetachError::CaptureUnhealthy { command, detail });

        // FSEventStreamFlushSync guarantees that every event which occurred
        // before this call has reached the native callback. Draining the Rust
        // channel immediately afterward forms the internal completion barrier
        // before the watch map changes.
        if let Some((stream, _)) = &self.stream
            && let Err(source) = stream.flush_sync()
            && first_error.is_none()
        {
            first_error = Some(CaptureDetachError::StreamFlush { command, source });
        }
        let (disconnected, drain_error) = self.drain_stream_queue();
        if let Some(source) = drain_error
            && first_error.is_none()
        {
            first_error = Some(CaptureDetachError::Emit { command, source });
        }
        if let Err(source) = self.flush_pending_rename_as_refusal(
            "macOS FSEvents command ended with an unpaired rename event; refusing ambiguous undo",
        ) && first_error.is_none()
        {
            first_error = Some(CaptureDetachError::Emit { command, source });
        }

        let removed = self.watches.contains_key(&command);
        let mut rebuild_is_safe = true;
        if removed && self.watches.len() > 1 {
            let survivors = self
                .watches
                .iter()
                .filter(|(candidate, _)| **candidate != command)
                .map(|(candidate, root)| (*candidate, root.clone()))
                .collect();
            if let Err(source) = self.refuse_commands(
                survivors,
                "macOS FSEvents watch-set rebuild cannot prove a gap-free queue handoff; refusing commands that remain in flight",
            )
            {
                // Keep the old stream (which watches a harmless superset)
                // instead of introducing the very handoff gap whose refusal
                // could not be delivered.
                rebuild_is_safe = false;
                if first_error.is_none() {
                    first_error = Some(CaptureDetachError::Emit { command, source });
                }
            }
        }
        let removed = self.watches.remove(&command).is_some();
        if removed
            && rebuild_is_safe
            && let Err(source) = self.rebuild_stream()
            && first_error.is_none()
        {
            first_error = Some(CaptureDetachError::StreamRestart { command, source });
        }
        if removed {
            tracing::info!(
                %command.session,
                seq = command.seq,
                rebuild_is_safe,
                "fsevents watch detached after drain barrier attempt"
            );
        }
        if disconnected && first_error.is_none() {
            first_error = Some(CaptureDetachError::StreamDisconnected { command });
        }
        if let Some(detail) = self.unsafe_commands.remove(&command)
            && first_error.is_none()
        {
            first_error = Some(CaptureDetachError::CaptureUnhealthy { command, detail });
        }
        first_error.map_or(Ok(()), Err)
    }

    fn drain_stream_queue(&mut self) -> (bool, Option<crate::ipc::ConnError>) {
        let mut disconnected = false;
        let mut first_error = None;
        while let Some(next) = self.stream.as_ref().map(|(_, rx)| rx.try_recv()) {
            match next {
                Ok(record) => {
                    if let Err(error) = self.handle_event(record)
                        && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if disconnected
            && let Err(error) = self.handle_stream_disconnect()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        (disconnected, first_error)
    }

    fn handle_stream_disconnect(&mut self) -> Result<(), crate::ipc::ConnError> {
        // Change local state before attempting IPC. Even if the refusal cannot
        // be delivered, this pump must never resume emitting from a dead
        // stream or later pair a rename half across the coverage gap.
        self.pending_rename = None;
        self.stream = None;
        self.refuse_all_active("macOS FSEvents stream disconnected; capture coverage was lost")
    }

    fn handle_control_disconnect(&mut self) -> Result<(), crate::ipc::ConnError> {
        self.pending_rename = None;
        self.refuse_all_active(
            "macOS FSEvents control channel disconnected; capture coverage ended unexpectedly",
        )
    }

    /// Start a stream over the current watch set and swap it into place
    /// only after startup succeeds. Starting first prevents the avoidable
    /// blind window caused by tearing down the active stream up front.
    fn rebuild_stream(&mut self) -> Result<(), crate::fsevents::FsEventsError> {
        if self.watches.is_empty() {
            self.stream = None;
            return Ok(());
        }

        let roots: Vec<PathBuf> = self.watches.values().cloned().collect();
        let replacement =
            FsEventsStream::start_with_options(roots.clone(), StreamOptions::default())?;
        tracing::info!(n_roots = roots.len(), "fsevents stream (re)started");
        // Assignment evaluates `replacement` before dropping the previous
        // value, so a live old stream remains until the new stream is ready.
        self.stream = Some(replacement);
        Ok(())
    }

    /// Longest-prefix match: among all watch roots, find the one that
    /// is a path-prefix of `event_path`. Returns the matching
    /// `(CommandId, root_path)` or `None` if the event falls outside
    /// every tracked tree.
    fn find_owning_command(&self, event_path: &Path) -> Option<(CommandId, PathBuf)> {
        find_owning_command(&self.watches, event_path)
    }

    fn handle_event(&mut self, record: FsEventRecord) -> Result<(), crate::ipc::ConnError> {
        let affected = self.commands_affected_by_event(&record);
        match self.handle_event_inner(record) {
            Ok(()) => Ok(()),
            Err(error) => {
                let detail = format!(
                    "macOS FSEvents response delivery failed before command close: {error}"
                );
                for command in affected {
                    self.mark_unsafe(command, detail.clone());
                }
                Err(error)
            }
        }
    }

    fn handle_event_inner(&mut self, record: FsEventRecord) -> Result<(), crate::ipc::ConnError> {
        if record.must_scan_subdirs() {
            tracing::warn!(
                path = %record.path.display(),
                "fsevents requested MustScanSubdirs; refusing every active command"
            );
            self.pending_rename = None;
            self.refuse_all_active(
                "macOS FSEvents reported MustScanSubdirs after dropping events; refusing incomplete capture",
            )?;
            return Ok(());
        }
        if record.is_root_changed() {
            tracing::warn!(
                path = %record.path.display(),
                "fsevents reported a changed watch root; refusing affected commands"
            );
            let affected = self.commands_affected_by_root_change(&record.path);
            if let Some(pending) = self.pending_rename.as_ref()
                && affected
                    .iter()
                    .any(|(command, _)| *command == pending.command)
            {
                self.pending_rename = None;
            }
            self.refuse_commands(
                affected,
                "macOS FSEvents watch root changed; capture coverage is no longer valid",
            )?;
            return Ok(());
        }

        let Some((command, _root)) = self.find_owning_command(&record.path) else {
            // Event for a path outside any tracked tree. Common during
            // recursive watch on a dir whose siblings churn; just drop.
            return Ok(());
        };

        // Renames take priority over Create/Unlink because FSEvents
        // sets multiple flag bits on a rename event.
        if record.is_renamed() {
            self.handle_rename(&record, command)?;
            return Ok(());
        }

        if record.is_removed() {
            self.emit_unlink(command, &record.path)?;
            return Ok(());
        }

        if record.is_created() {
            self.emit_create(command, &record)?;
        }

        // is_modified and is_meta_changed without any of the above are
        // skipped per M01.A Decision 1 — no pre-image, no useful undo
        // info to ship. The doctor (M02) surfaces this gap.
        Ok(())
    }

    fn commands_affected_by_event(&self, record: &FsEventRecord) -> Vec<CommandId> {
        let mut affected = if record.must_scan_subdirs() {
            self.watches.keys().copied().collect::<Vec<_>>()
        } else if record.is_root_changed() {
            self.commands_affected_by_root_change(&record.path)
                .into_iter()
                .map(|(command, _)| command)
                .collect()
        } else {
            self.find_owning_command(&record.path)
                .map(|(command, _)| vec![command])
                .unwrap_or_default()
        };
        // A mismatched rename first has to refuse the older half before it can
        // retain the new one. If either send fails, both commands are unsafe.
        if record.is_renamed()
            && let Some(pending) = &self.pending_rename
        {
            affected.push(pending.command);
        }
        affected.sort_unstable();
        affected.dedup();
        affected
    }

    fn commands_affected_by_root_change(&self, event_path: &Path) -> Vec<(CommandId, PathBuf)> {
        let mut affected: Vec<_> = self
            .watches
            .iter()
            .filter(|(_, root)| root.starts_with(event_path) || event_path.starts_with(root))
            .map(|(command, root)| (*command, root.clone()))
            .collect();
        // A root-change flag without an overlapping path is itself malformed;
        // conservatively treat the stream's complete watch set as affected.
        if affected.is_empty() {
            affected.extend(
                self.watches
                    .iter()
                    .map(|(command, root)| (*command, root.clone())),
            );
        }
        affected
    }

    fn refuse_all_active(&mut self, detail: &str) -> Result<(), crate::ipc::ConnError> {
        self.refuse_commands(
            self.watches
                .iter()
                .map(|(command, root)| (*command, root.clone()))
                .collect(),
            detail,
        )
    }

    fn refuse_commands(
        &mut self,
        commands: Vec<(CommandId, PathBuf)>,
        detail: &str,
    ) -> Result<(), crate::ipc::ConnError> {
        let mut first_error = None;
        for (command, root) in commands {
            if let Err(error) = self.emit_capture_refused(command, Some(&root), detail) {
                self.mark_unsafe(
                    command,
                    format!("{detail}; CaptureRefused delivery failed: {error}"),
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Pair `record` with `self.pending_rename` if the latter is fresh
    /// enough; else stash `record` as the new pending half.
    fn handle_rename(
        &mut self,
        record: &FsEventRecord,
        command: CommandId,
    ) -> Result<(), crate::ipc::ConnError> {
        if let Some(prev) = self.pending_rename.take() {
            if prev.ts.elapsed() < PENDING_RENAME_TIMEOUT && prev.command == command {
                // Paired. The second half's path exists; stat it for
                // dev/inode and emit a Rename.
                match std::fs::symlink_metadata(&record.path) {
                    Ok(meta) => {
                        self.emit_tree_mutation(
                            command,
                            TreeOpWire::Rename {
                                from: prev.from_path.to_string_lossy().into_owned(),
                                to: record.path.to_string_lossy().into_owned(),
                                dev: meta.dev(),
                                inode: meta.ino(),
                            },
                        )?;
                    }
                    Err(_) => {
                        self.emit_capture_refused(
                            command,
                            Some(&record.path),
                            "macOS FSEvents rename pair could not be verified; refusing ambiguous undo",
                        )?;
                    }
                }
                return Ok(());
            }
            self.emit_capture_refused(
                prev.command,
                Some(&prev.from_path),
                "macOS FSEvents rename event was not paired before another rename; refusing ambiguous undo",
            )?;
        }
        self.pending_rename = Some(PendingRename {
            command,
            from_path: record.path.clone(),
            ts: Instant::now(),
        });
        Ok(())
    }

    /// Called from the pump loop on every iteration to drain pending
    /// renames whose pair never arrived.
    fn flush_stale_pending_rename(&mut self) -> Result<(), crate::ipc::ConnError> {
        let stale = matches!(
            &self.pending_rename,
            Some(p) if p.ts.elapsed() >= PENDING_RENAME_TIMEOUT
        );
        if stale {
            let pending = self.pending_rename.take().unwrap();
            if let Err(error) = self.emit_capture_refused(
                pending.command,
                Some(&pending.from_path),
                "macOS FSEvents rename event timed out without a pair; refusing ambiguous undo",
            ) {
                self.mark_unsafe(
                    pending.command,
                    format!("macOS FSEvents stale-rename refusal delivery failed: {error}"),
                );
                return Err(error);
            }
        }
        Ok(())
    }

    fn flush_pending_rename_as_refusal(
        &mut self,
        detail: &str,
    ) -> Result<(), crate::ipc::ConnError> {
        if let Some(pending) = self.pending_rename.take()
            && let Err(error) =
                self.emit_capture_refused(pending.command, Some(&pending.from_path), detail)
        {
            self.mark_unsafe(
                pending.command,
                format!("{detail}; CaptureRefused delivery failed: {error}"),
            );
            return Err(error);
        }
        Ok(())
    }

    fn emit_create(
        &self,
        command: CommandId,
        record: &FsEventRecord,
    ) -> Result<(), crate::ipc::ConnError> {
        // Stat the new path so we have dev/inode/mode/kind. Skip the
        // event if the file is already gone (FSEvents Create + Remove
        // pair within a short window can race the stat).
        let Ok(meta) = std::fs::symlink_metadata(&record.path) else {
            return Ok(());
        };
        let kind = if meta.is_symlink() {
            FileKindWire::Symlink
        } else if meta.is_dir() {
            FileKindWire::Directory
        } else if meta.is_file() {
            FileKindWire::Regular
        } else {
            // FIFO / socket / block / char — record as Regular for
            // wire-shape purposes; the daemon's executor will handle
            // unlinking by path regardless.
            FileKindWire::Regular
        };
        self.emit_tree_mutation(
            command,
            TreeOpWire::Create {
                dev: meta.dev(),
                inode: meta.ino(),
                path: record.path.to_string_lossy().into_owned(),
                kind,
                mode: meta.mode(),
            },
        )
    }

    fn emit_unlink(&self, command: CommandId, path: &Path) -> Result<(), crate::ipc::ConnError> {
        // Post-hoc on the removal: the file is gone, so dev/inode are
        // lost. Emit zeros — the daemon-side executor inverts via
        // path, not by (dev, inode).
        //
        // G02 added kind+mode so the planner can synthesize a typed
        // RecreatePath. FSEvents-degraded has no held fd to fstat
        // before the unlink commits, so we fall back to the
        // serde-default values (Regular file / 0o644) the wire spec
        // documents — matches the pre-G02 hard-coded behavior. M03's
        // ES path will populate real kind+mode via AUTH_UNLINK pre-stat.
        self.emit_tree_mutation(
            command,
            TreeOpWire::Unlink {
                dev: 0,
                inode: 0,
                path: path.to_string_lossy().into_owned(),
                kind: FileKindWire::Regular,
                mode: 0o644,
            },
        )
    }

    fn emit_tree_mutation(
        &self,
        command: CommandId,
        op: TreeOpWire,
    ) -> Result<(), crate::ipc::ConnError> {
        let ts_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let ev = HelperResponse::TreeMutation {
            session: command.session,
            seq: command.seq,
            op,
            ts_unix_nanos,
            partial: true,
        };
        self.conn.send_response(&ev)
    }

    fn emit_capture_refused(
        &self,
        command: CommandId,
        path: Option<&Path>,
        detail: &str,
    ) -> Result<(), crate::ipc::ConnError> {
        self.conn.send_response(&HelperResponse::CaptureRefused {
            session: command.session,
            seq: command.seq,
            path: path.map(|path| path.to_string_lossy().into_owned()),
            detail: detail.to_owned(),
        })
    }
}

/// Free-function form so the pure-logic edge cases are unit-testable
/// without constructing an `Arc<Conn>`.
fn find_owning_command(
    watches: &BTreeMap<CommandId, PathBuf>,
    event_path: &Path,
) -> Option<(CommandId, PathBuf)> {
    let mut best: Option<(CommandId, PathBuf, usize)> = None;
    for (cmd, root) in watches {
        if event_path.starts_with(root) {
            let len = root.as_os_str().len();
            match &best {
                Some((_, _, best_len)) if *best_len >= len => {}
                _ => best = Some((*cmd, root.clone(), len)),
            }
        }
    }
    best.map(|(c, r, _)| (c, r))
}

/// Publish an attach result, retaining a cancellation token until detach. A
/// receiver drop catches the common timeout case immediately; retaining the
/// token closes the narrower race where `send` succeeds after `recv_timeout`
/// has decided to return but before the receiver is dropped.
fn complete_attach_or_cleanup(
    state: &mut PumpState,
    command: CommandId,
    completion: std::sync::mpsc::Sender<Result<(), CaptureAttachError>>,
    cancelled: Arc<AtomicBool>,
    result: Result<(), CaptureAttachError>,
) {
    let attached = result.is_ok();
    if attached {
        state
            .attach_cancellations
            .insert(command, Arc::clone(&cancelled));
    }
    if completion.send(result).is_err() {
        cancelled.store(true, Ordering::Release);
        tracing::warn!(
            %command.session,
            seq = command.seq,
            "fsevents attach caller dropped completion channel"
        );
    }
    if attached && cancelled.load(Ordering::Acquire) {
        state.cleanup_cancelled_attach(command);
    }
}

fn pump(conn: Arc<Conn>, ctrl_rx: Receiver<ControlMsg>) {
    let mut state = PumpState::new(conn);
    tracing::info!("macos fsevents capture pump started");
    loop {
        // A completion send can win the channel race at the exact instant the
        // request thread times out. Retained cancellation tokens close that
        // boundary: the next pump iteration still removes the late watch.
        state.cleanup_cancelled_attaches();

        // 1. Control first (low-latency attach/detach).
        match ctrl_rx.try_recv() {
            Ok(ControlMsg::Attach {
                command,
                root_path,
                completion,
                cancelled,
            }) => {
                let result = state.attach(command, root_path);
                complete_attach_or_cleanup(&mut state, command, completion, cancelled, result);
                continue;
            }
            Ok(ControlMsg::Detach {
                command,
                completion,
            }) => {
                let result = state.detach(command);
                if completion.send(result).is_err() {
                    tracing::warn!(
                        %command.session,
                        seq = command.seq,
                        "fsevents detach caller dropped completion channel"
                    );
                }
                continue;
            }
            Ok(ControlMsg::Shutdown) => {
                tracing::info!("macos fsevents capture pump shutdown requested");
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                if let Err(error) = state.handle_control_disconnect() {
                    tracing::error!(%error, "could not report FSEvents control-channel loss");
                }
                tracing::warn!("macos fsevents control channel closed; pump exiting");
                return;
            }
        }

        // 2. Stream events.
        let event_taken = if let Some((_, rx)) = &state.stream {
            match rx.try_recv() {
                Ok(record) => Some(Some(record)),
                Err(TryRecvError::Empty) => Some(None),
                Err(TryRecvError::Disconnected) => {
                    // Stream's worker thread exited unexpectedly. Drop
                    // the slot; next attach will recreate.
                    tracing::warn!("fsevents stream channel disconnected; clearing slot");
                    None
                }
            }
        } else {
            Some(None) // no stream, no event to handle
        };

        match event_taken {
            Some(Some(record)) => {
                if let Err(error) = state.handle_event(record) {
                    tracing::error!(%error, "fsevents event emission failed");
                }
                continue;
            }
            None => {
                if let Err(error) = state.handle_stream_disconnect() {
                    tracing::error!(%error, "could not report FSEvents stream loss");
                }
            }
            Some(None) => {}
        }

        // 3. Flush stale pending-rename halves.
        if let Err(error) = state.flush_stale_pending_rename() {
            tracing::error!(%error, "could not report ambiguous FSEvents rename");
        }

        // 4. Idle.
        std::thread::sleep(PUMP_IDLE_SLEEP);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    #[test]
    fn watch_tree_waits_until_fsevents_stream_start_is_reported() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let control = CaptureControl { tx };
        let session = Uuid::nil();

        let waiter = std::thread::spawn(move || {
            control.on_watch_tree(session, 17, 4242, "/tmp/capture-root")
        });

        let ControlMsg::Attach {
            command,
            root_path,
            completion,
            cancelled,
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

        // Queueing Attach is not readiness: the caller stays blocked until
        // FSEventStreamStart has succeeded in the pump thread.
        assert!(!waiter.is_finished());
        completion
            .send(Ok(()))
            .expect("watch request should still be waiting");
        assert!(waiter.join().expect("watch request panicked").is_ok());
    }

    #[test]
    fn watch_tree_propagates_fsevents_attach_failure() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let control = CaptureControl { tx };
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
            .send(Err(CaptureAttachError::CanonicalizeRoot {
                root_path: failed_root.clone(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            }))
            .expect("watch request should still be waiting");

        match waiter.join().expect("watch request panicked") {
            Err(CaptureAttachError::CanonicalizeRoot { root_path, source }) => {
                assert_eq!(root_path, failed_root);
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("unexpected watch result: {other:?}"),
        }
    }

    #[test]
    fn watch_tree_rejects_missing_cwd_without_queueing_attach() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let control = CaptureControl { tx };

        let result = control.on_watch_tree(Uuid::nil(), 29, 6262, "");
        assert!(matches!(
            result,
            Err(CaptureAttachError::CwdUnavailable { root_pid: 6262 })
        ));
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn watch_tree_reports_a_closed_control_channel() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        drop(rx);
        let control = CaptureControl { tx };

        let result = control.on_watch_tree(Uuid::nil(), 31, 7272, "/tmp/capture-root");
        assert!(matches!(
            result,
            Err(CaptureAttachError::ControlChannelClosed)
        ));
    }

    #[test]
    fn watch_tree_completion_wait_is_bounded() {
        let (completion_tx, completion_rx) = channel::<Result<(), CaptureAttachError>>();
        let cancelled = AtomicBool::new(false);

        assert!(matches!(
            recv_attach_completion(completion_rx, Duration::ZERO, &cancelled),
            Err(CaptureAttachError::CompletionTimeout)
        ));
        assert!(cancelled.load(Ordering::Acquire));
        drop(completion_tx);
    }

    #[test]
    fn late_successful_attach_is_cleaned_up_after_completion_timeout() {
        let (helper, _daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        let command = cmd(35);
        state
            .watches
            .insert(command, PathBuf::from("/tmp/capture-root"));
        let (completion_tx, completion_rx) = channel::<Result<(), CaptureAttachError>>();
        let cancelled = Arc::new(AtomicBool::new(false));
        drop(completion_rx);

        complete_attach_or_cleanup(&mut state, command, completion_tx, cancelled, Ok(()));

        assert!(!state.watches.contains_key(&command));
        assert!(!state.unsafe_commands.contains_key(&command));
        assert!(!state.attach_cancellations.contains_key(&command));
    }

    #[test]
    fn timeout_cancellation_cleans_up_even_when_completion_send_won_race() {
        let (helper, _daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        let command = cmd(36);
        state
            .watches
            .insert(command, PathBuf::from("/tmp/capture-root"));
        let (completion_tx, completion_rx) = channel::<Result<(), CaptureAttachError>>();
        let cancelled = Arc::new(AtomicBool::new(false));

        complete_attach_or_cleanup(
            &mut state,
            command,
            completion_tx,
            Arc::clone(&cancelled),
            Ok(()),
        );
        assert!(state.watches.contains_key(&command));
        cancelled.store(true, Ordering::Release);
        drop(completion_rx);

        state.cleanup_cancelled_attaches();

        assert!(!state.watches.contains_key(&command));
        assert!(!state.attach_cancellations.contains_key(&command));
    }

    #[test]
    fn unwatch_tree_waits_for_pump_completion() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let control = CaptureControl { tx };
        let session = Uuid::nil();

        let waiter = std::thread::spawn(move || control.on_unwatch_tree(session, 37));
        let ControlMsg::Detach {
            command,
            completion,
        } = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("capture pump should receive detach")
        else {
            panic!("expected detach control message");
        };
        assert_eq!(command, cmd(37));
        assert!(!waiter.is_finished());
        completion
            .send(Ok(()))
            .expect("unwatch request should still be waiting");
        assert!(waiter.join().expect("unwatch request panicked").is_ok());
    }

    #[test]
    fn unwatch_tree_reports_a_closed_control_channel() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        drop(rx);
        let control = CaptureControl { tx };

        assert!(matches!(
            control.on_unwatch_tree(Uuid::nil(), 41),
            Err(CaptureDetachError::ControlChannelClosed)
        ));
    }

    #[test]
    fn unwatch_tree_completion_wait_is_bounded() {
        let (completion_tx, completion_rx) = channel::<Result<(), CaptureDetachError>>();

        assert!(matches!(
            recv_detach_completion(completion_rx, Duration::ZERO),
            Err(CaptureDetachError::CompletionTimeout)
        ));
        drop(completion_tx);
    }

    #[test]
    fn must_scan_refuses_every_active_command_without_emitting_a_tree_op() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(1), PathBuf::from("/tmp/first"));
        state.watches.insert(cmd(2), PathBuf::from("/tmp/second"));

        state
            .handle_event(FsEventRecord {
                path: PathBuf::from("/tmp/first/lost"),
                flags: 0x01, // kFSEventStreamEventFlagMustScanSubDirs
            })
            .unwrap();

        for expected_seq in [1, 2] {
            assert!(matches!(
                daemon.recv_response().unwrap(),
                HelperResponse::CaptureRefused { seq, detail, .. }
                    if seq == expected_seq && detail.contains("MustScanSubdirs")
            ));
        }
    }

    #[test]
    fn root_change_refuses_only_the_overlapping_watch() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        state
            .watches
            .insert(cmd(1), PathBuf::from("/tmp/project/nested"));
        state.watches.insert(cmd(2), PathBuf::from("/var/other"));

        state
            .handle_event(FsEventRecord {
                path: PathBuf::from("/tmp/project"),
                flags: 0x20, // kFSEventStreamEventFlagRootChanged
            })
            .unwrap();

        assert!(matches!(
            daemon.recv_response().unwrap(),
            HelperResponse::CaptureRefused { seq: 1, detail, .. }
                if detail.contains("watch root changed")
        ));
    }

    #[test]
    fn detach_resolves_an_unpaired_rename_before_completion() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(9), PathBuf::from("/tmp/project"));
        state.pending_rename = Some(PendingRename {
            command: cmd(9),
            from_path: PathBuf::from("/tmp/project/old"),
            ts: Instant::now(),
        });

        state.detach(cmd(9)).unwrap();
        assert!(state.pending_rename.is_none());
        assert!(matches!(
            daemon.recv_response().unwrap(),
            HelperResponse::CaptureRefused {
                seq: 9,
                path: Some(path),
                detail,
                ..
            } if path == "/tmp/project/old" && detail.contains("unpaired rename")
        ));
    }

    #[test]
    fn stream_disconnect_clears_rename_state_and_refuses_all_watches() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(11), PathBuf::from("/tmp/project"));
        state.pending_rename = Some(PendingRename {
            command: cmd(11),
            from_path: PathBuf::from("/tmp/project/old"),
            ts: Instant::now(),
        });

        state.handle_stream_disconnect().unwrap();
        assert!(state.pending_rename.is_none());
        assert!(state.stream.is_none());
        assert!(matches!(
            daemon.recv_response().unwrap(),
            HelperResponse::CaptureRefused { seq: 11, detail, .. }
                if detail.contains("stream disconnected")
        ));
    }

    #[test]
    fn control_disconnect_refuses_every_active_watch() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(12), PathBuf::from("/tmp/first"));
        state.watches.insert(cmd(13), PathBuf::from("/tmp/second"));

        state.handle_control_disconnect().unwrap();
        for expected_seq in [12, 13] {
            assert!(matches!(
                daemon.recv_response().unwrap(),
                HelperResponse::CaptureRefused { seq, detail, .. }
                    if seq == expected_seq && detail.contains("control channel disconnected")
            ));
        }
    }

    #[test]
    fn detach_returns_error_when_final_refusal_cannot_be_sent() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        drop(daemon);
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(14), PathBuf::from("/tmp/project"));
        state.pending_rename = Some(PendingRename {
            command: cmd(14),
            from_path: PathBuf::from("/tmp/project/old"),
            ts: Instant::now(),
        });

        assert!(matches!(
            state.detach(cmd(14)),
            Err(CaptureDetachError::Emit { .. })
        ));
        assert!(!state.watches.contains_key(&cmd(14)));
        assert!(!state.unsafe_commands.contains_key(&cmd(14)));
    }

    #[test]
    fn normal_event_delivery_failure_is_sticky_until_detach() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        drop(daemon);
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(15), PathBuf::from("/tmp/project"));

        assert!(
            state
                .handle_event(FsEventRecord {
                    path: PathBuf::from("/tmp/project/deleted"),
                    flags: 0x200, // kFSEventStreamEventFlagItemRemoved
                })
                .is_err()
        );
        assert!(state.unsafe_commands.contains_key(&cmd(15)));

        match state.detach(cmd(15)) {
            Err(CaptureDetachError::CaptureUnhealthy { command, detail }) => {
                assert_eq!(command, cmd(15));
                assert!(detail.contains("response delivery failed"));
            }
            other => panic!("unexpected detach result: {other:?}"),
        }
        assert!(!state.watches.contains_key(&cmd(15)));
        assert!(!state.unsafe_commands.contains_key(&cmd(15)));
    }

    #[test]
    fn stale_rename_refusal_failure_is_sticky_until_detach() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        drop(daemon);
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(16), PathBuf::from("/tmp/project"));
        state.pending_rename = Some(PendingRename {
            command: cmd(16),
            from_path: PathBuf::from("/tmp/project/old"),
            ts: Instant::now()
                .checked_sub(PENDING_RENAME_TIMEOUT + Duration::from_millis(1))
                .unwrap(),
        });

        assert!(state.flush_stale_pending_rename().is_err());
        assert!(state.pending_rename.is_none());
        assert!(state.unsafe_commands.contains_key(&cmd(16)));

        match state.detach(cmd(16)) {
            Err(CaptureDetachError::CaptureUnhealthy { command, detail }) => {
                assert_eq!(command, cmd(16));
                assert!(detail.contains("stale-rename refusal delivery failed"));
            }
            other => panic!("unexpected detach result: {other:?}"),
        }
        assert!(!state.watches.contains_key(&cmd(16)));
        assert!(!state.unsafe_commands.contains_key(&cmd(16)));
    }

    #[test]
    fn stream_disconnect_refusal_failure_marks_every_watch_unsafe() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        drop(daemon);
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(17), PathBuf::from("/tmp/first"));
        state.watches.insert(cmd(18), PathBuf::from("/tmp/second"));

        assert!(state.handle_stream_disconnect().is_err());
        assert!(state.unsafe_commands.contains_key(&cmd(17)));
        assert!(state.unsafe_commands.contains_key(&cmd(18)));

        for command in [cmd(17), cmd(18)] {
            assert!(matches!(
                state.detach(command),
                Err(CaptureDetachError::CaptureUnhealthy {
                    command: failed,
                    ..
                }) if failed == command
            ));
        }
        assert!(state.watches.is_empty());
        assert!(state.unsafe_commands.is_empty());
    }

    #[test]
    fn control_disconnect_refusal_failure_is_sticky_until_detach() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        drop(daemon);
        let mut state = PumpState::new(Arc::new(helper));
        state.watches.insert(cmd(19), PathBuf::from("/tmp/project"));

        assert!(state.handle_control_disconnect().is_err());
        assert!(state.unsafe_commands.contains_key(&cmd(19)));
        assert!(matches!(
            state.detach(cmd(19)),
            Err(CaptureDetachError::CaptureUnhealthy { command, .. }) if command == cmd(19)
        ));
        assert!(!state.watches.contains_key(&cmd(19)));
        assert!(!state.unsafe_commands.contains_key(&cmd(19)));
    }

    #[test]
    fn find_owning_command_prefers_longest_prefix() {
        let mut watches = BTreeMap::new();
        watches.insert(cmd(1), PathBuf::from("/tmp"));
        watches.insert(cmd(2), PathBuf::from("/tmp/nested"));

        // /tmp/nested/file matches the inner (longer) prefix.
        let (got_cmd, got_root) =
            find_owning_command(&watches, Path::new("/tmp/nested/file")).unwrap();
        assert_eq!(got_cmd, cmd(2));
        assert_eq!(got_root, PathBuf::from("/tmp/nested"));

        // /tmp/sibling matches the outer.
        let (got_cmd, _) = find_owning_command(&watches, Path::new("/tmp/sibling")).unwrap();
        assert_eq!(got_cmd, cmd(1));

        // /other/path matches neither.
        assert!(find_owning_command(&watches, Path::new("/other/path")).is_none());
    }

    #[test]
    fn find_owning_command_empty_watches_returns_none() {
        let watches: BTreeMap<CommandId, PathBuf> = BTreeMap::new();
        assert!(find_owning_command(&watches, Path::new("/anywhere")).is_none());
    }

    #[test]
    fn find_owning_command_exact_root_match() {
        let mut watches = BTreeMap::new();
        watches.insert(cmd(1), PathBuf::from("/tmp/exact"));
        let (got_cmd, _) = find_owning_command(&watches, Path::new("/tmp/exact")).unwrap();
        assert_eq!(got_cmd, cmd(1));
    }
}
