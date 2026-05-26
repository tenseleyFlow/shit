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
//! `(CommandId, root_path)`, the pump tears down the existing
//! FSEvents stream and starts a new one over all tracked roots. This
//! costs ~50–200ms per attach/detach (FSEvents kernel registration
//! latency) and is acceptable because attach happens at PreExec, not
//! on the per-event hot path.
//!
//! Wire-event mapping (Decision 1 in `.docs/sprints/macos/M01.A-…md`):
//!
//! | FSEvents flag       | Wire emit |
//! |---------------------|-----------|
//! | `is_created`        | `TreeOpWire::Create { dev, inode, path, kind, mode }` |
//! | `is_removed`        | `TreeOpWire::Unlink { dev: 0, inode: 0, path }` — inode lost when the file was removed before our stat |
//! | `is_renamed` (paired) | `TreeOpWire::Rename { from, to, dev, inode }` |
//! | `is_renamed` (timeout) | `TreeOpWire::Unlink { path }` for unmatched halves |
//! | `is_modified`       | **skipped** — no pre-image, no useful undo. Doctor surfaces the gap. |
//! | `is_meta_changed`   | **skipped for M01.A** — `CapturedMetadataChange` needs a before-state we don't have post-hoc. M03's ES path captures both. |
//! | `is_root_changed`   | warn-only; the watch root itself was moved/deleted |
//! | `must_scan_subdirs` | warn-only; full rescan deferred to v1.x |

#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
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
/// shell command); a `try_send` overflow logs and drops, which
/// degrades the affected WatchTree quietly rather than blocking
/// the request loop.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

// ─────────────────────────────────────────────────────────────────────
// Control-channel messages
// ─────────────────────────────────────────────────────────────────────

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
        _root_pid: u32,
        cwd_path: &str,
    ) {
        if cwd_path.is_empty() {
            tracing::warn!(
                %session,
                command_seq,
                "WatchTree without cwd_path on macOS; watch dropped"
            );
            return;
        }
        let path = PathBuf::from(cwd_path);
        let command = CommandId {
            session,
            seq: command_seq,
        };
        if let Err(e) = self.tx.try_send(ControlMsg::Attach {
            command,
            root_path: path,
        }) {
            tracing::warn!(
                %session,
                command_seq,
                err = %e,
                "fsevents control channel full; WatchTree dropped"
            );
        }
    }

    pub fn on_unwatch_tree(&self, session: Uuid, command_seq: u64) {
        let command = CommandId {
            session,
            seq: command_seq,
        };
        if let Err(e) = self.tx.try_send(ControlMsg::Detach { command }) {
            tracing::warn!(
                %session,
                command_seq,
                err = %e,
                "fsevents control channel full; UnwatchTree dropped"
            );
        }
    }

    /// Signal the pump thread to exit. Best-effort.
    pub fn shutdown(&self) {
        let _ = self.tx.try_send(ControlMsg::Shutdown);
    }
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
}

impl PumpState {
    fn new(conn: Arc<Conn>) -> Self {
        Self {
            conn,
            watches: BTreeMap::new(),
            stream: None,
            pending_rename: None,
        }
    }

    fn attach(&mut self, command: CommandId, root_path: PathBuf) {
        // Canonicalize so subsequent path-prefix comparisons match
        // FSEvents-reported paths (which arrive realpath-resolved).
        let canonical = match std::fs::canonicalize(&root_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    %command.session,
                    seq = command.seq,
                    path = %root_path.display(),
                    err = %e,
                    "canonicalize watch root failed; using non-canonical path"
                );
                root_path
            }
        };
        tracing::info!(
            %command.session,
            seq = command.seq,
            path = %canonical.display(),
            "fsevents watch attached"
        );
        self.watches.insert(command, canonical);
        self.rebuild_stream();
    }

    fn detach(&mut self, command: CommandId) {
        if self.watches.remove(&command).is_some() {
            tracing::info!(
                %command.session,
                seq = command.seq,
                "fsevents watch detached"
            );
            self.rebuild_stream();
        }
    }

    /// Tear down the active stream and start a new one over the
    /// current watch set. Called on every attach/detach.
    fn rebuild_stream(&mut self) {
        // Drop existing stream (its Drop calls Stop/Invalidate/Release
        // and joins the worker thread).
        self.stream = None;

        if self.watches.is_empty() {
            return;
        }

        let roots: Vec<PathBuf> = self.watches.values().cloned().collect();
        match FsEventsStream::start_with_options(roots.clone(), StreamOptions::default()) {
            Ok((stream, rx)) => {
                tracing::info!(
                    n_roots = roots.len(),
                    "fsevents stream (re)started"
                );
                self.stream = Some((stream, rx));
            }
            Err(e) => {
                tracing::error!(
                    err = %e,
                    n_roots = roots.len(),
                    "fsevents stream start failed; tracked commands will see no events until next attach"
                );
            }
        }
    }

    /// Longest-prefix match: among all watch roots, find the one that
    /// is a path-prefix of `event_path`. Returns the matching
    /// `(CommandId, root_path)` or `None` if the event falls outside
    /// every tracked tree.
    fn find_owning_command(&self, event_path: &Path) -> Option<(CommandId, PathBuf)> {
        find_owning_command(&self.watches, event_path)
    }

    fn handle_event(&mut self, record: FsEventRecord) {
        // Root-changed: the watch root itself moved/disappeared.
        // Log loudly; the daemon may want to invalidate the tree but
        // for M01.A we don't synthesize an UnwatchTree.
        if record.is_root_changed() {
            tracing::warn!(
                path = %record.path.display(),
                "fsevents reported root changed for {}", record.path.display()
            );
            // continue — there may be other flag bits on this event
        }
        if record.must_scan_subdirs() {
            tracing::warn!(
                path = %record.path.display(),
                "fsevents requested MustScanSubdirs (kernel ring overflowed); some events lost"
            );
            // continue — best-effort
        }

        let Some((command, _root)) = self.find_owning_command(&record.path) else {
            // Event for a path outside any tracked tree. Common during
            // recursive watch on a dir whose siblings churn; just drop.
            return;
        };

        // Renames take priority over Create/Unlink because FSEvents
        // sets multiple flag bits on a rename event.
        if record.is_renamed() {
            self.handle_rename(&record, command);
            return;
        }

        if record.is_removed() {
            self.emit_unlink(command, &record.path);
            return;
        }

        if record.is_created() {
            self.emit_create(command, &record);
        }

        // is_modified and is_meta_changed without any of the above are
        // skipped per M01.A Decision 1 — no pre-image, no useful undo
        // info to ship. The doctor (M02) surfaces this gap.
    }

    /// Pair `record` with `self.pending_rename` if the latter is fresh
    /// enough; else stash `record` as the new pending half.
    fn handle_rename(&mut self, record: &FsEventRecord, command: CommandId) {
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
                        );
                    }
                    Err(_) => {
                        // The "after" path doesn't exist either — odd;
                        // both halves were rename-out. Emit two Unlinks.
                        self.emit_unlink(command, &prev.from_path);
                        self.emit_unlink(command, &record.path);
                    }
                }
                return;
            }
            // Stale pending — flush it as an Unlink and accept this
            // record as the new pending half.
            self.emit_unlink(prev.command, &prev.from_path);
        }
        self.pending_rename = Some(PendingRename {
            command,
            from_path: record.path.clone(),
            ts: Instant::now(),
        });
    }

    /// Called from the pump loop on every iteration to drain pending
    /// renames whose pair never arrived.
    fn flush_stale_pending_rename(&mut self) {
        let stale = matches!(
            &self.pending_rename,
            Some(p) if p.ts.elapsed() >= PENDING_RENAME_TIMEOUT
        );
        if stale {
            let pending = self.pending_rename.take().unwrap();
            self.emit_unlink(pending.command, &pending.from_path);
        }
    }

    fn emit_create(&self, command: CommandId, record: &FsEventRecord) {
        // Stat the new path so we have dev/inode/mode/kind. Skip the
        // event if the file is already gone (FSEvents Create + Remove
        // pair within a short window can race the stat).
        let Ok(meta) = std::fs::symlink_metadata(&record.path) else {
            return;
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
        );
    }

    fn emit_unlink(&self, command: CommandId, path: &Path) {
        // Post-hoc on the removal: the file is gone, so dev/inode are
        // lost. Emit zeros — the daemon-side executor inverts via
        // path, not by (dev, inode).
        self.emit_tree_mutation(
            command,
            TreeOpWire::Unlink {
                dev: 0,
                inode: 0,
                path: path.to_string_lossy().into_owned(),
            },
        );
    }

    fn emit_tree_mutation(&self, command: CommandId, op: TreeOpWire) {
        let ts_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let ev = HelperResponse::TreeMutation {
            session: command.session,
            seq: command.seq,
            op,
            ts_unix_nanos,
        };
        if let Err(e) = self.conn.send_response(&ev) {
            tracing::warn!(
                %command.session,
                seq = command.seq,
                err = %e,
                "send TreeMutation failed"
            );
        }
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

fn pump(conn: Arc<Conn>, ctrl_rx: Receiver<ControlMsg>) {
    let mut state = PumpState::new(conn);
    tracing::info!("macos fsevents capture pump started");
    loop {
        // 1. Control first (low-latency attach/detach).
        match ctrl_rx.try_recv() {
            Ok(ControlMsg::Attach { command, root_path }) => {
                state.attach(command, root_path);
                continue;
            }
            Ok(ControlMsg::Detach { command }) => {
                state.detach(command);
                continue;
            }
            Ok(ControlMsg::Shutdown) => {
                tracing::info!("macos fsevents capture pump shutdown requested");
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                tracing::info!("macos fsevents control channel closed; pump exiting");
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
                state.handle_event(record);
                continue;
            }
            None => {
                state.stream = None;
            }
            Some(None) => {}
        }

        // 3. Flush stale pending-rename halves.
        state.flush_stale_pending_rename();

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
