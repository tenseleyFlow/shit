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
    DrainEvent, DrainSession, KqueueFd, TrackedSubtree, VnodeEventKind, init as kqueue_init,
    read_pre_image, register_subtree, spawn_drain,
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
    staging_dir: PathBuf,
    conn: Arc<Conn>,
    seq_counter: u64,
}

impl PumpState {
    fn new(staging_dir: PathBuf, conn: Arc<Conn>) -> Self {
        Self {
            watches: BTreeMap::new(),
            fd_to_command: HashMap::new(),
            staging_dir,
            conn,
            seq_counter: 0,
        }
    }

    /// Next monotonically-increasing seq for the wire's `seq` field.
    /// Helper-local; not the daemon's command_seq (which is the
    /// CommandId's seq). This is a per-event sequence so the daemon
    /// can de-duplicate retransmits if we ever add them.
    fn next_seq(&mut self) -> u64 {
        self.seq_counter = self.seq_counter.wrapping_add(1);
        self.seq_counter
    }

    fn attach(&mut self, kq: &KqueueFd, command: CommandId, root_path: &Path) {
        let subtree = match register_subtree(kq, root_path, DEFAULT_DEPTH) {
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
        self.watches.insert(
            command,
            WatchState {
                subtree,
                dedupe: HashMap::new(),
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
        // Only Write/Extend/Delete trigger pre-image capture; other
        // kinds (Attrib, Link, Rename, Revoke) get a debug log for
        // now — full coverage lands when paired with the planner's
        // TreeOp variants in a follow-up.
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
        // Compute helper-local seq before we mutably borrow `ws` so the
        // borrow-checker doesn't see two `&mut self` borrows alive at once.
        let seq = self.next_seq();
        let Some(ws) = self.watches.get_mut(&command) else {
            // fd_to_command had us, but the watch state is gone —
            // race with detach. Drop.
            return;
        };
        let (dev, inode) = match fstat_dev_inode(fd) {
            Some(t) => t,
            None => {
                tracing::warn!(fd, "fstat failed; skipping capture");
                return;
            }
        };
        if !should_capture_dedupe(&ws.dedupe, (dev, inode)) {
            tracing::trace!(fd, dev, inode, "dedupe hit; skipping recapture");
            return;
        }
        let path = ws.subtree.path_for_fd(fd).map(|p| p.to_path_buf());
        // Read pre-image bytes from the tracked fd. For Delete, the
        // fd survives unlink and pread still returns original bytes
        // (S23.4's architectural test proves this).
        let bytes = match read_pre_image(fd) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(fd, error = %e, "read_pre_image failed");
                return;
            }
        };
        // Stat for metadata. After Delete the fstat above already
        // returned valid (dev, inode); same call works for mode/uid/gid/mtime.
        let meta = match fstat_meta(fd) {
            Some(m) => m,
            None => {
                tracing::warn!(fd, "fstat for meta failed; skipping capture");
                return;
            }
        };
        // Stage the bytes into a temp file under staging_dir, then
        // attach the fd via SCM_RIGHTS.
        let staging_fd = match write_to_staging(&self.staging_dir, &bytes) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::warn!(error = %e, "staging write failed; skipping capture");
                return;
            }
        };
        // blake3 the bytes; this is what the daemon will verify.
        let claimed_hash = blake3_of(&bytes);
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let resp = HelperResponse::CapturedPreImage {
            session: command.session,
            seq,
            dev,
            inode,
            path: path.as_deref().map(path_to_string),
            blob_hash: claimed_hash,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None, // TODO: compute when not Delete
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            is_delete,
            fd_sent_via_scm: true,
        };
        if let Err(e) = self.conn.send_response_with_fd(&resp, staging_fd.as_raw_fd()) {
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
            bytes = bytes.len(),
            now_nanos,
            "CapturedPreImage sent",
        );
    }
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

fn fstat_dev_inode(fd: RawFd) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is expected valid; st is writable.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return None;
    }
    Some((st.st_dev as u64, st.st_ino as u64))
}

#[derive(Debug, Clone, Copy)]
struct StatMeta {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_unix_nanos: i128,
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
        mtime_unix_nanos: mtime,
    })
}

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
        f.sync_all()?;
    }
    // Reopen read-only for the SCM_RIGHTS send; the file lives on
    // disk until the daemon ingests + unlinks.
    let f = std::fs::OpenOptions::new().read(true).open(&path)?;
    // SAFETY: we just opened f; consume it into an OwnedFd.
    Ok(f.into())
}

fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn path_to_string(p: &Path) -> String {
    String::from_utf8_lossy(p.as_os_str().as_bytes()).to_string()
}

/// Handle the request_loop holds. Cheaply cloneable.
#[derive(Clone)]
pub struct CaptureControl {
    tx: SyncSender<ControlMsg>,
}

impl CaptureControl {
    pub fn on_watch_tree(&self, session: Uuid, command_seq: u64, root_pid: u32) {
        let path = match super::cwd::resolve_pid_cwd(root_pid) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    %session,
                    command_seq,
                    root_pid,
                    "could not resolve root_pid cwd; watch dropped",
                );
                return;
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
) -> std::io::Result<(CaptureControl, JoinHandle<()>)> {
    std::fs::create_dir_all(&staging_dir)?;
    // Single shared kqueue: the drain thread reads events, the pump
    // thread calls `register_subtree` to add new fd watches. Both
    // operations on the same fd are thread-safe at the kernel level.
    let kq = Arc::new(kqueue_init().map_err(std::io::Error::other)?);
    let drain_session = spawn_drain(Arc::clone(&kq), 4096).map_err(std::io::Error::other)?;
    let (ctrl_tx, ctrl_rx) = sync_channel::<ControlMsg>(64);
    let handle = std::thread::Builder::new()
        .name("shit-bsd-capture-pump".to_string())
        .spawn(move || pump(kq, drain_session, conn, staging_dir, ctrl_rx))?;
    Ok((CaptureControl { tx: ctrl_tx }, handle))
}

fn pump(
    kq: Arc<KqueueFd>,
    drain_session: DrainSession,
    conn: Arc<Conn>,
    staging_dir: PathBuf,
    ctrl_rx: Receiver<ControlMsg>,
) {
    let mut state = PumpState::new(staging_dir, conn);
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
    fn blake3_of_matches_known_vector() {
        // Empty input → BLAKE3 of "" = af1349b9f5f9a1a6a0404dea36dcc949...
        let got = blake3_of(b"");
        assert_eq!(
            got[..4],
            [0xAF, 0x13, 0x49, 0xB9],
            "blake3('') prefix mismatch",
        );
    }

    #[test]
    fn write_to_staging_round_trips_bytes() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"staging-round-trip";
        let fd = write_to_staging(dir.path(), bytes).unwrap();
        let mut f = std::fs::File::from(fd);
        let mut out = Vec::new();
        f.read_to_end(&mut out).unwrap();
        assert_eq!(out.as_slice(), bytes);
    }

    #[test]
    fn fstat_dev_inode_works_on_open_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe");
        std::fs::write(&path, b"x").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let (dev, inode) = fstat_dev_inode(f.as_raw_fd()).expect("fstat ok");
        assert!(dev > 0 || inode > 0);
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
        let mut state = PumpState::new(dir.path().to_path_buf(), Arc::new(conn_a));
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
