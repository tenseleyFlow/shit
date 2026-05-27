// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS EndpointSecurity capture producer (M03.1.I).
//!
//! Sibling of `capture/macos.rs` (the FSEvents-degraded producer
//! shipped in M01.A). The two coexist per the M03.1.I design
//! decision: ES is primary (pre-image-content capture); FSEvents
//! continues as fallback for tree-ops if ES wrapper has a latent
//! bug. Daemon ingests both kinds (FilePreImage from ES vs
//! TreeOp::Unlink from FSEvents are distinct `CaptureEventKind`
//! variants — no dedup conflict).
//!
//! Structurally mirrors `capture/bsd.rs`: a pump thread owns the
//! capture state + the ring buffer that decouples the kernel ES
//! callback from blob hashing + sendmsg. The callback (kernel-
//! thread-owned) does inline clonefile to capture pre-image bytes
//! before the syscall commits; the pump thread does blake3 + the
//! SCM_RIGHTS sendmsg.
//!
//! ## Sub-slice layout
//!
//! - M03.1.I.2 (this file's first commit): scaffold — ControlMsg,
//!   CaptureControl, spawn + pump shell. No event handling yet.
//! - M03.1.I.3: PumpState carries tracked_tokens/cwds; ES callback
//!   does the audit_token filter + NOTIFY_FORK auto-add + NOTIFY_EXIT
//!   remove.
//! - M03.1.I.4: AUTH_UNLINK clonefile capture + worker emission.
//! - M03.1.I.5: main.rs spawns this alongside FSEvents producer.
//! - M03.1.I.6: handshake reports `endpoint-security` when this is
//!   the active tier.

#![cfg(target_os = "macos")]
// Whole module is dead until M03.1.I.5 wires main.rs to spawn this
// alongside the FSEvents producer. The allow comes off in I.5.
#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::raw::c_ulong;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use shit_planner::events::CommandId;
use uuid::Uuid;

use crate::es::message::{EsMessage, audit_token_t};
use crate::es::sys;
use crate::ipc::Conn;

/// Channel capacity for control messages from the request loop.
/// Mirrors `capture::bsd`'s sizing.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Pump idle-sleep when both the control channel and the
/// (M03.1.I.4) ring report Empty.
const PUMP_IDLE_SLEEP: Duration = Duration::from_millis(50);

// ─────────────────────────────────────────────────────────────────────
// PumpHandle — shared between kernel callback + pump thread
// ─────────────────────────────────────────────────────────────────────
//
// Kernel callback (Apple-owned serial dispatch queue) reads:
// - pid_to_token (resolve pids harvested by NOTIFY_EXEC)
// - tracked_tokens (filter AUTH events)
// - ring_tx (push CaptureRecord on AUTH match)
// - staging_dir (clonefile destination — M03.1.I.4)
//
// Pump thread writes:
// - on ControlMsg::Attach: looks up root_pid in pid_to_token →
//   inserts (audit_token, CommandId) into tracked_tokens
// - on ControlMsg::Detach: removes from tracked_tokens
//
// Callback also writes:
// - NOTIFY_EXEC: pid_to_token.insert(pid, token)
// - NOTIFY_FORK: if parent in tracked, tracked_tokens.insert(child)
// - NOTIFY_EXIT: pid_to_token.remove + tracked_tokens.remove
//
// Single-shared because the helper only runs one producer at a time.

/// State the ES callback reads + writes. Initialized exactly once
/// by [`pump`] at startup via [`PUMP`].
pub struct PumpHandle {
    /// pid → audit_token map, populated by NOTIFY_EXEC observation +
    /// initial bsdinfo lookup. Used by ControlMsg::Attach to resolve
    /// the daemon-supplied root_pid to its audit_token.
    pub pid_to_token: Mutex<HashMap<i32, audit_token_t>>,
    /// audit_token → CommandId map. AUTH_UNLINK handler reads
    /// (filter); NOTIFY_FORK handler writes (auto-add children
    /// of tracked processes, inheriting the parent's CommandId).
    pub tracked_tokens: Mutex<HashMap<audit_token_t, CommandId>>,
    /// Bounded ring the callback pushes CaptureRecords into. The
    /// pump thread drains; if full, the callback drops the record
    /// + DENYs (preserves the undo invariant: never silently lose
    ///   a pre-image).
    pub ring_tx: SyncSender<CaptureRecord>,
    /// Directory the inline clonefile writes the staging file into.
    pub staging_dir: PathBuf,
    /// Diagnostic counters: events the callback saw, events the
    /// filter passed, events the worker emitted.
    pub events_seen: AtomicU64,
    pub events_passed_filter: AtomicU64,
    pub events_emitted: AtomicU64,
}

/// Singleton: the active producer's state. The kernel callback
/// reads it via `PUMP.get()`. Initialized inside [`pump`] before
/// EsClient subscription; never replaced.
pub static PUMP: OnceLock<PumpHandle> = OnceLock::new();

/// CaptureRecord — what the callback queues for the pump worker
/// after an AUTH match. M03.1.I.4 adds the staging_fd field +
/// the worker reads it for hash + sendmsg.
pub struct CaptureRecord {
    pub command: CommandId,
    pub path: PathBuf,
    pub dev: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_unix_nanos: i128,
    pub is_delete: bool,
    // M03.1.I.4: pub staging_fd: std::os::fd::OwnedFd,
}

// ─────────────────────────────────────────────────────────────────────
// Producer handler — global Block invoked by the ES kernel callback
// ─────────────────────────────────────────────────────────────────────
//
// Three event types delivered:
// - NOTIFY_EXEC: harvest pid→token mapping
// - NOTIFY_FORK: propagate tracked-token to child (parent observed
//   in tracked_tokens → child inherits the CommandId)
// - NOTIFY_EXIT: prune both maps
// - AUTH_UNLINK: if process in tracked_tokens, push CaptureRecord
//   to ring + respond ALLOW (M03.1.I.4 adds the clonefile step);
//   if not tracked, respond ALLOW immediately

extern "C" fn producer_invoke(
    _block: *const sys::Block<()>,
    client: *mut sys::es_client_t,
    message: *const c_void,
) {
    // SAFETY: kernel-owned for the callback duration. EsMessage
    // borrows the pointer only for this scope.
    let msg = unsafe { EsMessage::from_raw(message) };
    let event_type = msg.event_type();

    // PUMP must have been initialized by the pump thread before any
    // ES events arrive. If it hasn't (race or bug), bail without
    // dispatching — for AUTH events we still must respond ALLOW so
    // the kernel doesn't 5-s-timeout-kill us.
    let pump = match PUMP.get() {
        Some(p) => p,
        None => {
            if event_type == sys::es_event_type_t::AUTH_UNLINK {
                respond_allow(client, message);
            }
            return;
        }
    };
    pump.events_seen.fetch_add(1, Ordering::Relaxed);

    if event_type == sys::es_event_type_t::NOTIFY_EXEC {
        handle_notify_exec(pump, &msg);
        return;
    }
    if event_type == sys::es_event_type_t::NOTIFY_FORK {
        handle_notify_fork(pump, &msg);
        return;
    }
    if event_type == sys::es_event_type_t::NOTIFY_EXIT {
        handle_notify_exit(pump, &msg);
        return;
    }
    if event_type == sys::es_event_type_t::AUTH_UNLINK {
        // handle_auth_unlink calls respond_allow internally (after
        // the M03.1.I.4 clonefile step lands).
        handle_auth_unlink(pump, client, message, &msg);
    }
    // Unknown event type — shouldn't happen since we control the
    // subscription set. Respond ALLOW if it's an AUTH variant we
    // didn't recognize, to be safe.
}

fn respond_allow(client: *mut sys::es_client_t, message: *const c_void) {
    // SAFETY: kernel callback contract — message + client valid here.
    unsafe {
        let _ = sys::es_respond_auth_result(
            client,
            message as *const sys::es_message_t,
            sys::es_auth_result_t::ALLOW,
            true,
        );
    }
}

fn handle_notify_exec(pump: &PumpHandle, msg: &EsMessage<'_>) {
    // Apple stores pid at val[5] of audit_token_t per libbsm's
    // audit_token_to_pid() macro. We avoid that detail here — we
    // store the FULL audit_token keyed by pid. Stale entries get
    // pruned on NOTIFY_EXIT.
    let token = msg.process_audit_token();
    let pid = pid_from_audit_token(&token);
    if let Ok(mut g) = pump.pid_to_token.lock() {
        g.insert(pid, token);
    }
}

fn handle_notify_fork(pump: &PumpHandle, msg: &EsMessage<'_>) {
    let parent_token = msg.process_audit_token();
    // If parent is tracked, child inherits the same CommandId.
    let inherit = match pump.tracked_tokens.lock() {
        Ok(g) => g.get(&parent_token).copied(),
        Err(_) => return,
    };
    if let Some(command) = inherit
        && let Some(child_token) = msg.fork_child_audit_token()
    {
        if let Ok(mut g) = pump.tracked_tokens.lock() {
            g.insert(child_token, command);
        }
        // Also record the child's pid → token mapping for any later
        // direct-pid lookups (e.g., a follow-on WatchTree of the
        // same descendant).
        let child_pid = pid_from_audit_token(&child_token);
        if let Ok(mut g) = pump.pid_to_token.lock() {
            g.insert(child_pid, child_token);
        }
    }
}

fn handle_notify_exit(pump: &PumpHandle, msg: &EsMessage<'_>) {
    let token = msg.process_audit_token();
    let pid = pid_from_audit_token(&token);
    if let Ok(mut g) = pump.pid_to_token.lock() {
        g.remove(&pid);
    }
    if let Ok(mut g) = pump.tracked_tokens.lock() {
        g.remove(&token);
    }
}

fn handle_auth_unlink(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let token = msg.process_audit_token();
    let command = match pump.tracked_tokens.lock() {
        Ok(g) => g.get(&token).copied(),
        Err(_) => None,
    };
    let Some(command) = command else {
        // Not tracked — ALLOW without recording.
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    // M03.1.I.4 inserts the clonefile + record-push here. Stage 3
    // just records the event for diagnostic visibility + ALLOWs.
    if let Some(path) = msg.unlink_target_path() {
        tracing::debug!(
            %command.session,
            seq = command.seq,
            path = %path.display(),
            "macos-es AUTH_UNLINK pass filter (capture wiring is M03.1.I.4)"
        );
    }
    respond_allow(client, message);
}

/// Extract the BSD pid stored in `audit_token_t.val[5]` per Apple's
/// `audit_token_to_pid()` macro in `<bsm/libbsm.h>`.
fn pid_from_audit_token(token: &audit_token_t) -> i32 {
    token.val[5] as i32
}

// ─────────────────────────────────────────────────────────────────────
// Producer block — descriptor + static
// ─────────────────────────────────────────────────────────────────────

static PRODUCER_DESCRIPTOR: sys::BlockDescriptor = sys::BlockDescriptor {
    reserved: 0,
    size: core::mem::size_of::<sys::Block<()>>() as c_ulong,
};

/// Pre-built global Block invoked by the ES kernel callback for
/// every delivered message. Reads `PUMP` to dispatch on event_type.
pub static PRODUCER_HANDLER: sys::Block<()> = sys::Block {
    isa: unsafe { &sys::_NSConcreteGlobalBlock as *const _ },
    flags: sys::BLOCK_IS_GLOBAL,
    reserved: 0,
    invoke: producer_invoke as *const c_void,
    descriptor: &PRODUCER_DESCRIPTOR,
    _phantom: std::marker::PhantomData,
};

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

/// Cheaply-cloneable handle the request loop holds. Mirrors
/// `capture::bsd::CaptureControl` so main.rs can dispatch
/// WatchTree to both producers identically.
#[derive(Clone)]
pub struct CaptureControl {
    tx: SyncSender<ControlMsg>,
}

impl CaptureControl {
    /// Register a new tracked tree. The pump records the
    /// (CommandId, cwd_path) pair; M03.1.I.3 also resolves the
    /// root_pid to its audit_token for the kernel-side filter.
    ///
    /// `cwd_path` must be non-empty — macOS doesn't have a
    /// FreeBSD-style sysctl(KERN_PROC_CWD) fallback we'd want to
    /// rely on.
    pub fn on_watch_tree(&self, session: Uuid, command_seq: u64, _root_pid: u32, cwd_path: &str) {
        if cwd_path.is_empty() {
            tracing::warn!(
                %session,
                command_seq,
                "WatchTree without cwd_path on macOS ES; watch dropped"
            );
            return;
        }
        let command = CommandId {
            session,
            seq: command_seq,
        };
        if let Err(e) = self.tx.try_send(ControlMsg::Attach {
            command,
            root_path: PathBuf::from(cwd_path),
        }) {
            tracing::warn!(
                %session,
                command_seq,
                err = %e,
                "macos-es control channel full; WatchTree dropped"
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
                "macos-es control channel full; UnwatchTree dropped"
            );
        }
    }

    /// Signal the pump thread to exit. Best-effort.
    pub fn shutdown(&self) {
        let _ = self.tx.try_send(ControlMsg::Shutdown);
    }
}

/// Spawn the ES capture pump. Returns a control handle for the
/// request loop and the pump's `JoinHandle`.
///
/// The pump owns the [`EsClient`] (`!Send`) so the client must be
/// created + destroyed on the same thread per Apple's contract.
///
/// `staging_dir` is where inline clonefile writes go; the pump's
/// worker side reads + hashes + ships via SCM_RIGHTS to the daemon.
///
/// Errors at `spawn` time only if the OS refuses the thread spawn —
/// the ES client creation happens INSIDE the pump (so we can return
/// the JoinHandle either way and the caller checks the handle's
/// outcome for late-failure cases like NOT_ENTITLED).
///
/// [`EsClient`]: crate::es::EsClient
pub fn spawn(
    conn: Arc<Conn>,
    staging_dir: PathBuf,
) -> std::io::Result<(CaptureControl, JoinHandle<()>)> {
    std::fs::create_dir_all(&staging_dir)?;
    let (ctrl_tx, ctrl_rx) = sync_channel::<ControlMsg>(CONTROL_CHANNEL_CAPACITY);
    let handle = std::thread::Builder::new()
        .name("shit-macos-es-capture-pump".to_string())
        .spawn(move || pump(conn, staging_dir, ctrl_rx))?;
    Ok((CaptureControl { tx: ctrl_tx }, handle))
}

// ─────────────────────────────────────────────────────────────────────
// Pump
// ─────────────────────────────────────────────────────────────────────

/// Owns the [`EsClient`] for its lifetime + the staging dir + the
/// conn for daemon emission. The kernel-side tracking state lives in
/// [`PUMP`] (not here) so the kernel callback can read it without a
/// borrow of `self`.
///
/// [`EsClient`]: crate::es::client::EsClient
struct PumpState {
    #[allow(dead_code)] // M03.1.I.4 sends CapturedPreImage via this
    conn: Arc<Conn>,
    staging_dir: PathBuf,
    /// Drop ⇒ es_delete_client. Held for the pump thread's lifetime.
    /// !Send: the EsClient + this PumpState live on the pump thread.
    #[allow(dead_code)]
    client: crate::es::client::EsClient,
    /// Drain side of the ring the kernel callback pushes into.
    ring_rx: Receiver<CaptureRecord>,
}

impl PumpState {
    /// Construct the pump state + install `PUMP` + subscribe ES.
    ///
    /// Must be called on the pump thread (EsClient is `!Send`).
    fn new(
        conn: Arc<Conn>,
        staging_dir: PathBuf,
    ) -> Result<Self, crate::es::client::EsClientError> {
        // Bound the ring at a size that gives the worker a few seconds
        // of headroom at peak rate but back-pressures the kernel
        // callback (which DENYs on Full) before unbounded memory growth.
        // 1024 matches the BSD producer's sizing.
        let (ring_tx, ring_rx) = sync_channel::<CaptureRecord>(1024);

        // Install PUMP exactly once. If a prior pump init left PUMP
        // populated (shouldn't happen — single producer per process),
        // bail rather than silently shadowing.
        let handle = PumpHandle {
            pid_to_token: Mutex::new(HashMap::new()),
            tracked_tokens: Mutex::new(HashMap::new()),
            ring_tx,
            staging_dir: staging_dir.clone(),
            events_seen: AtomicU64::new(0),
            events_passed_filter: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
        };
        if PUMP.set(handle).is_err() {
            tracing::warn!(
                "macos-es PUMP already initialized; this build only supports one ES \
                 producer per process"
            );
        }

        // Subscribe with the producer handler. AUTH_UNLINK is the
        // only AUTH event for I.3 (I.4 adds AUTH_RENAME +
        // AUTH_TRUNCATE + AUTH_WRITE). NOTIFY_EXEC/FORK/EXIT are
        // for tree tracking — they MUST be in the subscription set
        // even though we never respond to them, otherwise the kernel
        // never delivers them.
        let events = [
            sys::es_event_type_t::AUTH_UNLINK,
            sys::es_event_type_t::NOTIFY_EXEC,
            sys::es_event_type_t::NOTIFY_FORK,
            sys::es_event_type_t::NOTIFY_EXIT,
        ];
        let client = unsafe {
            crate::es::client::EsClient::new_with_handler(
                &PRODUCER_HANDLER as *const _ as *const c_void,
                &events,
            )?
        };

        Ok(Self {
            conn,
            staging_dir,
            client,
            ring_rx,
        })
    }

    fn attach(&mut self, command: CommandId, root_path: PathBuf, root_pid: Option<i32>) {
        // Resolve the daemon-supplied root_pid to its audit_token.
        // Two sources, tried in order:
        //
        // 1. pid_to_token (populated by NOTIFY_EXEC). This is the
        //    cheap + correct path for any process that exec'd
        //    AFTER our subscription started.
        // 2. proc_pidinfo(PROC_PIDTBSDINFO) via libproc — fallback
        //    for processes that already existed (e.g. the user's
        //    long-running shell). I.3 ships path 1; path 2 is a
        //    follow-up in I.4 if we discover gaps.
        //
        // Without a token resolved, the watch is essentially a no-op
        // until a tracked child exec's. We accept that for I.3 — the
        // smoke we'll run in I.7 spawns a fresh subprocess as the
        // command runner, which routes through NOTIFY_EXEC.
        let resolved = root_pid.and_then(|pid| {
            let pump = PUMP.get()?;
            let g = pump.pid_to_token.lock().ok()?;
            g.get(&pid).copied()
        });
        match resolved {
            Some(token) => {
                if let Some(pump) = PUMP.get()
                    && let Ok(mut g) = pump.tracked_tokens.lock()
                {
                    g.insert(token, command);
                }
                tracing::info!(
                    %command.session,
                    seq = command.seq,
                    path = %root_path.display(),
                    pid = root_pid.unwrap_or(-1),
                    "macos-es watch attached (audit_token resolved)"
                );
            }
            None => {
                tracing::info!(
                    %command.session,
                    seq = command.seq,
                    path = %root_path.display(),
                    pid = root_pid.unwrap_or(-1),
                    "macos-es watch attached (pid not yet seen via NOTIFY_EXEC; \
                     descendants will be auto-tracked once they exec)"
                );
            }
        }
    }

    fn detach(&mut self, command: CommandId) {
        if let Some(pump) = PUMP.get()
            && let Ok(mut g) = pump.tracked_tokens.lock()
        {
            g.retain(|_, cmd| *cmd != command);
        }
        tracing::info!(
            %command.session,
            seq = command.seq,
            "macos-es watch detached"
        );
    }

    fn drain_ring_once(&mut self) -> bool {
        // I.4 hashes + emits CapturedPreImage from each record.
        // I.3 just drains + logs so the ring doesn't back-pressure
        // the callback into DENY territory during smoke runs.
        match self.ring_rx.try_recv() {
            Ok(rec) => {
                tracing::debug!(
                    path = %rec.path.display(),
                    dev = rec.dev,
                    inode = rec.inode,
                    "macos-es drained capture record (worker emission lands in I.4)"
                );
                if let Some(pump) = PUMP.get() {
                    pump.events_emitted.fetch_add(1, Ordering::Relaxed);
                }
                true
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                tracing::warn!("macos-es ring disconnected; pump exiting");
                false
            }
        }
    }
}

fn pump(conn: Arc<Conn>, staging_dir: PathBuf, ctrl_rx: Receiver<ControlMsg>) {
    let mut state = match PumpState::new(conn, staging_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(err = ?e, "macos-es PumpState init failed; ES producer disabled");
            // Drain the control channel so callers don't see backpressure;
            // FSEvents producer is still active per the coexistence design.
            for msg in ctrl_rx {
                if matches!(msg, ControlMsg::Shutdown) {
                    break;
                }
            }
            return;
        }
    };
    tracing::info!(
        staging = %state.staging_dir.display(),
        "macos-es capture pump started (I.3: tree tracking live; I.4: capture pipeline pending)"
    );

    loop {
        // 1. Control channel first (low latency for attach/detach).
        match ctrl_rx.try_recv() {
            Ok(ControlMsg::Attach { command, root_path }) => {
                // I.3 has no root_pid plumbing yet — that lands in I.5
                // when main.rs forwards the daemon's WatchTree.root_pid
                // through. For now we pass None and rely on NOTIFY_FORK
                // auto-add to populate the tracked set as descendants
                // exec under whatever shell the smoke launches.
                state.attach(command, root_path, None);
                continue;
            }
            Ok(ControlMsg::Detach { command }) => {
                state.detach(command);
                continue;
            }
            Ok(ControlMsg::Shutdown) => {
                tracing::info!("macos-es capture pump shutdown requested");
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                tracing::info!("macos-es control channel closed; pump exiting");
                return;
            }
        }

        // 2. Drain the kernel-callback → pump ring. If a record was
        //    available, loop again immediately (avoid the idle sleep)
        //    to keep up with bursts.
        if state.drain_ring_once() {
            continue;
        }

        // 3. Idle.
        std::thread::sleep(PUMP_IDLE_SLEEP);
    }
}

// Drop ordering: pump returns → PumpState dropped → EsClient::drop →
// es_delete_client. PUMP stays populated (OnceLock can't reset) but
// the callback no longer fires because ES torn down its delivery loop.
