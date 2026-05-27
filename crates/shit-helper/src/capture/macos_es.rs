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
// alongside the FSEvents producer. Sub-slices I.3 and I.4 fill in
// real logic before that; the allow comes off in I.5.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use shit_planner::events::CommandId;
use uuid::Uuid;

use crate::ipc::Conn;

/// Channel capacity for control messages from the request loop.
/// Mirrors `capture::bsd`'s sizing.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Pump idle-sleep when both the control channel and the
/// (M03.1.I.4) ring report Empty.
const PUMP_IDLE_SLEEP: Duration = Duration::from_millis(50);

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
// Pump — scaffold
// ─────────────────────────────────────────────────────────────────────

/// Stage 1 (M03.1.I.2): empty placeholder. M03.1.I.3 fills in:
/// - `tracked_tokens: HashMap<audit_token_t, CommandId>`
/// - `tracked_cwds: HashMap<CommandId, PathBuf>`
/// - reference to the static `PUMP` slot the kernel callback reads
struct PumpState {
    #[allow(dead_code)] // M03.1.I.4 sends CapturedPreImage via this
    conn: Arc<Conn>,
    #[allow(dead_code)] // M03.1.I.4 writes clonefile here
    staging_dir: PathBuf,
}

impl PumpState {
    fn new(conn: Arc<Conn>, staging_dir: PathBuf) -> Self {
        Self { conn, staging_dir }
    }

    fn attach(&mut self, command: CommandId, root_path: PathBuf) {
        // M03.1.I.3 — resolves root_pid (forwarded by request loop)
        // to its audit_token via NOTIFY_EXEC observation OR libproc,
        // then inserts into tracked_tokens + tracked_cwds.
        tracing::info!(
            %command.session,
            seq = command.seq,
            path = %root_path.display(),
            "macos-es watch attached (scaffold — no real tracking yet)"
        );
    }

    fn detach(&mut self, command: CommandId) {
        tracing::info!(
            %command.session,
            seq = command.seq,
            "macos-es watch detached (scaffold)"
        );
    }
}

fn pump(conn: Arc<Conn>, staging_dir: PathBuf, ctrl_rx: Receiver<ControlMsg>) {
    let mut state = PumpState::new(conn, staging_dir);
    tracing::info!("macos-es capture pump started (scaffold; M03.1.I.3+ adds tracking + capture)");
    loop {
        // 1. Control channel first (low latency for attach/detach).
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
                tracing::info!("macos-es capture pump shutdown requested");
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                tracing::info!("macos-es control channel closed; pump exiting");
                return;
            }
        }

        // 2. M03.1.I.4 — drain the kernel-callback → pump ring here.

        // 3. Idle.
        std::thread::sleep(PUMP_IDLE_SLEEP);
    }
}
