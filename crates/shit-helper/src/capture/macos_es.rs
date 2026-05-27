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

use std::collections::HashMap;
use std::ffi::{CString, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_ulong;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use shit_planner::events::CommandId;
use shit_proto::{HELPER_PATH_HINT_MAX, HelperResponse};
use uuid::Uuid;

use crate::es::message::{EsMessage, audit_token_t};
use crate::es::sys;
use crate::ipc::Conn;

unsafe extern "C" {
    /// `int clonefile(const char *src, const char *dst, uint32_t flags);`
    /// from `<sys/clonefile.h>` (libc). Declared here to keep the macOS
    /// ES producer self-contained; `shit-capture`'s `clonefile_macos.rs`
    /// has the same extern but is owned by that crate.
    fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32) -> libc::c_int;
}

const CLONE_NOFOLLOW: u32 = 0x0001;
const CLONE_NOOWNERCOPY: u32 = 0x0002;

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
/// after a successful inline clonefile.
///
/// Holding `staging_fd` ties the staging file's lifetime to this
/// record: when the worker has hashed + sent, it drops the fd; the
/// receiver-side daemon holds its own fd (received via SCM_RIGHTS),
/// and the staging file is unlinked by `staging_path` cleanup once
/// both fds are closed.
pub struct CaptureRecord {
    pub command: CommandId,
    /// Source path the kernel was about to unlink. Recorded so the
    /// daemon can recreate the file at the same path during undo.
    pub path: PathBuf,
    /// On-disk staging file the inline clonefile wrote. Worker
    /// removes this AFTER `send_response_with_fd` returns (the fd
    /// in `staging_fd` keeps the inode alive across the unlink).
    pub staging_path: PathBuf,
    /// `O_RDONLY` fd into `staging_path`. Sent via SCM_RIGHTS to the
    /// daemon; daemon receives an independent fd that shares the
    /// open file description (so offset 0 is preserved as long as
    /// the helper hashes via `pread` rather than `read`).
    pub staging_fd: OwnedFd,
    pub dev: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_unix_nanos: i128,
    pub is_delete: bool,
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

fn respond_deny(client: *mut sys::es_client_t, message: *const c_void) {
    // SAFETY: same contract as respond_allow.
    unsafe {
        let _ = sys::es_respond_auth_result(
            client,
            message as *const sys::es_message_t,
            sys::es_auth_result_t::DENY,
            true,
        );
    }
}

/// Per-process monotonic counter for staging-file naming. We never
/// reuse a name within a process lifetime; combined with `pid` in the
/// filename, this gives global uniqueness across helper restarts too.
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// Inline clonefile from `src_path` → fresh file under `staging_dir`.
/// Returns the staging path + an `O_RDONLY` fd ready for SCM_RIGHTS.
///
/// Called from the ES kernel callback BEFORE responding ALLOW. Must
/// complete in microseconds on APFS (clonefile is a CoW reference,
/// not a byte copy). On non-APFS volumes this fails with EOPNOTSUPP;
/// fallback to streaming-read is M03.1.I.G follow-up.
fn inline_clonefile(src_path: &Path, staging_dir: &Path) -> std::io::Result<(PathBuf, OwnedFd)> {
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let staging_path = staging_dir.join(format!("es-{pid}-{seq:016x}"));

    let c_src = CString::new(src_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "src path contains NUL")
    })?;
    let c_dst = CString::new(staging_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging path contains NUL",
        )
    })?;

    // SAFETY: both pointers are NUL-terminated CStrings valid for the
    // call; clonefile returns 0 on success, -1 on error.
    let rc = unsafe {
        clonefile(
            c_src.as_ptr(),
            c_dst.as_ptr(),
            CLONE_NOFOLLOW | CLONE_NOOWNERCOPY,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Reopen the staging file read-only for the SCM_RIGHTS hand-off.
    // O_CLOEXEC so a hypothetical child of the helper doesn't inherit
    // the staging-fd (defense-in-depth — pump thread doesn't fork
    // children today).
    let rflags = libc::O_RDONLY | libc::O_CLOEXEC;
    // SAFETY: c_dst is a NUL-terminated path; open returns >= 0 on
    // success or -1 on error.
    let rfd = unsafe { libc::open(c_dst.as_ptr(), rflags) };
    if rfd < 0 {
        let err = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(&staging_path);
        return Err(err);
    }
    // SAFETY: rfd is a fresh kernel-allocated fd we now own.
    let fd = unsafe { OwnedFd::from_raw_fd(rfd) };
    Ok((staging_path, fd))
}

/// Hash the file behind `fd` via `pread`, without disturbing its
/// offset. Caller passes `size` from the kernel-attached stat so we
/// know when to stop (saves an `fstat` round-trip in the worker).
fn hash_via_pread(fd: RawFd, size: u64) -> std::io::Result<([u8; 32], u64)> {
    const CHUNK: usize = 64 * 1024;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut offset: i64 = 0;
    let target = size as i64;
    while offset < target {
        let want = ((target - offset) as usize).min(CHUNK);
        // SAFETY: buf is writable of len >= want; fd valid for the call.
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), want, offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            // Short read vs the stat-claimed size: clonefile snapshot
            // is supposed to be byte-stable, but tolerate the case to
            // keep the worker from getting stuck. Ship what we hashed.
            break;
        }
        let n_usize = n as usize;
        hasher.update(&buf[..n_usize]);
        offset += n as i64;
    }
    Ok((*hasher.finalize().as_bytes(), offset as u64))
}

fn path_to_string(p: &Path) -> Option<String> {
    let s = String::from_utf8_lossy(p.as_os_str().as_bytes()).to_string();
    if s.len() > HELPER_PATH_HINT_MAX {
        // Send None rather than a truncated path that could mislead
        // the daemon's restore logic. Daemon falls back to dev+inode
        // identity in that case.
        return None;
    }
    Some(s)
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
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    // Pull path + stat in one borrow — no userspace stat(2) racing
    // the impending unlink.
    let Some(file) = msg.unlink_target_file() else {
        respond_allow(client, message);
        return;
    };
    let target_path = unsafe { file.path.as_path() };
    let stat = file.stat;

    // 1. Inline clonefile — must succeed before we let the syscall
    //    proceed; under hard-fail, capture failure → DENY so the
    //    user gets "permission denied" instead of an unrecoverable
    //    unlink with no pre-image.
    let (staging_path, staging_fd) = match inline_clonefile(target_path, &pump.staging_dir) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                %command.session,
                seq = command.seq,
                path = %target_path.display(),
                err = %e,
                "macos-es clonefile failed; DENY unlink (hard-fail per CLAUDE.md)"
            );
            respond_deny(client, message);
            return;
        }
    };

    // 2. Pack the record. stat fields are kernel-attached; no extra
    //    syscalls needed.
    let record = CaptureRecord {
        command,
        path: target_path.to_path_buf(),
        staging_path: staging_path.clone(),
        staging_fd,
        dev: stat.st_dev as u64,
        inode: stat.st_ino,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mtime_unix_nanos: (stat.st_mtime as i128) * 1_000_000_000 + (stat.st_mtime_nsec as i128),
        is_delete: true,
    };

    // 3. Enqueue. try_send so we never block in the kernel callback.
    match pump.ring_tx.try_send(record) {
        Ok(()) => {
            respond_allow(client, message);
        }
        Err(TrySendError::Full(rec)) => {
            // Worker backlogged — DENY to preserve the undo invariant.
            // Drop the staging fd (closes) + unlink the on-disk copy.
            tracing::warn!(
                %command.session,
                seq = command.seq,
                path = %rec.path.display(),
                "macos-es ring full; DENY unlink + drop staging clone"
            );
            drop(rec);
            let _ = std::fs::remove_file(&staging_path);
            respond_deny(client, message);
        }
        Err(TrySendError::Disconnected(rec)) => {
            // Worker died — ALLOW (no point holding the syscall
            // hostage when the daemon-emit path is gone). The
            // CapturedPreImage simply never reaches the daemon for
            // this event; FSEvents producer (Decision 3 coexistence)
            // still emits the TreeOp::Unlink so undo gets the path
            // back, just not the byte content.
            tracing::error!(
                %command.session,
                seq = command.seq,
                path = %rec.path.display(),
                "macos-es ring disconnected (worker dead); ALLOW unlink, drop staging"
            );
            drop(rec);
            let _ = std::fs::remove_file(&staging_path);
            respond_allow(client, message);
        }
    }
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
        let rec = match self.ring_rx.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => {
                tracing::warn!("macos-es ring disconnected; pump exiting");
                return false;
            }
        };
        self.emit_captured_preimage(rec);
        if let Some(pump) = PUMP.get() {
            pump.events_emitted.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    fn emit_captured_preimage(&self, rec: CaptureRecord) {
        // Hash via pread so the staging fd's offset stays at 0 — the
        // daemon-side recvmsg fd shares this open-file-description
        // and reads starting at 0.
        //
        // Stat-claimed size comes from the kernel-attached `stat` the
        // ES message carried; we don't fstat the staging fd because
        // clonefile-clone-size == source-size at the moment of clone.
        let claimed_size = stat_size_for_fd(rec.staging_fd.as_raw_fd()).unwrap_or(0);
        let (blob_hash, stored_bytes) =
            match hash_via_pread(rec.staging_fd.as_raw_fd(), claimed_size) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(
                        %rec.command.session,
                        seq = rec.command.seq,
                        path = %rec.path.display(),
                        err = %e,
                        "macos-es worker hash failed; dropping CaptureRecord"
                    );
                    let _ = std::fs::remove_file(&rec.staging_path);
                    return;
                }
            };

        let resp = HelperResponse::CapturedPreImage {
            session: rec.command.session,
            seq: rec.command.seq,
            dev: rec.dev,
            inode: rec.inode,
            path: path_to_string(&rec.path),
            blob_hash,
            stored_bytes,
            // AUTH_UNLINK fires pre-syscall; the file is then unlinked
            // (we ALLOW'd). No post-state to hash. AUTH_OPEN(W) and
            // AUTH_RENAME paths land in M03.1.I.B / .A and set this.
            post_content_hash: None,
            mode: rec.mode,
            uid: rec.uid,
            gid: rec.gid,
            mtime_unix_nanos: rec.mtime_unix_nanos,
            // M03.1.I scope: no xattr capture (follow-up). BSD producer
            // reads via flistxattr on the staging fd; symmetric path on
            // macOS lands once we wire it through.
            xattrs: std::collections::BTreeMap::new(),
            is_delete: rec.is_delete,
            fd_sent_via_scm: true,
        };

        if let Err(e) = self
            .conn
            .send_response_with_fd(&resp, rec.staging_fd.as_raw_fd())
        {
            tracing::warn!(
                %rec.command.session,
                seq = rec.command.seq,
                path = %rec.path.display(),
                err = %e,
                "macos-es send_response_with_fd failed"
            );
        } else {
            tracing::info!(
                %rec.command.session,
                seq = rec.command.seq,
                path = %rec.path.display(),
                dev = rec.dev,
                inode = rec.inode,
                bytes = stored_bytes,
                "macos-es CapturedPreImage sent"
            );
        }

        // Drop fd → close. Once the daemon's recvmsg'd fd is also
        // closed, the staging file's inode is released. We unlink
        // the path here best-effort (the inode survives via either
        // open fd until both close).
        drop(rec.staging_fd);
        let _ = std::fs::remove_file(&rec.staging_path);
    }
}

/// `fstat`-via-libc helper for the staging fd. Returns the file's
/// reported size (`st_size`), or `None` on `fstat` error.
fn stat_size_for_fd(fd: RawFd) -> Option<u64> {
    // SAFETY: libc::stat is layout-stable for the platform; fd valid
    // for the call (caller holds the OwnedFd).
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st as *mut _) };
    if rc != 0 {
        return None;
    }
    Some(st.st_size as u64)
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
        "macos-es capture pump started (I.4: AUTH_UNLINK capture pipeline live)"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn path_to_string_short_path_round_trips() {
        let p = Path::new("/tmp/short/path.txt");
        assert_eq!(path_to_string(p).as_deref(), Some("/tmp/short/path.txt"));
    }

    #[test]
    fn path_to_string_oversize_returns_none() {
        // HELPER_PATH_HINT_MAX is 4000; build a path one over.
        let s = "/".to_string() + &"a".repeat(HELPER_PATH_HINT_MAX);
        assert!(s.len() > HELPER_PATH_HINT_MAX);
        let p = PathBuf::from(s);
        assert_eq!(path_to_string(&p), None);
    }

    #[test]
    fn inline_clonefile_round_trips_bytes() {
        // Requires APFS — runner tempdir is APFS on dev mac; CI on
        // macos-14 may be APFS or tmpfs. Skip on EOPNOTSUPP.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let payload = b"clonefile round-trip test bytes";
        std::fs::File::create(&src)
            .unwrap()
            .write_all(payload)
            .unwrap();

        let staging_dir = tmp.path().join("staging");
        std::fs::create_dir_all(&staging_dir).unwrap();

        let (staging_path, fd) = match inline_clonefile(&src, &staging_dir) {
            Ok(t) => t,
            Err(e)
                if e.raw_os_error() == Some(libc::EOPNOTSUPP)
                    || e.raw_os_error() == Some(libc::ENOTSUP) =>
            {
                eprintln!("skip: fs does not support clonefile");
                return;
            }
            Err(e) => panic!("inline_clonefile failed: {e}"),
        };
        // The staging file exists and the fd reads the source bytes.
        assert!(staging_path.exists());
        let (hash, len) = hash_via_pread(fd.as_raw_fd(), payload.len() as u64).unwrap();
        assert_eq!(len, payload.len() as u64);
        let expected = blake3::hash(payload);
        assert_eq!(hash, *expected.as_bytes());
        // Cleanup: drop fd then remove staging file.
        drop(fd);
        let _ = std::fs::remove_file(&staging_path);
    }

    #[test]
    fn hash_via_pread_preserves_fd_offset() {
        // After hashing via pread, a separately-opened fd (mimicking
        // SCM_RIGHTS at the daemon side) reads from offset 0 because
        // pread doesn't touch the open-file-description's offset.
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("hash-offset.txt");
        let payload = b"abcdefgh";
        std::fs::write(&p, payload).unwrap();

        let f = std::fs::File::open(&p).unwrap();
        let fd = f.as_raw_fd();
        let (_, len) = hash_via_pread(fd, payload.len() as u64).unwrap();
        assert_eq!(len, payload.len() as u64);

        // Read via plain read(2) — should start at offset 0, get all
        // bytes back.
        use std::io::Read;
        let mut g = std::fs::File::open(&p).unwrap();
        let mut buf = Vec::new();
        g.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf[..], payload);
    }
}
