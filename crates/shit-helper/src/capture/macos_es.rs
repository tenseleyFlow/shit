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
//! - M03.1.I.2: scaffold — ControlMsg, CaptureControl, spawn + pump
//!   shell. No event handling yet.
//! - M03.1.I.3: PumpState carries tracked-pid map; ES callback does
//!   the pid filter + NOTIFY_FORK auto-add + NOTIFY_EXIT prune.
//! - M03.1.I.4: AUTH_UNLINK clonefile capture + worker emission via
//!   SCM_RIGHTS staging fd.
//! - M03.1.I.5: main.rs spawns this alongside FSEvents producer.
//! - M03.1.I.6: handshake reports `endpoint-security` when this is
//!   the active tier.
//! - M03.1.I.7: VM smoke covering PreExec → mutate → CapturedPreImage
//!   → undo cycle.
//!
//! ## Pid-keyed tracking (M03.1.I.7 finding)
//!
//! The filter is keyed on PID, not full `audit_token_t`. During I.7
//! bring-up we observed that the kernel-attached `audit_token` differs
//! between `NOTIFY_EXEC` (post-exec snapshot) and the immediately-
//! following `AUTH_UNLINK` for the SAME process — typically by a +1
//! bump of `val[7]` (pidversion). The mechanism appears to be some
//! mid-process kernel transition we don't yet fully model. Using
//! pid as the lookup key (with `audit_token` cached for diagnostics)
//! sidesteps this entirely; NOTIFY_EXIT prunes the entry on
//! termination so subsequent pid reuse can't false-match.
//
// Module-level gate is at `crates/shit-helper/src/capture/mod.rs`; no
// inner `#![cfg]` here (rustc's `duplicated_attributes` lint flags
// the dup under `-D warnings`).

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

use crate::es::message::{EsMessage, audit_token_for_pid, audit_token_t};
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
// - tracked_pids (filter AUTH events)
// - ring_tx (push CaptureRecord on AUTH match)
// - staging_dir (clonefile destination)
//
// Pump thread writes:
// - on ControlMsg::Attach: inserts (root_pid, CommandId) into
//   tracked_pids; opportunistically populates pid_to_token via
//   Mach for diagnostic visibility
// - on ControlMsg::Detach: removes the CommandId's entry
//
// Callback also writes:
// - NOTIFY_EXEC: refreshes pid_to_token (debug only)
// - NOTIFY_FORK: if parent's pid in tracked, inserts child pid
// - NOTIFY_EXIT: prunes both maps for the dying pid
//
// Single-shared because the helper only runs one producer at a time.

/// State the ES callback reads + writes. Initialized exactly once
/// by [`pump`] at startup via [`PUMP`].
pub struct PumpHandle {
    /// pid → most-recently-observed audit_token. Diagnostic +
    /// debugging aid; the filter no longer uses this since
    /// `audit_token_t` proved unstable across exec/unlink even for
    /// the same process (pidversion drift discovered M03.1.I.7).
    pub pid_to_token: Mutex<HashMap<i32, audit_token_t>>,
    /// pid → CommandId map. ALL AUTH events filter on this. We use
    /// pid (not audit_token) because Apple's pidversion field in
    /// `audit_token_t` increments mid-process unexpectedly, so the
    /// post-exec NOTIFY_EXEC and the subsequent AUTH_UNLINK from the
    /// SAME process can carry different audit_tokens. Pid is the
    /// stable identifier within a process's lifetime; NOTIFY_EXIT
    /// prunes the entry so pid reuse never confuses us.
    pub tracked_pids: Mutex<HashMap<i32, CommandId>>,
    /// Per-command (dev, inode) dedup for AUTH_OPEN(W). Real-world
    /// commands open the same file many times (compiler reads a
    /// header repeatedly under -j); clonefile-on-first-open is
    /// sufficient — subsequent opens use the cached PreImage. The
    /// daemon's restore path is keyed on (dev, inode) so emitting
    /// duplicates would be harmless but wasteful.
    pub open_dedup: Mutex<HashMap<(CommandId, u64, u64), ()>>,
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

/// CaptureRecord — what the callback queues for the pump worker.
///
/// Two variants:
/// - `PreImage`: AUTH_UNLINK or AUTH_RENAME-overwrite — carries a
///   staging fd from the inline clonefile. Worker hashes + emits
///   `HelperResponse::CapturedPreImage` via SCM_RIGHTS.
/// - `TreeOp`: AUTH_RENAME or any future tree-only event — no fd,
///   no clonefile. Worker emits `HelperResponse::TreeMutation`.
///
/// A single AUTH_RENAME of an existing file generates BOTH variants:
/// PreImage for the destination's pre-mutation bytes, TreeOp for the
/// rename itself.
pub enum CaptureRecord {
    PreImage(PreImageRecord),
    TreeOp(TreeOpRecord),
}

pub struct PreImageRecord {
    pub command: CommandId,
    /// Path of the file whose bytes we're capturing (UNLINK target
    /// or RENAME destination).
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
    /// True for UNLINK + RENAME-overwrite (the file at `path` is
    /// gone post-syscall, replaced by the rename source's bytes or
    /// removed entirely). Daemon uses this to journal a paired
    /// TreeOp::Unlink for the inverse-during-undo flow.
    pub is_delete: bool,
}

pub struct TreeOpRecord {
    pub command: CommandId,
    pub op: shit_proto::TreeOpWire,
    pub ts_unix_nanos: u64,
}

// ─────────────────────────────────────────────────────────────────────
// Producer handler — global Block invoked by the ES kernel callback
// ─────────────────────────────────────────────────────────────────────
//
// Four event types delivered:
// - NOTIFY_EXEC: refresh pid_to_token (diagnostic only — the
//   tracked-pid set survives exec automatically since pid is stable)
// - NOTIFY_FORK: propagate tracked status to child (parent's pid in
//   tracked_pids → child pid inherits the CommandId)
// - NOTIFY_EXIT: prune both maps for the dying pid
// - AUTH_UNLINK: if process pid in tracked_pids, inline-clonefile +
//   enqueue CaptureRecord + respond ALLOW; if ring full, DENY (the
//   undo invariant trumps the syscall's success). Untracked: ALLOW
//   immediately.

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
    } else if event_type == sys::es_event_type_t::AUTH_RENAME {
        handle_auth_rename(pump, client, message, &msg);
    } else if event_type == sys::es_event_type_t::AUTH_TRUNCATE {
        handle_auth_truncate(pump, client, message, &msg);
    } else if event_type == sys::es_event_type_t::AUTH_OPEN {
        handle_auth_open(pump, client, message, &msg);
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

/// AUTH_OPEN uses a different responder than the other AUTH events:
/// `es_respond_flags_result(authorized_flags=fflag)` means "allow the
/// open with exactly the access modes requested". Passing the
/// original `fflag` is the equivalent of "ALLOW" for the flag-based
/// response API. Passing `0` would deny everything.
fn respond_allow_open_flags(client: *mut sys::es_client_t, message: *const c_void, fflag: u32) {
    // SAFETY: same kernel-callback contract.
    unsafe {
        let _ =
            sys::es_respond_flags_result(client, message as *const sys::es_message_t, fflag, true);
    }
}

fn respond_deny_open_flags(client: *mut sys::es_client_t, message: *const c_void) {
    // SAFETY: same kernel-callback contract.
    unsafe {
        let _ = sys::es_respond_flags_result(client, message as *const sys::es_message_t, 0, true);
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
    // Refresh pid → audit_token (debug aid only since the filter
    // now uses pid). Tracked status, if any, is keyed by pid and
    // survives exec automatically.
    let new_token = msg.process_audit_token();
    let pid = pid_from_audit_token(&new_token);
    if let Ok(mut g) = pump.pid_to_token.lock() {
        g.insert(pid, new_token);
    }
}

fn handle_notify_fork(pump: &PumpHandle, msg: &EsMessage<'_>) {
    let parent_token = msg.process_audit_token();
    let parent_pid = pid_from_audit_token(&parent_token);
    let inherit = match pump.tracked_pids.lock() {
        Ok(g) => g.get(&parent_pid).copied(),
        Err(_) => return,
    };
    if let Some(command) = inherit
        && let Some(child_token) = msg.fork_child_audit_token()
    {
        let child_pid = pid_from_audit_token(&child_token);
        if let Ok(mut g) = pump.tracked_pids.lock() {
            g.insert(child_pid, command);
        }
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
    if let Ok(mut g) = pump.tracked_pids.lock() {
        g.remove(&pid);
    }
}

fn handle_auth_unlink(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let token = msg.process_audit_token();
    let pid = pid_from_audit_token(&token);
    let command = match pump.tracked_pids.lock() {
        Ok(g) => g.get(&pid).copied(),
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
    let record = CaptureRecord::PreImage(PreImageRecord {
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
    });

    enqueue_capture_record(pump, client, message, record, Some(&staging_path));
}

/// AUTH_TRUNCATE handler. Captures the file's pre-truncate bytes via
/// inline clonefile. Structurally identical to UNLINK except is_delete
/// is false — the path still exists post-syscall, just with 0 bytes.
/// Daemon journals FilePreImage without a paired TreeOp::Unlink, so
/// undo restores the bytes to the same path.
fn handle_auth_truncate(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let token = msg.process_audit_token();
    let pid = pid_from_audit_token(&token);
    let command = match pump.tracked_pids.lock() {
        Ok(g) => g.get(&pid).copied(),
        Err(_) => None,
    };
    let Some(command) = command else {
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let Some(file) = msg.truncate_target_file() else {
        respond_allow(client, message);
        return;
    };
    let target_path = unsafe { file.path.as_path() };
    let stat = file.stat;

    let (staging_path, staging_fd) = match inline_clonefile(target_path, &pump.staging_dir) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                %command.session,
                seq = command.seq,
                path = %target_path.display(),
                err = %e,
                "macos-es truncate clone failed; DENY truncate"
            );
            respond_deny(client, message);
            return;
        }
    };

    let record = CaptureRecord::PreImage(PreImageRecord {
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
        // The path still exists after the syscall; we just need to
        // restore its bytes during undo. No TreeOp::Unlink pairing.
        is_delete: false,
    });
    enqueue_capture_record(pump, client, message, record, Some(&staging_path));
}

/// Kernel `FFLAGS` write-intent bits. From `<sys/fcntl.h>`:
/// FREAD=0x01, FWRITE=0x02. FAPPEND (0x08) implies write but
/// post-pends; the original bytes survive an append, so we don't
/// need a pre-image just for FAPPEND — only when the file would be
/// modified destructively (FWRITE without O_APPEND, OR FWRITE with
/// the O_TRUNC bit which arrives as AUTH_TRUNCATE separately).
///
/// In practice every fopen("w") sets FWRITE (and O_TRUNC, which
/// fires AUTH_TRUNCATE separately). fopen("r+") sets FWRITE without
/// truncation — that's the path where AUTH_OPEN(W) capture is the
/// ONLY source for the pre-image (no AUTH_TRUNCATE follow-up).
const FFLAG_FWRITE: i32 = 0x02;

/// AUTH_OPEN handler. Filters for write-intent (FWRITE bit); on
/// match, inline-clonefile the pre-write bytes (per-command dedup
/// so repeated opens of the same inode are free after the first).
/// Pure read-opens pass through with no work.
///
/// Response API is `es_respond_flags_result` (unique to AUTH_OPEN);
/// `authorized_flags = fflag` is the equivalent of ALLOW.
fn handle_auth_open(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let Some(event) = msg.as_open() else {
        respond_allow_open_flags(client, message, 0xFFFFFFFF);
        return;
    };
    let fflag = event.fflag;

    // Read-only opens: nothing to capture, fast-path ALLOW.
    if fflag & FFLAG_FWRITE == 0 {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    }

    let token = msg.process_audit_token();
    let pid = pid_from_audit_token(&token);
    let command = match pump.tracked_pids.lock() {
        Ok(g) => g.get(&pid).copied(),
        Err(_) => None,
    };
    let Some(command) = command else {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    if event.file.is_null() {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    }
    let file = unsafe { &*event.file };
    let target_path = unsafe { file.path.as_path() };
    let stat = file.stat;
    let key = (command, stat.st_dev as u64, stat.st_ino);

    // Per-command (dev, inode) dedup. First write-open captures; the
    // rest are free.
    let first_time = match pump.open_dedup.lock() {
        Ok(mut g) => g.insert(key, ()).is_none(),
        Err(_) => true,
    };
    if !first_time {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    }

    // Skip files of size 0 — there's nothing to preserve. Saves a
    // clonefile syscall + a wasted CapturedPreImage event for the
    // common "create a new file" path (touch, > newfile).
    if stat.st_size == 0 {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    }

    let (staging_path, staging_fd) = match inline_clonefile(target_path, &pump.staging_dir) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                %command.session,
                seq = command.seq,
                path = %target_path.display(),
                err = %e,
                "macos-es open-write clone failed; DENY open"
            );
            respond_deny_open_flags(client, message);
            return;
        }
    };

    let record = CaptureRecord::PreImage(PreImageRecord {
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
        // The path survives post-open; we just captured the pre-write
        // bytes. Undo restores the bytes; no TreeOp::Unlink needed.
        is_delete: false,
    });

    // Enqueue + respond. We can't use the shared `enqueue_capture_record`
    // helper because the AUTH_OPEN responder is flags-based, not
    // auth-result-based. Inline the same try_send semantics.
    match pump.ring_tx.try_send(record) {
        Ok(()) => respond_allow_open_flags(client, message, fflag as u32),
        Err(TrySendError::Full(rec)) => {
            if let CaptureRecord::PreImage(p) = rec {
                drop(p.staging_fd);
                let _ = std::fs::remove_file(&p.staging_path);
            }
            tracing::warn!("macos-es open-write ring full; DENY open");
            respond_deny_open_flags(client, message);
        }
        Err(TrySendError::Disconnected(rec)) => {
            if let CaptureRecord::PreImage(p) = rec {
                drop(p.staging_fd);
                let _ = std::fs::remove_file(&p.staging_path);
            }
            tracing::error!("macos-es open-write ring disconnected (worker dead); ALLOW open");
            respond_allow_open_flags(client, message, fflag as u32);
        }
    }
}

/// AUTH_RENAME handler. Always emits TreeMutation(Rename); also emits
/// CapturedPreImage for the destination's pre-rename bytes when the
/// destination is an existing file (rename overwrites it, losing
/// the dst's prior content).
fn handle_auth_rename(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let token = msg.process_audit_token();
    let pid = pid_from_audit_token(&token);
    let command = match pump.tracked_pids.lock() {
        Ok(g) => g.get(&pid).copied(),
        Err(_) => None,
    };
    let Some(command) = command else {
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let Some(rename) = msg.as_rename() else {
        respond_allow(client, message);
        return;
    };
    if rename.source.is_null() {
        respond_allow(client, message);
        return;
    }
    let source_file = unsafe { &*rename.source };
    let source_path = unsafe { source_file.path.as_path() }.to_path_buf();
    let source_stat = source_file.stat;

    // Resolve destination path + (if pre-existing) its file pointer
    // for the dst-clone step. The `unsafe` blocks read tagged-union
    // variants — guarded by `destination_type`.
    let (dest_path, dest_existing) = match rename.destination_type {
        crate::es::message::es_destination_type_t::EXISTING_FILE => unsafe {
            let dest_ptr = rename.destination.existing_file;
            if dest_ptr.is_null() {
                (PathBuf::new(), None)
            } else {
                let f = &*dest_ptr;
                (f.path.as_path().to_path_buf(), Some(f))
            }
        },
        crate::es::message::es_destination_type_t::NEW_PATH => unsafe {
            let np = &*rename.destination.new_path;
            if np.dir.is_null() {
                (PathBuf::new(), None)
            } else {
                let dir_path = (*np.dir).path.as_path();
                let filename = np.filename.as_bytes();
                (
                    dir_path.join(std::path::Path::new(std::ffi::OsStr::from_bytes(filename))),
                    None,
                )
            }
        },
        _ => (PathBuf::new(), None),
    };

    let ts_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // If destination pre-exists, capture its bytes BEFORE letting
    // the rename proceed (rename overwrites destination atomically).
    if let Some(dest_file) = dest_existing {
        let (staging_path, staging_fd) = match inline_clonefile(&dest_path, &pump.staging_dir) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    %command.session,
                    seq = command.seq,
                    dest = %dest_path.display(),
                    err = %e,
                    "macos-es rename dst-clone failed; DENY rename"
                );
                respond_deny(client, message);
                return;
            }
        };
        let dest_stat = dest_file.stat;
        let record = CaptureRecord::PreImage(PreImageRecord {
            command,
            path: dest_path.clone(),
            staging_path: staging_path.clone(),
            staging_fd,
            dev: dest_stat.st_dev as u64,
            inode: dest_stat.st_ino,
            mode: dest_stat.st_mode as u32,
            uid: dest_stat.st_uid,
            gid: dest_stat.st_gid,
            mtime_unix_nanos: (dest_stat.st_mtime as i128) * 1_000_000_000
                + (dest_stat.st_mtime_nsec as i128),
            is_delete: true,
        });
        // try_send the PreImage half; on failure short-circuit so we
        // don't enqueue an orphaned tree-op without its pre-image.
        match pump.ring_tx.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(rec)) => {
                if let CaptureRecord::PreImage(p) = rec {
                    drop(p.staging_fd);
                    let _ = std::fs::remove_file(&p.staging_path);
                }
                tracing::warn!(
                    %command.session,
                    seq = command.seq,
                    "macos-es ring full during rename dst capture; DENY"
                );
                respond_deny(client, message);
                return;
            }
            Err(TrySendError::Disconnected(rec)) => {
                if let CaptureRecord::PreImage(p) = rec {
                    drop(p.staging_fd);
                    let _ = std::fs::remove_file(&p.staging_path);
                }
                respond_allow(client, message);
                return;
            }
        }
    }

    // Always emit TreeMutation(Rename) so undo can invert the
    // namespace shift. dev/inode come from source (the renamed file).
    let tree_record = CaptureRecord::TreeOp(TreeOpRecord {
        command,
        op: shit_proto::TreeOpWire::Rename {
            from: path_to_string(&source_path).unwrap_or_default(),
            to: path_to_string(&dest_path).unwrap_or_default(),
            dev: source_stat.st_dev as u64,
            inode: source_stat.st_ino,
        },
        ts_unix_nanos,
    });
    enqueue_capture_record(pump, client, message, tree_record, None);
}

fn enqueue_capture_record(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    record: CaptureRecord,
    staging_to_cleanup: Option<&Path>,
) {
    match pump.ring_tx.try_send(record) {
        Ok(()) => respond_allow(client, message),
        Err(TrySendError::Full(rec)) => {
            cleanup_dropped_record(rec, staging_to_cleanup);
            tracing::warn!("macos-es ring full; DENY syscall");
            respond_deny(client, message);
        }
        Err(TrySendError::Disconnected(rec)) => {
            cleanup_dropped_record(rec, staging_to_cleanup);
            tracing::error!("macos-es ring disconnected (worker dead); ALLOW syscall");
            respond_allow(client, message);
        }
    }
}

fn cleanup_dropped_record(rec: CaptureRecord, fallback_path: Option<&Path>) {
    match rec {
        CaptureRecord::PreImage(p) => {
            drop(p.staging_fd);
            let _ = std::fs::remove_file(&p.staging_path);
        }
        CaptureRecord::TreeOp(_) => {
            if let Some(p) = fallback_path {
                let _ = std::fs::remove_file(p);
            }
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
        /// Daemon-supplied pid of the process the shell hook ran in.
        /// Used to resolve the audit_token via [`PumpHandle::pid_to_token`]
        /// (populated by NOTIFY_EXEC from helper-startup forward).
        root_pid: i32,
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
    pub fn on_watch_tree(&self, session: Uuid, command_seq: u64, root_pid: u32, cwd_path: &str) {
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
            root_pid: root_pid as i32,
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
            tracked_pids: Mutex::new(HashMap::new()),
            open_dedup: Mutex::new(HashMap::new()),
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
            sys::es_event_type_t::AUTH_OPEN,
            sys::es_event_type_t::AUTH_UNLINK,
            sys::es_event_type_t::AUTH_RENAME,
            sys::es_event_type_t::AUTH_TRUNCATE,
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

        // M03.1.I.E mute list. Suppresses events targeting paths we
        // never want to capture:
        // - Our own state/staging dirs (avoids the feedback loop where
        //   the daemon writing to its DB triggers AUTH events that
        //   re-fill the journal that re-triggers writes that...)
        // - /dev/null + /dev/random + /dev/urandom (always-noisy)
        // - ~/Library/Caches + the user-tempdir Caches mirror
        //   (/private/var/folders/.../C/) — high event rate, never
        //   useful for undo
        //
        // Best-effort: failures log + continue (correctness unaffected,
        // only perf).
        if let Some(state_dir) = staging_dir.parent() {
            client.mute_target_prefix(state_dir);
        }
        client.mute_target_prefix(std::path::Path::new("/dev/null"));
        client.mute_target_prefix(std::path::Path::new("/dev/random"));
        client.mute_target_prefix(std::path::Path::new("/dev/urandom"));
        if let Some(home) = std::env::var_os("HOME") {
            let home = std::path::Path::new(&home);
            client.mute_target_prefix(&home.join("Library/Caches"));
        }
        // NOTE: the per-user macOS cache mirror lives under
        // /private/var/folders/<XX>/<YYYY>/C/, but the same parent
        // tree holds /private/var/folders/.../T/ (per-user tempdir)
        // which is where smoke scratchdirs and many legitimate
        // mutations live. A prefix-mute at `/private/var/folders`
        // would silence too much. Resolving the exact `C` subpath
        // would need `confstr(_CS_DARWIN_USER_CACHE_DIR)`; out of
        // scope for I.E — current muting is sufficient for the
        // sqlite-shm feedback loop fix this slice targets.

        Ok(Self {
            conn,
            staging_dir,
            client,
            ring_rx,
        })
    }

    fn attach(&mut self, command: CommandId, root_path: PathBuf, root_pid: Option<i32>) {
        let Some(pid) = root_pid else {
            tracing::warn!(
                %command.session,
                seq = command.seq,
                "macos-es WatchTree without root_pid; descendants only"
            );
            return;
        };
        if let Some(pump) = PUMP.get() {
            if let Ok(mut g) = pump.tracked_pids.lock() {
                g.insert(pid, command);
            }
            // Mach lookup is best-effort — populates pid_to_token
            // for diagnostic purposes only since the filter is now
            // pid-keyed. The shell pre-dates the helper subscription
            // in the typical smoke flow, so without this nothing
            // logs the shell's audit_token.
            if let Some(t) = audit_token_for_pid(pid)
                && let Ok(mut g) = pump.pid_to_token.lock()
            {
                g.insert(pid, t);
            }
        }
        tracing::info!(
            %command.session,
            seq = command.seq,
            path = %root_path.display(),
            pid,
            "macos-es watch attached"
        );
    }

    fn detach(&mut self, command: CommandId) {
        if let Some(pump) = PUMP.get() {
            if let Ok(mut g) = pump.tracked_pids.lock() {
                g.retain(|_, cmd| *cmd != command);
            }
            // Drop the per-command open-dedup entries — the next
            // command's PreImage shouldn't be suppressed by a
            // stale entry from a previous command.
            if let Ok(mut g) = pump.open_dedup.lock() {
                g.retain(|(cmd, _, _), _| *cmd != command);
            }
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
        match rec {
            CaptureRecord::PreImage(p) => self.emit_captured_preimage(p),
            CaptureRecord::TreeOp(t) => self.emit_tree_mutation(t),
        }
        if let Some(pump) = PUMP.get() {
            pump.events_emitted.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    fn emit_captured_preimage(&self, rec: PreImageRecord) {
        // Hash via pread so the staging fd's offset stays at 0 — the
        // daemon-side recvmsg fd shares this open-file-description
        // and reads starting at 0.
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
            // AUTH_UNLINK + AUTH_RENAME-overwrite both fire pre-syscall;
            // by the time the worker runs, the original bytes at `path`
            // are gone (replaced or removed). No post-state to hash.
            post_content_hash: None,
            mode: rec.mode,
            uid: rec.uid,
            gid: rec.gid,
            mtime_unix_nanos: rec.mtime_unix_nanos,
            // M03.1.I scope: no xattr capture (follow-up).
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

        drop(rec.staging_fd);
        let _ = std::fs::remove_file(&rec.staging_path);
    }

    fn emit_tree_mutation(&self, rec: TreeOpRecord) {
        let resp = HelperResponse::TreeMutation {
            session: rec.command.session,
            seq: rec.command.seq,
            op: rec.op,
            ts_unix_nanos: rec.ts_unix_nanos,
        };
        if let Err(e) = self.conn.send_response(&resp) {
            tracing::warn!(
                %rec.command.session,
                seq = rec.command.seq,
                err = %e,
                "macos-es TreeMutation send failed"
            );
        }
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

    // Periodic diagnostic — every 2s, log the event counters so the
    // smoke output reveals whether ES is delivering at all.
    let mut last_tick = std::time::Instant::now();
    loop {
        // 1. Control channel first (low latency for attach/detach).
        match ctrl_rx.try_recv() {
            Ok(ControlMsg::Attach {
                command,
                root_path,
                root_pid,
            }) => {
                state.attach(command, root_path, Some(root_pid));
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

        // 3. Periodic counter dump for operator observability.
        // DEBUG level so it's available via RUST_LOG=debug but
        // doesn't flood prod INFO logs.
        if last_tick.elapsed() >= Duration::from_secs(10) {
            if let Some(pump) = PUMP.get() {
                let seen = pump.events_seen.load(Ordering::Relaxed);
                let passed = pump.events_passed_filter.load(Ordering::Relaxed);
                let emitted = pump.events_emitted.load(Ordering::Relaxed);
                let tracked = pump.tracked_pids.lock().map(|g| g.len()).unwrap_or(0);
                tracing::debug!(seen, passed, emitted, tracked, "macos-es counters");
            }
            last_tick = std::time::Instant::now();
        }

        // 4. Idle.
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
