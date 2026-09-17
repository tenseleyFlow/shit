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
//! thread-owned) stages a descriptor-bound clone before responding to AUTH,
//! retains it in a bounded pending table, and moves it to the worker ring only
//! after an exactly matching successful NOTIFY. The pump thread then does
//! blake3 + the SCM_RIGHTS sendmsg. Failed syscalls never become actionable
//! journal records.
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
//! Process tracking is keyed by the complete audit token and keeps a parallel
//! pid-to-token guard. NOTIFY_EXEC deliberately transfers same-UID processes
//! to the post-exec token; a token change observed before that notification is
//! handled is refused rather than accepted by pid. Fork inheritance is limited
//! to the authenticated daemon UID, and a lineage that crosses a privilege
//! boundary stays refused until its command detaches.
//
// Module-level gate is at `crates/shit-helper/src/capture/mod.rs`; no
// inner `#![cfg]` here (rustc's `duplicated_attributes` lint flags
// the dup under `-D warnings`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CString, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_ulong;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use shit_planner::events::CommandId;
use shit_proto::{HELPER_PATH_HINT_MAX, HelperResponse};
use uuid::Uuid;

use crate::es::message::{EsMessage, audit_token_for_pid, audit_token_t};
use crate::es::sys;
use crate::ipc::Conn;

unsafe extern "C" {
    /// `int fclonefileat(int srcfd, int dst_dirfd, const char *dst, uint32_t flags);`
    /// from `<sys/clonefile.h>`.  The descriptor-bound source is essential:
    /// path-based clonefile can capture a replacement inode after ES supplied
    /// the pre-operation identity.
    fn fclonefileat(
        srcfd: libc::c_int,
        dst_dirfd: libc::c_int,
        dst: *const libc::c_char,
        flags: u32,
    ) -> libc::c_int;
    fn arc4random_buf(buf: *mut c_void, nbytes: libc::size_t);
}

const CLONE_NOFOLLOW: u32 = 0x0001;
const CLONE_NOOWNERCOPY: u32 = 0x0002;
const CLONE_ACL: u32 = 0x0004;

/// Channel capacity for control messages from the request loop.
/// Mirrors `capture::bsd`'s sizing.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Pump idle-sleep when both the control channel and the
/// (M03.1.I.4) ring report Empty.
const PUMP_IDLE_SLEEP: Duration = Duration::from_millis(50);

/// Keep request-loop waits below the daemon's five-second watch/unwatch
/// deadline while leaving ample time for the pump's 50 ms poll interval, the
/// 250 ms detach NOTIFY grace, and an ordinary bounded-ring drain. ES startup
/// has already completed before a [`CaptureControl`] is returned.
///
/// Expiry bounds only the caller's wait. It does not cancel the queued control
/// message or prove that the pump cleaned up; callers must treat pump state as
/// unknown and withhold readiness/flush acknowledgement.
const CONTROL_COMPLETION_TIMEOUT: Duration = Duration::from_secs(4);

/// Capacity shared by staged AUTH snapshots and committed records waiting for
/// the worker.  Reserving record units before ALLOW ensures that a later
/// successful NOTIFY always has queue capacity; overflow is rejected while
/// the syscall is still blockable.
const RECORD_CHANNEL_CAPACITY: usize = 1024;

/// An AUTH that has not produced a matching NOTIFY within this interval is
/// ambiguous.  It is converted to CaptureRefused (or on detach, synchronously
/// refused) rather than ever being committed as an actionable inverse.
const PENDING_AUTH_TTL: Duration = Duration::from_secs(30);
const DETACH_NOTIFY_GRACE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MutationFamily {
    Open,
    Unlink,
    Rename,
    Truncate,
    SetMode,
    SetOwner,
    UTimes,
}

/// Strongest AUTH→NOTIFY correlation key available in EndpointSecurity.
/// Apple does not expose the opaque AUTH id on the later NOTIFY message, so we
/// require the full audit token, v4 thread id, event family, kernel-attached
/// inode identities, and exact (non-lossy) paths.  One thread cannot execute
/// two syscalls simultaneously; an existing exact key is therefore an
/// ambiguity and the second AUTH is denied rather than replacing state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    process: audit_token_t,
    thread_id: u64,
    family: MutationFamily,
    primary_dev: u64,
    primary_inode: u64,
    primary_path: PathBuf,
    secondary_dev: u64,
    secondary_inode: u64,
    secondary_path: Option<PathBuf>,
    qualifier: u64,
}

struct PendingSnapshot {
    command: CommandId,
    path: Option<String>,
    records: Vec<CaptureRecord>,
    /// Write-open snapshots are deduplicated only after a successful NOTIFY.
    open_dedup_key: Option<(CommandId, u64, u64)>,
    /// Temporal lower bounds reject a delayed NOTIFY from an earlier
    /// identical syscall on the same thread.
    auth_mach_time: u64,
    auth_global_seq_num: u64,
    created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessDisposition {
    Tracked(CommandId),
    Refused(CommandId),
}

impl ProcessDisposition {
    fn command(self) -> CommandId {
        match self {
            Self::Tracked(command) | Self::Refused(command) => command,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessLookup {
    Untracked,
    Tracked(CommandId),
    Refused(CommandId),
}

#[derive(Default)]
struct ProcessTable {
    by_token: HashMap<audit_token_t, ProcessDisposition>,
    by_pid: HashMap<i32, audit_token_t>,
}

impl ProcessTable {
    fn lookup(&self, token: audit_token_t) -> ProcessLookup {
        match self.by_token.get(&token).copied() {
            Some(ProcessDisposition::Tracked(command)) => ProcessLookup::Tracked(command),
            Some(ProcessDisposition::Refused(command)) => ProcessLookup::Refused(command),
            None if self.by_pid.contains_key(&pid_from_audit_token(&token)) => {
                let command = self
                    .by_pid
                    .get(&pid_from_audit_token(&token))
                    .and_then(|expected| self.by_token.get(expected))
                    .map(|state| state.command());
                command.map_or(ProcessLookup::Untracked, ProcessLookup::Refused)
            }
            None => ProcessLookup::Untracked,
        }
    }

    fn insert_root(
        &mut self,
        token: audit_token_t,
        command: CommandId,
    ) -> Result<(), &'static str> {
        let pid = pid_from_audit_token(&token);
        if self.by_pid.contains_key(&pid) || self.by_token.contains_key(&token) {
            return Err("pid or audit token is already attached to an ES command");
        }
        self.by_pid.insert(pid, token);
        self.by_token
            .insert(token, ProcessDisposition::Tracked(command));
        Ok(())
    }

    fn insert_descendant(&mut self, token: audit_token_t, state: ProcessDisposition) {
        let pid = pid_from_audit_token(&token);
        if let Some(previous) = self.by_pid.insert(pid, token) {
            self.by_token.remove(&previous);
        }
        self.by_token.insert(token, state);
    }

    fn transfer_exec(
        &mut self,
        old_token: audit_token_t,
        new_token: audit_token_t,
        live_identity_allowed: bool,
    ) {
        let old_pid = pid_from_audit_token(&old_token);
        let new_pid = pid_from_audit_token(&new_token);
        let prior = match self.lookup(old_token) {
            ProcessLookup::Tracked(command) => Some(ProcessDisposition::Tracked(command)),
            ProcessLookup::Refused(command) => Some(ProcessDisposition::Refused(command)),
            ProcessLookup::Untracked => None,
        };
        let Some(prior) = prior else {
            return;
        };
        self.by_token.remove(&old_token);
        if self.by_pid.get(&old_pid) == Some(&old_token) {
            self.by_pid.remove(&old_pid);
        }
        let command = prior.command();
        let next = if old_pid == new_pid
            && matches!(prior, ProcessDisposition::Tracked(_))
            && live_identity_allowed
        {
            ProcessDisposition::Tracked(command)
        } else {
            ProcessDisposition::Refused(command)
        };
        self.insert_descendant(new_token, next);
    }

    fn remove_exit(&mut self, token: audit_token_t) {
        self.by_token.remove(&token);
        let pid = pid_from_audit_token(&token);
        if self.by_pid.get(&pid) == Some(&token) {
            self.by_pid.remove(&pid);
        }
    }

    fn remove_command(&mut self, command: CommandId) {
        let tokens: Vec<_> = self
            .by_token
            .iter()
            .filter_map(|(token, state)| (state.command() == command).then_some(*token))
            .collect();
        for token in tokens {
            self.remove_exit(token);
        }
    }

    fn len(&self) -> usize {
        self.by_token.len()
    }
}

#[derive(Default)]
struct PendingTable {
    entries: HashMap<PendingKey, PendingSnapshot>,
    /// Commands currently allowed to stage new AUTH snapshots. Keeping this
    /// bit in the same mutex as `entries` closes the detach race where an AUTH
    /// callback resolves a process just before detach, then inserts after the
    /// detach thread has observed an empty pending table.
    active_commands: HashSet<CommandId>,
}

impl PendingTable {
    fn activate(&mut self, command: CommandId) -> bool {
        self.active_commands.insert(command)
    }

    fn deactivate(&mut self, command: CommandId) {
        self.active_commands.remove(&command);
    }

    fn insert(
        &mut self,
        key: PendingKey,
        snapshot: PendingSnapshot,
    ) -> Result<(), Box<PendingSnapshot>> {
        if !self.active_commands.contains(&snapshot.command) || self.entries.contains_key(&key) {
            return Err(Box::new(snapshot));
        }
        self.entries.insert(key, snapshot);
        Ok(())
    }

    fn remove(&mut self, key: &PendingKey) -> Option<PendingSnapshot> {
        self.entries.remove(key)
    }

    fn take_expired(&mut self, now: Instant) -> Vec<PendingSnapshot> {
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, value)| {
                now.saturating_duration_since(value.created_at) >= PENDING_AUTH_TTL
            })
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| self.entries.remove(&key))
            .collect()
    }

    fn take_command(&mut self, command: CommandId) -> Vec<PendingSnapshot> {
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, value)| value.command == command)
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| self.entries.remove(&key))
            .collect()
    }

    fn contains_command(&self, command: CommandId) -> bool {
        self.entries
            .values()
            .any(|snapshot| snapshot.command == command)
    }

    fn contains_context(
        &self,
        process: audit_token_t,
        thread_id: u64,
        family: MutationFamily,
    ) -> bool {
        self.entries
            .keys()
            .any(|key| key.process == process && key.thread_id == thread_id && key.family == family)
    }

    fn take_all(&mut self) -> Vec<PendingSnapshot> {
        self.active_commands.clear();
        self.entries.drain().map(|(_, snapshot)| snapshot).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────
// PumpHandle — shared between kernel callback + pump thread
// ─────────────────────────────────────────────────────────────────────
//
// Kernel callback reads:
// - processes (full-audit-token AUTH filter + guarded lineage state)
// - ring_tx (commit CaptureRecord only on matching successful NOTIFY)
// - staging_dir (clonefile destination)
//
// Pump thread writes validated root identities on attach and removes every
// lineage entry for a command on detach.
//
// Callback also transfers identities across same-UID exec, inherits same-UID
// fork children, marks privilege transitions refused, and prunes exits.
//
// Single-shared because the helper only runs one producer at a time.

/// State the ES callback reads + writes. Initialized exactly once
/// by [`pump`] at startup via [`PUMP`].
pub struct PumpHandle {
    processes: Mutex<ProcessTable>,
    /// UID authenticated by the helper-daemon handshake. Watches and every
    /// inherited process must keep both real and effective UID equal to it.
    daemon_uid: u32,
    /// Audit session of the authenticated daemon process. A same-UID process
    /// from another login/session is outside this capture boundary.
    daemon_asid: u32,
    /// Per-command (dev, inode) dedup for AUTH_OPEN(W). Real-world
    /// commands open the same file many times (compiler reads a
    /// header repeatedly under -j); clonefile-on-first-open is
    /// sufficient — subsequent opens use the cached PreImage. The
    /// daemon's restore path is keyed on (dev, inode) so emitting
    /// duplicates would be harmless but wasteful.
    pub open_dedup: Mutex<HashMap<(CommandId, u64, u64), ()>>,
    /// AUTH snapshots awaiting an exactly matching successful NOTIFY.
    pending: Mutex<PendingTable>,
    /// Record units held either in `pending` or in `ring_tx`.  Each AUTH
    /// reserves its worst-case number of output records before it is allowed.
    outstanding_records: AtomicUsize,
    /// False before the worker is ready and as soon as it begins shutdown.
    worker_alive: AtomicBool,
    /// Bounded ring successful NOTIFY callbacks commit CaptureRecords into.
    /// AUTH reserves worst-case ring units before ALLOW, so a full worker
    /// pipeline is detected while the syscall can still be denied.
    pub ring_tx: SyncSender<CaptureRecord>,
    /// Verified root-owned 0700 staging directory. Capture creates only
    /// unpredictable relative leaves through this held descriptor, opens them
    /// with `O_NOFOLLOW`, then immediately unlinks them.
    pub staging_dir_fd: OwnedFd,
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

/// CaptureRecord — what a matched successful NOTIFY queues for the worker.
///
/// Capture variants include:
/// - `PreImage`: AUTH_UNLINK or AUTH_RENAME-overwrite — carries a
///   staging fd from the inline clonefile. Worker hashes + emits
///   `HelperResponse::CapturedPreImage` via SCM_RIGHTS.
/// - `TreeOp`: AUTH_RENAME or any future tree-only event — no fd,
///   no clonefile. Worker emits `HelperResponse::TreeMutation`.
/// - `CaptureRefused`: a mutation we observed but cannot invert without
///   losing state, such as AUTH_UTIMES while atime is not modeled.
///
/// A single successful RENAME-overwrite generates BOTH variants:
/// PreImage for the destination's pre-mutation bytes, TreeOp for the
/// rename itself.
pub enum CaptureRecord {
    PreImage(PreImageRecord),
    TreeOp(TreeOpRecord),
    /// The callback observed a mutation for which this capture tier cannot
    /// produce a complete inverse. The worker emits a non-actionable
    /// `CaptureRefused` event so undo fails loudly instead of applying a
    /// lossy approximation.
    CaptureRefused(CaptureRefusedRecord),
}

pub struct CaptureRefusedRecord {
    pub command: CommandId,
    pub path: Option<String>,
    pub detail: &'static str,
}

pub struct PreImageRecord {
    pub command: CommandId,
    /// Path of the file whose bytes we're capturing (UNLINK target
    /// or RENAME destination).
    pub path: PathBuf,
    /// Already-unlinked staging fd. Sent via SCM_RIGHTS to the daemon; daemon
    /// receives an independent fd that shares the open file description (so
    /// offset 0 is preserved as long as the helper hashes via `pread`).
    pub staging_fd: OwnedFd,
    pub dev: u64,
    pub inode: u64,
    pub expected_size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_unix_nanos: i128,
    /// M03.x.SETATTR — kernel-attached st_flags at pre-syscall time.
    /// 0 when the file has no BSD flags set.
    pub flags: u32,
    /// Complete, strictly captured xattr set from the stable snapshot.  Kept
    /// in the AUTH-stage record so worker-time read failures cannot silently
    /// turn into an empty set after the mutation has already committed.
    pub xattrs: BTreeMap<String, Vec<u8>>,
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
// - AUTH mutation: if tracked, stage the complete pre-image/refusal and
//   reserve worker capacity before ALLOW. Matching successful NOTIFY commits
//   it; failure or mismatch never creates an actionable inverse.

extern "C" fn producer_invoke(
    _block: *const sys::Block<()>,
    client: *mut sys::es_client_t,
    message: *const c_void,
) {
    // SAFETY: kernel-owned for the callback duration. EsMessage
    // borrows the pointer only for this scope.
    let msg = unsafe { EsMessage::from_raw(message) };
    let event_type = msg.event_type();

    // PUMP must have been initialized by the pump thread before any ES events
    // arrive. If it has not (race or bug), explicitly deny subscribed AUTH
    // mutations so the kernel neither times out nor executes uncaptured work.
    let pump = match PUMP.get() {
        Some(p) => p,
        None => {
            if event_type == sys::es_event_type_t::AUTH_OPEN {
                respond_deny_open_flags(client, message);
            } else if matches!(
                event_type,
                sys::es_event_type_t::AUTH_UNLINK
                    | sys::es_event_type_t::AUTH_RENAME
                    | sys::es_event_type_t::AUTH_TRUNCATE
                    | sys::es_event_type_t::AUTH_SETMODE
                    | sys::es_event_type_t::AUTH_SETOWNER
                    | sys::es_event_type_t::AUTH_UTIMES
            ) {
                respond_deny(client, message);
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
    if matches!(
        event_type,
        sys::es_event_type_t::NOTIFY_OPEN
            | sys::es_event_type_t::NOTIFY_UNLINK
            | sys::es_event_type_t::NOTIFY_RENAME
            | sys::es_event_type_t::NOTIFY_TRUNCATE
            | sys::es_event_type_t::NOTIFY_SETMODE
            | sys::es_event_type_t::NOTIFY_SETOWNER
            | sys::es_event_type_t::NOTIFY_UTIMES
    ) {
        commit_notify(pump, &msg);
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
    } else if event_type == sys::es_event_type_t::AUTH_SETMODE
        || event_type == sys::es_event_type_t::AUTH_SETOWNER
        || event_type == sys::es_event_type_t::AUTH_UTIMES
    {
        handle_auth_metadata(pump, client, message, &msg, event_type);
    }
    // Unknown event type — shouldn't happen since we control the
    // subscription set. Respond ALLOW if it's an AUTH variant we
    // didn't recognize, to be safe.
}

fn respond_allow(client: *mut sys::es_client_t, message: *const c_void) -> bool {
    // SAFETY: kernel callback contract — message + client valid here.
    unsafe {
        sys::es_respond_auth_result(
            client,
            message as *const sys::es_message_t,
            sys::es_auth_result_t::ALLOW,
            false,
        ) == sys::es_return_t::SUCCESS
    }
}

fn respond_deny(client: *mut sys::es_client_t, message: *const c_void) {
    // SAFETY: same contract as respond_allow.
    unsafe {
        let _ = sys::es_respond_auth_result(
            client,
            message as *const sys::es_message_t,
            sys::es_auth_result_t::DENY,
            false,
        );
    }
}

/// AUTH_OPEN uses a different responder than the other AUTH events:
/// `es_respond_flags_result(authorized_flags=fflag)` means "allow the
/// open with exactly the access modes requested". Passing the
/// original `fflag` is the equivalent of "ALLOW" for the flag-based
/// response API. Passing `0` would deny everything.
fn respond_allow_open_flags(
    client: *mut sys::es_client_t,
    message: *const c_void,
    fflag: u32,
) -> bool {
    // SAFETY: same kernel-callback contract.
    unsafe {
        sys::es_respond_flags_result(client, message as *const sys::es_message_t, fflag, false)
            == sys::es_return_t::SUCCESS
    }
}

fn respond_deny_open_flags(client: *mut sys::es_client_t, message: *const c_void) {
    // SAFETY: same kernel-callback contract.
    unsafe {
        let _ = sys::es_respond_flags_result(client, message as *const sys::es_message_t, 0, false);
    }
}

/// Hard cap on stream-copy fallback size. Files larger than this on
/// non-APFS volumes are NOT captured — the inline copy would push us
/// toward the ES 5-second auth deadline. 32 MiB matches the design
/// doc's stated limit; raised later if real workloads need it.
const STREAM_COPY_CAP: u64 = 32 * 1024 * 1024;

/// Inline pre-image stage. Tries APFS `fclonefileat(2)` first (µs-fast,
/// CoW reference, no byte copy); falls back to a streaming read on
/// non-APFS volumes (EOPNOTSUPP / ENOTSUP / EXDEV).
///
/// `expected_size` from the kernel-attached stat lets the fallback
/// short-circuit oversize files BEFORE allocating a buffer or
/// touching disk — preserves the ES 5-s auth deadline.
fn inline_clonefile(
    src_path: &Path,
    staging_dir_fd: RawFd,
    expected: &libc::stat,
) -> std::io::Result<(OwnedFd, BTreeMap<String, Vec<u8>>)> {
    if expected.st_size < 0 || (expected.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "EndpointSecurity target is not a regular file with a valid size",
        ));
    }

    let c_src = CString::new(src_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "src path contains NUL")
    })?;

    // Bind capture to one source descriptor, then verify it against the
    // kernel-attached ES identity before cloning/copying any bytes.
    let src_raw = unsafe {
        libc::open(
            c_src.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if src_raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `src_raw` is a fresh descriptor owned here.
    let src_fd = unsafe { OwnedFd::from_raw_fd(src_raw) };
    verify_fd_identity(src_fd.as_raw_fd(), expected)?;

    let staged = match clone_to_unlinked_staging(src_fd.as_raw_fd(), staging_dir_fd)? {
        Some(fd) => {
            verify_staging_fd(fd.as_raw_fd(), expected.st_size as u64)?;
            let xattrs = crate::capture::xattr::try_read_user_xattrs(fd.as_raw_fd())?;
            (fd, xattrs)
        }
        None => {
            stream_copy_to_staging(src_fd.as_raw_fd(), staging_dir_fd, expected.st_size as u64)?
        }
    };
    verify_fd_identity(src_fd.as_raw_fd(), expected)?;
    Ok(staged)
}

fn random_staging_leaf() -> CString {
    let mut random = [0u8; 16];
    // SAFETY: `random` is writable for exactly the supplied byte count.
    unsafe { arc4random_buf(random.as_mut_ptr().cast(), random.len()) };
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut leaf = Vec::with_capacity(3 + random.len() * 2);
    leaf.extend_from_slice(b"es-");
    for byte in random {
        leaf.push(HEX[(byte >> 4) as usize]);
        leaf.push(HEX[(byte & 0x0f) as usize]);
    }
    // The fixed prefix and hexadecimal alphabet never contain NUL.
    CString::new(leaf).expect("hex staging leaf is NUL-free")
}

/// Try an APFS descriptor-bound clone. `Ok(None)` means the filesystem does
/// not support cloning and the caller should use the bounded stream fallback.
/// A successful clone is opened relative to the held staging dirfd and
/// unlinked before its fd is returned.
fn clone_to_unlinked_staging(
    src_fd: RawFd,
    staging_dir_fd: RawFd,
) -> std::io::Result<Option<OwnedFd>> {
    for _ in 0..16 {
        let leaf = random_staging_leaf();
        let rc = unsafe {
            fclonefileat(
                src_fd,
                staging_dir_fd,
                leaf.as_ptr(),
                CLONE_NOFOLLOW | CLONE_NOOWNERCOPY | CLONE_ACL,
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            if matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP) | Some(libc::ENOTSUP) | Some(libc::EXDEV)
            ) {
                // Defensive cleanup in case a filesystem created a leaf before
                // reporting that cloning is unsupported.
                unsafe { libc::unlinkat(staging_dir_fd, leaf.as_ptr(), 0) };
                return Ok(None);
            }
            return Err(error);
        }

        let raw = unsafe {
            libc::openat(
                staging_dir_fd,
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::unlinkat(staging_dir_fd, leaf.as_ptr(), 0) };
            return Err(error);
        }
        // SAFETY: `raw` is a fresh descriptor owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::unlinkat(staging_dir_fd, leaf.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            drop(fd);
            // Best effort only; if the first unlink failed, the held root-only
            // directory still prevents an unprivileged attacker reaching it.
            unsafe { libc::unlinkat(staging_dir_fd, leaf.as_ptr(), 0) };
            return Err(error);
        }
        return Ok(Some(fd));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique random staging leaf",
    ))
}

fn create_unlinked_staging_fd(staging_dir_fd: RawFd) -> std::io::Result<OwnedFd> {
    for _ in 0..16 {
        let leaf = random_staging_leaf();
        let raw = unsafe {
            libc::openat(
                staging_dir_fd,
                leaf.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: `raw` is a fresh descriptor owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::unlinkat(staging_dir_fd, leaf.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            drop(fd);
            unsafe { libc::unlinkat(staging_dir_fd, leaf.as_ptr(), 0) };
            return Err(error);
        }
        return Ok(fd);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique random staging leaf",
    ))
}

/// Stream-copy fallback for non-APFS / cross-volume cases. Uses the already
/// identity-verified source fd, opens staging O_WRONLY|O_CREAT|O_EXCL, and copies up to
/// [`STREAM_COPY_CAP`] bytes via a 64 KiB reusable buffer (no file-sized
/// allocation on the hot path). Returns an already-unlinked staging fd and
/// the xattrs read from the identity-bound source descriptor.
///
/// Files larger than the cap return an `InvalidData` error so the
/// caller can DENY the syscall under hard-fail policy — capturing a
/// truncated pre-image would lie about what undo can restore.
fn stream_copy_to_staging(
    src_fd: RawFd,
    staging_dir_fd: RawFd,
    expected_size: u64,
) -> std::io::Result<(OwnedFd, BTreeMap<String, Vec<u8>>)> {
    if expected_size > STREAM_COPY_CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "file {expected_size} bytes exceeds stream-copy cap {STREAM_COPY_CAP} bytes (non-APFS path)"
            ),
        ));
    }

    let fd = create_unlinked_staging_fd(staging_dir_fd)?;

    const CHUNK: usize = 64 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let target = expected_size as i64;
    let mut offset: i64 = 0;
    while offset < target {
        let want = ((target - offset) as usize).min(CHUNK);
        // SAFETY: src fd valid; buf writable of len >= want.
        let n = unsafe { libc::pread(src_fd, buf.as_mut_ptr().cast(), want, offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("source ended after {offset} of {expected_size} bytes"),
            ));
        }
        let n_usize = n as usize;
        let mut written = 0usize;
        while written < n_usize {
            // SAFETY: wfd_raw valid; buf valid.
            let wrc = unsafe {
                libc::pwrite(
                    fd.as_raw_fd(),
                    buf.as_ptr().add(written).cast(),
                    (n_usize - written) as libc::size_t,
                    offset + written as i64,
                )
            };
            if wrc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if wrc == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "zero-length write while staging pre-image",
                ));
            }
            written += wrc as usize;
        }
        offset += n as i64;
    }
    if unsafe { libc::fsync(fd.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    verify_staging_fd(fd.as_raw_fd(), expected_size)?;
    let xattrs = crate::capture::xattr::try_read_user_xattrs(src_fd)?;
    Ok((fd, xattrs))
}

fn verify_fd_identity(fd: RawFd, expected: &libc::stat) -> std::io::Result<()> {
    let actual = fstat_fd(fd)?;
    if actual.st_dev != expected.st_dev
        || actual.st_ino != expected.st_ino
        || actual.st_size != expected.st_size
        || (actual.st_mode & libc::S_IFMT) != libc::S_IFREG
        || actual.st_mode != expected.st_mode
        || actual.st_uid != expected.st_uid
        || actual.st_gid != expected.st_gid
        || actual.st_mtime != expected.st_mtime
        || actual.st_mtime_nsec != expected.st_mtime_nsec
        || actual.st_ctime != expected.st_ctime
        || actual.st_ctime_nsec != expected.st_ctime_nsec
        || actual.st_flags != expected.st_flags
        || actual.st_gen != expected.st_gen
        || actual.st_nlink != expected.st_nlink
        || actual.st_birthtime != expected.st_birthtime
        || actual.st_birthtime_nsec != expected.st_birthtime_nsec
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "opened source does not match EndpointSecurity identity/content metadata",
        ));
    }
    Ok(())
}

fn verify_staging_fd(fd: RawFd, expected_size: u64) -> std::io::Result<()> {
    let actual = fstat_fd(fd)?;
    if actual.st_size < 0
        || actual.st_size as u64 != expected_size
        || (actual.st_mode & libc::S_IFMT) != libc::S_IFREG
        || actual.st_nlink != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "staging fd is not an unlinked regular snapshot of {expected_size} bytes (size={}, nlink={})",
                actual.st_size, actual.st_nlink
            ),
        ));
    }
    Ok(())
}

fn fstat_fd(fd: RawFd) -> std::io::Result<libc::stat> {
    // SAFETY: `fd` is borrowed-valid and `st` points to initialized storage.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("snapshot ended after {offset} of {size} bytes"),
            ));
        }
        let n_usize = n as usize;
        hasher.update(&buf[..n_usize]);
        offset += n as i64;
    }
    Ok((*hasher.finalize().as_bytes(), offset as u64))
}

fn path_to_string(p: &Path) -> Option<String> {
    let s = std::str::from_utf8(p.as_os_str().as_bytes()).ok()?;
    if s.len() > HELPER_PATH_HINT_MAX {
        // Send None rather than a truncated path that could mislead
        // the daemon's restore logic. Daemon falls back to dev+inode
        // identity in that case.
        return None;
    }
    Some(s.to_owned())
}

fn mutation_family(event_type: sys::es_event_type_t) -> Option<MutationFamily> {
    if event_type == sys::es_event_type_t::AUTH_OPEN
        || event_type == sys::es_event_type_t::NOTIFY_OPEN
    {
        Some(MutationFamily::Open)
    } else if event_type == sys::es_event_type_t::AUTH_UNLINK
        || event_type == sys::es_event_type_t::NOTIFY_UNLINK
    {
        Some(MutationFamily::Unlink)
    } else if event_type == sys::es_event_type_t::AUTH_RENAME
        || event_type == sys::es_event_type_t::NOTIFY_RENAME
    {
        Some(MutationFamily::Rename)
    } else if event_type == sys::es_event_type_t::AUTH_TRUNCATE
        || event_type == sys::es_event_type_t::NOTIFY_TRUNCATE
    {
        Some(MutationFamily::Truncate)
    } else if event_type == sys::es_event_type_t::AUTH_SETMODE
        || event_type == sys::es_event_type_t::NOTIFY_SETMODE
    {
        Some(MutationFamily::SetMode)
    } else if event_type == sys::es_event_type_t::AUTH_SETOWNER
        || event_type == sys::es_event_type_t::NOTIFY_SETOWNER
    {
        Some(MutationFamily::SetOwner)
    } else if event_type == sys::es_event_type_t::AUTH_UTIMES
        || event_type == sys::es_event_type_t::NOTIFY_UTIMES
    {
        Some(MutationFamily::UTimes)
    } else {
        None
    }
}

fn exact_file_path(file: &crate::es::message::es_file_t) -> std::io::Result<PathBuf> {
    if file.path_truncated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "EndpointSecurity truncated a path",
        ));
    }
    let path = unsafe { file.path.as_path() };
    let bytes = path.as_os_str().as_bytes();
    let normalized: PathBuf = path.components().collect();
    let has_unsafe_component = path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    });
    if bytes.is_empty()
        || bytes.contains(&0)
        || !path.is_absolute()
        || has_unsafe_component
        || normalized.as_os_str() != path.as_os_str()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "EndpointSecurity supplied a non-normalized or unsafe path",
        ));
    }
    Ok(path.to_path_buf())
}

fn make_pending_key(msg: &EsMessage<'_>, family: MutationFamily) -> std::io::Result<PendingKey> {
    let thread_id = msg.thread_id().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "EndpointSecurity message has no v4 thread id",
        )
    })?;

    let (primary, primary_path, secondary, secondary_path, qualifier) = match family {
        MutationFamily::Open => {
            let event = msg.as_open().ok_or_else(invalid_es_payload)?;
            let file = unsafe { event.file.as_ref() }.ok_or_else(invalid_es_payload)?;
            (
                &file.stat,
                exact_file_path(file)?,
                None,
                None,
                event.fflag as u32 as u64,
            )
        }
        MutationFamily::Unlink => {
            let event = msg.as_unlink().ok_or_else(invalid_es_payload)?;
            let file = unsafe { event.target.as_ref() }.ok_or_else(invalid_es_payload)?;
            (&file.stat, exact_file_path(file)?, None, None, 0)
        }
        MutationFamily::Truncate => {
            let event = msg.as_truncate().ok_or_else(invalid_es_payload)?;
            let file = unsafe { event.target.as_ref() }.ok_or_else(invalid_es_payload)?;
            (&file.stat, exact_file_path(file)?, None, None, 0)
        }
        MutationFamily::SetMode => {
            let event = msg.as_setmode().ok_or_else(invalid_es_payload)?;
            let file = unsafe { event.target.as_ref() }.ok_or_else(invalid_es_payload)?;
            (
                &file.stat,
                exact_file_path(file)?,
                None,
                None,
                event.mode as u64,
            )
        }
        MutationFamily::SetOwner => {
            let event = msg.as_setowner().ok_or_else(invalid_es_payload)?;
            let file = unsafe { event.target.as_ref() }.ok_or_else(invalid_es_payload)?;
            (
                &file.stat,
                exact_file_path(file)?,
                None,
                None,
                ((event.uid as u64) << 32) | event.gid as u64,
            )
        }
        MutationFamily::UTimes => {
            let event = msg.as_utimes().ok_or_else(invalid_es_payload)?;
            let file = unsafe { event.target.as_ref() }.ok_or_else(invalid_es_payload)?;
            // The exact timestamp payload is not needed to disambiguate one
            // syscall on one thread, but fold it in as an additional guard.
            let qualifier = (event.mtime.tv_sec as u64)
                ^ (event.mtime.tv_nsec as u64).rotate_left(17)
                ^ (event.atime.tv_sec as u64).rotate_left(31)
                ^ (event.atime.tv_nsec as u64).rotate_left(47);
            (&file.stat, exact_file_path(file)?, None, None, qualifier)
        }
        MutationFamily::Rename => {
            let event = msg.as_rename().ok_or_else(invalid_es_payload)?;
            let source = unsafe { event.source.as_ref() }.ok_or_else(invalid_es_payload)?;
            let source_path = exact_file_path(source)?;
            let (dest_stat, dest_path, qualifier) = match event.destination_type {
                crate::es::message::es_destination_type_t::EXISTING_FILE => {
                    let dest = unsafe { event.destination.existing_file.as_ref() }
                        .ok_or_else(invalid_es_payload)?;
                    (Some(&dest.stat), exact_file_path(dest)?, 0)
                }
                crate::es::message::es_destination_type_t::NEW_PATH => {
                    let new_path = unsafe { &*event.destination.new_path };
                    let dir = unsafe { new_path.dir.as_ref() }.ok_or_else(invalid_es_payload)?;
                    let filename = unsafe { new_path.filename.as_bytes() };
                    if filename.is_empty()
                        || filename == b"."
                        || filename == b".."
                        || filename.contains(&b'/')
                        || filename.contains(&0)
                    {
                        return Err(invalid_es_payload());
                    }
                    let dir_path = exact_file_path(dir)?;
                    (
                        None,
                        dir_path.join(std::ffi::OsStr::from_bytes(filename)),
                        1,
                    )
                }
                _ => return Err(invalid_es_payload()),
            };
            (
                &source.stat,
                source_path,
                dest_stat,
                Some(dest_path),
                qualifier,
            )
        }
    };

    Ok(PendingKey {
        process: msg.process_audit_token(),
        thread_id,
        family,
        primary_dev: primary.st_dev as u64,
        primary_inode: primary.st_ino,
        primary_path,
        secondary_dev: secondary.map(|stat| stat.st_dev as u64).unwrap_or(0),
        secondary_inode: secondary.map(|stat| stat.st_ino).unwrap_or(0),
        secondary_path,
        qualifier,
    })
}

fn invalid_es_payload() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "EndpointSecurity event payload is incomplete",
    )
}

fn reserve_record_units(pump: &PumpHandle, units: usize) -> bool {
    let mut current = pump.outstanding_records.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(units) else {
            return false;
        };
        if next > RECORD_CHANNEL_CAPACITY {
            return false;
        }
        match pump.outstanding_records.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn release_record_units(pump: &PumpHandle, units: usize) {
    if units != 0 {
        let previous = pump.outstanding_records.fetch_sub(units, Ordering::AcqRel);
        debug_assert!(previous >= units, "macos-es record reservation underflow");
    }
}

#[derive(Clone, Copy)]
enum AuthResponder {
    Ordinary,
    Open { fflag: u32 },
}

fn allow_auth(
    responder: AuthResponder,
    client: *mut sys::es_client_t,
    message: *const c_void,
) -> bool {
    match responder {
        AuthResponder::Ordinary => respond_allow(client, message),
        AuthResponder::Open { fflag } => respond_allow_open_flags(client, message, fflag),
    }
}

fn deny_auth(responder: AuthResponder, client: *mut sys::es_client_t, message: *const c_void) {
    match responder {
        AuthResponder::Ordinary => respond_deny(client, message),
        AuthResponder::Open { .. } => respond_deny_open_flags(client, message),
    }
}

fn cleanup_pending_snapshot(snapshot: PendingSnapshot) {
    for record in snapshot.records {
        cleanup_dropped_record(record);
    }
}

fn stage_pending_auth(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    responder: AuthResponder,
    key: PendingKey,
    snapshot: PendingSnapshot,
) {
    expire_pending_auth(pump);

    let units = snapshot.records.len();
    if units == 0
        || !pump.worker_alive.load(Ordering::Acquire)
        || !reserve_record_units(pump, units)
    {
        cleanup_pending_snapshot(snapshot);
        tracing::error!("macos-es worker unavailable or capture capacity exhausted; DENY syscall");
        deny_auth(responder, client, message);
        return;
    }
    if !pump.worker_alive.load(Ordering::Acquire) {
        cleanup_pending_snapshot(snapshot);
        release_record_units(pump, units);
        deny_auth(responder, client, message);
        return;
    }

    let Ok(mut pending) = pump.pending.lock() else {
        cleanup_pending_snapshot(snapshot);
        release_record_units(pump, units);
        pump.worker_alive.store(false, Ordering::Release);
        tracing::error!("macos-es pending table poisoned; DENY syscall");
        deny_auth(responder, client, message);
        return;
    };
    let inserted = pending.insert(key.clone(), snapshot);
    drop(pending);
    if let Err(snapshot) = inserted {
        cleanup_pending_snapshot(*snapshot);
        release_record_units(pump, units);
        tracing::error!(
            "macos-es inactive command or duplicate pending AUTH correlation key; DENY syscall"
        );
        deny_auth(responder, client, message);
        return;
    }

    if !allow_auth(responder, client, message) {
        match pump.pending.lock() {
            Ok(mut pending) => {
                if let Some(snapshot) = pending.remove(&key) {
                    // Keep the table lock until the refusal is queued so a
                    // concurrent detach cannot observe an empty table and
                    // empty ring between those two operations.
                    queue_refusal_for_pending(pump, snapshot, AUTH_RESPONSE_FAILED_REFUSAL);
                } else {
                    pump.worker_alive.store(false, Ordering::Release);
                }
            }
            Err(poisoned) => {
                pump.worker_alive.store(false, Ordering::Release);
                if let Some(snapshot) = poisoned.into_inner().remove(&key) {
                    queue_refusal_for_pending(pump, snapshot, AUTH_RESPONSE_FAILED_REFUSAL);
                }
            }
        }
        tracing::error!("macos-es ALLOW response failed; refusing ambiguous capture");
    }
}

const EXPIRED_AUTH_REFUSAL: &str = "macOS EndpointSecurity AUTH snapshot expired without an exactly matching successful NOTIFY; refusing ambiguous undo";
const DETACHED_AUTH_REFUSAL: &str = "macOS EndpointSecurity command detached with an AUTH snapshot still awaiting successful NOTIFY; refusing ambiguous undo";
const AUTH_RESPONSE_FAILED_REFUSAL: &str =
    "macOS EndpointSecurity failed to acknowledge the AUTH decision; refusing ambiguous undo";
const MALFORMED_NOTIFY_REFUSAL: &str = "macOS EndpointSecurity delivered a matching NOTIFY with an unreadable authorization result; refusing ambiguous undo";

fn queue_refusal_for_pending(pump: &PumpHandle, snapshot: PendingSnapshot, detail: &'static str) {
    let units = snapshot.records.len();
    for record in snapshot.records {
        cleanup_dropped_record(record);
    }
    let refusal = CaptureRecord::CaptureRefused(CaptureRefusedRecord {
        command: snapshot.command,
        path: snapshot.path,
        detail,
    });
    if units > 1 {
        release_record_units(pump, units - 1);
    }
    match pump.ring_tx.try_send(refusal) {
        Ok(()) => {}
        Err(TrySendError::Full(record)) => {
            cleanup_dropped_record(record);
            release_record_units(pump, 1);
            tracing::error!(
                "macos-es reserved queue invariant violated while refusing pending AUTH"
            );
        }
        Err(TrySendError::Disconnected(record)) => {
            cleanup_dropped_record(record);
            release_record_units(pump, 1);
            pump.worker_alive.store(false, Ordering::Release);
            tracing::error!("macos-es worker died while refusing pending AUTH");
        }
    }
}

fn expire_pending_auth(pump: &PumpHandle) {
    match pump.pending.lock() {
        Ok(mut pending) => {
            let expired = pending.take_expired(Instant::now());
            for snapshot in expired {
                // See the detach-barrier note in `stage_pending_auth`.
                queue_refusal_for_pending(pump, snapshot, EXPIRED_AUTH_REFUSAL);
            }
        }
        Err(poisoned) => {
            pump.worker_alive.store(false, Ordering::Release);
            let mut pending = poisoned.into_inner();
            let expired = pending.take_all();
            for snapshot in expired {
                queue_refusal_for_pending(pump, snapshot, EXPIRED_AUTH_REFUSAL);
            }
        }
    }
}

fn notify_follows_auth(snapshot: &PendingSnapshot, mach_time: u64, global_seq_num: u64) -> bool {
    mach_time >= snapshot.auth_mach_time && global_seq_num > snapshot.auth_global_seq_num
}

fn commit_notify(pump: &PumpHandle, msg: &EsMessage<'_>) {
    // NOTIFY subscriptions are system-wide. Avoid path decoding/allocation for
    // the common case where no AUTH snapshot is outstanding at all.
    if pump.outstanding_records.load(Ordering::Acquire) == 0 {
        return;
    }
    expire_pending_auth(pump);
    let Some(family) = mutation_family(msg.event_type()) else {
        return;
    };
    let Some(thread_id) = msg.thread_id() else {
        return;
    };
    let process = msg.process_audit_token();
    let has_context = match pump.pending.lock() {
        Ok(pending) => pending.contains_context(process, thread_id, family),
        Err(_) => true,
    };
    if !has_context {
        return;
    }
    let Ok(key) = make_pending_key(msg, family) else {
        return;
    };
    let mut pending = match pump.pending.lock() {
        Ok(pending) => pending,
        Err(poisoned) => {
            pump.worker_alive.store(false, Ordering::Release);
            let mut pending = poisoned.into_inner();
            let snapshot = pending.remove(&key);
            if let Some(snapshot) = snapshot {
                queue_refusal_for_pending(
                    pump,
                    snapshot,
                    "macOS EndpointSecurity pending correlation state became unavailable; refusing ambiguous undo",
                );
            }
            return;
        }
    };
    let Some(snapshot) = pending.remove(&key) else {
        return;
    };

    let notify_global_seq_num = msg.global_seq_num().unwrap_or(0);
    if !notify_follows_auth(&snapshot, msg.mach_time(), notify_global_seq_num) {
        // A delayed NOTIFY from an earlier identical syscall can otherwise
        // satisfy the semantic key after a new AUTH was staged. Keep waiting
        // for the first temporally valid notification.
        let reinserted = pending.insert(key, snapshot);
        if let Err(snapshot) = reinserted {
            queue_refusal_for_pending(
                pump,
                *snapshot,
                "macOS EndpointSecurity correlation state collided while rejecting a stale NOTIFY; refusing ambiguous undo",
            );
        }
        return;
    }

    enum NotifyDisposition {
        Commit,
        DiscardDenied,
        RefuseAmbiguous,
    }
    let disposition = match (family, msg.notify_result()) {
        (MutationFamily::Open, Some(Err(flags))) if open_requires_snapshot(flags as i32) => {
            NotifyDisposition::Commit
        }
        (MutationFamily::Open, Some(Err(_))) => NotifyDisposition::DiscardDenied,
        (MutationFamily::Open, _) => NotifyDisposition::RefuseAmbiguous,
        (_, Some(Ok(true))) => NotifyDisposition::Commit,
        (_, Some(Ok(false))) => NotifyDisposition::DiscardDenied,
        _ => NotifyDisposition::RefuseAmbiguous,
    };
    match disposition {
        NotifyDisposition::Commit => {}
        NotifyDisposition::DiscardDenied => {
            let units = snapshot.records.len();
            cleanup_pending_snapshot(snapshot);
            release_record_units(pump, units);
            return;
        }
        NotifyDisposition::RefuseAmbiguous => {
            queue_refusal_for_pending(pump, snapshot, MALFORMED_NOTIFY_REFUSAL);
            return;
        }
    }

    if let Some(dedup_key) = snapshot.open_dedup_key {
        let first_success = match pump.open_dedup.lock() {
            Ok(mut dedup) => dedup.insert(dedup_key, ()).is_none(),
            Err(_) => {
                pump.worker_alive.store(false, Ordering::Release);
                queue_refusal_for_pending(
                    pump,
                    snapshot,
                    "macOS EndpointSecurity write-open dedup state became unavailable; refusing ambiguous undo",
                );
                return;
            }
        };
        if !first_success {
            let units = snapshot.records.len();
            cleanup_pending_snapshot(snapshot);
            release_record_units(pump, units);
            return;
        }
    }

    let total = snapshot.records.len();
    let mut sent = 0usize;
    let mut records = snapshot.records.into_iter();
    while let Some(record) = records.next() {
        match pump.ring_tx.try_send(record) {
            Ok(()) => sent += 1,
            Err(TrySendError::Full(record)) => {
                cleanup_dropped_record(record);
                for remaining in records {
                    cleanup_dropped_record(remaining);
                }
                tracing::error!(
                    "macos-es reserved queue invariant violated after successful NOTIFY"
                );
                break;
            }
            Err(TrySendError::Disconnected(record)) => {
                cleanup_dropped_record(record);
                for remaining in records {
                    cleanup_dropped_record(remaining);
                }
                pump.worker_alive.store(false, Ordering::Release);
                tracing::error!("macos-es worker died after successful NOTIFY");
                break;
            }
        }
    }
    release_record_units(pump, total - sent);
}

fn handle_notify_exec(pump: &PumpHandle, msg: &EsMessage<'_>) {
    let old_token = msg.process_audit_token();
    let Some(new_token) = msg.exec_target_audit_token() else {
        // Keep the old pid guard in place. Any post-exec token will mismatch
        // and therefore be refused until detach rather than escaping capture.
        tracing::error!("macos-es NOTIFY_EXEC omitted its target identity");
        return;
    };
    let live_identity_allowed =
        live_process_matches_boundary(new_token, pump.daemon_uid, pump.daemon_asid);
    match pump.processes.lock() {
        Ok(mut processes) => processes.transfer_exec(old_token, new_token, live_identity_allowed),
        Err(_) => {
            pump.worker_alive.store(false, Ordering::Release);
            tracing::error!("macos-es process table poisoned during exec transition");
        }
    }
}

fn handle_notify_fork(pump: &PumpHandle, msg: &EsMessage<'_>) {
    let parent_token = msg.process_audit_token();
    let Some(child_token) = msg.fork_child_audit_token() else {
        return;
    };
    match pump.processes.lock() {
        Ok(mut processes) => {
            let state = match processes.lookup(parent_token) {
                ProcessLookup::Tracked(command)
                    if live_process_matches_boundary(
                        child_token,
                        pump.daemon_uid,
                        pump.daemon_asid,
                    ) =>
                {
                    Some(ProcessDisposition::Tracked(command))
                }
                ProcessLookup::Tracked(command) | ProcessLookup::Refused(command) => {
                    Some(ProcessDisposition::Refused(command))
                }
                ProcessLookup::Untracked => None,
            };
            if let Some(state) = state {
                processes.insert_descendant(child_token, state);
            }
        }
        Err(_) => {
            pump.worker_alive.store(false, Ordering::Release);
            tracing::error!("macos-es process table poisoned during fork transition");
        }
    }
}

fn handle_notify_exit(pump: &PumpHandle, msg: &EsMessage<'_>) {
    let token = msg.process_audit_token();
    match pump.processes.lock() {
        Ok(mut processes) => processes.remove_exit(token),
        Err(_) => {
            pump.worker_alive.store(false, Ordering::Release);
            tracing::error!("macos-es process table poisoned during exit transition");
        }
    }
}

fn command_for_auth(pump: &PumpHandle, token: audit_token_t) -> Result<Option<CommandId>, ()> {
    match pump.processes.lock() {
        Ok(processes) => match processes.lookup(token) {
            ProcessLookup::Untracked => Ok(None),
            ProcessLookup::Tracked(command) => Ok(Some(command)),
            ProcessLookup::Refused(command) => {
                tracing::error!(
                    %command.session,
                    seq = command.seq,
                    pid = pid_from_audit_token(&token),
                    "macos-es DENY mutation from ambiguous or privilege-transitioned lineage"
                );
                Err(())
            }
        },
        Err(_) => {
            pump.worker_alive.store(false, Ordering::Release);
            tracing::error!("macos-es process table poisoned; DENY mutation");
            Err(())
        }
    }
}

fn handle_auth_unlink(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let token = msg.process_audit_token();
    let command = match command_for_auth(pump, token) {
        Ok(command) => command,
        Err(()) => {
            respond_deny(client, message);
            return;
        }
    };
    let Some(command) = command else {
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let key = match make_pending_key(msg, MutationFamily::Unlink) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(err = %error, "macos-es cannot correlate unlink AUTH; DENY");
            respond_deny(client, message);
            return;
        }
    };

    // Pull path + stat in one borrow; descriptor-bound staging below verifies
    // that the live object still matches this kernel-attached identity.
    let Some(file) = msg.unlink_target_file() else {
        respond_deny(client, message);
        return;
    };
    let target_path = key.primary_path.clone();
    let stat = file.stat;

    // 1. Inline clonefile — must succeed before we let the syscall
    //    proceed; under hard-fail, capture failure → DENY so the
    //    user gets "permission denied" instead of an unrecoverable
    //    unlink with no pre-image.
    let (staging_fd, xattrs) =
        match inline_clonefile(&target_path, pump.staging_dir_fd.as_raw_fd(), &stat) {
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
        staging_fd,
        dev: stat.st_dev as u64,
        inode: stat.st_ino,
        expected_size: stat.st_size as u64,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mtime_unix_nanos: (stat.st_mtime as i128) * 1_000_000_000 + (stat.st_mtime_nsec as i128),
        flags: stat.st_flags,
        xattrs,
        is_delete: true,
    });
    stage_pending_auth(
        pump,
        client,
        message,
        AuthResponder::Ordinary,
        key,
        PendingSnapshot {
            command,
            path: path_to_string(&target_path),
            records: vec![record],
            open_dedup_key: None,
            auth_mach_time: msg.mach_time(),
            auth_global_seq_num: msg.global_seq_num().unwrap_or(0),
            created_at: Instant::now(),
        },
    );
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
    let command = match command_for_auth(pump, token) {
        Ok(command) => command,
        Err(()) => {
            respond_deny(client, message);
            return;
        }
    };
    let Some(command) = command else {
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let key = match make_pending_key(msg, MutationFamily::Truncate) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(err = %error, "macos-es cannot correlate truncate AUTH; DENY");
            respond_deny(client, message);
            return;
        }
    };

    let Some(file) = msg.truncate_target_file() else {
        respond_deny(client, message);
        return;
    };
    let target_path = key.primary_path.clone();
    let stat = file.stat;

    let (staging_fd, xattrs) =
        match inline_clonefile(&target_path, pump.staging_dir_fd.as_raw_fd(), &stat) {
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
        staging_fd,
        dev: stat.st_dev as u64,
        inode: stat.st_ino,
        expected_size: stat.st_size as u64,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mtime_unix_nanos: (stat.st_mtime as i128) * 1_000_000_000 + (stat.st_mtime_nsec as i128),
        flags: stat.st_flags,
        xattrs,
        // The path still exists after the syscall; we just need to
        // restore its bytes during undo. No TreeOp::Unlink pairing.
        is_delete: false,
    });
    stage_pending_auth(
        pump,
        client,
        message,
        AuthResponder::Ordinary,
        key,
        PendingSnapshot {
            command,
            path: path_to_string(&target_path),
            records: vec![record],
            open_dedup_key: None,
            auth_mach_time: msg.mach_time(),
            auth_global_seq_num: msg.global_seq_num().unwrap_or(0),
            created_at: Instant::now(),
        },
    );
}

const UTIMES_CAPTURE_REFUSAL: &str = "macOS EndpointSecurity AUTH_UTIMES changes both atime and mtime, but captured metadata does not preserve atime; refusing lossy timestamp undo";
const SETMODE_CAPTURE_REFUSAL: &str = "macOS EndpointSecurity SETMODE is not actionable yet: the broad metadata inverse cannot represent every mode/ACL side effect safely; refusing lossy metadata undo";
const SETOWNER_CAPTURE_REFUSAL: &str = "macOS EndpointSecurity SETOWNER is not actionable yet: ownership changes can alter mode/ACL state that the broad metadata inverse cannot model safely; refusing lossy metadata undo";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataCapturePolicy {
    Refuse(&'static str),
    Unsupported,
}

fn metadata_capture_policy(event_type: sys::es_event_type_t) -> MetadataCapturePolicy {
    if event_type == sys::es_event_type_t::AUTH_SETMODE {
        MetadataCapturePolicy::Refuse(SETMODE_CAPTURE_REFUSAL)
    } else if event_type == sys::es_event_type_t::AUTH_SETOWNER {
        MetadataCapturePolicy::Refuse(SETOWNER_CAPTURE_REFUSAL)
    } else if event_type == sys::es_event_type_t::AUTH_UTIMES {
        MetadataCapturePolicy::Refuse(UTIMES_CAPTURE_REFUSAL)
    } else {
        MetadataCapturePolicy::Unsupported
    }
}

/// Metadata events remain non-actionable until the inverse schema can express
/// their complete side effects (atime/ACL/chown-cleared mode bits).  The
/// refusal is staged at AUTH and emitted only after an exactly matching,
/// successful NOTIFY, so a failed chmod/chown/utimes does not poison undo.
fn handle_auth_metadata(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
    event_type: sys::es_event_type_t,
) {
    let token = msg.process_audit_token();
    let command = match command_for_auth(pump, token) {
        Ok(command) => command,
        Err(()) => {
            respond_deny(client, message);
            return;
        }
    };
    let Some(command) = command else {
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let detail = match metadata_capture_policy(event_type) {
        MetadataCapturePolicy::Refuse(detail) => detail,
        MetadataCapturePolicy::Unsupported => {
            respond_deny(client, message);
            return;
        }
    };
    let family = if event_type == sys::es_event_type_t::AUTH_SETMODE {
        MutationFamily::SetMode
    } else if event_type == sys::es_event_type_t::AUTH_SETOWNER {
        MutationFamily::SetOwner
    } else {
        MutationFamily::UTimes
    };
    let key = match make_pending_key(msg, family) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(err = %error, "macos-es cannot correlate metadata AUTH; DENY");
            respond_deny(client, message);
            return;
        }
    };
    let path = path_to_string(&key.primary_path);
    let record = CaptureRecord::CaptureRefused(CaptureRefusedRecord {
        command,
        path: path.clone(),
        detail,
    });
    stage_pending_auth(
        pump,
        client,
        message,
        AuthResponder::Ordinary,
        key,
        PendingSnapshot {
            command,
            path,
            records: vec![record],
            open_dedup_key: None,
            auth_mach_time: msg.mach_time(),
            auth_global_seq_num: msg.global_seq_num().unwrap_or(0),
            created_at: Instant::now(),
        },
    );
}

/// Kernel `FFLAGS` write-intent bits. From `<sys/fcntl.h>`:
/// FREAD=0x01, FWRITE=0x02. FAPPEND (0x08) implies write but
/// post-pends; the original bytes survive an append, so we don't
/// need a pre-image just for FAPPEND.
const FFLAG_FWRITE: i32 = 0x02;

/// O_TRUNC bit in fflag. AUTH_OPEN can be the only pre-mutation event for an
/// `open(..., O_TRUNC)` operation, so it must follow the same snapshot path as
/// every other write open. It remains named separately for focused tests and
/// diagnostics.
const FFLAG_OTRUNC: i32 = 0x0400;

fn open_requires_snapshot(fflag: i32) -> bool {
    fflag & (FFLAG_FWRITE | FFLAG_OTRUNC) != 0
}

/// AUTH_OPEN handler. Filters for write intent (`FWRITE` or `O_TRUNC`); on
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
        respond_deny_open_flags(client, message);
        return;
    };
    let fflag = event.fflag;

    // Read-only opens: nothing to capture, fast-path ALLOW.
    if !open_requires_snapshot(fflag) {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    }
    let token = msg.process_audit_token();
    let command = match command_for_auth(pump, token) {
        Ok(command) => command,
        Err(()) => {
            respond_deny_open_flags(client, message);
            return;
        }
    };
    let Some(command) = command else {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let key = match make_pending_key(msg, MutationFamily::Open) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(err = %error, "macos-es cannot correlate write-open AUTH; DENY");
            respond_deny_open_flags(client, message);
            return;
        }
    };
    if event.file.is_null() {
        respond_deny_open_flags(client, message);
        return;
    }
    let file = unsafe { &*event.file };
    let target_path = key.primary_path.clone();
    let stat = file.stat;
    let dedup_key = (command, stat.st_dev as u64, stat.st_ino);

    // A prior *successful* write-open already established the command's
    // original pre-image. Failed AUTH attempts never enter this map.
    let already_captured = match pump.open_dedup.lock() {
        Ok(g) => g.contains_key(&dedup_key),
        Err(_) => {
            respond_deny_open_flags(client, message);
            return;
        }
    };
    if already_captured {
        respond_allow_open_flags(client, message, fflag as u32);
        return;
    }

    // Existing zero-byte files are still real pre-images: restoring an empty
    // file is distinct from treating it as newly created/nonexistent.
    let (staging_fd, xattrs) =
        match inline_clonefile(&target_path, pump.staging_dir_fd.as_raw_fd(), &stat) {
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
        staging_fd,
        dev: stat.st_dev as u64,
        inode: stat.st_ino,
        expected_size: stat.st_size as u64,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mtime_unix_nanos: (stat.st_mtime as i128) * 1_000_000_000 + (stat.st_mtime_nsec as i128),
        flags: stat.st_flags,
        xattrs,
        // The path survives post-open; we just captured the pre-write
        // bytes. Undo restores the bytes; no TreeOp::Unlink needed.
        is_delete: false,
    });
    stage_pending_auth(
        pump,
        client,
        message,
        AuthResponder::Open {
            fflag: fflag as u32,
        },
        key,
        PendingSnapshot {
            command,
            path: path_to_string(&target_path),
            records: vec![record],
            open_dedup_key: Some(dedup_key),
            auth_mach_time: msg.mach_time(),
            auth_global_seq_num: msg.global_seq_num().unwrap_or(0),
            created_at: Instant::now(),
        },
    );
}

/// AUTH_RENAME handler. Stages TreeMutation(Rename), plus CapturedPreImage
/// when the destination exists. Neither becomes visible until a matching
/// successful NOTIFY_RENAME arrives.
fn handle_auth_rename(
    pump: &PumpHandle,
    client: *mut sys::es_client_t,
    message: *const c_void,
    msg: &EsMessage<'_>,
) {
    let token = msg.process_audit_token();
    let command = match command_for_auth(pump, token) {
        Ok(command) => command,
        Err(()) => {
            respond_deny(client, message);
            return;
        }
    };
    let Some(command) = command else {
        respond_allow(client, message);
        return;
    };
    pump.events_passed_filter.fetch_add(1, Ordering::Relaxed);

    let key = match make_pending_key(msg, MutationFamily::Rename) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(err = %error, "macos-es cannot correlate rename AUTH; DENY");
            respond_deny(client, message);
            return;
        }
    };
    let Some(rename) = msg.as_rename() else {
        respond_deny(client, message);
        return;
    };
    let Some(source_file) = (unsafe { rename.source.as_ref() }) else {
        respond_deny(client, message);
        return;
    };
    let source_path = key.primary_path.clone();
    let source_stat = source_file.stat;
    let Some(dest_path) = key.secondary_path.clone() else {
        respond_deny(client, message);
        return;
    };
    let from = match path_to_string(&source_path) {
        Some(path) => path,
        None => {
            respond_deny(client, message);
            return;
        }
    };
    let to = match path_to_string(&dest_path) {
        Some(path) => path,
        None => {
            respond_deny(client, message);
            return;
        }
    };

    let ts_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    let mut records = Vec::with_capacity(2);
    // If destination pre-exists, capture its bytes BEFORE allowing the
    // rename. Both this record and the tree-op remain pending until NOTIFY.
    if rename.destination_type == crate::es::message::es_destination_type_t::EXISTING_FILE {
        let Some(dest_file) = (unsafe { rename.destination.existing_file.as_ref() }) else {
            respond_deny(client, message);
            return;
        };
        let (staging_fd, xattrs) =
            match inline_clonefile(&dest_path, pump.staging_dir_fd.as_raw_fd(), &dest_file.stat) {
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
            staging_fd,
            dev: dest_stat.st_dev as u64,
            inode: dest_stat.st_ino,
            expected_size: dest_stat.st_size as u64,
            mode: dest_stat.st_mode as u32,
            uid: dest_stat.st_uid,
            gid: dest_stat.st_gid,
            mtime_unix_nanos: (dest_stat.st_mtime as i128) * 1_000_000_000
                + (dest_stat.st_mtime_nsec as i128),
            flags: dest_stat.st_flags,
            xattrs,
            is_delete: true,
        });
        records.push(record);
    }

    // Always emit TreeMutation(Rename) so undo can invert the
    // namespace shift. dev/inode come from source (the renamed file).
    let tree_record = CaptureRecord::TreeOp(TreeOpRecord {
        command,
        op: shit_proto::TreeOpWire::Rename {
            from,
            to,
            dev: source_stat.st_dev as u64,
            inode: source_stat.st_ino,
        },
        ts_unix_nanos,
    });
    records.push(tree_record);
    stage_pending_auth(
        pump,
        client,
        message,
        AuthResponder::Ordinary,
        key,
        PendingSnapshot {
            command,
            path: path_to_string(&source_path),
            records,
            open_dedup_key: None,
            auth_mach_time: msg.mach_time(),
            auth_global_seq_num: msg.global_seq_num().unwrap_or(0),
            created_at: Instant::now(),
        },
    );
}

fn cleanup_dropped_record(rec: CaptureRecord) {
    match rec {
        CaptureRecord::PreImage(p) => drop(p.staging_fd),
        CaptureRecord::TreeOp(_) | CaptureRecord::CaptureRefused(_) => {}
    }
}

/// Extract the BSD pid stored in `audit_token_t.val[5]` per Apple's
/// `audit_token_to_pid()` macro in `<bsm/libbsm.h>`.
fn pid_from_audit_token(token: &audit_token_t) -> i32 {
    token.val[5] as i32
}

fn audit_token_has_uid(token: &audit_token_t, daemon_uid: u32) -> bool {
    // `<bsm/audit.h>` user-token layout: euid at val[1], ruid at val[3].
    token.val[1] == daemon_uid && token.val[3] == daemon_uid
}

fn audit_token_matches_boundary(token: &audit_token_t, daemon_uid: u32, daemon_asid: u32) -> bool {
    audit_token_has_uid(token, daemon_uid) && token.val[6] == daemon_asid
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
        root_pid: i32,
        /// Zero-capacity rendezvous: if the caller's bounded wait expires,
        /// `send` fails and the pump rolls a successful late attach back.
        completion: SyncSender<Result<(), CaptureAttachError>>,
    },
    Detach {
        command: CommandId,
        completion: SyncSender<Result<(), CaptureDetachError>>,
    },
    Shutdown,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureStartError {
    #[error("initialize macOS EndpointSecurity staging root: {0}")]
    Staging(#[source] std::io::Error),
    #[error("spawn macOS EndpointSecurity capture pump: {0}")]
    ThreadSpawn(#[source] std::io::Error),
    #[error(transparent)]
    EndpointSecurity(#[from] crate::es::client::EsClientError),
    #[error("macOS EndpointSecurity producer singleton is already initialized")]
    AlreadyInitialized,
    #[error("macOS EndpointSecurity pump exited before reporting startup")]
    StartupChannelClosed,
    #[error("invalid authenticated daemon pid {0}")]
    InvalidDaemonPid(u32),
    #[error("could not resolve audit identity for authenticated daemon pid {0}")]
    DaemonAuditTokenUnavailable(i32),
    #[error("authenticated daemon pid {pid} does not match uid {daemon_uid}")]
    DaemonIdentityMismatch { pid: i32, daemon_uid: u32 },
    #[error("could not validate authenticated daemon pid {pid}: {source}")]
    DaemonValidation {
        pid: i32,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureAttachError {
    #[error("invalid macOS EndpointSecurity root pid {0}")]
    InvalidPid(u32),
    #[error("macOS EndpointSecurity watch cwd must be an absolute non-empty path")]
    InvalidCwd,
    #[error("macOS EndpointSecurity capture control channel is full")]
    ControlChannelFull,
    #[error("macOS EndpointSecurity capture control channel is closed")]
    ControlChannelClosed,
    #[error("macOS EndpointSecurity capture pump dropped the attach completion channel")]
    CompletionChannelClosed,
    #[error(
        "macOS EndpointSecurity capture pump timed out after {timeout:?} while attaching; pump state is unknown"
    )]
    CompletionTimeout { timeout: Duration },
    #[error("macOS EndpointSecurity worker is unavailable")]
    WorkerUnavailable,
    #[error("could not resolve audit identity for pid {0}")]
    AuditTokenUnavailable(i32),
    #[error("pid {pid} does not belong to authenticated daemon uid {daemon_uid}")]
    WrongUid { pid: i32, daemon_uid: u32 },
    #[error("could not validate pid {pid}: {source}")]
    ProcessValidation {
        pid: i32,
        #[source]
        source: std::io::Error,
    },
    #[error("pid {pid} cwd does not match requested watch root {root_path:?}")]
    CwdMismatch { pid: i32, root_path: PathBuf },
    #[error("macOS EndpointSecurity process tracking state is unavailable")]
    TrackingUnavailable,
    #[error("macOS EndpointSecurity process identity is already attached: {0}")]
    AlreadyAttached(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureDetachError {
    #[error("macOS EndpointSecurity capture control channel is full")]
    ControlChannelFull,
    #[error("macOS EndpointSecurity capture control channel is closed")]
    ControlChannelClosed,
    #[error("macOS EndpointSecurity capture pump dropped the detach completion channel")]
    CompletionChannelClosed,
    #[error(
        "macOS EndpointSecurity capture pump timed out after {timeout:?} while detaching; pump state is unknown"
    )]
    CompletionTimeout { timeout: Duration },
    #[error("macOS EndpointSecurity worker is unavailable")]
    WorkerUnavailable,
    #[error("macOS EndpointSecurity tracking state is unavailable")]
    TrackingUnavailable,
    #[error("macOS EndpointSecurity record ring disconnected during detach")]
    RingDisconnected,
    #[error("emit final macOS EndpointSecurity state while detaching: {0}")]
    Emit(#[source] crate::ipc::ConnError),
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
        root_pid: u32,
        cwd_path: &str,
    ) -> Result<(), CaptureAttachError> {
        if cwd_path.is_empty() || !Path::new(cwd_path).is_absolute() {
            return Err(CaptureAttachError::InvalidCwd);
        }
        let root_pid = i32::try_from(root_pid)
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or(CaptureAttachError::InvalidPid(root_pid))?;
        let command = CommandId {
            session,
            seq: command_seq,
        };
        // A rendezvous channel closes the attach-timeout race: the pump cannot
        // successfully hand off `Ok(())` after this receiver has timed out.
        let (completion_tx, completion_rx) = sync_channel(0);
        self.tx
            .try_send(ControlMsg::Attach {
                command,
                root_path: PathBuf::from(cwd_path),
                root_pid,
                completion: completion_tx,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => CaptureAttachError::ControlChannelFull,
                TrySendError::Disconnected(_) => CaptureAttachError::ControlChannelClosed,
            })?;
        recv_attach_completion(completion_rx, CONTROL_COMPLETION_TIMEOUT)
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
        let (completion_tx, completion_rx) = sync_channel(0);
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
) -> Result<(), CaptureAttachError> {
    completion
        .recv_timeout(timeout)
        .map_err(|error| match error {
            RecvTimeoutError::Timeout => CaptureAttachError::CompletionTimeout { timeout },
            RecvTimeoutError::Disconnected => CaptureAttachError::CompletionChannelClosed,
        })?
}

fn recv_detach_completion(
    completion: Receiver<Result<(), CaptureDetachError>>,
    timeout: Duration,
) -> Result<(), CaptureDetachError> {
    completion
        .recv_timeout(timeout)
        .map_err(|error| match error {
            RecvTimeoutError::Timeout => CaptureDetachError::CompletionTimeout { timeout },
            RecvTimeoutError::Disconnected => CaptureDetachError::CompletionChannelClosed,
        })?
}

/// Deliver an attach result across the zero-capacity rendezvous. `true` means
/// attach succeeded after its caller disappeared, so the pump must immediately
/// detach the command instead of leaving stale active tracking behind.
fn late_attach_requires_rollback(
    completion: SyncSender<Result<(), CaptureAttachError>>,
    result: Result<(), CaptureAttachError>,
) -> bool {
    let attached = result.is_ok();
    completion.send(result).is_err() && attached
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
    daemon_pid: u32,
    daemon_uid: u32,
) -> Result<(CaptureControl, JoinHandle<()>), CaptureStartError> {
    let daemon_pid = i32::try_from(daemon_pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or(CaptureStartError::InvalidDaemonPid(daemon_pid))?;
    let daemon_token = validate_daemon_identity(daemon_pid, daemon_uid)?;
    let daemon_asid = daemon_token.val[6];
    let staging_dir_fd = open_staging_root(&staging_dir).map_err(CaptureStartError::Staging)?;
    let (ctrl_tx, ctrl_rx) = sync_channel::<ControlMsg>(CONTROL_CHANNEL_CAPACITY);
    let (startup_tx, startup_rx) = sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("shit-macos-es-capture-pump".to_string())
        .spawn(move || {
            pump(
                conn,
                staging_dir,
                staging_dir_fd,
                daemon_uid,
                daemon_asid,
                ctrl_rx,
                startup_tx,
            )
        })
        .map_err(CaptureStartError::ThreadSpawn)?;
    match startup_rx.recv() {
        Ok(Ok(())) => Ok((CaptureControl { tx: ctrl_tx }, handle)),
        Ok(Err(error)) => {
            drop(ctrl_tx);
            let _ = handle.join();
            Err(error)
        }
        Err(_) => {
            drop(ctrl_tx);
            let _ = handle.join();
            Err(CaptureStartError::StartupChannelClosed)
        }
    }
}

fn open_staging_root(path: &Path) -> std::io::Result<OwnedFd> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging root path contains NUL",
        )
    })?;
    if unsafe { libc::mkdir(c_path.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
    }
    let raw = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stat = fstat_fd(fd.as_raw_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR || stat.st_uid != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "EndpointSecurity staging root must be a root-owned directory",
        ));
    }
    if stat.st_mode & 0o7777 != 0o700 {
        if unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        stat = fstat_fd(fd.as_raw_fd())?;
    }
    if stat.st_uid != 0
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "EndpointSecurity staging root failed root-owner/mode verification",
        ));
    }
    Ok(fd)
}

fn read_proc_bsdinfo(pid: i32) -> std::io::Result<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let rc =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if rc != size {
        return Err(if rc < 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::other(format!(
                "PROC_PIDTBSDINFO returned {rc} bytes, expected {size}"
            ))
        });
    }
    Ok(info)
}

fn read_proc_cwd_identity(pid: i32) -> std::io::Result<(u32, u64)> {
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as i32;
    let rc = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if rc != size {
        return Err(if rc < 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::other(format!(
                "PROC_PIDVNODEPATHINFO returned {rc} bytes, expected {size}"
            ))
        });
    }
    let stat = info.pvi_cdir.vip_vi.vi_stat;
    Ok((stat.vst_dev, stat.vst_ino))
}

fn proc_identity_matches(info: &libc::proc_bsdinfo, pid: i32, daemon_uid: u32) -> bool {
    info.pbi_pid as i32 == pid
        && info.pbi_uid == daemon_uid
        && info.pbi_ruid == daemon_uid
        && info.pbi_svuid == daemon_uid
}

fn live_process_matches_boundary(token: audit_token_t, daemon_uid: u32, daemon_asid: u32) -> bool {
    let pid = pid_from_audit_token(&token);
    if pid <= 0 || !audit_token_matches_boundary(&token, daemon_uid, daemon_asid) {
        return false;
    }
    let Ok(info) = read_proc_bsdinfo(pid) else {
        return false;
    };
    if !proc_identity_matches(&info, pid, daemon_uid) {
        return false;
    }
    audit_token_for_pid(pid) == Some(token)
}

fn validate_attached_process(
    pid: i32,
    daemon_uid: u32,
    daemon_asid: u32,
    root_path: &Path,
) -> Result<audit_token_t, CaptureAttachError> {
    let token = audit_token_for_pid(pid).ok_or(CaptureAttachError::AuditTokenUnavailable(pid))?;
    if pid_from_audit_token(&token) != pid
        || !audit_token_matches_boundary(&token, daemon_uid, daemon_asid)
    {
        return Err(CaptureAttachError::WrongUid { pid, daemon_uid });
    }
    let bsd = read_proc_bsdinfo(pid)
        .map_err(|source| CaptureAttachError::ProcessValidation { pid, source })?;
    if !proc_identity_matches(&bsd, pid, daemon_uid) {
        return Err(CaptureAttachError::WrongUid { pid, daemon_uid });
    }
    let expected_cwd = read_proc_cwd_identity(pid)
        .map_err(|source| CaptureAttachError::ProcessValidation { pid, source })?;
    let c_path = CString::new(root_path.as_os_str().as_bytes()).map_err(|_| {
        CaptureAttachError::ProcessValidation {
            pid,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "watch root contains NUL",
            ),
        }
    })?;
    let raw = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(CaptureAttachError::ProcessValidation {
            pid,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `raw` is a fresh descriptor owned here.
    let root_fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let root_stat = fstat_fd(root_fd.as_raw_fd())
        .map_err(|source| CaptureAttachError::ProcessValidation { pid, source })?;
    if (root_stat.st_dev as u32, root_stat.st_ino) != expected_cwd {
        return Err(CaptureAttachError::CwdMismatch {
            pid,
            root_path: root_path.to_path_buf(),
        });
    }
    let token_after =
        audit_token_for_pid(pid).ok_or(CaptureAttachError::AuditTokenUnavailable(pid))?;
    if token_after != token || !audit_token_matches_boundary(&token_after, daemon_uid, daemon_asid)
    {
        return Err(CaptureAttachError::WrongUid { pid, daemon_uid });
    }
    Ok(token)
}

fn validate_daemon_identity(pid: i32, daemon_uid: u32) -> Result<audit_token_t, CaptureStartError> {
    let token =
        audit_token_for_pid(pid).ok_or(CaptureStartError::DaemonAuditTokenUnavailable(pid))?;
    if pid_from_audit_token(&token) != pid || !audit_token_has_uid(&token, daemon_uid) {
        return Err(CaptureStartError::DaemonIdentityMismatch { pid, daemon_uid });
    }
    let bsd = read_proc_bsdinfo(pid)
        .map_err(|source| CaptureStartError::DaemonValidation { pid, source })?;
    if !proc_identity_matches(&bsd, pid, daemon_uid) {
        return Err(CaptureStartError::DaemonIdentityMismatch { pid, daemon_uid });
    }
    let token_after =
        audit_token_for_pid(pid).ok_or(CaptureStartError::DaemonAuditTokenUnavailable(pid))?;
    if token_after != token || !audit_token_has_uid(&token_after, daemon_uid) {
        return Err(CaptureStartError::DaemonIdentityMismatch { pid, daemon_uid });
    }
    Ok(token)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RingPoll {
    Drained,
    Empty,
    Disconnected,
}

impl Drop for PumpState {
    fn drop(&mut self) {
        let Some(pump) = PUMP.get() else {
            return;
        };
        pump.worker_alive.store(false, Ordering::Release);
        let pending = match pump.pending.lock() {
            Ok(mut table) => table.take_all(),
            Err(poisoned) => poisoned.into_inner().take_all(),
        };
        for snapshot in pending {
            let units = snapshot.records.len();
            cleanup_pending_snapshot(snapshot);
            release_record_units(pump, units);
        }
        while let Ok(record) = self.ring_rx.try_recv() {
            cleanup_dropped_record(record);
            release_record_units(pump, 1);
        }
    }
}

impl PumpState {
    /// Construct the pump state + install `PUMP` + subscribe ES.
    ///
    /// Must be called on the pump thread (EsClient is `!Send`).
    fn new(
        conn: Arc<Conn>,
        staging_dir: PathBuf,
        staging_dir_fd: OwnedFd,
        daemon_uid: u32,
        daemon_asid: u32,
    ) -> Result<Self, CaptureStartError> {
        // Bound the ring at a size that gives the worker a few seconds
        // of headroom at peak rate but back-pressures the kernel
        // callback (which DENYs on Full) before unbounded memory growth.
        // 1024 matches the BSD producer's sizing.
        let (ring_tx, ring_rx) = sync_channel::<CaptureRecord>(RECORD_CHANNEL_CAPACITY);

        // Install PUMP exactly once. If a prior pump init left PUMP
        // populated (shouldn't happen — single producer per process),
        // bail rather than silently shadowing.
        let handle = PumpHandle {
            processes: Mutex::new(ProcessTable::default()),
            daemon_uid,
            daemon_asid,
            open_dedup: Mutex::new(HashMap::new()),
            pending: Mutex::new(PendingTable::default()),
            outstanding_records: AtomicUsize::new(0),
            worker_alive: AtomicBool::new(false),
            ring_tx,
            staging_dir_fd,
            events_seen: AtomicU64::new(0),
            events_passed_filter: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
        };
        PUMP.set(handle)
            .map_err(|_| CaptureStartError::AlreadyInitialized)?;

        // Subscribe with the producer handler. Every mutation AUTH family has
        // its paired NOTIFY subscription so staged records can be committed
        // only after the operation succeeds. NOTIFY_EXEC/FORK/EXIT provide
        // process-tree tracking and require no response.
        let events = [
            sys::es_event_type_t::AUTH_OPEN,
            sys::es_event_type_t::AUTH_UNLINK,
            sys::es_event_type_t::AUTH_RENAME,
            sys::es_event_type_t::AUTH_TRUNCATE,
            sys::es_event_type_t::AUTH_SETMODE,
            sys::es_event_type_t::AUTH_SETOWNER,
            sys::es_event_type_t::AUTH_UTIMES,
            sys::es_event_type_t::NOTIFY_OPEN,
            sys::es_event_type_t::NOTIFY_UNLINK,
            sys::es_event_type_t::NOTIFY_RENAME,
            sys::es_event_type_t::NOTIFY_TRUNCATE,
            sys::es_event_type_t::NOTIFY_SETMODE,
            sys::es_event_type_t::NOTIFY_SETOWNER,
            sys::es_event_type_t::NOTIFY_UTIMES,
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

        if let Some(pump) = PUMP.get() {
            pump.worker_alive.store(true, Ordering::Release);
        }

        Ok(Self {
            conn,
            staging_dir,
            client,
            ring_rx,
        })
    }

    fn attach(
        &mut self,
        command: CommandId,
        root_path: PathBuf,
        pid: i32,
    ) -> Result<(), CaptureAttachError> {
        let pump = PUMP.get().ok_or(CaptureAttachError::WorkerUnavailable)?;
        if !pump.worker_alive.load(Ordering::Acquire) {
            return Err(CaptureAttachError::WorkerUnavailable);
        }
        let token = validate_attached_process(pid, pump.daemon_uid, pump.daemon_asid, &root_path)?;
        {
            let mut pending = pump
                .pending
                .lock()
                .map_err(|_| CaptureAttachError::TrackingUnavailable)?;
            if !pending.activate(command) {
                return Err(CaptureAttachError::AlreadyAttached(
                    "command is already attached to EndpointSecurity",
                ));
            }
        }
        let process_result = pump
            .processes
            .lock()
            .map_err(|_| CaptureAttachError::TrackingUnavailable)
            .and_then(|mut processes| {
                processes
                    .insert_root(token, command)
                    .map_err(CaptureAttachError::AlreadyAttached)
            });
        if let Err(error) = process_result {
            if let Ok(mut pending) = pump.pending.lock() {
                pending.deactivate(command);
            } else {
                pump.worker_alive.store(false, Ordering::Release);
            }
            return Err(error);
        }
        tracing::info!(
            %command.session,
            seq = command.seq,
            path = %root_path.display(),
            pid,
            "macos-es watch attached"
        );
        Ok(())
    }

    fn detach(&mut self, command: CommandId) -> Result<(), CaptureDetachError> {
        let pump = PUMP.get().ok_or(CaptureDetachError::WorkerUnavailable)?;
        let mut first_error = (!pump.worker_alive.load(Ordering::Acquire))
            .then_some(CaptureDetachError::WorkerUnavailable);

        // Stop future AUTH staging before removing process identities. An AUTH
        // callback that already resolved the process must acquire this same
        // mutex to insert, so it will DENY rather than appear behind the
        // detach barrier.
        match pump.pending.lock() {
            Ok(mut pending) => pending.deactivate(command),
            Err(poisoned) => {
                pump.worker_alive.store(false, Ordering::Release);
                poisoned.into_inner().deactivate(command);
                first_error = Some(CaptureDetachError::TrackingUnavailable);
            }
        }
        match pump.processes.lock() {
            Ok(mut processes) => processes.remove_command(command),
            Err(poisoned) => {
                pump.worker_alive.store(false, Ordering::Release);
                poisoned.into_inner().remove_command(command);
                if first_error.is_none() {
                    first_error = Some(CaptureDetachError::TrackingUnavailable);
                }
            }
        }

        // ES delivers NOTIFY asynchronously. Give already-authorized syscalls
        // a bounded grace to either commit/discard, draining every committed
        // record as it becomes visible. `commit_notify` keeps the pending-table
        // mutex through its ring enqueue, so observing no pending snapshot and
        // then an empty ring is an internal completion barrier.
        let deadline = Instant::now() + DETACH_NOTIFY_GRACE;
        loop {
            self.drain_ring_until_empty(&mut first_error);
            let still_pending = match pump.pending.lock() {
                Ok(pending) => pending.contains_command(command),
                Err(poisoned) => {
                    pump.worker_alive.store(false, Ordering::Release);
                    let still_pending = poisoned.into_inner().contains_command(command);
                    if first_error.is_none() {
                        first_error = Some(CaptureDetachError::TrackingUnavailable);
                    }
                    still_pending
                }
            };
            if !still_pending || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        let unresolved = match pump.pending.lock() {
            Ok(mut pending) => pending.take_command(command),
            Err(poisoned) => {
                pump.worker_alive.store(false, Ordering::Release);
                if first_error.is_none() {
                    first_error = Some(CaptureDetachError::TrackingUnavailable);
                }
                poisoned.into_inner().take_command(command)
            }
        };
        for snapshot in unresolved {
            if let Err(source) = self.emit_pending_refusal(pump, snapshot, DETACHED_AUTH_REFUSAL)
                && first_error.is_none()
            {
                first_error = Some(CaptureDetachError::Emit(source));
            }
        }
        self.drain_ring_until_empty(&mut first_error);

        // Drop the per-command open-dedup entries — the next command's
        // PreImage shouldn't be suppressed by stale state.
        match pump.open_dedup.lock() {
            Ok(mut dedup) => dedup.retain(|(cmd, _, _), _| *cmd != command),
            Err(poisoned) => {
                pump.worker_alive.store(false, Ordering::Release);
                poisoned
                    .into_inner()
                    .retain(|(cmd, _, _), _| *cmd != command);
                if first_error.is_none() {
                    first_error = Some(CaptureDetachError::TrackingUnavailable);
                }
            }
        }
        tracing::info!(
            %command.session,
            seq = command.seq,
            "macos-es watch detached after completion barrier"
        );
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn drain_ring_until_empty(&mut self, first_error: &mut Option<CaptureDetachError>) {
        loop {
            match self.drain_ring_once() {
                Ok(RingPoll::Drained) => {}
                Ok(RingPoll::Empty) => return,
                Ok(RingPoll::Disconnected) => {
                    if first_error.is_none() {
                        *first_error = Some(CaptureDetachError::RingDisconnected);
                    }
                    return;
                }
                Err(source) => {
                    if first_error.is_none() {
                        *first_error = Some(CaptureDetachError::Emit(source));
                    }
                }
            }
        }
    }

    fn emit_pending_refusal(
        &self,
        pump: &PumpHandle,
        snapshot: PendingSnapshot,
        detail: &'static str,
    ) -> Result<(), crate::ipc::ConnError> {
        let PendingSnapshot {
            command,
            path,
            records,
            ..
        } = snapshot;
        let units = records.len();
        for record in records {
            cleanup_dropped_record(record);
        }
        release_record_units(pump, units);
        self.emit_capture_refused(CaptureRefusedRecord {
            command,
            path,
            detail,
        })
    }

    fn drain_ring_once(&mut self) -> Result<RingPoll, crate::ipc::ConnError> {
        let rec = match self.ring_rx.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) => return Ok(RingPoll::Empty),
            Err(TryRecvError::Disconnected) => {
                tracing::warn!("macos-es ring disconnected; pump exiting");
                return Ok(RingPoll::Disconnected);
            }
        };
        let emitted = match rec {
            CaptureRecord::PreImage(p) => self.emit_captured_preimage(p),
            CaptureRecord::TreeOp(t) => self.emit_tree_mutation(t),
            CaptureRecord::CaptureRefused(r) => self.emit_capture_refused(r),
        };
        if let Some(pump) = PUMP.get() {
            release_record_units(pump, 1);
            if emitted.is_ok() {
                pump.events_emitted.fetch_add(1, Ordering::Relaxed);
            }
        }
        emitted.map(|()| RingPoll::Drained)
    }

    fn emit_captured_preimage(&self, rec: PreImageRecord) -> Result<(), crate::ipc::ConnError> {
        // Hash via pread so the staging fd's offset stays at 0 — the
        // daemon-side recvmsg fd shares this open-file-description
        // and reads starting at 0.
        let claimed_size = match verify_staging_fd(rec.staging_fd.as_raw_fd(), rec.expected_size) {
            Ok(()) => rec.expected_size,
            Err(error) => {
                tracing::error!(
                    %rec.command.session,
                    seq = rec.command.seq,
                    path = %rec.path.display(),
                    err = %error,
                    "macos-es staging identity verification failed; refusing capture"
                );
                return self.emit_capture_refused(CaptureRefusedRecord {
                    command: rec.command,
                    path: path_to_string(&rec.path),
                    detail: "macOS EndpointSecurity could not verify the staging snapshot; refusing unsafe undo",
                });
            }
        };
        let (blob_hash, stored_bytes) = match hash_via_pread(
            rec.staging_fd.as_raw_fd(),
            claimed_size,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    %rec.command.session,
                    seq = rec.command.seq,
                    path = %rec.path.display(),
                    err = %e,
                    "macos-es worker hash failed; refusing capture"
                );
                return self.emit_capture_refused(CaptureRefusedRecord {
                    command: rec.command,
                    path: path_to_string(&rec.path),
                    detail: "macOS EndpointSecurity could not hash the complete staging snapshot; refusing unsafe undo",
                });
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
            xattrs: rec.xattrs,
            is_delete: rec.is_delete,
            fd_sent_via_scm: true,
            // M03.x.SETATTR — st_flags from the kernel-attached stat
            // taken at AUTH event time (pre-syscall). clonefile
            // preserves flags but we capture from the original
            // record (rec.flags) rather than the staging fd's stat
            // because the original is what undo needs to restore.
            flags: rec.flags,
        };

        self.conn
            .send_response_with_fd(&resp, rec.staging_fd.as_raw_fd())?;
        tracing::info!(
            %rec.command.session,
            seq = rec.command.seq,
            path = %rec.path.display(),
            dev = rec.dev,
            inode = rec.inode,
            bytes = stored_bytes,
            "macos-es CapturedPreImage sent"
        );
        Ok(())
    }

    fn emit_tree_mutation(&self, rec: TreeOpRecord) -> Result<(), crate::ipc::ConnError> {
        let resp = HelperResponse::TreeMutation {
            session: rec.command.session,
            seq: rec.command.seq,
            op: rec.op,
            ts_unix_nanos: rec.ts_unix_nanos,
            partial: false,
        };
        self.conn.send_response(&resp)
    }

    fn emit_capture_refused(&self, rec: CaptureRefusedRecord) -> Result<(), crate::ipc::ConnError> {
        let resp = HelperResponse::CaptureRefused {
            session: rec.command.session,
            seq: rec.command.seq,
            path: rec.path,
            detail: rec.detail.to_owned(),
        };
        self.conn.send_response(&resp)
    }
}

fn pump(
    conn: Arc<Conn>,
    staging_dir: PathBuf,
    staging_dir_fd: OwnedFd,
    daemon_uid: u32,
    daemon_asid: u32,
    ctrl_rx: Receiver<ControlMsg>,
    startup_tx: SyncSender<Result<(), CaptureStartError>>,
) {
    let mut state = match PumpState::new(conn, staging_dir, staging_dir_fd, daemon_uid, daemon_asid)
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(err = ?e, "macos-es PumpState init failed; ES producer disabled");
            let _ = startup_tx.send(Err(e));
            return;
        }
    };
    if startup_tx.send(Ok(())).is_err() {
        return;
    }
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
                completion,
            }) => {
                let result = state.attach(command, root_path, root_pid);
                if late_attach_requires_rollback(completion, result) {
                    // The zero-capacity completion rendezvous fails only when
                    // the request-loop waiter has gone away (notably after its
                    // bounded timeout). A successful late attach must not keep
                    // this command active forever. Detach removes tracking
                    // before its bounded NOTIFY/drain work; an error is logged,
                    // never reported as proof that worker cleanup completed.
                    tracing::warn!(
                        %command.session,
                        seq = command.seq,
                        "macos-es attach caller timed out; rolling back late attach"
                    );
                    if let Err(error) = state.detach(command) {
                        tracing::error!(
                            %command.session,
                            seq = command.seq,
                            %error,
                            "macos-es late-attach rollback did not complete cleanly"
                        );
                    }
                }
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
                        "macos-es detach caller dropped completion channel"
                    );
                }
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

        // 2. Expire AUTH snapshots even during otherwise-idle commands.
        if let Some(pump) = PUMP.get() {
            expire_pending_auth(pump);
        }

        // 3. Drain the kernel-callback → pump ring. If a record was
        //    available, loop again immediately (avoid the idle sleep)
        //    to keep up with bursts.
        match state.drain_ring_once() {
            Ok(RingPoll::Drained) => continue,
            Ok(RingPoll::Empty) => {}
            Ok(RingPoll::Disconnected) => {
                if let Some(pump) = PUMP.get() {
                    pump.worker_alive.store(false, Ordering::Release);
                }
                tracing::error!("macos-es record ring disconnected; pump exiting");
                return;
            }
            Err(error) => {
                if let Some(pump) = PUMP.get() {
                    pump.worker_alive.store(false, Ordering::Release);
                }
                tracing::error!(%error, "macos-es record emission failed; pump exiting");
                return;
            }
        }

        // 4. Periodic counter dump for operator observability.
        // DEBUG level so it's available via RUST_LOG=debug but
        // doesn't flood prod INFO logs.
        if last_tick.elapsed() >= Duration::from_secs(10) {
            if let Some(pump) = PUMP.get() {
                let seen = pump.events_seen.load(Ordering::Relaxed);
                let passed = pump.events_passed_filter.load(Ordering::Relaxed);
                let emitted = pump.events_emitted.load(Ordering::Relaxed);
                let tracked = pump.processes.lock().map(|g| g.len()).unwrap_or(0);
                tracing::debug!(seen, passed, emitted, tracked, "macos-es counters");
            }
            last_tick = std::time::Instant::now();
        }

        // 5. Idle.
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
    fn metadata_families_are_explicitly_non_actionable() {
        assert_eq!(
            metadata_capture_policy(sys::es_event_type_t::AUTH_UTIMES),
            MetadataCapturePolicy::Refuse(UTIMES_CAPTURE_REFUSAL)
        );
        assert_eq!(
            metadata_capture_policy(sys::es_event_type_t::AUTH_SETMODE),
            MetadataCapturePolicy::Refuse(SETMODE_CAPTURE_REFUSAL)
        );
        assert_eq!(
            metadata_capture_policy(sys::es_event_type_t::AUTH_SETOWNER),
            MetadataCapturePolicy::Refuse(SETOWNER_CAPTURE_REFUSAL)
        );
    }

    #[test]
    fn truncating_open_requires_a_preimage() {
        assert!(open_requires_snapshot(FFLAG_FWRITE));
        assert!(open_requires_snapshot(FFLAG_OTRUNC));
        assert!(open_requires_snapshot(FFLAG_FWRITE | FFLAG_OTRUNC));
        assert!(!open_requires_snapshot(0x01));
    }

    #[test]
    fn process_identity_requires_real_effective_and_saved_uid() {
        let pid = 42;
        let uid = 501;
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        info.pbi_pid = pid as u32;
        info.pbi_uid = uid;
        info.pbi_ruid = uid;
        info.pbi_svuid = uid;
        assert!(proc_identity_matches(&info, pid, uid));

        info.pbi_svuid = 0;
        assert!(!proc_identity_matches(&info, pid, uid));
        info.pbi_svuid = uid;
        info.pbi_ruid = 0;
        assert!(!proc_identity_matches(&info, pid, uid));
        info.pbi_ruid = uid;
        info.pbi_uid = 0;
        assert!(!proc_identity_matches(&info, pid, uid));
    }

    #[test]
    fn live_process_boundary_revalidates_the_complete_self_identity() {
        let token = crate::es::message::audit_token_self().expect("self audit token");
        let uid = unsafe { libc::geteuid() };
        assert_eq!(unsafe { libc::getuid() }, uid);
        assert!(live_process_matches_boundary(token, uid, token.val[6]));
    }

    #[test]
    fn attach_completion_timeout_closes_the_late_success_rendezvous() {
        let (completion, receiver) = sync_channel(0);
        let timeout = Duration::from_millis(10);

        let error = recv_attach_completion(receiver, timeout).unwrap_err();
        assert!(matches!(
            error,
            CaptureAttachError::CompletionTimeout { timeout: actual }
                if actual == timeout
        ));
        assert!(
            late_attach_requires_rollback(completion, Ok(())),
            "a pump finishing after timeout must roll back its late attach"
        );
    }

    #[test]
    fn detach_completion_timeout_closes_the_late_success_rendezvous() {
        let (completion, receiver) = sync_channel(0);
        let timeout = Duration::from_millis(10);

        let error = recv_detach_completion(receiver, timeout).unwrap_err();
        assert!(matches!(
            error,
            CaptureDetachError::CompletionTimeout { timeout: actual }
                if actual == timeout
        ));
        assert!(
            completion.send(Ok(())).is_err(),
            "a pump finishing after timeout must not resurrect the flush ack"
        );
    }

    #[test]
    fn unwatch_tree_waits_for_es_pump_completion() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        let control = CaptureControl { tx };
        let session = Uuid::nil();
        let waiter = std::thread::spawn(move || control.on_unwatch_tree(session, 63));

        let ControlMsg::Detach {
            command,
            completion,
        } = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("ES pump should receive detach")
        else {
            panic!("expected detach control message");
        };
        assert_eq!(command.session, session);
        assert_eq!(command.seq, 63);
        assert!(!waiter.is_finished());
        completion
            .send(Ok(()))
            .expect("unwatch request should still be waiting");
        assert!(waiter.join().expect("unwatch request panicked").is_ok());
    }

    #[test]
    fn unwatch_tree_reports_a_closed_es_control_channel() {
        let (tx, rx) = sync_channel::<ControlMsg>(1);
        drop(rx);
        let control = CaptureControl { tx };
        assert!(matches!(
            control.on_unwatch_tree(Uuid::nil(), 64),
            Err(CaptureDetachError::ControlChannelClosed)
        ));
    }

    fn process_test_token(pid: u32, uid: u32, asid: u32, generation: u32) -> audit_token_t {
        let mut val = [0u32; 8];
        val[1] = uid;
        val[3] = uid;
        val[5] = pid;
        val[6] = asid;
        val[7] = generation;
        audit_token_t { val }
    }

    #[test]
    fn process_table_refuses_token_generation_and_privilege_transitions() {
        let command = CommandId {
            session: Uuid::nil(),
            seq: 77,
        };
        let uid = 501;
        let asid = 9001;
        let original = process_test_token(42, uid, asid, 1);
        let mut table = ProcessTable::default();
        table.insert_root(original, command).unwrap();

        // An unseen token generation for the same pid is ambiguous until a
        // matching NOTIFY_EXEC transfers it, so mutation must be refused.
        let next = process_test_token(42, uid, asid, 2);
        assert_eq!(table.lookup(next), ProcessLookup::Refused(command));
        table.transfer_exec(original, next, true);
        assert_eq!(table.lookup(next), ProcessLookup::Tracked(command));

        let privileged = process_test_token(42, 0, asid, 3);
        table.transfer_exec(next, privileged, false);
        assert_eq!(table.lookup(privileged), ProcessLookup::Refused(command));

        let other_session = process_test_token(42, uid, asid + 1, 4);
        table.transfer_exec(privileged, other_session, false);
        assert_eq!(table.lookup(other_session), ProcessLookup::Refused(command));
    }

    #[test]
    fn process_table_refuses_exec_when_live_saved_uid_validation_fails() {
        let command = CommandId {
            session: Uuid::nil(),
            seq: 78,
        };
        let original = process_test_token(42, 501, 9001, 1);
        let next = process_test_token(42, 501, 9001, 2);
        let mut table = ProcessTable::default();
        table.insert_root(original, command).unwrap();

        table.transfer_exec(original, next, false);
        assert_eq!(table.lookup(next), ProcessLookup::Refused(command));
    }

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
    fn path_to_string_rejects_non_utf8_instead_of_lossy_conversion() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/\xff".to_vec()));
        assert_eq!(path_to_string(&path), None);
    }

    #[test]
    fn inline_clonefile_round_trips_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let payload = b"clonefile round-trip test bytes";
        std::fs::File::create(&src)
            .unwrap()
            .write_all(payload)
            .unwrap();

        let staging_dir = tmp.path().join("staging");
        std::fs::create_dir_all(&staging_dir).unwrap();
        let staging_root = std::fs::File::open(&staging_dir).unwrap();

        let source = std::fs::File::open(&src).unwrap();
        let stat = fstat_fd(source.as_raw_fd()).unwrap();
        let (fd, _xattrs) = inline_clonefile(&src, staging_root.as_raw_fd(), &stat).unwrap();
        // The staging inode is inaccessible by name before it enters any
        // pending/worker queue, but its held fd retains the exact bytes.
        assert_eq!(fstat_fd(fd.as_raw_fd()).unwrap().st_nlink, 0);
        assert_eq!(std::fs::read_dir(&staging_dir).unwrap().count(), 0);
        let (hash, len) = hash_via_pread(fd.as_raw_fd(), payload.len() as u64).unwrap();
        assert_eq!(len, payload.len() as u64);
        let expected = blake3::hash(payload);
        assert_eq!(hash, *expected.as_bytes());
        drop(fd);
    }

    #[test]
    fn stream_copy_round_trips_bytes() {
        // stream_copy_to_staging is the non-APFS fallback. It's
        // platform-portable (just pread + write), so we test it
        // directly on any tempdir.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let payload = b"stream-copy round-trip test bytes";
        std::fs::write(&src, payload).unwrap();

        let staging = tmp.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let staging_root = std::fs::File::open(&staging).unwrap();
        let source = std::fs::File::open(&src).unwrap();
        let (fd, _xattrs) = stream_copy_to_staging(
            source.as_raw_fd(),
            staging_root.as_raw_fd(),
            payload.len() as u64,
        )
        .expect("stream-copy");
        assert_eq!(fstat_fd(fd.as_raw_fd()).unwrap().st_nlink, 0);
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
        // pread the staging fd + verify content matches.
        let (hash, len) = hash_via_pread(fd.as_raw_fd(), payload.len() as u64).unwrap();
        assert_eq!(len, payload.len() as u64);
        let expected = blake3::hash(payload);
        assert_eq!(hash, *expected.as_bytes());
        // pwrite staging preserves the shared open-file-description offset at
        // zero for the eventual SCM_RIGHTS receiver.
        use std::io::Read;
        let mut staged_file: std::fs::File = fd.into();
        let mut bytes = Vec::new();
        staged_file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, payload);
    }

    #[test]
    fn stream_copy_refuses_oversize_file() {
        // Cap enforcement — caller's `expected_size` must be <=
        // STREAM_COPY_CAP. Anything larger errors out before we
        // touch the disk, preserving the ES 5-s auth deadline.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("oversize.txt");
        std::fs::write(&src, b"x").unwrap();
        let staging = tmp.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let staging_root = std::fs::File::open(&staging).unwrap();
        let source = std::fs::File::open(&src).unwrap();
        let res = stream_copy_to_staging(
            source.as_raw_fd(),
            staging_root.as_raw_fd(),
            STREAM_COPY_CAP + 1,
        );
        assert!(res.is_err(), "expected oversize-rejection error");
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    }

    #[test]
    fn stream_copy_rejects_short_source_and_removes_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("short.txt");
        std::fs::write(&src, b"x").unwrap();
        let source = std::fs::File::open(&src).unwrap();
        let staging = tmp.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let staging_root = std::fs::File::open(&staging).unwrap();

        let error =
            stream_copy_to_staging(source.as_raw_fd(), staging_root.as_raw_fd(), 2).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
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

    #[test]
    fn hash_via_pread_rejects_short_snapshot() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"x").unwrap();
        let file = std::fs::File::open(tmp.path()).unwrap();
        let error = hash_via_pread(file.as_raw_fd(), 2).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn zero_byte_existing_file_is_a_real_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("empty");
        std::fs::File::create(&src).unwrap();
        let source = std::fs::File::open(&src).unwrap();
        let stat = fstat_fd(source.as_raw_fd()).unwrap();
        let staging_dir = tmp.path().join("staging");
        std::fs::create_dir(&staging_dir).unwrap();
        let staging_root = std::fs::File::open(&staging_dir).unwrap();

        let (fd, _xattrs) = inline_clonefile(&src, staging_root.as_raw_fd(), &stat).unwrap();
        assert_eq!(fstat_fd(fd.as_raw_fd()).unwrap().st_size, 0);
        assert_eq!(fstat_fd(fd.as_raw_fd()).unwrap().st_nlink, 0);
        let (hash, bytes) = hash_via_pread(fd.as_raw_fd(), 0).unwrap();
        assert_eq!(bytes, 0);
        assert_eq!(hash, *blake3::hash(&[]).as_bytes());
        drop(fd);
    }

    fn pending_test_key() -> PendingKey {
        PendingKey {
            process: audit_token_t { val: [7; 8] },
            thread_id: 42,
            family: MutationFamily::Unlink,
            primary_dev: 1,
            primary_inode: 2,
            primary_path: PathBuf::from("/tmp/file"),
            secondary_dev: 0,
            secondary_inode: 0,
            secondary_path: None,
            qualifier: 0,
        }
    }

    fn pending_test_snapshot(created_at: Instant, seq: u64) -> PendingSnapshot {
        let command = CommandId {
            session: Uuid::nil(),
            seq,
        };
        PendingSnapshot {
            command,
            path: Some("/tmp/file".to_owned()),
            records: vec![CaptureRecord::CaptureRefused(CaptureRefusedRecord {
                command,
                path: Some("/tmp/file".to_owned()),
                detail: "test",
            })],
            open_dedup_key: None,
            auth_mach_time: 0,
            auth_global_seq_num: 0,
            created_at,
        }
    }

    #[test]
    fn pending_table_rejects_exact_key_collision_without_replacement() {
        let now = Instant::now();
        let key = pending_test_key();
        let mut table = PendingTable::default();
        assert!(table.activate(CommandId {
            session: Uuid::nil(),
            seq: 1,
        }));
        assert!(table.activate(CommandId {
            session: Uuid::nil(),
            seq: 2,
        }));
        assert!(
            table
                .insert(key.clone(), pending_test_snapshot(now, 1))
                .is_ok()
        );
        let rejected = table.insert(key.clone(), pending_test_snapshot(now, 2));
        assert!(rejected.is_err());
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries.get(&key).unwrap().command.seq, 1);
    }

    #[test]
    fn pending_table_expires_only_stale_auth_snapshots() {
        let now = Instant::now();
        let stale_key = pending_test_key();
        let mut fresh_key = pending_test_key();
        fresh_key.thread_id += 1;
        let mut table = PendingTable::default();
        assert!(table.activate(CommandId {
            session: Uuid::nil(),
            seq: 1,
        }));
        assert!(table.activate(CommandId {
            session: Uuid::nil(),
            seq: 2,
        }));
        assert!(
            table
                .insert(
                    stale_key.clone(),
                    pending_test_snapshot(now - PENDING_AUTH_TTL - Duration::from_millis(1), 1,),
                )
                .is_ok()
        );
        assert!(
            table
                .insert(fresh_key.clone(), pending_test_snapshot(now, 2))
                .is_ok()
        );

        let expired = table.take_expired(now);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].command.seq, 1);
        assert!(!table.entries.contains_key(&stale_key));
        assert!(table.entries.contains_key(&fresh_key));
    }

    #[test]
    fn pending_table_rejects_auth_after_detach_deactivation() {
        let command = CommandId {
            session: Uuid::nil(),
            seq: 3,
        };
        let mut table = PendingTable::default();
        assert!(table.activate(command));
        table.deactivate(command);
        assert!(
            table
                .insert(
                    pending_test_key(),
                    pending_test_snapshot(Instant::now(), command.seq),
                )
                .is_err()
        );
        assert!(table.entries.is_empty());
    }

    #[test]
    fn notify_must_be_temporally_after_the_staged_auth() {
        let mut snapshot = pending_test_snapshot(Instant::now(), 1);
        snapshot.auth_mach_time = 100;
        snapshot.auth_global_seq_num = 20;

        assert!(notify_follows_auth(&snapshot, 100, 21));
        assert!(notify_follows_auth(&snapshot, 101, 21));
        assert!(!notify_follows_auth(&snapshot, 99, 21));
        assert!(!notify_follows_auth(&snapshot, 101, 20));
        assert!(!notify_follows_auth(&snapshot, 101, 19));
    }
}
