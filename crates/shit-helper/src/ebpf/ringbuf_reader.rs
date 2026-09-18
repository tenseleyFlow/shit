// SPDX-License-Identifier: AGPL-3.0-or-later

//! L04 — Userspace consumer of the eBPF-LSM ringbufs.
//!
//! Pops records from `unlink_events` (and future `setattr_events`,
//! `mkdir_events`, `open_events`), decodes the C struct layout
//! defined in `bpf/src/common.h`, and dispatches into the helper's
//! capture runtime.
//!
//! **Status (L04 phase 2 chunk 2):** structure + decoder + stub
//! dispatcher that logs each event. The actual hook into
//! [`crate::capture::linux::LinuxCaptureRuntime::handle_event`]
//! (and the path-resolution + race-to-open work) lands in phase 2
//! chunk 3 via [`super::ringbuf_reader::LsmReader::dispatch_unlink`].
//!
//! Wire layout — must stay byte-identical with `bpf/src/common.h`:
//!
//! ```text
//! shit_event_hdr     (40 bytes)
//!   u8  kind              offset  0
//!   u8  _pad[3]           offset  1
//!   u32 pid               offset  4
//!   u32 tgid              offset  8
//!   u32 parent_pid        offset 12   (task->real_parent->tgid)
//!   u64 ts_ns             offset 16
//!   u8  comm[16]          offset 24
//! shit_unlink_event  (328 bytes total)
//!   shit_event_hdr hdr    offset   0
//!   u64 dev               offset  40
//!   u64 inode             offset  48
//!   u64 parent_inode      offset  56
//!   u32 name_len          offset  64
//!   u32 _pad3             offset  68
//!   u8  name[256]         offset  72  (NAME_MAX+1, NUL-terminated)
//! ```
//!
//! Lifetime model: the reader owns a `RingBuf<MapData>` (taken from
//! the [`EbpfLoader`] via [`crate::ebpf::loader::EbpfLoader::take_unlink_ringbuf`])
//! and runs in its own OS thread. A `JoinHandle` is returned so the
//! helper's shutdown path can join it after closing the BPF Ebpf
//! instance (which closes the ringbuf fd, which makes `next()`
//! return None deterministically).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aya::maps::{MapData, RingBuf};

use super::loader::RingbufLossCounter;

/// Header common to every event, mirroring `struct shit_event_hdr`
/// in `bpf/src/common.h`. The `kind` byte indicates the tail layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventHeader {
    pub kind: u8,
    pub _pad: [u8; 3],
    /// Kernel thread ID (the low 32 bits of `bpf_get_current_pid_tgid`).
    /// Useful for diagnostics, but never for process-tree attribution.
    pub pid: u32,
    /// Process/thread-group ID (the high 32 bits of
    /// `bpf_get_current_pid_tgid`). This is the PID used for exclusion and
    /// command-tree attribution.
    pub tgid: u32,
    /// Task->real_parent->tgid at hook-fire time. Captured in the BPF
    /// program so userspace can match against tracked roots without
    /// a /proc lookup that would fail for already-exited subprocs.
    pub parent_pid: u32,
    pub ts_ns: u64,
    pub comm: [u8; 16],
}

const _: () = assert!(std::mem::size_of::<EventHeader>() == 40);

/// `kind` values, matching `enum shit_event_kind` in common.h.
pub mod kind {
    pub const UNLINK: u8 = 1;
    pub const SETATTR: u8 = 2;
    pub const MKDIR: u8 = 3;
    pub const OPEN: u8 = 4;
    pub const CREATE: u8 = 5;
    pub const RENAME: u8 = 6;
    pub const RMDIR: u8 = 7;
    pub const RELEASE: u8 = 8;
    /// AU29 — `lsm/inode_mknod`. Payload reuses CreateEvent; the
    /// discriminator is the kind tag here so the dispatcher can
    /// route mknod through its own handler if a future change wants
    /// to (current behavior reuses on_create's path).
    pub const MKNOD: u8 = 9;
}

/// `attr_valid` bits, mirror of `SHIT_ATTR_*` in common.h. Set by the
/// BPF program from the kernel's `iattr::ia_valid`; the userspace
/// consumer masks `new_*` fields on these bits.
pub mod attr {
    pub const MODE: u32 = 1 << 0;
    pub const UID: u32 = 1 << 1;
    pub const GID: u32 = 1 << 2;
    pub const SIZE: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;
    pub const CTIME: u32 = 1 << 6;
}

/// Max basename bytes the BPF program writes into `UnlinkEvent::name`.
/// Matches `SHIT_NAME_MAX + 1` in `common.h` (NAME_MAX + trailing NUL).
pub const NAME_BUF_LEN: usize = 256;

/// `lsm/inode_unlink` event — mirrors `struct shit_unlink_event`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkEvent {
    pub hdr: EventHeader,
    pub dev: u64,
    pub inode: u64,
    pub parent_inode: u64,
    pub name_len: u32,
    pub _pad3: u32,
    pub name: [u8; NAME_BUF_LEN],
}

const _: () = assert!(std::mem::size_of::<UnlinkEvent>() == 328);

impl Default for UnlinkEvent {
    fn default() -> Self {
        Self {
            hdr: EventHeader::default(),
            dev: 0,
            inode: 0,
            parent_inode: 0,
            name_len: 0,
            _pad3: 0,
            name: [0; NAME_BUF_LEN],
        }
    }
}

impl std::fmt::Debug for UnlinkEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlinkEvent")
            .field("hdr", &self.hdr)
            .field("dev", &self.dev)
            .field("inode", &self.inode)
            .field("parent_inode", &self.parent_inode)
            .field("name_len", &self.name_len)
            .field("name", &self.basename_os_str())
            .finish()
    }
}

impl UnlinkEvent {
    /// Returns the basename as a borrowed `&OsStr` without a lossy UTF-8
    /// conversion. Defensively clamps
    /// `name_len` to `NAME_BUF_LEN` so a malformed kernel record can't
    /// induce an out-of-bounds slice. Returns `""` if the BPF program
    /// reported `name_len == 0` (str_read failed).
    pub fn basename_os_str(&self) -> &OsStr {
        let len = (self.name_len as usize).min(NAME_BUF_LEN);
        OsStr::from_bytes(&self.name[..len])
    }
}

/// `lsm/inode_setattr` event — mirrors `struct shit_setattr_event`.
/// Captures the (dev, inode) being modified plus old/new values for
/// mode/uid/gid/size. Userspace masks the `new_*` fields on
/// `attr_valid` (only the bits set are meaningful).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SetattrEvent {
    pub hdr: EventHeader,
    pub dev: u64,
    pub inode: u64,
    pub attr_valid: u32,
    pub old_mode: u32,
    pub old_uid: u32,
    pub old_gid: u32,
    pub new_mode: u32,
    pub new_uid: u32,
    pub new_gid: u32,
    pub _pad3: u32,
    pub old_size: u64,
    pub new_size: u64,
}

const _: () = assert!(std::mem::size_of::<SetattrEvent>() == 104);

/// `lsm/inode_mkdir` event — mirrors `struct shit_mkdir_event`.
/// Captures the parent directory's (dev, inode), the basename of
/// the about-to-be-created subdirectory, and the umask-applied mode.
/// The new directory's own (dev, inode) is unknown at hook-time
/// (the dir doesn't exist yet); userspace stat's the path after the
/// syscall completes to resolve it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MkdirEvent {
    pub hdr: EventHeader,
    pub parent_dev: u64,
    pub parent_inode: u64,
    pub mode: u32,
    pub name_len: u32,
    pub name: [u8; NAME_BUF_LEN],
}

const _: () = assert!(std::mem::size_of::<MkdirEvent>() == 320);

impl Default for MkdirEvent {
    fn default() -> Self {
        Self {
            hdr: EventHeader::default(),
            parent_dev: 0,
            parent_inode: 0,
            mode: 0,
            name_len: 0,
            name: [0; NAME_BUF_LEN],
        }
    }
}

impl std::fmt::Debug for MkdirEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MkdirEvent")
            .field("hdr", &self.hdr)
            .field("parent_dev", &self.parent_dev)
            .field("parent_inode", &self.parent_inode)
            .field("mode", &format_args!("{:o}", self.mode))
            .field("name", &self.basename_os_str())
            .finish()
    }
}

impl MkdirEvent {
    pub fn basename_os_str(&self) -> &OsStr {
        let len = (self.name_len as usize).min(NAME_BUF_LEN);
        OsStr::from_bytes(&self.name[..len])
    }
}

/// `lsm/inode_create` event — mirrors `struct shit_create_event`.
/// Same shape as [`MkdirEvent`] but discriminates as `kind::CREATE`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CreateEvent {
    pub hdr: EventHeader,
    pub parent_dev: u64,
    pub parent_inode: u64,
    pub mode: u32,
    pub name_len: u32,
    pub name: [u8; NAME_BUF_LEN],
}

const _: () = assert!(std::mem::size_of::<CreateEvent>() == 320);

impl Default for CreateEvent {
    fn default() -> Self {
        Self {
            hdr: EventHeader::default(),
            parent_dev: 0,
            parent_inode: 0,
            mode: 0,
            name_len: 0,
            name: [0; NAME_BUF_LEN],
        }
    }
}

impl std::fmt::Debug for CreateEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateEvent")
            .field("hdr", &self.hdr)
            .field("parent_dev", &self.parent_dev)
            .field("parent_inode", &self.parent_inode)
            .field("mode", &format_args!("{:o}", self.mode))
            .field("name", &self.basename_os_str())
            .finish()
    }
}

impl CreateEvent {
    pub fn basename_os_str(&self) -> &OsStr {
        let len = (self.name_len as usize).min(NAME_BUF_LEN);
        OsStr::from_bytes(&self.name[..len])
    }
}

/// `lsm/file_open` event — mirrors `struct shit_open_event`.
/// BPF pre-filters to write-intent (FMODE_WRITE), so every record
/// here is a "file is about to be mutated" signal.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenEvent {
    pub hdr: EventHeader,
    pub dev: u64,
    pub inode: u64,
    pub f_mode: u32,
    pub f_flags: u32,
}

const _: () = assert!(std::mem::size_of::<OpenEvent>() == 64);

/// `lsm/file_release` event — same C-struct shape as
/// [`OpenEvent`], discriminated by `kind::RELEASE`. Fires when the
/// kernel's struct-file refcount hits zero (last fd close +
/// last mmap unmap) AND `FMODE_WRITE` was set on the file. The
/// userspace release-handler diffs the inode's current content
/// against the open-time `pre_snapshot` and emits a
/// CapturedPreImage iff they differ.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReleaseEvent {
    pub hdr: EventHeader,
    pub dev: u64,
    pub inode: u64,
    pub f_mode: u32,
    pub f_flags: u32,
}

const _: () = assert!(std::mem::size_of::<ReleaseEvent>() == 64);

/// `lsm/inode_rename` event — mirrors `struct shit_rename_event`.
/// Carries both ends of the rename. `dev`/`inode` are the target's
/// identity (invariant across rename within a single filesystem).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameEvent {
    pub hdr: EventHeader,
    pub dev: u64,
    pub inode: u64,
    pub old_parent_inode: u64,
    pub new_parent_inode: u64,
    pub old_name_len: u32,
    pub new_name_len: u32,
    pub old_name: [u8; NAME_BUF_LEN],
    pub new_name: [u8; NAME_BUF_LEN],
}

const _: () = assert!(std::mem::size_of::<RenameEvent>() == 592);

impl Default for RenameEvent {
    fn default() -> Self {
        Self {
            hdr: EventHeader::default(),
            dev: 0,
            inode: 0,
            old_parent_inode: 0,
            new_parent_inode: 0,
            old_name_len: 0,
            new_name_len: 0,
            old_name: [0; NAME_BUF_LEN],
            new_name: [0; NAME_BUF_LEN],
        }
    }
}

impl std::fmt::Debug for RenameEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenameEvent")
            .field("hdr", &self.hdr)
            .field("dev", &self.dev)
            .field("inode", &self.inode)
            .field("old_parent_inode", &self.old_parent_inode)
            .field("new_parent_inode", &self.new_parent_inode)
            .field("old_name", &self.old_basename_os_str())
            .field("new_name", &self.new_basename_os_str())
            .finish()
    }
}

impl RenameEvent {
    pub fn old_basename_os_str(&self) -> &OsStr {
        let len = (self.old_name_len as usize).min(NAME_BUF_LEN);
        OsStr::from_bytes(&self.old_name[..len])
    }
    pub fn new_basename_os_str(&self) -> &OsStr {
        let len = (self.new_name_len as usize).min(NAME_BUF_LEN);
        OsStr::from_bytes(&self.new_name[..len])
    }
}

/// Sink trait for decoded LSM events. The phase-2-chunk-2 stub
/// implementation just logs; the production sink wires events into
/// [`crate::capture::linux::LinuxCaptureRuntime`].
///
/// Default impls let an implementor that only cares about one event
/// kind skip the others — used by the unit tests and by future
/// kinds being added incrementally.
///
/// `Send + Sync + 'static` because the reader thread owns its sink.
pub trait LsmEventSink: Send + Sync + 'static {
    fn on_unlink(&self, _ev: &UnlinkEvent) {}
    fn on_setattr(&self, _ev: &SetattrEvent) {}
    fn on_mkdir(&self, _ev: &MkdirEvent) {}
    fn on_create(&self, _ev: &CreateEvent) {}
    fn on_open(&self, _ev: &OpenEvent) {}
    fn on_rename(&self, _ev: &RenameEvent) {}
    /// G03 — `inode_rmdir` events. Wire shape is identical to
    /// `UnlinkEvent` (kernel LSM hook signature is the same).
    fn on_rmdir(&self, _ev: &UnlinkEvent) {}
    /// L04.2 — `file_release` events. Fires at last-fd-close of a
    /// writable file; the handler diffs current content against
    /// the open-time snapshot and emits a `CapturedPreImage` iff
    /// they differ. Closes the in-place-write capture gap.
    fn on_release(&self, _ev: &ReleaseEvent) {}
    /// The per-object BPF counter advanced (or became unreadable). A dropped
    /// ringbuf record carries no identity, so production conservatively marks
    /// every command active at observation time as non-undoable.
    fn on_ringbuf_health_event(&self, _source: &'static str, _event: &RingbufHealthEvent) {}
}

/// Observable state changes from one BPF object's out-of-band loss counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingbufHealthEvent {
    RecordsDropped { delta: u64, total: u64 },
    CounterReadFailed { detail: String },
}

/// Stateful u64-delta calculation for a counter created at zero with the BPF
/// object. `wrapping_sub` makes the overflow behavior explicit and testable.
#[derive(Debug, Default)]
struct LossCounterTracker {
    previous: u64,
    read_failed: bool,
}

impl LossCounterTracker {
    fn observe(&mut self, result: Result<u64, String>) -> Option<RingbufHealthEvent> {
        match result {
            Ok(total) => {
                self.read_failed = false;
                let delta = total.wrapping_sub(self.previous);
                self.previous = total;
                (delta != 0).then_some(RingbufHealthEvent::RecordsDropped { delta, total })
            }
            Err(detail) if !self.read_failed => {
                self.read_failed = true;
                Some(RingbufHealthEvent::CounterReadFailed { detail })
            }
            Err(_) => None,
        }
    }
}

fn dispatch_loss_observation(
    tracker: &mut LossCounterTracker,
    source: &'static str,
    result: Result<u64, String>,
    sink: &(dyn LsmEventSink + 'static),
) -> Option<RingbufHealthEvent> {
    let event = tracker.observe(result);
    if let Some(event) = &event {
        sink.on_ringbuf_health_event(source, event);
    }
    event
}

/// Production sink — bridges decoded BPF events into the
/// [`crate::capture::linux::LinuxCaptureRuntime`]. Resolves the
/// event's `pid` to a tracked [`shit_planner::events::CommandId`] via
/// the shared `TreeMap` (same one fanotify uses), then dispatches to
/// the appropriate `handle_lsm_*` method.
///
/// Untracked pids are silently dropped — same policy as fanotify's
/// per-event ALLOW-without-capture path.
///
/// `excluded_pids` is a small set of process IDs whose events MUST
/// be dropped even if the tree walk says they're tracked. This is
/// critical for the LSM tier because the daemon and helper run as
/// descendants of the smoke harness (or whatever shell launched
/// shit) and their own internal file ops (blob staging rename,
/// helper-staging writes, etc.) would otherwise be journaled as
/// user-visible mutations. Fanotify-perm doesn't have this problem
/// because its marks are scoped to the command's cwd only, but
/// LSM hooks observe system-wide.
#[cfg(target_os = "linux")]
pub struct LinuxCaptureSink {
    pub runtime: std::sync::Arc<std::sync::Mutex<crate::capture::linux::LinuxCaptureRuntime>>,
    pub tree: std::sync::Arc<std::sync::Mutex<crate::fanotify::tree::TreeMap>>,
    /// Dedicated daemon connection used to persist a refusal when the BPF
    /// loss counter advances. This cannot be reconstructed from a dropped
    /// record because that record's command identity is precisely what was
    /// lost.
    pub conn: std::sync::Arc<crate::ipc::Conn>,
    /// PIDs whose LSM events are dropped unconditionally. Typically
    /// `[helper_self_pid, daemon_pid]`.
    pub excluded_pids: Vec<u32>,
}

#[cfg(target_os = "linux")]
impl LinuxCaptureSink {
    /// Return the process identity carried by an event. BPF's `pid` field is
    /// the calling thread's TID; exclusions and process trees are keyed by
    /// the thread-group ID (the userspace process PID).
    fn process_pid(header: &EventHeader) -> u32 {
        header.tgid
    }

    /// Returns true if events from `process_pid` should be filtered out
    /// before tree lookup.
    fn is_excluded(&self, process_pid: u32) -> bool {
        self.excluded_pids.contains(&process_pid)
    }
}

#[cfg(target_os = "linux")]
impl LsmEventSink for LinuxCaptureSink {
    fn on_ringbuf_health_event(&self, source: &'static str, event: &RingbufHealthEvent) {
        let commands = self.tree.lock().unwrap().active_commands();
        let detail = match event {
            RingbufHealthEvent::RecordsDropped { delta, total } => format!(
                "eBPF {source} ring buffer dropped {delta} event(s) (counter total {total}); exact command attribution is unavailable"
            ),
            RingbufHealthEvent::CounterReadFailed { detail } => format!(
                "eBPF {source} ring-buffer loss counter became unreadable; capture completeness cannot be proven: {detail}"
            ),
        };

        tracing::error!(
            source,
            event = ?event,
            active_commands = commands.len(),
            "eBPF capture health failure; refusing every active command"
        );
        for (session, seq) in commands {
            let refusal = shit_proto::HelperResponse::CaptureRefused {
                session,
                seq,
                path: None,
                detail: detail.clone(),
            };
            if let Err(error) = self.conn.send_response(&refusal) {
                // A permanently torn helper/daemon link cannot report its own
                // failure. Log that limitation explicitly; do not claim the
                // refusal reached durable storage.
                tracing::error!(
                    %error,
                    %session,
                    seq,
                    source,
                    "permanent IPC failure prevented eBPF-loss refusal delivery"
                );
            }
        }
    }

    fn on_unlink(&self, ev: &UnlinkEvent) {
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm unlink event");
            return;
        };
        let view = crate::capture::linux::LsmUnlinkView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            dev: ev.dev,
            inode: ev.inode,
            parent_inode: ev.parent_inode,
            basename: ev.basename_os_str(),
            is_directory: false,
        };
        self.runtime.lock().unwrap().handle_lsm_unlink(&view);
        drop(tree);
    }

    fn on_rmdir(&self, ev: &UnlinkEvent) {
        // G03 — identical wire to on_unlink. We route through the
        // same handle_lsm_unlink path with is_directory=true so the
        // handler skips content capture (dirs have no bytes) and
        // emits a marker CapturedPreImage with the dir's mode.
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm rmdir event");
            return;
        };
        let view = crate::capture::linux::LsmUnlinkView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            dev: ev.dev,
            inode: ev.inode,
            parent_inode: ev.parent_inode,
            basename: ev.basename_os_str(),
            is_directory: true,
        };
        self.runtime.lock().unwrap().handle_lsm_unlink(&view);
        drop(tree);
    }

    fn on_release(&self, ev: &ReleaseEvent) {
        // L04.2 — writable-fd close. Handler diffs against pre-image
        // snapshot and emits CapturedPreImage iff content changed.
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm release event");
            return;
        };
        let view = crate::capture::linux::LsmReleaseView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            ts_ns: ev.hdr.ts_ns,
            dev: ev.dev,
            inode: ev.inode,
            f_mode: ev.f_mode,
            f_flags: ev.f_flags,
        };
        self.runtime.lock().unwrap().handle_lsm_release(&view);
        drop(tree);
    }

    fn on_setattr(&self, ev: &SetattrEvent) {
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm setattr event");
            return;
        };
        let view = crate::capture::linux::LsmSetattrView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            ts_ns: ev.hdr.ts_ns,
            dev: ev.dev,
            inode: ev.inode,
            attr_valid: ev.attr_valid,
            old_mode: ev.old_mode,
            old_uid: ev.old_uid,
            old_gid: ev.old_gid,
            old_size: ev.old_size,
            new_mode: ev.new_mode,
            new_uid: ev.new_uid,
            new_gid: ev.new_gid,
            new_size: ev.new_size,
        };
        self.runtime.lock().unwrap().handle_lsm_setattr(&view);
        drop(tree);
    }

    fn on_mkdir(&self, ev: &MkdirEvent) {
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm mkdir event");
            return;
        };
        let view = crate::capture::linux::LsmMkdirView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            parent_dev: ev.parent_dev,
            parent_inode: ev.parent_inode,
            mode: ev.mode,
            basename: ev.basename_os_str(),
        };
        self.runtime.lock().unwrap().handle_lsm_mkdir(&view);
        drop(tree);
    }

    fn on_create(&self, ev: &CreateEvent) {
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm create event");
            return;
        };
        let view = crate::capture::linux::LsmCreateView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            ts_ns: ev.hdr.ts_ns,
            parent_dev: ev.parent_dev,
            parent_inode: ev.parent_inode,
            mode: ev.mode,
            basename: ev.basename_os_str(),
        };
        self.runtime.lock().unwrap().handle_lsm_create(&view);
        drop(tree);
    }

    fn on_open(&self, ev: &OpenEvent) {
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm open event");
            return;
        };
        let view = crate::capture::linux::LsmOpenView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            ts_ns: ev.hdr.ts_ns,
            dev: ev.dev,
            inode: ev.inode,
            f_mode: ev.f_mode,
            f_flags: ev.f_flags,
        };
        self.runtime.lock().unwrap().handle_lsm_open(&view);
        drop(tree);
    }

    fn on_rename(&self, ev: &RenameEvent) {
        let process_pid = Self::process_pid(&ev.hdr);
        if self.is_excluded(process_pid) {
            return;
        }
        let pid = process_pid as i32;
        let mut tree = self.tree.lock().unwrap();
        let Some((session, seq)) = tree.is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm rename event");
            return;
        };
        let view = crate::capture::linux::LsmRenameView {
            command: shit_planner::events::CommandId { session, seq },
            pid: process_pid,
            dev: ev.dev,
            inode: ev.inode,
            old_parent_inode: ev.old_parent_inode,
            new_parent_inode: ev.new_parent_inode,
            old_basename: ev.old_basename_os_str(),
            new_basename: ev.new_basename_os_str(),
        };
        self.runtime.lock().unwrap().handle_lsm_rename(&view);
        drop(tree);
    }
}

/// Stub sink — logs each event at info-level. Useful for the manual
/// smoke (step 4 of the sprint implementation order: "load the
/// program, `rm` a file, see the log line").
pub struct LoggingSink;

impl LsmEventSink for LoggingSink {
    fn on_unlink(&self, ev: &UnlinkEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        let basename = ev.basename_os_str();
        tracing::info!(
            kind = "unlink",
            pid = ev.hdr.pid,
            tgid = ev.hdr.tgid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            parent_inode = ev.parent_inode,
            name_len = ev.name_len,
            basename = ?basename,
            comm,
            "lsm event"
        );
    }

    fn on_setattr(&self, ev: &SetattrEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        tracing::info!(
            kind = "setattr",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            attr_valid = ev.attr_valid,
            old_mode = format_args!("{:o}", ev.old_mode),
            new_mode = format_args!("{:o}", ev.new_mode),
            comm,
            "lsm event"
        );
    }

    fn on_mkdir(&self, ev: &MkdirEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        let basename = ev.basename_os_str();
        tracing::info!(
            kind = "mkdir",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            parent_dev = ev.parent_dev,
            parent_inode = ev.parent_inode,
            mode = format_args!("{:o}", ev.mode),
            basename = ?basename,
            comm,
            "lsm event"
        );
    }

    fn on_create(&self, ev: &CreateEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        let basename = ev.basename_os_str();
        tracing::info!(
            kind = "create",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            parent_dev = ev.parent_dev,
            parent_inode = ev.parent_inode,
            mode = format_args!("{:o}", ev.mode),
            basename = ?basename,
            comm,
            "lsm event"
        );
    }

    fn on_open(&self, ev: &OpenEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        tracing::info!(
            kind = "open",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            f_mode = format_args!("{:#x}", ev.f_mode),
            f_flags = format_args!("{:#x}", ev.f_flags),
            comm,
            "lsm event"
        );
    }

    fn on_rename(&self, ev: &RenameEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        let old = ev.old_basename_os_str();
        let new = ev.new_basename_os_str();
        tracing::info!(
            kind = "rename",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            old_basename = ?old,
            new_basename = ?new,
            comm,
            "lsm event"
        );
    }
}

/// Convert a `[u8; 16]` `comm` array (NUL-terminated, like
/// `/proc/<pid>/comm`) into a Rust string. Stops at the first NUL.
fn comm_to_string(buf: &[u8; 16]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Decode a raw ringbuf record as an [`UnlinkEvent`]. Returns `None`
/// when the record is too short (kernel truncation under pressure)
/// or when the `kind` byte mismatches.
///
/// Safety: the C side allocates with `bpf_ringbuf_reserve` which is
/// 8-byte aligned, but the userspace ringbuf surface hands us a
/// `&[u8]` of unspecified alignment. We copy through a `MaybeUninit`
/// rather than transmute to avoid any alignment hazard.
pub fn decode_unlink(bytes: &[u8]) -> Option<UnlinkEvent> {
    decode_event::<UnlinkEvent>(bytes, kind::UNLINK)
}

/// G03 — rmdir events share `UnlinkEvent`'s C struct shape but tag
/// themselves with `SHIT_EVT_RMDIR`. Userspace dispatches them to
/// `on_rmdir` so the sink can mark the captured pre-image as a
/// directory.
pub fn decode_rmdir(bytes: &[u8]) -> Option<UnlinkEvent> {
    decode_event::<UnlinkEvent>(bytes, kind::RMDIR)
}

/// L04.2 — release events share `OpenEvent`'s C struct shape (same
/// scalar set: dev, inode, f_mode, f_flags) but tag with
/// `SHIT_EVT_RELEASE`. The release-handler uses the same fields
/// open-handler does, just at last-fd-close time instead of
/// open-time.
pub fn decode_release(bytes: &[u8]) -> Option<ReleaseEvent> {
    decode_event::<ReleaseEvent>(bytes, kind::RELEASE)
}

/// Decode a raw ringbuf record as a [`SetattrEvent`]. Same shape as
/// [`decode_unlink`].
pub fn decode_setattr(bytes: &[u8]) -> Option<SetattrEvent> {
    decode_event::<SetattrEvent>(bytes, kind::SETATTR)
}

/// Decode a raw ringbuf record as a [`MkdirEvent`].
pub fn decode_mkdir(bytes: &[u8]) -> Option<MkdirEvent> {
    decode_event::<MkdirEvent>(bytes, kind::MKDIR)
}

/// Decode a raw ringbuf record as a [`CreateEvent`].
pub fn decode_create(bytes: &[u8]) -> Option<CreateEvent> {
    decode_event::<CreateEvent>(bytes, kind::CREATE)
}

/// AU29 — decode a raw ringbuf record from the mknod ringbuf as a
/// [`CreateEvent`]. The payload shape is identical to inode_create;
/// the differentiator is the `kind::MKNOD` tag.
pub fn decode_mknod(bytes: &[u8]) -> Option<CreateEvent> {
    decode_event::<CreateEvent>(bytes, kind::MKNOD)
}

/// Decode a raw ringbuf record as an [`OpenEvent`].
pub fn decode_open(bytes: &[u8]) -> Option<OpenEvent> {
    decode_event::<OpenEvent>(bytes, kind::OPEN)
}

/// Decode a raw ringbuf record as a [`RenameEvent`].
pub fn decode_rename(bytes: &[u8]) -> Option<RenameEvent> {
    decode_event::<RenameEvent>(bytes, kind::RENAME)
}

/// Internal helper shared by per-kind decoders. `T` must be `repr(C)`
/// with a leading `EventHeader` so byte 0 is the `kind` discriminant.
fn decode_event<T: Copy>(bytes: &[u8], expected_kind: u8) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    if bytes[0] != expected_kind {
        return None;
    }
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: T is sized, slice is at least size_of::<T> bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            out.as_mut_ptr() as *mut u8,
            std::mem::size_of::<T>(),
        );
        Some(out.assume_init())
    }
}

/// Per-record dispatcher for a given ringbuf. Each ringbuf's record
/// shape (UnlinkEvent vs SetattrEvent) maps to a different decoder
/// and sink method via a closure. Constructed once at
/// LsmReader::spawn time and called once per drained record.
#[allow(clippy::type_complexity)]
type RecordHandler = Box<dyn Fn(&[u8], &(dyn LsmEventSink + 'static)) + Send + 'static>;

#[derive(Clone, Copy)]
struct ReaderIdentity {
    thread_name: &'static str,
    source: &'static str,
}

/// Result of synchronizing with one LSM reader. `health_epoch` advances for
/// every newly observed ring-buffer loss or loss-counter read outage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LsmFlushReport {
    pub health_epoch: u64,
}

struct FlushRequest {
    deadline: Instant,
    reply: mpsc::SyncSender<Result<LsmFlushReport, String>>,
}

struct ReaderThreadControl {
    alive: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    health_epoch: Arc<AtomicU64>,
    counter_read_failed: Arc<AtomicBool>,
    flush_rx: mpsc::Receiver<FlushRequest>,
}

/// Cloneable control plane for a single ring-buffer reader.
///
/// A successful flush is acknowledged by the reader thread itself, after it
/// has drained the ring to an observed-empty state, synchronously completed
/// every resulting sink callback, and polled the out-of-band loss counter.
#[derive(Clone)]
pub struct LsmFlushControl {
    source: &'static str,
    tx: mpsc::Sender<FlushRequest>,
    running: Arc<AtomicBool>,
    health_epoch: Arc<AtomicU64>,
    counter_read_failed: Arc<AtomicBool>,
}

impl LsmFlushControl {
    pub fn source(&self) -> &'static str {
        self.source
    }

    /// Snapshot reader health before a command is made visible to the event
    /// dispatcher. The epoch is compared with the post-command flush report.
    pub fn health_snapshot(&self) -> Result<u64, String> {
        if !self.running.load(Ordering::Acquire) {
            return Err(format!("eBPF {} reader is not running", self.source));
        }
        if self.counter_read_failed.load(Ordering::Acquire) {
            return Err(format!(
                "eBPF {} loss counter is currently unreadable",
                self.source
            ));
        }
        Ok(self.health_epoch.load(Ordering::Acquire))
    }

    pub fn flush_until(&self, deadline: Instant) -> Result<LsmFlushReport, String> {
        if !self.running.load(Ordering::Acquire) {
            return Err(format!("eBPF {} reader is not running", self.source));
        }
        if Instant::now() >= deadline {
            return Err(format!("eBPF {} reader flush timed out", self.source));
        }
        let (reply, receive) = mpsc::sync_channel(1);
        self.tx
            .send(FlushRequest { deadline, reply })
            .map_err(|_| format!("eBPF {} reader control disconnected", self.source))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("eBPF {} reader flush timed out", self.source));
        }
        receive
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    format!("eBPF {} reader flush timed out", self.source)
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    format!("eBPF {} reader exited during flush", self.source)
                }
            })?
    }
}

/// Flush every reader against one aggregate deadline. Every source is asked
/// even when an earlier one fails, so the error identifies the complete set
/// that did not cross its barrier. Successful return proves every listed
/// source replied.
pub fn flush_all_readers(
    controls: &[LsmFlushControl],
    deadline: Instant,
) -> Result<Vec<LsmFlushReport>, String> {
    let mut reports = Vec::with_capacity(controls.len());
    let mut failures = Vec::new();
    for control in controls {
        match control.flush_until(deadline) {
            Ok(report) => reports.push(report),
            Err(error) => failures.push(error),
        }
    }
    if failures.is_empty() {
        Ok(reports)
    } else {
        Err(failures.join("; "))
    }
}

fn finish_flush<D, P>(deadline: Instant, mut drain: D, mut poll_loss: P) -> Result<(), String>
where
    D: FnMut(Instant) -> Result<(), String>,
    P: FnMut() -> Result<(), String>,
{
    if Instant::now() >= deadline {
        return Err("reader flush deadline expired before drain".to_string());
    }
    // The second drain closes the window in which records can arrive while
    // the loss map is being read. It need only reach one observed-empty state;
    // tree->runtime locking at detach orders records that arrive afterwards.
    drain(deadline)?;
    poll_loss()?;
    drain(deadline)?;
    poll_loss()?;
    if Instant::now() >= deadline {
        return Err("reader flush deadline expired after drain".to_string());
    }
    Ok(())
}

/// Userspace consumer of a single L04 LSM ringbuf. One OS thread per
/// LsmReader instance — separate ringbufs (`unlink_events`,
/// `setattr_events`, ...) each get their own reader. Dispatches via
/// the provided [`RecordHandler`] closure into the [`LsmEventSink`].
pub struct LsmReader {
    alive: Arc<AtomicBool>,
    flush: LsmFlushControl,
    handle: Option<JoinHandle<()>>,
}

impl LsmReader {
    /// Spawn an unlink-ringbuf reader. Convenience over
    /// [`Self::spawn_with_handler`] — wires the unlink decoder.
    pub fn spawn(
        unlink_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-unlink",
            "inode_unlink",
            unlink_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_unlink(bytes) {
                    sink.on_unlink(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as UnlinkEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// G03 — spawn an rmdir-ringbuf reader. Wire shape is identical
    /// to unlink (same kernel hook signature) but dispatched via
    /// `on_rmdir` so userspace can flag the event as a directory
    /// removal at the sink level.
    pub fn spawn_rmdir(
        rmdir_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-rmdir",
            "inode_rmdir",
            rmdir_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_rmdir(bytes) {
                    sink.on_rmdir(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as UnlinkEvent (rmdir)"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// L04.2 — spawn a file_release ringbuf reader. The BPF
    /// program pre-filters to writable closes; userspace dispatches
    /// via `on_release` which routes through `handle_lsm_release`
    /// for content-diff capture.
    pub fn spawn_release(
        release_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-release",
            "file_release",
            release_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_release(bytes) {
                    sink.on_release(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as ReleaseEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// Spawn a setattr-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_setattr`.
    pub fn spawn_setattr(
        setattr_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-setattr",
            "inode_setattr",
            setattr_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_setattr(bytes) {
                    sink.on_setattr(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as SetattrEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// Spawn a mkdir-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_mkdir`.
    pub fn spawn_mkdir(
        mkdir_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-mkdir",
            "inode_mkdir",
            mkdir_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_mkdir(bytes) {
                    sink.on_mkdir(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as MkdirEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// Spawn a create-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_create`.
    pub fn spawn_create(
        create_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_create_like(
            "shit-lsm-create",
            "inode_create",
            create_rb,
            loss_counter,
            sink,
            idle_sleep,
        )
    }

    pub fn spawn_symlink(
        symlink_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_create_like(
            "shit-lsm-symlink",
            "inode_symlink",
            symlink_rb,
            loss_counter,
            sink,
            idle_sleep,
        )
    }

    pub fn spawn_link(
        link_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_create_like(
            "shit-lsm-link",
            "inode_link",
            link_rb,
            loss_counter,
            sink,
            idle_sleep,
        )
    }

    fn spawn_create_like(
        thread_name: &'static str,
        source: &'static str,
        create_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            thread_name,
            source,
            create_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_create(bytes) {
                    sink.on_create(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as CreateEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// AU29 — spawn a mknod-ringbuf reader. Wire shape is identical
    /// to `inode_create` (the kernel hook returns the same
    /// `(parent_inode, parent_dev, mode, name)` payload) but uses
    /// `kind::MKNOD`. Routes through `on_create` so the userspace
    /// `handle_lsm_create` body handles FIFOs / sockets without a
    /// duplicate code path; the kind discriminator for the planner
    /// comes from the wire's `mode` (S_IFMT bits).
    pub fn spawn_mknod(
        mknod_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-mknod",
            "inode_mknod",
            mknod_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_mknod(bytes) {
                    sink.on_create(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as CreateEvent (mknod)"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// Spawn an open-ringbuf reader. Convenience wrapper for
    /// `lsm/file_open` (write-intent opens only; BPF pre-filters).
    pub fn spawn_open(
        open_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-open",
            "file_open",
            open_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_open(bytes) {
                    sink.on_open(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as OpenEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// Spawn a rename-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_rename`.
    pub fn spawn_rename(
        rename_rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-rename",
            "inode_rename",
            rename_rb,
            loss_counter,
            sink,
            Box::new(|bytes, sink| {
                if let Some(ev) = decode_rename(bytes) {
                    sink.on_rename(&ev);
                } else {
                    tracing::warn!(
                        bytes = bytes.len(),
                        first_byte = bytes.first().copied().unwrap_or(0),
                        "ringbuf record could not be decoded as RenameEvent"
                    );
                }
            }),
            idle_sleep,
        )
    }

    /// Generic spawn — caller supplies the per-record handler.
    /// `thread_name` is used for /proc/self/task/*/comm and the
    /// tracing span label.
    pub fn spawn_with_handler(
        thread_name: &'static str,
        source: &'static str,
        rb: RingBuf<MapData>,
        loss_counter: RingbufLossCounter,
        sink: Arc<dyn LsmEventSink>,
        handler: RecordHandler,
        idle_sleep: Duration,
    ) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let alive_t = Arc::clone(&alive);
        let running = Arc::new(AtomicBool::new(true));
        let running_t = Arc::clone(&running);
        let health_epoch = Arc::new(AtomicU64::new(0));
        let health_epoch_t = Arc::clone(&health_epoch);
        let counter_read_failed = Arc::new(AtomicBool::new(false));
        let counter_read_failed_t = Arc::clone(&counter_read_failed);
        let (flush_tx, flush_rx) = mpsc::channel();
        let identity = ReaderIdentity {
            thread_name,
            source,
        };
        let handle = std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                reader_thread(
                    identity,
                    rb,
                    loss_counter,
                    sink,
                    handler,
                    ReaderThreadControl {
                        alive: alive_t,
                        running: running_t,
                        health_epoch: health_epoch_t,
                        counter_read_failed: counter_read_failed_t,
                        flush_rx,
                    },
                    idle_sleep,
                );
            })
            .expect("spawn lsm reader");
        LsmReader {
            alive,
            flush: LsmFlushControl {
                source,
                tx: flush_tx,
                running,
                health_epoch,
                counter_read_failed,
            },
            handle: Some(handle),
        }
    }

    pub fn flush_control(&self) -> LsmFlushControl {
        self.flush.clone()
    }

    /// Ask the reader to exit. Idempotent. The thread sees the flag
    /// flip on its next sleep-tick (≤ `idle_sleep`).
    pub fn stop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }

    /// Block until the reader thread has exited. Calls `stop()`
    /// internally first.
    pub fn join(mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for LsmReader {
    fn drop(&mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn reader_thread(
    identity: ReaderIdentity,
    mut rb: RingBuf<MapData>,
    loss_counter: RingbufLossCounter,
    sink: Arc<dyn LsmEventSink>,
    handler: RecordHandler,
    control: ReaderThreadControl,
    idle_sleep: Duration,
) {
    struct RunningGuard(Arc<AtomicBool>);
    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _running_guard = RunningGuard(Arc::clone(&control.running));
    let mut loss_tracker = LossCounterTracker::default();

    let mut poll_loss = || -> Result<(), String> {
        let result = loss_counter.get(&0, 0).map_err(|error| error.to_string());
        let read_succeeded = result.is_ok();
        let event =
            dispatch_loss_observation(&mut loss_tracker, identity.source, result, sink.as_ref());
        control
            .counter_read_failed
            .store(!read_succeeded, Ordering::Release);
        if event.is_some() {
            control.health_epoch.fetch_add(1, Ordering::AcqRel);
        }
        if read_succeeded {
            Ok(())
        } else {
            Err(format!(
                "eBPF {} loss counter is unreadable",
                identity.source
            ))
        }
    };

    let service_flush =
        |request: FlushRequest,
         rb: &mut RingBuf<MapData>,
         poll_loss: &mut dyn FnMut() -> Result<(), String>| {
            let result = finish_flush(
                request.deadline,
                |deadline| {
                    while let Some(rec) = rb.next() {
                        let slice: &[u8] = &rec[..];
                        handler(slice, sink.as_ref());
                        if Instant::now() >= deadline {
                            return Err(format!(
                                "eBPF {} reader flush timed out while draining",
                                identity.source
                            ));
                        }
                    }
                    Ok(())
                },
                poll_loss,
            )
            .map(|()| LsmFlushReport {
                health_epoch: control.health_epoch.load(Ordering::Acquire),
            });
            let _ = request.reply.send(result);
        };

    while control.alive.load(Ordering::Acquire) {
        while let Ok(request) = control.flush_rx.try_recv() {
            service_flush(request, &mut rb, &mut poll_loss);
        }
        let _ = poll_loss();
        let mut drained_this_pass = 0u32;
        while let Some(rec) = rb.next() {
            let slice: &[u8] = &rec[..];
            handler(slice, sink.as_ref());
            drained_this_pass += 1;
            if drained_this_pass >= 1024 {
                break;
            }
        }
        let _ = poll_loss();
        match control.flush_rx.recv_timeout(idle_sleep) {
            Ok(request) => service_flush(request, &mut rb, &mut poll_loss),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = poll_loss();
    tracing::info!(thread = identity.thread_name, "lsm-rb reader exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn header_layout_is_40_bytes() {
        assert_eq!(std::mem::size_of::<EventHeader>(), 40);
        assert_eq!(std::mem::align_of::<EventHeader>(), 8);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_process_identity_is_tgid_not_thread_id() {
        let header = EventHeader {
            pid: 42_002,
            tgid: 42_000,
            ..EventHeader::default()
        };
        assert_eq!(LinuxCaptureSink::process_pid(&header), 42_000);
    }

    #[test]
    fn unlink_event_layout_is_328_bytes() {
        assert_eq!(std::mem::size_of::<UnlinkEvent>(), 328);
        assert_eq!(std::mem::align_of::<UnlinkEvent>(), 8);
    }

    #[test]
    fn decode_unlink_round_trips() {
        let mut name_buf = [0u8; NAME_BUF_LEN];
        name_buf[..7].copy_from_slice(b"foo.txt");
        let original = UnlinkEvent {
            hdr: EventHeader {
                kind: kind::UNLINK,
                _pad: [0; 3],
                pid: 12345,
                tgid: 12345,
                parent_pid: 0,
                ts_ns: 0xdead_beef_cafe_babe,
                comm: *b"rm\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            },
            dev: 0x00000801,
            inode: 9_876_543,
            parent_inode: 9_876_540,
            name_len: 7,
            _pad3: 0,
            name: name_buf,
        };
        let bytes: [u8; 328] = unsafe { std::mem::transmute(original) };
        let decoded = decode_unlink(&bytes).expect("decode");
        assert_eq!(decoded.hdr.kind, kind::UNLINK);
        assert_eq!(decoded.hdr.pid, 12345);
        assert_eq!(decoded.hdr.ts_ns, 0xdead_beef_cafe_babe);
        assert_eq!(decoded.dev, 0x00000801);
        assert_eq!(decoded.inode, 9_876_543);
        assert_eq!(decoded.parent_inode, 9_876_540);
        assert_eq!(decoded.name_len, 7);
        assert_eq!(decoded.basename_os_str(), OsStr::new("foo.txt"));
        assert_eq!(comm_to_string(&decoded.hdr.comm), "rm");
    }

    #[test]
    fn decode_unlink_rejects_short_record() {
        let bytes = [0u8; 32]; // shorter than the 328-byte struct
        assert!(decode_unlink(&bytes).is_none());
    }

    #[test]
    fn decode_unlink_rejects_wrong_kind() {
        let mut bytes = [0u8; 328];
        bytes[0] = kind::OPEN; // not UNLINK
        assert!(decode_unlink(&bytes).is_none());
    }

    #[test]
    fn basename_os_str_clamps_oversize_name_len() {
        // Defensive: even if BPF reports name_len > NAME_BUF_LEN (it
        // can't, but be paranoid), basename_os_str must clamp.
        let mut ev = UnlinkEvent::default();
        ev.name[..3].copy_from_slice(b"foo");
        ev.name_len = (NAME_BUF_LEN as u32) + 999;
        let s = ev.basename_os_str().as_bytes();
        assert_eq!(s.len(), NAME_BUF_LEN);
        assert!(s.starts_with(b"foo"));
    }

    #[test]
    fn basename_os_str_zero_len_yields_empty() {
        let mut ev = UnlinkEvent::default();
        ev.name[..3].copy_from_slice(b"foo");
        ev.name_len = 0;
        assert_eq!(ev.basename_os_str(), OsStr::new(""));
    }

    #[test]
    fn basename_os_str_preserves_non_utf8_bytes() {
        let mut ev = UnlinkEvent::default();
        ev.name[..5].copy_from_slice(b"bad-\xff");
        ev.name_len = 5;
        assert_eq!(ev.basename_os_str().as_bytes(), b"bad-\xff");
    }

    #[test]
    fn setattr_event_layout_is_104_bytes() {
        assert_eq!(std::mem::size_of::<SetattrEvent>(), 104);
        assert_eq!(std::mem::align_of::<SetattrEvent>(), 8);
    }

    #[test]
    fn decode_setattr_round_trips() {
        let original = SetattrEvent {
            hdr: EventHeader {
                kind: kind::SETATTR,
                _pad: [0; 3],
                pid: 7777,
                tgid: 7777,
                parent_pid: 0,
                ts_ns: 0x1122_3344_5566_7788,
                comm: *b"chmod\0\0\0\0\0\0\0\0\0\0\0",
            },
            dev: 0x802,
            inode: 12345,
            attr_valid: attr::MODE,
            old_mode: 0o100644,
            old_uid: 1000,
            old_gid: 1000,
            new_mode: 0o100755,
            new_uid: 0,
            new_gid: 0,
            _pad3: 0,
            old_size: 1024,
            new_size: 0,
        };
        let bytes: [u8; 104] = unsafe { std::mem::transmute(original) };
        let decoded = decode_setattr(&bytes).expect("decode");
        assert_eq!(decoded.hdr.kind, kind::SETATTR);
        assert_eq!(decoded.attr_valid, attr::MODE);
        assert_eq!(decoded.old_mode, 0o100644);
        assert_eq!(decoded.new_mode, 0o100755);
        assert_eq!(decoded.dev, 0x802);
        assert_eq!(decoded.inode, 12345);
    }

    #[test]
    fn decode_setattr_rejects_unlink_kind() {
        let mut bytes = [0u8; 104];
        bytes[0] = kind::UNLINK;
        assert!(decode_setattr(&bytes).is_none());
    }

    #[test]
    fn mkdir_event_layout_is_320_bytes() {
        assert_eq!(std::mem::size_of::<MkdirEvent>(), 320);
        assert_eq!(std::mem::align_of::<MkdirEvent>(), 8);
    }

    #[test]
    fn decode_mkdir_round_trips() {
        let mut name_buf = [0u8; NAME_BUF_LEN];
        name_buf[..3].copy_from_slice(b"bar");
        let original = MkdirEvent {
            hdr: EventHeader {
                kind: kind::MKDIR,
                _pad: [0; 3],
                pid: 999,
                tgid: 999,
                parent_pid: 0,
                ts_ns: 0xfedc_ba98_7654_3210,
                comm: *b"mkdir\0\0\0\0\0\0\0\0\0\0\0",
            },
            parent_dev: 0x802,
            parent_inode: 42,
            mode: 0o755,
            name_len: 3,
            name: name_buf,
        };
        let bytes: [u8; 320] = unsafe { std::mem::transmute(original) };
        let decoded = decode_mkdir(&bytes).expect("decode");
        assert_eq!(decoded.hdr.kind, kind::MKDIR);
        assert_eq!(decoded.parent_inode, 42);
        assert_eq!(decoded.mode, 0o755);
        assert_eq!(decoded.basename_os_str(), OsStr::new("bar"));
    }

    #[test]
    fn comm_to_string_stops_at_nul() {
        let mut buf = [0u8; 16];
        buf[..3].copy_from_slice(b"rm\0");
        // Trailing garbage past the NUL must not appear.
        buf[5] = b'X';
        assert_eq!(comm_to_string(&buf), "rm");
    }

    #[test]
    fn comm_to_string_handles_no_nul() {
        let buf = *b"verylongcommandnm"; // 17 chars compressed to 16
        let buf16: [u8; 16] = buf[..16].try_into().unwrap();
        assert_eq!(comm_to_string(&buf16), "verylongcommandn");
    }

    /// Test that the [`LoggingSink`] doesn't panic and is usable as
    /// `Arc<dyn LsmEventSink>`. The actual log assertion is left for
    /// the integration smoke.
    #[test]
    fn logging_sink_is_object_safe() {
        let sink: Arc<dyn LsmEventSink> = Arc::new(LoggingSink);
        let ev = UnlinkEvent::default();
        sink.on_unlink(&ev);
    }

    #[test]
    fn loss_counter_initial_zero_is_clean_and_initial_nonzero_is_loss() {
        let mut clean = LossCounterTracker::default();
        assert_eq!(clean.observe(Ok(0)), None);

        let mut already_lost = LossCounterTracker::default();
        assert_eq!(
            already_lost.observe(Ok(7)),
            Some(RingbufHealthEvent::RecordsDropped { delta: 7, total: 7 })
        );
    }

    #[test]
    fn loss_counter_reports_only_positive_deltas() {
        let mut tracker = LossCounterTracker::default();
        assert_eq!(
            tracker.observe(Ok(2)),
            Some(RingbufHealthEvent::RecordsDropped { delta: 2, total: 2 })
        );
        assert_eq!(tracker.observe(Ok(2)), None);
        assert_eq!(
            tracker.observe(Ok(5)),
            Some(RingbufHealthEvent::RecordsDropped { delta: 3, total: 5 })
        );
    }

    #[test]
    fn loss_counter_delta_survives_u64_wrap() {
        let mut tracker = LossCounterTracker {
            previous: u64::MAX - 2,
            read_failed: false,
        };
        assert_eq!(
            tracker.observe(Ok(3)),
            Some(RingbufHealthEvent::RecordsDropped { delta: 6, total: 3 })
        );
    }

    #[derive(Default)]
    struct HealthSink {
        events: Mutex<Vec<(&'static str, RingbufHealthEvent)>>,
    }

    impl LsmEventSink for HealthSink {
        fn on_ringbuf_health_event(&self, source: &'static str, event: &RingbufHealthEvent) {
            self.events.lock().unwrap().push((source, event.clone()));
        }
    }

    #[test]
    fn loss_and_counter_read_failure_propagate_to_sink() {
        let sink = HealthSink::default();
        let mut tracker = LossCounterTracker::default();

        dispatch_loss_observation(&mut tracker, "inode_unlink", Ok(4), &sink);
        dispatch_loss_observation(
            &mut tracker,
            "inode_unlink",
            Err("lookup failed".into()),
            &sink,
        );
        // A persistent lookup failure is one incident, not a refusal flood at
        // the 250us reader polling interval.
        dispatch_loss_observation(
            &mut tracker,
            "inode_unlink",
            Err("lookup still failed".into()),
            &sink,
        );

        assert_eq!(
            *sink.events.lock().unwrap(),
            vec![
                (
                    "inode_unlink",
                    RingbufHealthEvent::RecordsDropped { delta: 4, total: 4 }
                ),
                (
                    "inode_unlink",
                    RingbufHealthEvent::CounterReadFailed {
                        detail: "lookup failed".into()
                    }
                ),
            ]
        );
    }

    #[test]
    fn production_sink_refuses_every_active_command_on_loss() {
        let (helper_conn, daemon_conn) = crate::ipc::socketpair().unwrap();
        let helper_conn = Arc::new(helper_conn);
        let staging = tempfile::tempdir().unwrap();
        let runtime = crate::capture::linux::LinuxCaptureRuntime::new(
            staging.path().to_path_buf(),
            Arc::clone(&helper_conn),
        )
        .unwrap();
        let mut tree = crate::fanotify::tree::TreeMap::new();
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        tree.watch(second, 22, 2222);
        tree.watch(first, 11, 1111);
        let sink = LinuxCaptureSink {
            runtime: Arc::new(std::sync::Mutex::new(runtime)),
            tree: Arc::new(std::sync::Mutex::new(tree)),
            conn: helper_conn,
            excluded_pids: Vec::new(),
        };

        sink.on_ringbuf_health_event(
            "inode_unlink",
            &RingbufHealthEvent::RecordsDropped { delta: 3, total: 3 },
        );

        let first_msg = daemon_conn.recv_response().unwrap();
        let second_msg = daemon_conn.recv_response().unwrap();
        assert!(matches!(
            first_msg,
            shit_proto::HelperResponse::CaptureRefused {
                session,
                seq: 11,
                path: None,
                detail,
            } if session == first && detail.contains("dropped 3 event(s)")
        ));
        assert!(matches!(
            second_msg,
            shit_proto::HelperResponse::CaptureRefused {
                session,
                seq: 22,
                path: None,
                detail,
            } if session == second && detail.contains("exact command attribution is unavailable")
        ));
    }

    fn fake_flush_control(source: &'static str) -> (LsmFlushControl, mpsc::Receiver<FlushRequest>) {
        let (tx, rx) = mpsc::channel();
        (
            LsmFlushControl {
                source,
                tx,
                running: Arc::new(AtomicBool::new(true)),
                health_epoch: Arc::new(AtomicU64::new(0)),
                counter_read_failed: Arc::new(AtomicBool::new(false)),
            },
            rx,
        )
    }

    #[test]
    fn flush_waits_for_prior_record_callback_and_polls_loss() {
        let (callback_started_tx, callback_started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let order = Arc::new(Mutex::new(Vec::new()));
        let drain_order = Arc::clone(&order);
        let poll_order = Arc::clone(&order);
        std::thread::spawn(move || {
            let mut first_drain = true;
            let result = finish_flush(
                Instant::now() + Duration::from_secs(1),
                |_deadline| {
                    drain_order.lock().unwrap().push("drain");
                    if first_drain {
                        first_drain = false;
                        callback_started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                    }
                    Ok(())
                },
                || {
                    poll_order.lock().unwrap().push("loss");
                    Ok(())
                },
            );
            done_tx.send(result).unwrap();
        });

        callback_started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
        assert_eq!(
            *order.lock().unwrap(),
            vec!["drain", "loss", "drain", "loss"]
        );
    }

    #[test]
    fn flush_all_requires_every_reader_reply() {
        let (first, first_rx) = fake_flush_control("first");
        let (second, second_rx) = fake_flush_control("second");
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let request = first_rx.recv().unwrap();
            request
                .reply
                .send(Ok(LsmFlushReport { health_epoch: 3 }))
                .unwrap();
        });
        std::thread::spawn(move || {
            let request = second_rx.recv().unwrap();
            release_rx.recv().unwrap();
            request
                .reply
                .send(Ok(LsmFlushReport { health_epoch: 4 }))
                .unwrap();
        });
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            done_tx
                .send(flush_all_readers(
                    &[first, second],
                    Instant::now() + Duration::from_secs(1),
                ))
                .unwrap();
        });

        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            vec![
                LsmFlushReport { health_epoch: 3 },
                LsmFlushReport { health_epoch: 4 }
            ]
        );
    }

    #[test]
    fn flush_reports_disconnected_and_timed_out_reader() {
        let (disconnected, disconnected_rx) = fake_flush_control("gone");
        drop(disconnected_rx);
        assert!(
            disconnected
                .flush_until(Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .contains("disconnected")
        );

        let (timed_out, _held_rx) = fake_flush_control("stuck");
        assert!(
            timed_out
                .flush_until(Instant::now() + Duration::from_millis(10))
                .unwrap_err()
                .contains("timed out")
        );
    }

    /// Capture-into-Vec sink used in tests of higher-layer code that
    /// drives the reader. Not exposed publicly.
    #[allow(dead_code)]
    struct CapturingSink {
        events: Mutex<Vec<UnlinkEvent>>,
    }

    impl LsmEventSink for CapturingSink {
        fn on_unlink(&self, ev: &UnlinkEvent) {
            self.events.lock().unwrap().push(*ev);
        }
    }
}
