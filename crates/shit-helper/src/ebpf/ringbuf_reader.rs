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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use aya::maps::{MapData, RingBuf};

/// Header common to every event, mirroring `struct shit_event_hdr`
/// in `bpf/src/common.h`. The `kind` byte indicates the tail layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventHeader {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub pid: u32,
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
            .field("name", &self.basename_str())
            .finish()
    }
}

impl UnlinkEvent {
    /// Returns the basename as a borrowed `&str`. Defensively clamps
    /// `name_len` to `NAME_BUF_LEN` so a malformed kernel record can't
    /// induce an out-of-bounds slice. Returns `""` if the BPF program
    /// reported `name_len == 0` (str_read failed).
    pub fn basename_str(&self) -> std::borrow::Cow<'_, str> {
        let len = (self.name_len as usize).min(NAME_BUF_LEN);
        String::from_utf8_lossy(&self.name[..len])
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
            .field("name", &self.basename_str())
            .finish()
    }
}

impl MkdirEvent {
    pub fn basename_str(&self) -> std::borrow::Cow<'_, str> {
        let len = (self.name_len as usize).min(NAME_BUF_LEN);
        String::from_utf8_lossy(&self.name[..len])
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
            .field("name", &self.basename_str())
            .finish()
    }
}

impl CreateEvent {
    pub fn basename_str(&self) -> std::borrow::Cow<'_, str> {
        let len = (self.name_len as usize).min(NAME_BUF_LEN);
        String::from_utf8_lossy(&self.name[..len])
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
            .field("old_name", &self.old_basename_str())
            .field("new_name", &self.new_basename_str())
            .finish()
    }
}

impl RenameEvent {
    pub fn old_basename_str(&self) -> std::borrow::Cow<'_, str> {
        let len = (self.old_name_len as usize).min(NAME_BUF_LEN);
        String::from_utf8_lossy(&self.old_name[..len])
    }
    pub fn new_basename_str(&self) -> std::borrow::Cow<'_, str> {
        let len = (self.new_name_len as usize).min(NAME_BUF_LEN);
        String::from_utf8_lossy(&self.new_name[..len])
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
    /// PIDs whose LSM events are dropped unconditionally. Typically
    /// `[helper_self_pid, daemon_pid]`.
    pub excluded_pids: Vec<u32>,
}

#[cfg(target_os = "linux")]
impl LinuxCaptureSink {
    /// Returns true if events from `pid` should be filtered out
    /// before tree lookup.
    fn is_excluded(&self, pid: u32) -> bool {
        self.excluded_pids.contains(&pid)
    }
}

#[cfg(target_os = "linux")]
impl LsmEventSink for LinuxCaptureSink {
    fn on_unlink(&self, ev: &UnlinkEvent) {
        if self.is_excluded(ev.hdr.pid) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm unlink event");
            return;
        };
        let basename_cow = ev.basename_str();
        let view = crate::capture::linux::LsmUnlinkView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
            dev: ev.dev,
            inode: ev.inode,
            parent_inode: ev.parent_inode,
            basename: &basename_cow,
        };
        self.runtime.lock().unwrap().handle_lsm_unlink(&view);
    }

    fn on_setattr(&self, ev: &SetattrEvent) {
        if self.is_excluded(ev.hdr.pid) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm setattr event");
            return;
        };
        let view = crate::capture::linux::LsmSetattrView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
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
    }

    fn on_mkdir(&self, ev: &MkdirEvent) {
        if self.is_excluded(ev.hdr.pid) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm mkdir event");
            return;
        };
        let basename_cow = ev.basename_str();
        let view = crate::capture::linux::LsmMkdirView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
            parent_dev: ev.parent_dev,
            parent_inode: ev.parent_inode,
            mode: ev.mode,
            basename: &basename_cow,
        };
        self.runtime.lock().unwrap().handle_lsm_mkdir(&view);
    }

    fn on_create(&self, ev: &CreateEvent) {
        if self.is_excluded(ev.hdr.pid) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm create event");
            return;
        };
        let basename_cow = ev.basename_str();
        let view = crate::capture::linux::LsmCreateView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
            parent_dev: ev.parent_dev,
            parent_inode: ev.parent_inode,
            mode: ev.mode,
            basename: &basename_cow,
        };
        self.runtime.lock().unwrap().handle_lsm_create(&view);
    }

    fn on_open(&self, ev: &OpenEvent) {
        if self.is_excluded(ev.hdr.pid) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm open event");
            return;
        };
        let view = crate::capture::linux::LsmOpenView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
            dev: ev.dev,
            inode: ev.inode,
            f_mode: ev.f_mode,
            f_flags: ev.f_flags,
        };
        self.runtime.lock().unwrap().handle_lsm_open(&view);
    }

    fn on_rename(&self, ev: &RenameEvent) {
        if self.is_excluded(ev.hdr.pid) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_parent(pid, ev.hdr.parent_pid as i32)
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm rename event");
            return;
        };
        let old_basename = ev.old_basename_str();
        let new_basename = ev.new_basename_str();
        let view = crate::capture::linux::LsmRenameView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
            dev: ev.dev,
            inode: ev.inode,
            old_parent_inode: ev.old_parent_inode,
            new_parent_inode: ev.new_parent_inode,
            old_basename: &old_basename,
            new_basename: &new_basename,
        };
        self.runtime.lock().unwrap().handle_lsm_rename(&view);
    }
}

/// Stub sink — logs each event at info-level. Useful for the manual
/// smoke (step 4 of the sprint implementation order: "load the
/// program, `rm` a file, see the log line").
pub struct LoggingSink;

impl LsmEventSink for LoggingSink {
    fn on_unlink(&self, ev: &UnlinkEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        let basename = ev.basename_str();
        tracing::info!(
            kind = "unlink",
            pid = ev.hdr.pid,
            tgid = ev.hdr.tgid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            parent_inode = ev.parent_inode,
            name_len = ev.name_len,
            basename = %basename,
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
        let basename = ev.basename_str();
        tracing::info!(
            kind = "mkdir",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            parent_dev = ev.parent_dev,
            parent_inode = ev.parent_inode,
            mode = format_args!("{:o}", ev.mode),
            basename = %basename,
            comm,
            "lsm event"
        );
    }

    fn on_create(&self, ev: &CreateEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        let basename = ev.basename_str();
        tracing::info!(
            kind = "create",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            parent_dev = ev.parent_dev,
            parent_inode = ev.parent_inode,
            mode = format_args!("{:o}", ev.mode),
            basename = %basename,
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
        let old = ev.old_basename_str();
        let new = ev.new_basename_str();
        tracing::info!(
            kind = "rename",
            pid = ev.hdr.pid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            old_basename = %old,
            new_basename = %new,
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

/// Userspace consumer of a single L04 LSM ringbuf. One OS thread per
/// LsmReader instance — separate ringbufs (`unlink_events`,
/// `setattr_events`, ...) each get their own reader. Dispatches via
/// the provided [`RecordHandler`] closure into the [`LsmEventSink`].
pub struct LsmReader {
    alive: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LsmReader {
    /// Spawn an unlink-ringbuf reader. Convenience over
    /// [`Self::spawn_with_handler`] — wires the unlink decoder.
    pub fn spawn(
        unlink_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-unlink",
            unlink_rb,
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

    /// Spawn a setattr-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_setattr`.
    pub fn spawn_setattr(
        setattr_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-setattr",
            setattr_rb,
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
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-mkdir",
            mkdir_rb,
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
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-create",
            create_rb,
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

    /// Spawn an open-ringbuf reader. Convenience wrapper for
    /// `lsm/file_open` (write-intent opens only; BPF pre-filters).
    pub fn spawn_open(
        open_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-open",
            open_rb,
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
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-rename",
            rename_rb,
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
        rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        handler: RecordHandler,
        idle_sleep: Duration,
    ) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let alive_t = Arc::clone(&alive);
        let handle = std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                reader_thread(thread_name, rb, sink, handler, alive_t, idle_sleep);
            })
            .expect("spawn lsm reader");
        LsmReader {
            alive,
            handle: Some(handle),
        }
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
    thread_name: &'static str,
    mut rb: RingBuf<MapData>,
    sink: Arc<dyn LsmEventSink>,
    handler: RecordHandler,
    alive: Arc<AtomicBool>,
    idle_sleep: Duration,
) {
    while alive.load(Ordering::Acquire) {
        let mut drained_this_pass = 0u32;
        while let Some(rec) = rb.next() {
            let slice: &[u8] = &rec[..];
            handler(slice, sink.as_ref());
            drained_this_pass += 1;
            if drained_this_pass >= 1024 {
                break;
            }
        }
        std::thread::sleep(idle_sleep);
    }
    tracing::info!(thread = thread_name, "lsm-rb reader exiting");
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
        assert_eq!(decoded.basename_str(), "foo.txt");
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
    fn basename_str_clamps_oversize_name_len() {
        // Defensive: even if BPF reports name_len > NAME_BUF_LEN (it
        // can't, but be paranoid), basename_str must clamp.
        let mut ev = UnlinkEvent::default();
        ev.name[..3].copy_from_slice(b"foo");
        ev.name_len = (NAME_BUF_LEN as u32) + 999;
        let s = ev.basename_str();
        assert_eq!(s.len(), NAME_BUF_LEN);
        assert!(s.starts_with("foo"));
    }

    #[test]
    fn basename_str_zero_len_yields_empty() {
        let mut ev = UnlinkEvent::default();
        ev.name[..3].copy_from_slice(b"foo");
        ev.name_len = 0;
        assert_eq!(ev.basename_str(), "");
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
        assert_eq!(decoded.basename_str(), "bar");
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
