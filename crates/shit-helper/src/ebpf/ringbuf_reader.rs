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
//! shit_event_hdr     (72 bytes)
//!   u8  kind              offset  0
//!   u8  _pad[3]           offset  1
//!   u32 pid               offset  4
//!   u32 tgid              offset  8
//!   u32 parent_pid        offset 12   (task->real_parent->tgid)
//!   u64 ts_ns             offset 16
//!   u8  comm[16]          offset 24
//!   u32 ancestors[8]      offset 40   (grandparent upward, 0 past the top)
//! shit_unlink_event  (360 bytes total)
//!   shit_event_hdr hdr    offset   0
//!   u64 dev               offset  72
//!   u64 inode             offset  80
//!   u64 parent_inode      offset  88
//!   u32 name_len          offset  96
//!   u32 _pad3             offset 100
//!   u8  name[256]         offset 104  (NAME_MAX+1, NUL-terminated)
//! ```
//!
//! Lifetime model: the reader owns a `RingBuf<MapData>` (taken from
//! the [`EbpfLoader`] via [`crate::ebpf::loader::EbpfLoader::take_unlink_ringbuf`])
//! and runs in its own OS thread. A `JoinHandle` is returned so the
//! helper's shutdown path can join it after closing the BPF Ebpf
//! instance (which closes the ringbuf fd, which makes `next()`
//! return None deterministically).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::loader::RingbufLossCounter;

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
    /// Tgids above `parent_pid`, nearest first, read at hook-fire
    /// time. 0 past the top of the tree. Lets a grandchild of the
    /// tracked root be attributed after it and its parent have exited
    /// (#209: `sh -c 'chmod ...'` forks chmod under sh).
    pub ancestors: [u32; ANCESTRY_DEPTH],
}

/// Ancestors above the parent that the BPF programs record. Mirrors
/// `SHIT_ANCESTRY_DEPTH` in common.h.
pub const ANCESTRY_DEPTH: usize = 8;

const _: () = assert!(std::mem::size_of::<EventHeader>() == 72);

impl EventHeader {
    /// The event task's ancestry as recorded by BPF: parent first,
    /// then each tgid above it.
    pub fn ancestry(&self) -> [i32; ANCESTRY_DEPTH + 1] {
        let mut out = [0i32; ANCESTRY_DEPTH + 1];
        out[0] = self.parent_pid as i32;
        for (slot, a) in out[1..].iter_mut().zip(self.ancestors) {
            *slot = a as i32;
        }
        out
    }
}

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

const _: () = assert!(std::mem::size_of::<UnlinkEvent>() == 360);

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

const _: () = assert!(std::mem::size_of::<SetattrEvent>() == 136);

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

const _: () = assert!(std::mem::size_of::<MkdirEvent>() == 352);

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

const _: () = assert!(std::mem::size_of::<CreateEvent>() == 352);

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

const _: () = assert!(std::mem::size_of::<OpenEvent>() == 96);

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

const _: () = assert!(std::mem::size_of::<ReleaseEvent>() == 96);

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

const _: () = assert!(std::mem::size_of::<RenameEvent>() == 624);

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
    /// G03 — `inode_rmdir` events. Wire shape is identical to
    /// `UnlinkEvent` (kernel LSM hook signature is the same).
    fn on_rmdir(&self, _ev: &UnlinkEvent) {}
    /// L04.2 — `file_release` events. Fires at last-fd-close of a
    /// writable file; the handler diffs current content against
    /// the open-time snapshot and emits a `CapturedPreImage` iff
    /// they differ. Closes the in-place-write capture gap.
    fn on_release(&self, _ev: &ReleaseEvent) {}
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
    /// Returns true if the event comes from an excluded process or
    /// from anything it spawned. Matched on the tgid (`hdr.pid` is the
    /// thread id, so a worker thread of the helper or daemon would
    /// otherwise pass) and on every recorded ancestor: a `dpkg-query`
    /// or `systemctl` the helper or daemon runs has them in its
    /// ancestry, and above them the shell that started shitd, which
    /// can be a tracked root.
    fn is_excluded(&self, hdr: &EventHeader) -> bool {
        excluded_by_lineage(&self.excluded_pids, hdr)
    }
}

/// True when the event's process (its tgid, not its thread id) or any
/// recorded ancestor is in `excluded`. Ancestry ends at the first 0.
fn excluded_by_lineage(excluded: &[u32], hdr: &EventHeader) -> bool {
    std::iter::once(hdr.tgid)
        .chain(hdr.ancestry().into_iter().map(|a| a as u32))
        .take_while(|&p| p != 0)
        .any(|p| excluded.contains(&p))
}

/// Start-up tap for the `FMODE_CREATED` probe. While active, open events
/// from `tgid` are recorded before the exclusion filter drops them.
static FMODE_PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
/// `(kernel dev, inode, f_mode)` of one open event.
type ProbedOpen = (u64, u64, u32);
static FMODE_PROBE: std::sync::Mutex<Option<(u32, Vec<ProbedOpen>)>> = std::sync::Mutex::new(None);

/// Record open events from `tgid` until [`fmode_probe_finish`].
pub fn fmode_probe_begin(tgid: u32) {
    *FMODE_PROBE.lock().unwrap_or_else(|e| e.into_inner()) = Some((tgid, Vec::new()));
    FMODE_PROBE_ACTIVE.store(true, Ordering::Release);
}

/// Stop recording and return `(kernel dev, inode, f_mode)` per open seen.
pub fn fmode_probe_finish() -> Vec<(u64, u64, u32)> {
    FMODE_PROBE_ACTIVE.store(false, Ordering::Release);
    FMODE_PROBE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .map(|(_, seen)| seen)
        .unwrap_or_default()
}

fn fmode_probe_tap(ev: &OpenEvent) {
    if !FMODE_PROBE_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    if let Some((tgid, seen)) = FMODE_PROBE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        && *tgid == ev.hdr.tgid
    {
        seen.push((ev.dev, ev.inode, ev.f_mode));
    }
}

#[cfg(target_os = "linux")]
impl LsmEventSink for LinuxCaptureSink {
    fn on_unlink(&self, ev: &UnlinkEvent) {
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
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
            is_directory: false,
        };
        self.runtime.lock().unwrap().handle_lsm_unlink(&view);
    }

    fn on_rmdir(&self, ev: &UnlinkEvent) {
        // G03 — identical wire to on_unlink. We route through the
        // same handle_lsm_unlink path with is_directory=true so the
        // handler skips content capture (dirs have no bytes) and
        // emits a marker CapturedPreImage with the dir's mode.
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm rmdir event");
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
            is_directory: true,
        };
        self.runtime.lock().unwrap().handle_lsm_unlink(&view);
    }

    fn on_release(&self, ev: &ReleaseEvent) {
        // L04.2 — writable-fd close. Handler diffs against pre-image
        // snapshot and emits CapturedPreImage iff content changed.
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
        else {
            tracing::trace!(pid, "untracked pid; dropping lsm release event");
            return;
        };
        let view = crate::capture::linux::LsmReleaseView {
            command: shit_planner::events::CommandId { session, seq },
            pid: ev.hdr.pid,
            dev: ev.dev,
            inode: ev.inode,
            f_mode: ev.f_mode,
            f_flags: ev.f_flags,
        };
        self.runtime.lock().unwrap().handle_lsm_release(&view);
    }

    fn on_setattr(&self, ev: &SetattrEvent) {
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
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
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
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
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
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
        fmode_probe_tap(ev);
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
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
        if self.is_excluded(&ev.hdr) {
            return;
        }
        let pid = ev.hdr.pid as i32;
        let Some((session, seq)) = self
            .tree
            .lock()
            .unwrap()
            .is_tracked_with_ancestry(ev.hdr.tgid as i32, &ev.hdr.ancestry())
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

/// Total ring-buffer reserve failures observed across every LSM object
/// since the helper started. Counting only: R3 slice A records and logs
/// the loss; turning it into a refusal is a later slice.
static RINGBUF_LOSSES_OBSERVED: AtomicU64 = AtomicU64::new(0);

/// How often a reader polls its object's loss counter between flushes.
const LOSS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Time a reader may spend draining for one flush request. The drain
/// runs until the ring is empty; this bound only matters when producers
/// refill the ring as fast as it drains. It is half of the request
/// loop's `LSM_FLUSH_TIMEOUT` (2 s), so a reader that hits it still acks
/// inside the wait and the close reports a truncated tail instead of a
/// timeout; the daemon's barrier waits 5 s on top. A 256 KiB ring holds
/// at most about 4k records, which drain in milliseconds, so a drain
/// that has not emptied the ring in a second is not converging.
const FLUSH_DRAIN_BUDGET: Duration = Duration::from_secs(1);

/// Ring-buffer reserve failures observed so far, summed over objects.
pub fn ringbuf_losses_observed() -> u64 {
    RINGBUF_LOSSES_OBSERVED.load(Ordering::Relaxed)
}

/// Tracks one object's loss counter and reports increases.
struct LossTracker {
    counter: Option<RingbufLossCounter>,
    last: u64,
    unreadable_logged: bool,
}

impl LossTracker {
    fn new(counter: Option<RingbufLossCounter>) -> Self {
        Self {
            counter,
            last: 0,
            unreadable_logged: false,
        }
    }

    fn poll(&mut self, thread_name: &'static str) {
        let Some(counter) = &self.counter else {
            return;
        };
        match counter.get(&0, 0) {
            Ok(value) => {
                let delta = note_loss_value(&mut self.last, value);
                if delta > 0 {
                    RINGBUF_LOSSES_OBSERVED.fetch_add(delta, Ordering::Relaxed);
                    tracing::warn!(
                        thread = thread_name,
                        lost = delta,
                        total_for_object = value,
                        "eBPF ring buffer was full; events were dropped and capture is incomplete"
                    );
                }
            }
            Err(e) => {
                if !self.unreadable_logged {
                    self.unreadable_logged = true;
                    tracing::warn!(
                        thread = thread_name,
                        err = %e,
                        "eBPF ring-buffer loss counter is unreadable; drops cannot be counted"
                    );
                }
            }
        }
    }
}

/// Advance `last` to `value` and return how many losses that is. The
/// counter is a u64 that wraps, so the difference uses wrapping math.
fn note_loss_value(last: &mut u64, value: u64) -> u64 {
    let delta = value.wrapping_sub(*last);
    *last = value;
    delta
}

/// Handle the request loop uses to make one reader drain its ring
/// buffer and acknowledge. Cheap to clone.
#[derive(Clone)]
pub struct LsmFlushHandle {
    thread_name: &'static str,
    tx: mpsc::Sender<FlushRequest>,
}

/// One flush request: where the ack goes, and when the drain must stop.
/// The deadline is fixed when the request is sent, so time the reader
/// spends on records it was already handling counts against the budget.
pub struct FlushRequest {
    ack: mpsc::SyncSender<FlushAck>,
    deadline: Instant,
}

/// Records a reader dispatches between flush and loss-counter checks.
const READ_BATCH: u32 = 1024;

/// Dispatch up to [`READ_BATCH`] records. `next` handles one record and
/// returns false when the ring is empty; `poll` returns a flush request
/// if one is waiting. A request ends the batch at once and goes into
/// `pending`, so it does not wait behind the rest of the batch.
fn dispatch_batch(
    mut next: impl FnMut() -> bool,
    mut poll: impl FnMut() -> Option<FlushRequest>,
    pending: &mut Vec<FlushRequest>,
) {
    for _ in 0..READ_BATCH {
        if let Some(req) = poll() {
            pending.push(req);
            return;
        }
        if !next() {
            return;
        }
    }
}

/// A reader's answer to a flush request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushAck {
    /// The ring was empty when the drain stopped.
    Drained,
    /// The drain ran out of [`FLUSH_DRAIN_BUDGET`] with records still
    /// queued. Those reach userspace after the tree is unwatched and lose
    /// their attribution, so the close reports the command's tail as
    /// possibly missing.
    Truncated { drained: u32 },
}

/// Drain for a flush request. `next` handles one record and returns
/// false when the ring is empty; `expired` reports that the time budget
/// is spent. The drain runs until the ring is empty. When the budget is
/// spent, one more record found waiting makes the drain truncated; that
/// record is handled too, so the check loses nothing.
fn drain_for_flush(mut expired: impl FnMut() -> bool, mut next: impl FnMut() -> bool) -> FlushAck {
    let mut drained = 0u32;
    loop {
        if expired() {
            return if next() {
                FlushAck::Truncated { drained }
            } else {
                FlushAck::Drained
            };
        }
        if !next() {
            return FlushAck::Drained;
        }
        drained = drained.saturating_add(1);
    }
}

impl LsmFlushHandle {
    /// Ask the reader to dispatch every record already in its ring
    /// buffer. Returns the channel its ack arrives on.
    fn request(&self) -> Result<mpsc::Receiver<FlushAck>, String> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.tx
            .send(FlushRequest {
                ack: ack_tx,
                deadline: Instant::now() + FLUSH_DRAIN_BUDGET,
            })
            .map_err(|_| format!("eBPF {} reader is not running", self.thread_name))?;
        Ok(ack_rx)
    }
}

/// Flush every reader. All requests go out before any ack is awaited, so
/// the readers drain in parallel and one stuck reader cannot use up the
/// time of the rest. Every failure is reported.
pub fn flush_all_readers(handles: &[LsmFlushHandle], timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let requests: Vec<_> = handles.iter().map(LsmFlushHandle::request).collect();
    let mut failures = Vec::new();
    for (handle, request) in handles.iter().zip(requests) {
        match request {
            Ok(ack) => {
                let wait = deadline.saturating_duration_since(Instant::now());
                match ack.recv_timeout(wait) {
                    Ok(FlushAck::Drained) => {}
                    Ok(FlushAck::Truncated { drained }) => failures.push(format!(
                        "eBPF {} reader flush stopped after {drained} records with more queued",
                        handle.thread_name
                    )),
                    Err(_) => failures.push(format!(
                        "eBPF {} reader flush timed out",
                        handle.thread_name
                    )),
                }
            }
            Err(e) => failures.push(e),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Userspace consumer of a single L04 LSM ringbuf. One OS thread per
/// LsmReader instance — separate ringbufs (`unlink_events`,
/// `setattr_events`, ...) each get their own reader. Dispatches via
/// the provided [`RecordHandler`] closure into the [`LsmEventSink`].
pub struct LsmReader {
    alive: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    flush: LsmFlushHandle,
}

impl LsmReader {
    /// Spawn an unlink-ringbuf reader. Convenience over
    /// [`Self::spawn_with_handler`] — wires the unlink decoder.
    pub fn spawn(
        unlink_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
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
            loss_counter,
        )
    }

    /// G03 — spawn an rmdir-ringbuf reader. Wire shape is identical
    /// to unlink (same kernel hook signature) but dispatched via
    /// `on_rmdir` so userspace can flag the event as a directory
    /// removal at the sink level.
    pub fn spawn_rmdir(
        rmdir_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-rmdir",
            rmdir_rb,
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
            loss_counter,
        )
    }

    /// L04.2 — spawn a file_release ringbuf reader. The BPF
    /// program pre-filters to writable closes; userspace dispatches
    /// via `on_release` which routes through `handle_lsm_release`
    /// for content-diff capture.
    pub fn spawn_release(
        release_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-release",
            release_rb,
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
            loss_counter,
        )
    }

    /// Spawn a setattr-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_setattr`.
    pub fn spawn_setattr(
        setattr_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
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
            loss_counter,
        )
    }

    /// Spawn a mkdir-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_mkdir`.
    pub fn spawn_mkdir(
        mkdir_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
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
            loss_counter,
        )
    }

    /// Spawn a create-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_create`.
    pub fn spawn_create(
        create_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
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
            loss_counter,
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
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
    ) -> Self {
        Self::spawn_with_handler(
            "shit-lsm-mknod",
            mknod_rb,
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
            loss_counter,
        )
    }

    /// Spawn an open-ringbuf reader. Convenience wrapper for
    /// `lsm/file_open` (write-intent opens only; BPF pre-filters).
    pub fn spawn_open(
        open_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
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
            loss_counter,
        )
    }

    /// Spawn a rename-ringbuf reader. Convenience wrapper for
    /// `lsm/inode_rename`.
    pub fn spawn_rename(
        rename_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
        loss_counter: Option<RingbufLossCounter>,
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
            loss_counter,
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
        loss_counter: Option<RingbufLossCounter>,
    ) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let alive_t = Arc::clone(&alive);
        let (flush_tx, flush_rx) = mpsc::channel();
        let handle = std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                reader_thread(
                    thread_name,
                    rb,
                    sink,
                    handler,
                    alive_t,
                    idle_sleep,
                    LossTracker::new(loss_counter),
                    flush_rx,
                );
            })
            .expect("spawn lsm reader");
        LsmReader {
            alive,
            handle: Some(handle),
            flush: LsmFlushHandle {
                thread_name,
                tx: flush_tx,
            },
        }
    }

    /// Handle for the UnwatchTree close barrier.
    pub fn flush_handle(&self) -> LsmFlushHandle {
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

#[allow(clippy::too_many_arguments)]
fn reader_thread(
    thread_name: &'static str,
    mut rb: RingBuf<MapData>,
    sink: Arc<dyn LsmEventSink>,
    handler: RecordHandler,
    alive: Arc<AtomicBool>,
    idle_sleep: Duration,
    mut loss: LossTracker,
    flush_rx: mpsc::Receiver<FlushRequest>,
) {
    let mut last_loss_poll = Instant::now();
    let mut pending: Vec<FlushRequest> = Vec::new();
    while alive.load(Ordering::Acquire) {
        dispatch_batch(
            || {
                let Some(rec) = rb.next() else {
                    return false;
                };
                handler(&rec[..], sink.as_ref());
                true
            },
            || flush_rx.try_recv().ok(),
            &mut pending,
        );
        pending.extend(flush_rx.try_iter());
        // Close barrier: every record the kernel wrote before the
        // request is already in the ring, so draining until empty
        // dispatches the command's whole tail before the ack. The
        // budget runs from when the request was sent. A single handler
        // still runs to completion, so one that outlasts the requester's
        // wait shows up there as a timeout, which the close reports the
        // same way.
        for FlushRequest { ack, deadline } in pending.drain(..) {
            let outcome = drain_for_flush(
                || Instant::now() >= deadline,
                || {
                    let Some(rec) = rb.next() else {
                        return false;
                    };
                    handler(&rec[..], sink.as_ref());
                    true
                },
            );
            if let FlushAck::Truncated { drained } = outcome {
                tracing::warn!(
                    thread = thread_name,
                    drained,
                    "eBPF flush drain ran out of time with records still queued"
                );
            }
            loss.poll(thread_name);
            last_loss_poll = Instant::now();
            let _ = ack.send(outcome);
        }
        if last_loss_poll.elapsed() >= LOSS_POLL_INTERVAL {
            loss.poll(thread_name);
            last_loss_poll = Instant::now();
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
    fn loss_delta_counts_increases_and_wraps() {
        let mut last = 0;
        assert_eq!(note_loss_value(&mut last, 0), 0);
        assert_eq!(note_loss_value(&mut last, 3), 3);
        assert_eq!(note_loss_value(&mut last, 3), 0);
        last = u64::MAX;
        assert_eq!(note_loss_value(&mut last, 1), 2);
    }

    #[test]
    fn flush_reports_stopped_reader() {
        let (tx, rx) = mpsc::channel();
        drop(rx);
        let handle = LsmFlushHandle {
            thread_name: "test",
            tx,
        };
        let err = flush_all_readers(&[handle], Duration::from_millis(10)).unwrap_err();
        assert!(err.contains("not running"), "{err}");
    }

    #[test]
    fn flush_times_out_when_reader_never_acks() {
        let (tx, rx) = mpsc::channel::<FlushRequest>();
        let handle = LsmFlushHandle {
            thread_name: "test",
            tx,
        };
        let err = flush_all_readers(&[handle], Duration::from_millis(10)).unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        drop(rx);
    }

    #[test]
    fn stuck_reader_does_not_starve_the_others() {
        let (stuck_tx, stuck_rx) = mpsc::channel::<FlushRequest>();
        let (slow_tx, slow_rx) = mpsc::channel::<FlushRequest>();
        // Acks well inside the deadline, but only after the stuck reader's
        // whole wait would have used it up if requests went out in turn.
        let slow = std::thread::spawn(move || {
            let requested_at = Instant::now();
            let ack = slow_rx.recv().unwrap().ack;
            let waited = requested_at.elapsed();
            ack.send(FlushAck::Drained).unwrap();
            waited
        });
        let handles = [
            LsmFlushHandle {
                thread_name: "stuck",
                tx: stuck_tx,
            },
            LsmFlushHandle {
                thread_name: "slow",
                tx: slow_tx,
            },
        ];
        let err = flush_all_readers(&handles, Duration::from_millis(300)).unwrap_err();
        assert!(err.contains("stuck"), "{err}");
        assert!(!err.contains("slow"), "{err}");
        assert!(
            slow.join().unwrap() < Duration::from_millis(250),
            "the second reader was asked only after the first gave up"
        );
        drop(stuck_rx);
    }

    #[test]
    fn flush_succeeds_when_reader_acks() {
        let (tx, rx) = mpsc::channel::<FlushRequest>();
        let t = std::thread::spawn(move || {
            let ack = rx.recv().unwrap().ack;
            ack.send(FlushAck::Drained).unwrap();
        });
        let handle = LsmFlushHandle {
            thread_name: "test",
            tx,
        };
        flush_all_readers(&[handle], Duration::from_secs(5)).unwrap();
        t.join().unwrap();
    }

    #[test]
    fn truncated_flush_is_reported_as_incomplete() {
        let (tx, rx) = mpsc::channel::<FlushRequest>();
        let t = std::thread::spawn(move || {
            let ack = rx.recv().unwrap().ack;
            ack.send(FlushAck::Truncated { drained: 7 }).unwrap();
        });
        let handle = LsmFlushHandle {
            thread_name: "open",
            tx,
        };
        let err = flush_all_readers(&[handle], Duration::from_secs(5)).unwrap_err();
        assert!(
            err.contains("eBPF open reader flush stopped after 7 records"),
            "{err}"
        );
        t.join().unwrap();
    }

    /// A ring of `n` records; returns how many `next` handled.
    fn ring(n: u32) -> (std::cell::Cell<u32>, std::cell::Cell<u32>) {
        (std::cell::Cell::new(n), std::cell::Cell::new(0))
    }

    #[test]
    fn drain_empties_the_ring_past_any_record_count() {
        // More than the old FLUSH_DRAIN_MAX cap: a drain with time left
        // keeps going until the ring is empty.
        let (left, handled) = ring((1 << 16) + 10);
        let outcome = drain_for_flush(
            || false,
            || {
                if left.get() == 0 {
                    return false;
                }
                left.set(left.get() - 1);
                handled.set(handled.get() + 1);
                true
            },
        );
        assert_eq!(outcome, FlushAck::Drained);
        assert_eq!(handled.get(), (1 << 16) + 10);
    }

    #[test]
    fn drain_is_truncated_only_when_time_runs_out_with_records_left() {
        let (left, handled) = ring(5);
        let checks = std::cell::Cell::new(0u32);
        let outcome = drain_for_flush(
            || {
                checks.set(checks.get() + 1);
                checks.get() > 3
            },
            || {
                if left.get() == 0 {
                    return false;
                }
                left.set(left.get() - 1);
                handled.set(handled.get() + 1);
                true
            },
        );
        assert_eq!(outcome, FlushAck::Truncated { drained: 3 });
        assert_eq!(
            handled.get(),
            4,
            "the record that proved truncation is handled"
        );

        // Time runs out exactly as the ring empties: not truncated.
        let (left, _) = ring(3);
        let checks = std::cell::Cell::new(0u32);
        let outcome = drain_for_flush(
            || {
                checks.set(checks.get() + 1);
                checks.get() > 3
            },
            || {
                if left.get() == 0 {
                    return false;
                }
                left.set(left.get() - 1);
                true
            },
        );
        assert_eq!(outcome, FlushAck::Drained);
    }

    #[test]
    fn drain_budget_fits_inside_the_flush_wait() {
        assert!(FLUSH_DRAIN_BUDGET < crate::LSM_FLUSH_TIMEOUT);
    }

    /// #234 item 5: the budget runs from when the request is sent, not
    /// from when the reader gets to it.
    #[test]
    fn flush_deadline_is_fixed_when_the_request_is_sent() {
        let (tx, rx) = mpsc::channel::<FlushRequest>();
        let handle = LsmFlushHandle {
            thread_name: "test",
            tx,
        };
        let sent = Instant::now();
        let _ack = handle.request().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let req = rx.recv().unwrap();
        assert!(req.deadline <= sent + FLUSH_DRAIN_BUDGET + Duration::from_millis(5));
        assert!(req.deadline > sent);
    }

    /// #234 item 5: a request that arrives mid-batch ends the batch, so
    /// it does not wait behind up to [`READ_BATCH`] more records.
    #[test]
    fn flush_request_ends_the_batch_it_arrives_in() {
        let (tx, rx) = mpsc::channel::<FlushRequest>();
        let handled = std::cell::Cell::new(0u32);
        let mut pending = Vec::new();
        dispatch_batch(
            || {
                handled.set(handled.get() + 1);
                if handled.get() == 3 {
                    let (ack, _) = mpsc::sync_channel(1);
                    tx.send(FlushRequest {
                        ack,
                        deadline: Instant::now(),
                    })
                    .unwrap();
                }
                true
            },
            || rx.try_recv().ok(),
            &mut pending,
        );
        assert_eq!(handled.get(), 3);
        assert_eq!(pending.len(), 1);

        // Without a request the batch stops at its size.
        let handled = std::cell::Cell::new(0u32);
        let mut pending = Vec::new();
        dispatch_batch(
            || {
                handled.set(handled.get() + 1);
                true
            },
            || None,
            &mut pending,
        );
        assert_eq!(handled.get(), READ_BATCH);
        assert!(pending.is_empty());
    }

    /// A request whose budget ran out before the reader reached it still
    /// gets a truncation answer, inside the requester's wait.
    #[test]
    fn late_picked_up_request_acks_truncated() {
        let deadline = Instant::now();
        let (left, _) = ring(5);
        let outcome = drain_for_flush(
            || Instant::now() >= deadline,
            || {
                if left.get() == 0 {
                    return false;
                }
                left.set(left.get() - 1);
                true
            },
        );
        assert_eq!(outcome, FlushAck::Truncated { drained: 0 });
    }

    #[test]
    fn header_layout_is_72_bytes() {
        assert_eq!(std::mem::size_of::<EventHeader>(), 72);
        assert_eq!(std::mem::align_of::<EventHeader>(), 8);
    }

    #[test]
    fn unlink_event_layout_is_360_bytes() {
        assert_eq!(std::mem::size_of::<UnlinkEvent>(), 360);
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
                ancestors: [0; ANCESTRY_DEPTH],
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
        let bytes: [u8; 360] = unsafe { std::mem::transmute(original) };
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
        let bytes = [0u8; 32]; // shorter than the 360-byte struct
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
    fn setattr_event_layout_is_136_bytes() {
        assert_eq!(std::mem::size_of::<SetattrEvent>(), 136);
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
                ancestors: [0; ANCESTRY_DEPTH],
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
        let bytes: [u8; 136] = unsafe { std::mem::transmute(original) };
        let decoded = decode_setattr(&bytes).expect("decode");
        assert_eq!(decoded.hdr.kind, kind::SETATTR);
        assert_eq!(decoded.attr_valid, attr::MODE);
        assert_eq!(decoded.old_mode, 0o100644);
        assert_eq!(decoded.new_mode, 0o100755);
        assert_eq!(decoded.dev, 0x802);
        assert_eq!(decoded.inode, 12345);
    }

    #[test]
    fn ancestry_decodes_from_the_wire_offsets() {
        // common.h: parent_pid at 12, ancestors[8] at 40, header 72.
        let mut bytes = [0u8; 136];
        bytes[0] = kind::SETATTR;
        bytes[4..8].copy_from_slice(&300u32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&300u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&200u32.to_ne_bytes());
        bytes[40..44].copy_from_slice(&100u32.to_ne_bytes());
        bytes[44..48].copy_from_slice(&1u32.to_ne_bytes());
        bytes[72..80].copy_from_slice(&0x802u64.to_ne_bytes());
        let decoded = decode_setattr(&bytes).expect("decode");
        assert_eq!(decoded.hdr.ancestry(), [200, 100, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoded.dev, 0x802);
    }

    #[test]
    fn exclusion_matches_the_tgid_not_the_thread_id() {
        // A worker thread of an excluded process carries its own tid in
        // `pid`; only `tgid` names the process.
        let worker = EventHeader {
            pid: 501,
            tgid: 500,
            ..EventHeader::default()
        };
        assert!(excluded_by_lineage(&[500], &worker));
        assert!(!excluded_by_lineage(&[501], &worker));
    }

    #[test]
    fn exclusion_covers_processes_the_helper_or_daemon_spawned() {
        // dpkg-query (700) run by the helper (500), under shitd (400),
        // under the shell that started it (300), which is the tracked
        // root. The tgid is not excluded; its ancestry is.
        let mut ancestors = [0u32; ANCESTRY_DEPTH];
        ancestors[..2].copy_from_slice(&[400, 300]);
        let child = EventHeader {
            pid: 700,
            tgid: 700,
            parent_pid: 500,
            ancestors,
            ..EventHeader::default()
        };
        assert!(excluded_by_lineage(&[500], &child));
        assert!(excluded_by_lineage(&[400], &child));
        assert!(!excluded_by_lineage(&[301], &child));
    }

    #[test]
    fn exclusion_ignores_slots_past_the_first_zero() {
        let mut ancestors = [0u32; ANCESTRY_DEPTH];
        ancestors[2] = 500;
        let ev = EventHeader {
            pid: 700,
            tgid: 700,
            parent_pid: 600,
            ancestors,
            ..EventHeader::default()
        };
        assert!(!excluded_by_lineage(&[500], &ev));
    }

    #[test]
    fn decode_setattr_rejects_unlink_kind() {
        let mut bytes = [0u8; 136];
        bytes[0] = kind::UNLINK;
        assert!(decode_setattr(&bytes).is_none());
    }

    #[test]
    fn mkdir_event_layout_is_352_bytes() {
        assert_eq!(std::mem::size_of::<MkdirEvent>(), 352);
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
                ancestors: [0; ANCESTRY_DEPTH],
                ts_ns: 0xfedc_ba98_7654_3210,
                comm: *b"mkdir\0\0\0\0\0\0\0\0\0\0\0",
            },
            parent_dev: 0x802,
            parent_inode: 42,
            mode: 0o755,
            name_len: 3,
            name: name_buf,
        };
        let bytes: [u8; 352] = unsafe { std::mem::transmute(original) };
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
