// SPDX-License-Identifier: AGPL-3.0-or-later

//! ES message decode (M03.1.G).
//!
//! Vendored layout of `es_message_t` + supporting structs from
//! `<EndpointSecurity/ESMessage.h>`. Modeled on
//! `HarfangLab/endpoint-sec/endpoint-sec-sys/src/message.rs`
//! (cloned at `.docs/refs/endpoint-sec`; MIT-licensed).
//!
//! ## ABI stability + scope
//!
//! Apple guarantees the prefix layout of `es_message_t` is stable
//! across macOS minor versions. Additions only happen at the end of
//! the struct (and gated behind the `version` field). For M03 we
//! model the prefix up to and including the `event` union; trailing
//! fields (thread_id, global_seq_num, version-specific extensions)
//! exist in the kernel memory but we never access them, so their
//! exact offsets don't matter.
//!
//! The `es_events_t` union holds the per-event-type payload. Apple's
//! version of this union has ~120 variants; we model only the ones
//! we currently consume (M03.1.G: unlink). The union's size in our
//! model is therefore smaller than Apple's, but since we never read
//! past the union AND every variant in the C union starts at offset
//! 0 (union semantics), this works: casting our struct to the bytes
//! the kernel handed us is safe so long as we (1) only read the
//! prefix fields and (2) only read the union variant that matches
//! the `event_type` discriminant.
//!
//! ## What's in scope for this slice
//!
//! - `audit_token_t` (8 u32, opaque-ish — full decode in M03.1.H)
//! - `es_string_token_t` with byte/path accessors
//! - `es_file_t` (path + truncated bool + stat) — only `path` read
//! - `es_event_unlink_t` (target + parent_dir)
//! - `es_message_t` prefix up to event union
//! - Safe `EsMessage` newtype wrapping `*const es_message_t` with
//!   methods to read event_type + unlink target path
//!
//! Slice 3.5+ adds rename, open, etc. Slice 4 (M03.1.H) reads the
//! process audit_token for tree-tracking. Slice 5 (M03.1.I) feeds
//! decoded records into the producer.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::raw::c_char;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────
// Primitive types (mirror C definitions in <bsm/libbsm.h>, <sys/stat.h>)
// ─────────────────────────────────────────────────────────────────────

/// `audit_token_t` from `<bsm/libbsm.h>` — 32 bytes (8 u32). The
/// kernel-stable identity for a process within an exec lifecycle
/// (survives pid reuse). M03.1.H consumes this for tree-tracking.
/// The struct is part of the M03.1.G es_process_t layout (which
/// stays opaque to M03.1.G; M03.1.H makes its fields real and
/// removes this allow).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types, dead_code)]
pub struct audit_token_t {
    pub val: [u32; 8],
}

/// `es_string_token_t` from `<EndpointSecurity/ESTypes.h>`. A
/// length-prefixed C string the kernel hands us; we don't allocate
/// or free it (it's owned by the `es_message_t` we're called with).
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_string_token_t {
    pub length: usize,
    pub data: *const c_char,
}

impl es_string_token_t {
    /// View the token's bytes as a `&[u8]`. The lifetime is tied to
    /// the `es_message_t` that contains this token; callers must
    /// not let the slice outlive the kernel-provided message.
    ///
    /// # Safety
    ///
    /// `self.data` must be a valid pointer to at least `self.length`
    /// bytes. The kernel guarantees this for tokens inside a live
    /// `es_message_t`.
    pub unsafe fn as_bytes<'a>(&self) -> &'a [u8] {
        if self.data.is_null() || self.length == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.data as *const u8, self.length) }
    }

    /// Same as [`Self::as_bytes`] but as a `&Path`. macOS paths are
    /// historically byte-strings, but in practice always UTF-8 on
    /// modern filesystems.
    ///
    /// # Safety
    ///
    /// See [`Self::as_bytes`].
    pub unsafe fn as_path<'a>(&self) -> &'a Path {
        use std::os::unix::ffi::OsStrExt;
        let bytes = unsafe { self.as_bytes() };
        Path::new(std::ffi::OsStr::from_bytes(bytes))
    }
}

// ─────────────────────────────────────────────────────────────────────
// es_file_t — paths + stat data the kernel attaches to events
// ─────────────────────────────────────────────────────────────────────

/// `es_file_t` from ESMessage.h. We only read `path` for M03.1.G;
/// the `path_truncated` + `stat` fields are kept for layout
/// correctness so subsequent slices can read them without
/// recomputing offsets.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_file_t {
    pub path: es_string_token_t,
    pub path_truncated: bool,
    // `libc::stat` is platform-stable (macOS specifically uses the
    // 64-bit-inode variant since 10.6). Kept inline so es_file_t's
    // size matches Apple's exactly.
    pub stat: libc::stat,
}

// ─────────────────────────────────────────────────────────────────────
// es_process_t — opaque to M03.1.G; M03.1.H reads `audit_token`
// ─────────────────────────────────────────────────────────────────────

/// `es_process_t` from ESMessage.h. M03.1.H reads the
/// `audit_token` (offset 0); the trailing fields (ppid,
/// codesigning_flags, signing_id, executable, etc.) are kept
/// opaque until a slice that actually reads them lands.
///
/// We model just the audit_token field at offset 0; subsequent
/// fields exist in the kernel memory but we never deref them, so
/// their offsets don't matter for our read paths.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_process_t {
    pub audit_token: audit_token_t,
    // Apple's struct continues: ppid, original_ppid, group_id,
    // session_id, codesigning_flags, is_platform_binary,
    // is_es_client, cdhash, signing_id, team_id, executable, ...
    // Omitted from our model until we need to read them.
}

// ─────────────────────────────────────────────────────────────────────
// Event payloads (M03.1.G: unlink only)
// ─────────────────────────────────────────────────────────────────────

/// `es_event_unlink_t` from ESMessage.h. The `target` field is the
/// file being removed; `parent_dir` is its directory. `_reserved`
/// is 64 bytes Apple keeps for future fields.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_unlink_t {
    pub target: *const es_file_t,
    pub parent_dir: *const es_file_t,
    pub _reserved: [u8; 64],
}

/// `es_event_fork_t` from ESMessage.h. `msg.process` is the parent;
/// `child` points to the new child process. M03.1.I consumes this
/// to harvest the child's audit_token for tree-tracking.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_fork_t {
    pub child: *const es_process_t,
    pub _reserved: [u8; 64],
}

/// `es_destination_type_t` discriminant for `es_event_rename_t.destination`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct es_destination_type_t(pub u32);

impl es_destination_type_t {
    /// Destination is a pre-existing file that will be overwritten by
    /// the rename. The pre-existing bytes are LOST after the syscall;
    /// the M03.1.I.A capture path clonefiles this file's content into
    /// staging before responding ALLOW so undo can restore them.
    pub const EXISTING_FILE: Self = Self(0);
    /// Destination path doesn't exist yet; rename creates it. No
    /// pre-image to capture — `TreeOp::Rename(from→to)` alone lets
    /// undo invert the rename.
    pub const NEW_PATH: Self = Self(1);
}

/// `es_event_rename_destination_t.new_path` — directory + filename
/// for the case where the destination doesn't pre-exist.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_rename_new_path_t {
    pub dir: *const es_file_t,
    pub filename: es_string_token_t,
    pub filename_truncated: bool,
}

/// `es_event_rename_t.destination` union. The active variant is
/// selected by [`es_event_rename_t::destination_type`].
#[repr(C)]
#[allow(non_camel_case_types)]
pub union es_event_rename_destination_t {
    pub existing_file: *const es_file_t,
    pub new_path: std::mem::ManuallyDrop<es_event_rename_new_path_t>,
}

/// `es_event_rename_t` from ESMessage.h. `source` is the file being
/// renamed; `destination` is either an existing file (overwrite, with
/// content loss) or a new path (no loss).
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_rename_t {
    pub source: *const es_file_t,
    pub destination_type: es_destination_type_t,
    pub destination: es_event_rename_destination_t,
    pub _reserved: [u8; 64],
}

/// `es_event_exit_t` from ESMessage.h. `msg.process` is the dying
/// process (we read its audit_token to remove from the tracked
/// set). `stat` is the wait(2)-style exit status; we don't care
/// about the value, only the fact of the exit.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_exit_t {
    pub stat: std::os::raw::c_int,
    pub _reserved: [u8; 64],
}

/// `es_event_truncate_t` from ESMessage.h. Single field: the file
/// whose contents are about to be discarded. The pre-truncate bytes
/// are recoverable via clonefile in the AUTH callback (file still
/// exists at `target.path` with original bytes when the event fires).
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_truncate_t {
    pub target: *const es_file_t,
    pub _reserved: [u8; 64],
}

/// `es_events_t` union — Apple's version has ~120 variants; we
/// model only the variants we consume. All variants share offset 0
/// per union semantics, so reading the variant matching the
/// `event_type` discriminant gives correct bytes even if our union
/// is smaller than Apple's.
#[repr(C)]
#[allow(non_camel_case_types)]
pub union es_events_t {
    pub unlink: std::mem::ManuallyDrop<es_event_unlink_t>,
    pub rename: std::mem::ManuallyDrop<es_event_rename_t>,
    pub truncate: std::mem::ManuallyDrop<es_event_truncate_t>,
    pub fork: std::mem::ManuallyDrop<es_event_fork_t>,
    pub exit: std::mem::ManuallyDrop<es_event_exit_t>,
}

// ─────────────────────────────────────────────────────────────────────
// Action union — the auth/notify discriminant + payload
// ─────────────────────────────────────────────────────────────────────

/// `es_action_type_t` — discriminates the `action` union.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct es_action_type_t(pub u32);

impl es_action_type_t {
    /// AUTH event — handler must respond. M03.1.G doesn't dispatch
    /// on action_type yet (only one variant in scope); M03.1.H+ will.
    #[allow(dead_code)]
    pub const AUTH: Self = Self(0);
    #[allow(dead_code)]
    pub const NOTIFY: Self = Self(1);
}

/// `es_event_id_t` from ESMessage.h — opaque 32-byte auth ID. Apple
/// uses it internally for matching responses to requests; we don't
/// inspect it but it must be in the layout.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_event_id_t {
    pub _opaque: [u64; 4],
}

/// `es_result_t` from ESMessage.h — the result variant of the
/// action union for NOTIFY events. We don't access it in M03.1.G;
/// `[u64; 4]` matches Apple's documented size.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_result_t {
    pub _opaque: [u64; 4],
}

/// `es_message_t.action` union — auth event id or notify result.
#[repr(C)]
#[allow(non_camel_case_types)]
pub union es_action_t {
    pub auth: std::mem::ManuallyDrop<es_event_id_t>,
    pub notify: std::mem::ManuallyDrop<es_result_t>,
}

// ─────────────────────────────────────────────────────────────────────
// es_message_t — top-level message (prefix layout only)
// ─────────────────────────────────────────────────────────────────────

/// `es_message_t` from ESMessage.h, prefix layout up to and including
/// the `event` union. Trailing fields (thread_id, global_seq_num,
/// version-specific additions) exist in the kernel memory but we
/// don't access them, so they're omitted from this struct.
///
/// All field offsets up to `event` MUST match Apple's exactly, or
/// our decode reads garbage. The reference for the layout is
/// `HarfangLab/endpoint-sec/endpoint-sec-sys/src/message.rs` at
/// `.docs/refs/endpoint-sec/` (mirrored from Apple's headers).
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct es_message_t {
    pub version: u32,
    pub time: libc::timespec,
    pub mach_time: u64,
    pub deadline: u64,
    pub process: *const es_process_t,
    pub seq_num: u64,
    pub action_type: es_action_type_t,
    pub action: es_action_t,
    pub event_type: super::sys::es_event_type_t,
    pub event: es_events_t,
}

// ─────────────────────────────────────────────────────────────────────
// EsMessage — safe wrapper around *const es_message_t
// ─────────────────────────────────────────────────────────────────────

/// Safe newtype around the kernel-provided `*const es_message_t`.
/// Holds the pointer for the duration of the callback invocation;
/// must not outlive the callback.
pub struct EsMessage<'a> {
    raw: *const es_message_t,
    _lifetime: PhantomData<&'a es_message_t>,
}

impl<'a> EsMessage<'a> {
    /// # Safety
    ///
    /// `raw` must be a valid kernel-owned `*const es_message_t`
    /// pointer for the lifetime `'a`. In practice this is only
    /// safe to call from inside the ES message handler block,
    /// passing in the pointer the kernel delivered.
    pub unsafe fn from_raw(raw: *const c_void) -> Self {
        Self {
            raw: raw as *const es_message_t,
            _lifetime: PhantomData,
        }
    }

    /// The raw `*const es_message_t` for passing back to
    /// `es_respond_auth_result`. M03.1.G handler responds via the
    /// kernel-supplied pointer directly; this accessor exists for
    /// future code that holds an EsMessage and needs to respond
    /// later (M03.1.I+ producer integration).
    #[allow(dead_code)]
    pub fn raw(&self) -> *const c_void {
        self.raw as *const c_void
    }

    /// Discriminant for the `event` union — read this to know
    /// which `as_*` accessor is safe to call.
    pub fn event_type(&self) -> super::sys::es_event_type_t {
        // SAFETY: caller guarantees `raw` points to a valid
        // es_message_t for the lifetime of `self`.
        unsafe { (*self.raw).event_type }
    }

    /// `audit_token_t` of the process that took the action. The
    /// kernel-stable identity; used by M03.1.H tree-filtering.
    ///
    /// Apple documents `process` as non-null for every message; the
    /// internal null-check is defense-in-depth (and lets us fall
    /// through to a sentinel rather than crash on a malformed
    /// kernel state).
    pub fn process_audit_token(&self) -> audit_token_t {
        // SAFETY: message lifetime guarantees raw is valid; process
        // is documented non-null. Sentinel on the unexpected null
        // case so callers get a "definitely-not-tracked" token.
        unsafe {
            if (*self.raw).process.is_null() {
                return audit_token_t { val: [0; 8] };
            }
            (*(*self.raw).process).audit_token
        }
    }

    /// `Some(&es_event_unlink_t)` iff `event_type == AUTH_UNLINK`.
    /// Reading any other variant via the union would be UB.
    pub fn as_unlink(&self) -> Option<&'a es_event_unlink_t> {
        if self.event_type() != super::sys::es_event_type_t::AUTH_UNLINK {
            return None;
        }
        // SAFETY: discriminant check above guarantees the union
        // variant. Pointer is valid for the message lifetime.
        unsafe { Some(&*(&(*self.raw).event.unlink as *const _ as *const es_event_unlink_t)) }
    }

    /// Convenience: target path of an unlink event as a `&Path`.
    /// Returns `None` if the message isn't an unlink or the target
    /// pointer is null.
    pub fn unlink_target_path(&self) -> Option<&'a Path> {
        let event = self.as_unlink()?;
        if event.target.is_null() {
            return None;
        }
        // SAFETY: target is a non-null *const es_file_t valid for
        // the message lifetime; the string token inside has a
        // length + data that the kernel maintains.
        unsafe { Some((*event.target).path.as_path()) }
    }

    /// The full `es_file_t` for an unlink target — path + stat in one
    /// borrow. Used by the producer (M03.1.I.4) so the inline AUTH
    /// callback can read path, dev, inode, mode, uid, gid, mtime
    /// from the kernel-attached stat without a userspace stat(2)
    /// syscall (which would race the impending unlink).
    pub fn unlink_target_file(&self) -> Option<&'a es_file_t> {
        let event = self.as_unlink()?;
        if event.target.is_null() {
            return None;
        }
        // SAFETY: target is a non-null *const es_file_t valid for
        // the message lifetime.
        unsafe { Some(&*event.target) }
    }

    /// `Some(&es_event_rename_t)` iff `event_type == AUTH_RENAME`.
    pub fn as_rename(&self) -> Option<&'a es_event_rename_t> {
        if self.event_type() != super::sys::es_event_type_t::AUTH_RENAME {
            return None;
        }
        // SAFETY: discriminant guarantees the union variant.
        unsafe { Some(&*(&(*self.raw).event.rename as *const _ as *const es_event_rename_t)) }
    }

    /// `Some(&es_event_truncate_t)` iff `event_type == AUTH_TRUNCATE`.
    pub fn as_truncate(&self) -> Option<&'a es_event_truncate_t> {
        if self.event_type() != super::sys::es_event_type_t::AUTH_TRUNCATE {
            return None;
        }
        // SAFETY: discriminant guarantees the union variant.
        unsafe { Some(&*(&(*self.raw).event.truncate as *const _ as *const es_event_truncate_t)) }
    }

    /// Convenience: `es_file_t` for the truncate target. Returns
    /// `None` if the message isn't a truncate or the target ptr is null.
    pub fn truncate_target_file(&self) -> Option<&'a es_file_t> {
        let event = self.as_truncate()?;
        if event.target.is_null() {
            return None;
        }
        // SAFETY: target is non-null for the message lifetime.
        unsafe { Some(&*event.target) }
    }

    /// `Some(&es_event_fork_t)` iff `event_type == NOTIFY_FORK`.
    /// M03.1.I.3 consumes for tree-tracking.
    #[allow(dead_code)]
    pub fn as_fork(&self) -> Option<&'a es_event_fork_t> {
        if self.event_type() != super::sys::es_event_type_t::NOTIFY_FORK {
            return None;
        }
        // SAFETY: discriminant check above guarantees the union variant.
        unsafe { Some(&*(&(*self.raw).event.fork as *const _ as *const es_event_fork_t)) }
    }

    /// `Some(&es_event_exit_t)` iff `event_type == NOTIFY_EXIT`.
    /// M03.1.I.3 consumes for tree-tracking cleanup.
    #[allow(dead_code)]
    pub fn as_exit(&self) -> Option<&'a es_event_exit_t> {
        if self.event_type() != super::sys::es_event_type_t::NOTIFY_EXIT {
            return None;
        }
        // SAFETY: discriminant check.
        unsafe { Some(&*(&(*self.raw).event.exit as *const _ as *const es_event_exit_t)) }
    }

    /// Convenience: audit_token of the child process forked. Returns
    /// `None` if the message isn't a fork or the child pointer is null.
    /// M03.1.I.3 consumes for tree-tracking auto-add.
    #[allow(dead_code)]
    pub fn fork_child_audit_token(&self) -> Option<audit_token_t> {
        let event = self.as_fork()?;
        if event.child.is_null() {
            return None;
        }
        // SAFETY: child is non-null *const es_process_t valid for
        // the message lifetime; audit_token at offset 0.
        unsafe { Some((*event.child).audit_token) }
    }
}

// ─────────────────────────────────────────────────────────────────────
// audit_token_self — read our own audit_token via Mach
// ─────────────────────────────────────────────────────────────────────

/// Apple's `TASK_AUDIT_TOKEN` flavor (from `<mach/task_info.h>`).
const TASK_AUDIT_TOKEN: u32 = 15;

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    /// `extern mach_port_t mach_task_self_;` — our task port.
    static mach_task_self_: u32;

    /// `kern_return_t task_info(task_t, task_flavor_t,`
    /// `                         task_info_t, mach_msg_type_number_t *);`
    fn task_info(
        target_task: u32,
        flavor: u32,
        task_info_out: *mut u32,
        task_info_count: *mut u32,
    ) -> i32;
}

/// Read this process's `audit_token_t` via `task_info(mach_task_self_,
/// TASK_AUDIT_TOKEN, ...)`. M03.1.H seeds the tree-filter set with
/// the result so we can pre-populate "this process is tracked"
/// before any ES events arrive.
///
/// Returns `None` on Mach error (extremely rare for our own task).
pub fn audit_token_self() -> Option<audit_token_t> {
    let mut buf = [0u32; 8];
    let mut count = 8u32;
    // SAFETY: mach_task_self_ + task_info are linked from libSystem;
    // we pass a pointer to a stack array of the right size + a count
    // that matches the TASK_AUDIT_TOKEN flavor.
    let rc = unsafe {
        task_info(
            mach_task_self_,
            TASK_AUDIT_TOKEN,
            buf.as_mut_ptr(),
            &mut count,
        )
    };
    if rc != 0 || count < 8 {
        return None;
    }
    Some(audit_token_t { val: buf })
}

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    /// `kern_return_t task_name_for_pid(task_t target_tport, int pid, task_name_t *tn);`
    /// — read-only task port. Doesn't need the task_for_pid-allow
    /// entitlement; root-privileged callers can read any process's
    /// task-name port for the purposes of `task_info` queries.
    fn task_name_for_pid(target_tport: u32, pid: i32, tn: *mut u32) -> i32;
}

/// Resolve `pid` to its `audit_token_t` via Mach. Used as a fallback
/// when [`PumpHandle::pid_to_token`] doesn't have the pid yet — most
/// commonly because the shell predates the helper subscription, so
/// no NOTIFY_EXEC was delivered for it. Requires root (or the
/// `task_for_pid-allow` entitlement) per Apple's docs.
///
/// Returns `None` on Mach error (process doesn't exist, permission
/// denied, etc.).
pub fn audit_token_for_pid(pid: i32) -> Option<audit_token_t> {
    let mut task: u32 = 0;
    // SAFETY: mach_task_self_ + task_name_for_pid are linked from libSystem.
    let rc = unsafe { task_name_for_pid(mach_task_self_, pid, &mut task as *mut _) };
    if rc != 0 {
        return None;
    }
    let mut buf = [0u32; 8];
    let mut count = 8u32;
    // SAFETY: task is a valid mach_port_t for the duration of this call.
    let rc = unsafe { task_info(task, TASK_AUDIT_TOKEN, buf.as_mut_ptr(), &mut count) };
    // Release the task port — task_name_for_pid returns a +1 reference.
    // SAFETY: task is the same port we just got back; deallocate_port
    // is the documented release path.
    unsafe {
        let _ = mach_port_deallocate(mach_task_self_, task);
    }
    if rc != 0 || count < 8 {
        return None;
    }
    Some(audit_token_t { val: buf })
}

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    /// `kern_return_t mach_port_deallocate(ipc_space_t task, mach_port_name_t name);`
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_token_yields_empty_slice() {
        // Construct an empty token without touching the kernel —
        // exercise the as_bytes() safety check for length=0.
        let tok = es_string_token_t {
            length: 0,
            data: std::ptr::null(),
        };
        // SAFETY: length=0 short-circuits before any deref.
        let bytes = unsafe { tok.as_bytes() };
        assert!(bytes.is_empty());
    }

    #[test]
    fn string_token_with_static_bytes_decodes_to_path() {
        let s = b"/tmp/test/file.txt\0";
        let tok = es_string_token_t {
            length: s.len() - 1, // strip the NUL — length-prefix, not C-string
            data: s.as_ptr() as *const c_char,
        };
        // SAFETY: pointing into static storage; data lives for the
        // whole process.
        let p = unsafe { tok.as_path() };
        assert_eq!(p, Path::new("/tmp/test/file.txt"));
    }

    #[test]
    fn action_type_constants_match_apple() {
        // Drift-check: if Apple renumbers (they haven't since 10.15)
        // this catches it.
        assert_eq!(es_action_type_t::AUTH.0, 0);
        assert_eq!(es_action_type_t::NOTIFY.0, 1);
    }

    #[test]
    fn audit_token_self_returns_some_on_macos() {
        // Reading our own audit_token via Mach. Should never fail
        // for our own task; if it does, something's wrong with the
        // Mach binding.
        let tok = audit_token_self();
        assert!(tok.is_some(), "audit_token_self() returned None");
        // Apple stores pid at val[5] for the user-token form; we don't
        // pin to a specific layout since the field meanings are
        // documented but we read the whole 32 bytes opaquely.
        let tok = tok.unwrap();
        assert_eq!(tok.val.len(), 8);
    }
}
