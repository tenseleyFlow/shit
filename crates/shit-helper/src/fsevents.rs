// SPDX-License-Identifier: AGPL-3.0-or-later

//! FSEvents stream client (M01) — macOS degraded capture tier.
//!
//! FSEvents is Apple's userspace API over the kernel's fsevents driver.
//! It delivers post-hoc filesystem change notifications: events arrive
//! after the syscall completes. We cannot capture file-content
//! pre-images from this surface; the ES tier (M03) is the only path
//! that gives us pre-mutation auth events.
//!
//! M01 ships FSEvents as the no-Apple-paperwork baseline so the macOS
//! build is functional from day one. Every event we emit downstream
//! carries `partial = true` so the planner and `shit list` surface
//! the degradation honestly.
//!
//! Design:
//!
//! ```text
//! caller thread                      worker thread
//! ─────────────                      ──────────────
//! start(roots)                       (created by start)
//!   │                                 │
//!   ├─► spawn worker ─────────────►   CFRunLoopGetCurrent
//!   │                                 │
//!   │                                 FSEventStreamCreate(ctx, paths)
//!   │                                 ScheduleWithRunLoop(default)
//!   │                                 Start
//!   │                                 │
//!   │   (send runloop ref back) ◄─────┤
//!   │                                 │
//!   │                                 CFRunLoopRun  ──┐
//!   │                                                  │
//!   │   (FSEvents callback) ◄──────── kernel fsevents  │
//!   │     - decode flags                                │
//!   │     - emit FsEventRecord ──► (channel rx)         │
//!   │                                                   │
//! stop()                                                │
//!   │                                                   │
//!   ├── CFRunLoopStop(runloop) ─────────────────────────┘
//!   ├── FSEventStreamStop / Invalidate / Release
//!   └── join worker
//! ```
//!
//! The callback runs on the worker thread; it sends decoded events
//! through an `mpsc::Sender`. Recipients read from the `Receiver`
//! on any thread. M01 uses this from the capture/macos producer
//! (lands as part of M01.8).
//!
//! `kFSEventStreamCreateFlagNoDefer + latency=0.0` is critical — without
//! it FSEvents coalesces events for up to `latency` seconds before
//! delivering, which unacceptably increases capture latency.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, c_void};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use core_foundation_sys::array::{CFArrayCreate, CFArrayRef, kCFTypeArrayCallBacks};
use core_foundation_sys::base::{CFRelease, kCFAllocatorDefault};
use core_foundation_sys::runloop::{
    CFRunLoopGetCurrent, CFRunLoopRef, CFRunLoopRun, CFRunLoopStop, kCFRunLoopDefaultMode,
};
use core_foundation_sys::string::{
    CFStringCreateWithCString, CFStringGetCStringPtr, CFStringRef, kCFStringEncodingUTF8,
};

// ─────────────────────────────────────────────────────────────────────
// FSEvents FFI surface. The full header is at
// `MacOSX.sdk/System/Library/Frameworks/CoreServices.framework/.../FSEvents.h`.
// We vendor just the symbols M01 needs.
// ─────────────────────────────────────────────────────────────────────

#[allow(non_camel_case_types)]
type FSEventStreamRef = *mut c_void;
#[allow(non_camel_case_types)]
type FSEventStreamEventId = u64;
#[allow(non_camel_case_types)]
type FSEventStreamEventFlags = u32;
#[allow(non_camel_case_types)]
type FSEventStreamCallback = extern "C" fn(
    stream_ref: FSEventStreamRef,
    client_callback_info: *mut c_void,
    num_events: usize,
    event_paths: *const c_void,
    event_flags: *const FSEventStreamEventFlags,
    event_ids: *const FSEventStreamEventId,
);

#[repr(C)]
struct FSEventStreamContext {
    version: i64,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
}

const K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW: FSEventStreamEventId = 0xFFFF_FFFF_FFFF_FFFF;

/// Watch the root path and emit events when the root itself is moved
/// or deleted. We use this so the daemon can invalidate the tree when
/// the watch root vanishes.
const K_FS_EVENT_STREAM_CREATE_FLAG_WATCH_ROOT: u32 = 0x04;
/// Don't batch events for `latency` seconds — deliver promptly.
const K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER: u32 = 0x02;
/// Per-file events instead of per-directory aggregation. Required for
/// any useful capture surface.
const K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x10;
/// Ignore events caused by this process's own writes. Together with
/// our explicit path-mute for the state dir, this prevents feedback
/// loops when we write blobs.
const K_FS_EVENT_STREAM_CREATE_FLAG_IGNORE_SELF: u32 = 0x08;

// Event flag bits (kFSEventStreamEventFlag*). The full enumeration is
// in FSEvents.h. We surface the ones M01.A acts on. Additional flags
// (IS_FILE/IS_DIR/IS_SYMLINK/INODE_META_MOD/CHANGE_OWNER/XATTR_MOD)
// get added back here when M02 (doctor) or a later sprint needs them
// — deleted now per "no hypothetical future requirements."
const FLAG_MUST_SCAN_SUBDIRS: u32 = 0x01;
const FLAG_ROOT_CHANGED: u32 = 0x20;
const FLAG_ITEM_CREATED: u32 = 0x100;
const FLAG_ITEM_REMOVED: u32 = 0x200;
const FLAG_ITEM_RENAMED: u32 = 0x800;
// FLAG_ITEM_MODIFIED is referenced only by `is_modified`, which is
// test-only; gate it the same way to avoid a bin-target warning.
#[cfg_attr(not(test), allow(dead_code))]
const FLAG_ITEM_MODIFIED: u32 = 0x1000;

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: *const c_void,
        callback: FSEventStreamCallback,
        context: *const FSEventStreamContext,
        paths_to_watch: CFArrayRef,
        since_when: FSEventStreamEventId,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;

    fn FSEventStreamScheduleWithRunLoop(
        stream_ref: FSEventStreamRef,
        run_loop: CFRunLoopRef,
        run_loop_mode: CFStringRef,
    );

    fn FSEventStreamStart(stream_ref: FSEventStreamRef) -> bool;
    fn FSEventStreamStop(stream_ref: FSEventStreamRef);
    fn FSEventStreamInvalidate(stream_ref: FSEventStreamRef);
    fn FSEventStreamRelease(stream_ref: FSEventStreamRef);
}

// ─────────────────────────────────────────────────────────────────────
// Safe Rust surface
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FsEventsError {
    #[error("path contains interior NUL byte: {0:?}")]
    PathNul(PathBuf),
    #[error("path is not valid UTF-8: {0:?}")]
    PathNonUtf8(PathBuf),
    #[error("FSEventStreamCreate returned NULL — kernel refused subscription")]
    StreamCreateFailed,
    #[error("FSEventStreamStart returned false — could not start stream")]
    StreamStartFailed,
    #[error("worker thread failed to initialize within {0:?}")]
    WorkerStartupTimeout(Duration),
    #[error("at least one watch root is required")]
    NoRoots,
}

/// A single decoded FSEvents event. `partial = true` always — see
/// module docs. Downstream consumers translate this into a wire
/// `TreeMutation` (M01.A) or `CapturedPreImage` (when M03's ES path
/// supplies pre-image content via clonefile).
#[derive(Debug, Clone)]
pub struct FsEventRecord {
    pub path: PathBuf,
    pub flags: u32,
}

impl FsEventRecord {
    pub fn is_created(&self) -> bool {
        self.flags & FLAG_ITEM_CREATED != 0
    }
    pub fn is_removed(&self) -> bool {
        self.flags & FLAG_ITEM_REMOVED != 0
    }
    pub fn is_renamed(&self) -> bool {
        self.flags & FLAG_ITEM_RENAMED != 0
    }
    /// FSEvents reports both Created+Modified on first-write
    /// scenarios; tests rely on this to tolerate flag combos. Other
    /// callers should not use `is_modified` in degraded mode — there
    /// is no pre-image to undo a modification against.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_modified(&self) -> bool {
        self.flags & FLAG_ITEM_MODIFIED != 0
    }
    pub fn is_root_changed(&self) -> bool {
        self.flags & FLAG_ROOT_CHANGED != 0
    }
    pub fn must_scan_subdirs(&self) -> bool {
        self.flags & FLAG_MUST_SCAN_SUBDIRS != 0
    }
}

/// Pointer-newtype that asserts thread-safety for the wrapped raw
/// pointer. Apple documents that CFRunLoopRef and FSEventStreamRef
/// are safe to pass between threads (CFRunLoopStop / FSEventStreamStop
/// can be called from any thread once the stream/runloop is set up),
/// and CallbackContext is heap-allocated and we only ever read it
/// from inside the callback while the FSEvents stream owns the ptr.
///
/// Sync is also asserted because we wrap these in `Arc<Mutex<...>>`
/// and Arc requires Send + Sync of its payload.
struct ThreadSafePtr<T>(*mut T);
// Manual Copy/Clone/Debug impls: derive would add a spurious `T: Copy`
// bound because the derive macro doesn't know `*mut T` is Copy/Debug
// for any T.
impl<T> Clone for ThreadSafePtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for ThreadSafePtr<T> {}
impl<T> std::fmt::Debug for ThreadSafePtr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ThreadSafePtr({:p})", self.0)
    }
}
unsafe impl<T> Send for ThreadSafePtr<T> {}
unsafe impl<T> Sync for ThreadSafePtr<T> {}

/// Stream configuration. Production callers use [`Self::default`]
/// (IgnoreSelf on — avoids feedback loops when the helper writes
/// blobs); tests override `ignore_self` to false because the test
/// process IS the one mutating files.
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    /// Suppress events caused by the current process. Production: true.
    pub ignore_self: bool,
    /// Notify when the watch root itself moves/disappears. Production: true.
    pub watch_root: bool,
    /// Deliver per-file events (not just per-directory). Required for
    /// any useful capture surface. Production: true.
    pub file_events: bool,
    /// Skip the FSEvents coalescing/latency window. Production: true.
    pub no_defer: bool,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            ignore_self: true,
            watch_root: true,
            file_events: true,
            no_defer: true,
        }
    }
}

impl StreamOptions {
    fn to_flags(self) -> u32 {
        let mut f = 0u32;
        if self.ignore_self {
            f |= K_FS_EVENT_STREAM_CREATE_FLAG_IGNORE_SELF;
        }
        if self.watch_root {
            f |= K_FS_EVENT_STREAM_CREATE_FLAG_WATCH_ROOT;
        }
        if self.file_events {
            f |= K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS;
        }
        if self.no_defer {
            f |= K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER;
        }
        f
    }
}

/// Owns the FSEvents subscription + worker thread runloop. Drop stops
/// the stream and joins the worker. Construct via [`FsEventsStream::start`].
#[derive(Debug)]
pub struct FsEventsStream {
    /// Run-loop the worker thread is parked in. Cleared in `stop()`
    /// after CFRunLoopStop. Behind a Mutex because two threads
    /// (caller's `stop()` + worker's runloop-init) touch it.
    runloop: Arc<Mutex<Option<ThreadSafePtr<core_foundation_sys::runloop::__CFRunLoop>>>>,
    /// FSEventStream reference. We retain ownership and call
    /// Stop/Invalidate/Release on drop.
    stream_ref: Arc<Mutex<Option<ThreadSafePtr<c_void>>>>,
    /// Worker thread handle. Joined on stop().
    worker: Option<JoinHandle<()>>,
    /// Heap-allocated callback context. Held here so it outlives the
    /// callback closure — the FSEvents stream stores the raw pointer
    /// to this Box's payload.
    _ctx: Box<CallbackContext>,
}

/// Callback context the C callback receives via `clientCallBackInfo`.
/// Owns the sender end of the channel.
#[derive(Debug)]
struct CallbackContext {
    tx: Sender<FsEventRecord>,
}

impl FsEventsStream {
    /// Start watching `roots` with [`StreamOptions::default`]. See
    /// [`Self::start_with_options`] for the configurable variant.
    /// Test-only: the producer in `capture/macos.rs` calls
    /// `start_with_options` directly so the default helper is only
    /// reached from tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn start(roots: Vec<PathBuf>) -> Result<(Self, Receiver<FsEventRecord>), FsEventsError> {
        Self::start_with_options(roots, StreamOptions::default())
    }

    /// Start watching `roots`. Returns the stream handle plus a
    /// receiver that yields events as they arrive.
    ///
    /// The worker thread blocks in `CFRunLoopRun` until [`Self::stop`]
    /// or drop. Each FSEvents callback decodes paths/flags/ids into
    /// `FsEventRecord`s and sends them through the channel.
    pub fn start_with_options(
        roots: Vec<PathBuf>,
        options: StreamOptions,
    ) -> Result<(Self, Receiver<FsEventRecord>), FsEventsError> {
        if roots.is_empty() {
            return Err(FsEventsError::NoRoots);
        }

        // Validate roots are UTF-8 and NUL-free before we hand them to
        // CFString. CFStringCreateWithCString would silently fail on
        // invalid UTF-8 and we want a clear error.
        for r in &roots {
            let s = r
                .to_str()
                .ok_or_else(|| FsEventsError::PathNonUtf8(r.clone()))?;
            if s.as_bytes().contains(&0) {
                return Err(FsEventsError::PathNul(r.clone()));
            }
        }

        let (tx, rx) = channel::<FsEventRecord>();
        let ctx = Box::new(CallbackContext { tx });
        let ctx_ptr: ThreadSafePtr<CallbackContext> =
            ThreadSafePtr(Box::as_ref(&ctx) as *const _ as *mut _);

        let runloop: Arc<Mutex<Option<ThreadSafePtr<core_foundation_sys::runloop::__CFRunLoop>>>> =
            Arc::new(Mutex::new(None));
        let stream_ref: Arc<Mutex<Option<ThreadSafePtr<c_void>>>> = Arc::new(Mutex::new(None));

        // Coordinate worker startup so `start()` doesn't return before
        // CFRunLoopRun is engaged. Without this, `stop()` could race
        // CFRunLoopStop against a runloop that isn't yet running.
        let (ready_tx, ready_rx) = channel::<Result<(), FsEventsError>>();

        let runloop_for_worker = runloop.clone();
        let stream_ref_for_worker = stream_ref.clone();
        let worker = std::thread::Builder::new()
            .name("shit-fsevents".to_string())
            .spawn(move || {
                worker_main(
                    roots,
                    options,
                    ctx_ptr,
                    runloop_for_worker,
                    stream_ref_for_worker,
                    ready_tx,
                );
            })
            .expect("spawn fsevents worker");

        // Wait for the worker to either succeed setup or fail.
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = worker.join();
                return Err(e);
            }
            Err(_) => {
                // Worker didn't signal. Best-effort: try to stop the
                // runloop if it was set up, then bail.
                if let Some(rl) = *runloop.lock().unwrap() {
                    unsafe { CFRunLoopStop(rl.0 as CFRunLoopRef) };
                }
                let _ = worker.join();
                return Err(FsEventsError::WorkerStartupTimeout(Duration::from_secs(5)));
            }
        }

        Ok((
            FsEventsStream {
                runloop,
                stream_ref,
                worker: Some(worker),
                _ctx: ctx,
            },
            rx,
        ))
    }

    /// Stop the stream and join the worker. Safe to call once; further
    /// calls are no-ops. Drop also stops automatically.
    pub fn stop(&mut self) {
        // Stop the FSEvents stream first so no new callbacks fire.
        if let Some(s) = self.stream_ref.lock().unwrap().take() {
            unsafe {
                let s = s.0 as FSEventStreamRef;
                FSEventStreamStop(s);
                FSEventStreamInvalidate(s);
                FSEventStreamRelease(s);
            }
        }
        // Then stop the runloop so the worker thread exits.
        if let Some(rl) = self.runloop.lock().unwrap().take() {
            unsafe { CFRunLoopStop(rl.0 as CFRunLoopRef) };
        }
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

impl Drop for FsEventsStream {
    fn drop(&mut self) {
        self.stop();
    }
}

// ─────────────────────────────────────────────────────────────────────
// Worker thread
// ─────────────────────────────────────────────────────────────────────

fn worker_main(
    roots: Vec<PathBuf>,
    options: StreamOptions,
    ctx_ptr: ThreadSafePtr<CallbackContext>,
    runloop_slot: Arc<Mutex<Option<ThreadSafePtr<core_foundation_sys::runloop::__CFRunLoop>>>>,
    stream_ref_slot: Arc<Mutex<Option<ThreadSafePtr<c_void>>>>,
    ready_tx: Sender<Result<(), FsEventsError>>,
) {
    // Build CFArray<CFString> of paths.
    let cf_strings: Vec<CFStringRef> = match build_cf_string_array(&roots) {
        Ok(v) => v,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let cf_array = unsafe {
        CFArrayCreate(
            kCFAllocatorDefault,
            cf_strings.as_ptr() as *const _,
            cf_strings.len() as isize,
            &kCFTypeArrayCallBacks,
        )
    };
    if cf_array.is_null() {
        // Release the strings we own.
        for s in &cf_strings {
            unsafe { CFRelease(*s as *const _) };
        }
        let _ = ready_tx.send(Err(FsEventsError::StreamCreateFailed));
        return;
    }
    // CFArrayCreate retains each CFString; we can release our local
    // refs now.
    for s in &cf_strings {
        unsafe { CFRelease(*s as *const _) };
    }

    let stream_ctx = FSEventStreamContext {
        version: 0,
        info: ctx_ptr.0 as *mut c_void,
        retain: None,
        release: None,
        copy_description: None,
    };

    let stream_ref = unsafe {
        FSEventStreamCreate(
            ptr::null(),
            fsevents_callback,
            &stream_ctx,
            cf_array,
            K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW,
            0.0_f64,
            options.to_flags(),
        )
    };
    // CFArrayCreate retained the path strings; the array itself can
    // be released now — FSEventStreamCreate retains what it needs.
    unsafe { CFRelease(cf_array as *const _) };

    if stream_ref.is_null() {
        let _ = ready_tx.send(Err(FsEventsError::StreamCreateFailed));
        return;
    }

    let runloop = unsafe { CFRunLoopGetCurrent() };
    *runloop_slot.lock().unwrap() = Some(ThreadSafePtr(runloop as *mut _));
    *stream_ref_slot.lock().unwrap() = Some(ThreadSafePtr(stream_ref as *mut _));

    unsafe {
        FSEventStreamScheduleWithRunLoop(stream_ref, runloop, kCFRunLoopDefaultMode);
        if !FSEventStreamStart(stream_ref) {
            // Cleanup before bail.
            FSEventStreamInvalidate(stream_ref);
            FSEventStreamRelease(stream_ref);
            *stream_ref_slot.lock().unwrap() = None;
            *runloop_slot.lock().unwrap() = None;
            let _ = ready_tx.send(Err(FsEventsError::StreamStartFailed));
            return;
        }
    }

    let _ = ready_tx.send(Ok(()));

    // Block here until stop() calls CFRunLoopStop from the caller side.
    unsafe { CFRunLoopRun() };
}

fn build_cf_string_array(roots: &[PathBuf]) -> Result<Vec<CFStringRef>, FsEventsError> {
    let mut out = Vec::with_capacity(roots.len());
    for r in roots {
        let s = r
            .to_str()
            .ok_or_else(|| FsEventsError::PathNonUtf8(r.clone()))?;
        // CFString needs a null-terminated C string. We checked NUL-
        // freeness in start(); the +1 byte for the terminator is fine.
        let cstring = std::ffi::CString::new(s).map_err(|_| FsEventsError::PathNul(r.clone()))?;
        let cf = unsafe {
            CFStringCreateWithCString(kCFAllocatorDefault, cstring.as_ptr(), kCFStringEncodingUTF8)
        };
        if cf.is_null() {
            // Free what we got so far.
            for prev in &out {
                unsafe { CFRelease(*prev as *const _) };
            }
            return Err(FsEventsError::PathNonUtf8(r.clone()));
        }
        out.push(cf);
    }
    Ok(out)
}

/// FSEvents per-event callback. Runs on the worker thread's runloop.
///
/// `eventPaths` is technically `*const *const c_char` when the stream
/// was created with default flags, but since we pass
/// `kFSEventStreamCreateFlagFileEvents` Apple documents it stays the
/// same shape: an array of UTF-8 C strings. We treat it as such.
extern "C" fn fsevents_callback(
    _stream_ref: FSEventStreamRef,
    client_callback_info: *mut c_void,
    num_events: usize,
    event_paths: *const c_void,
    event_flags: *const FSEventStreamEventFlags,
    _event_ids: *const FSEventStreamEventId,
) {
    if client_callback_info.is_null() || num_events == 0 {
        return;
    }
    let ctx = unsafe { &*(client_callback_info as *const CallbackContext) };

    // event_paths is `const char *const *` — array of C string pointers.
    let paths: &[*const c_char] =
        unsafe { std::slice::from_raw_parts(event_paths as *const *const c_char, num_events) };
    let flags: &[FSEventStreamEventFlags] =
        unsafe { std::slice::from_raw_parts(event_flags, num_events) };

    for i in 0..num_events {
        let path_ptr = paths[i];
        if path_ptr.is_null() {
            continue;
        }
        let path_bytes = unsafe { CStr::from_ptr(path_ptr) }.to_bytes();
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(path_bytes));
        let record = FsEventRecord {
            path,
            flags: flags[i],
        };
        // Channel send failure means the receiver was dropped — caller
        // is shutting down. Stop emitting; CFRunLoopStop will arrive
        // shortly.
        if ctx.tx.send(record).is_err() {
            return;
        }
    }
}

// OsStr::from_bytes is unix-only. Bring it into scope here so the
// `from_bytes` call above resolves on macOS.
use std::os::unix::ffi::OsStrExt;

/// Attempt to extract a UTF-8 view from a `CFStringRef`. Used only by
/// tests / diagnostic paths; the callback decodes paths via the
/// C-string pointer array directly.
#[allow(dead_code)]
fn cf_string_to_string(cf: CFStringRef) -> Option<String> {
    if cf.is_null() {
        return None;
    }
    let ptr = unsafe { CFStringGetCStringPtr(cf, kCFStringEncodingUTF8) };
    if ptr.is_null() {
        // Fast path missed — the string isn't stored in UTF-8 internally.
        // We don't bother with the slow path here; this helper is
        // dev-only.
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{Duration, Instant};

    /// Drain events from `rx` until we see one matching `pred` or
    /// `deadline` elapses. Returns the matching record on success.
    fn wait_for_event<F: Fn(&FsEventRecord) -> bool>(
        rx: &Receiver<FsEventRecord>,
        deadline: Duration,
        pred: F,
    ) -> Option<FsEventRecord> {
        let start = Instant::now();
        while start.elapsed() < deadline {
            let remaining = deadline.saturating_sub(start.elapsed());
            match rx.recv_timeout(remaining) {
                Ok(r) => {
                    if pred(&r) {
                        return Some(r);
                    }
                }
                Err(_) => return None,
            }
        }
        None
    }

    #[test]
    fn start_rejects_empty_roots() {
        let err = FsEventsStream::start(vec![]).expect_err("must reject empty roots");
        assert!(matches!(err, FsEventsError::NoRoots));
    }

    /// Test stream options: same as production except `ignore_self`
    /// is off, because the test process is the one mutating files.
    fn test_options() -> StreamOptions {
        StreamOptions {
            ignore_self: false,
            ..StreamOptions::default()
        }
    }

    #[test]
    fn create_in_watched_dir_emits_event() {
        let tmp = tempfile::tempdir().unwrap();
        // FSEvents resolves paths via realpath; we need the canonical
        // path so the emitted event matches what we expect.
        let root = fs::canonicalize(tmp.path()).unwrap();

        let (mut stream, rx) =
            FsEventsStream::start_with_options(vec![root.clone()], test_options())
                .expect("start stream");

        // FSEvents needs a moment to register before the first event
        // reliably fires on a fresh stream.
        std::thread::sleep(Duration::from_millis(200));

        let target = root.join("hello.txt");
        let mut f = fs::File::create(&target).unwrap();
        f.write_all(b"hi").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let got = wait_for_event(&rx, Duration::from_secs(5), |r| {
            r.path == target && (r.is_created() || r.is_modified())
        });

        assert!(
            got.is_some(),
            "expected an event for {target:?}; rx exhausted within 5s"
        );

        stream.stop();
    }

    #[test]
    fn unlink_in_watched_dir_emits_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();

        // Pre-create the file BEFORE the stream starts so we observe
        // a pure removal event, not a create-then-remove pair.
        let target = root.join("doomed.txt");
        fs::write(&target, b"bye").unwrap();

        let (mut stream, rx) =
            FsEventsStream::start_with_options(vec![root.clone()], test_options())
                .expect("start stream");

        std::thread::sleep(Duration::from_millis(200));

        fs::remove_file(&target).unwrap();

        let got = wait_for_event(&rx, Duration::from_secs(5), |r| {
            r.path == target && r.is_removed()
        });

        assert!(
            got.is_some(),
            "expected an ItemRemoved event for {target:?}; rx exhausted within 5s"
        );

        stream.stop();
    }

    #[test]
    fn stop_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (mut stream, _rx) = FsEventsStream::start(vec![root]).expect("start stream");
        stream.stop();
        stream.stop(); // must not double-free / panic
    }

    #[test]
    fn rejects_non_utf8_paths() {
        // OsString from invalid UTF-8 (lone 0xFF). The validation
        // path is `PathBuf::to_str() -> None`.
        use std::os::unix::ffi::OsStringExt;
        let bad = PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xFF, b'a']));
        let err = FsEventsStream::start(vec![bad]).expect_err("must reject non-utf8");
        assert!(matches!(err, FsEventsError::PathNonUtf8(_)));
    }
}
