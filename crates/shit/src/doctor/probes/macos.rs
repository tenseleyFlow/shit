// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS-family runtime probes (M02).
//!
//! Each function populates one field of [`super::super::json::MacReport`].
//! Per the B03 / L05 convention, every probe:
//!
//! - completes in <500ms (so total `shit doctor --json` overhead
//!   stays under 2s — important for CI pre-flight use);
//! - is side-effect-free (no system state changes, no daemon
//!   spawns that outlive the probe);
//! - gracefully reports failure rather than panic. A probe that
//!   can't determine its answer returns the "neutral" value
//!   (`false`, empty Vec, `None`) so the JSON envelope still
//!   serializes cleanly even on a broken host.
//!
//! ## Scope notes
//!
//! - **EndpointSecurity** — M02 stages this. The probe returns
//!   `entitlement_present = false` + `notes = ["M03 not yet
//!   implemented"]` until M03 lands the ES FFI bindings. The doctor
//!   correctly reports `runtime_capture = "fsevents-degraded"`
//!   based on the FSEvents probe alone.
//! - **Sandbox profile** — the doctor caller is the `shit` CLI,
//!   which has no sandbox profile of its own. The
//!   `probe_sandbox_profile_loaded` here checks `sandbox_check` for
//!   the calling process; on a vanilla CLI run it returns false.
//!   The real "is the helper's profile loaded" check belongs to
//!   the helper-side handshake-probe path; M02 stubs that as a
//!   follow-up.
//! - **Codesign** — the probe runs `codesign --verify --strict --deep`
//!   on the resolved helper-bin path (not the doctor caller). If
//!   no helper bin is findable on disk (typical fresh-checkout),
//!   the probe returns `signature_kind = "unknown"`.

#![cfg(target_os = "macos")]
// Probe functions land here in M02.2–M02.8; M02.9 wires them into
// `doctor::mod.rs` and removes this allow. Unit tests already
// exercise the parsers and the stub.
#![allow(dead_code)]

use crate::doctor::json::{
    CodesignReport, EndpointSecurityReport, FsEventsProbeReport, SandboxReport, SipReport,
};
use std::ffi::{CString, c_void};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────
// Full Disk Access (FDA)
// ─────────────────────────────────────────────────────────────────────

/// FDA states surfaced by the probe. Doctor maps this to `bool` +
/// remediation notes for the JSON envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdaState {
    /// At least one FDA-protected path was readable. FDA is granted.
    Granted,
    /// At least one FDA-protected path returned EPERM. FDA is denied.
    Denied,
    /// All probe paths returned ENOENT — user never used Mail and
    /// the TCC.db fallback was missing too. Treat as "not granted"
    /// for the bool envelope but flag separately.
    Indeterminate,
}

/// Paths probed in order. The first path that returns success
/// shortcuts to `Granted`; the first path that returns EPERM
/// shortcuts to `Denied`. ENOENT on all paths → `Indeterminate`.
///
/// Order matters: try Mail (used by most macOS desktops) first.
/// Fall back to TCC.db which is FDA-required on every box but
/// requires expanding `~` and a non-default location prefix.
fn fda_probe_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(h) = home.as_ref() {
        // Mail's primary index lives under V*; we don't glob —
        // a stat() on the parent directory is enough to trigger
        // the FDA check.
        paths.push(h.join("Library/Mail"));
        paths.push(h.join("Library/Application Support/com.apple.TCC/TCC.db"));
        paths.push(h.join("Library/Application Support/com.apple.TCC"));
    }
    paths
}

/// Three-state FDA probe. Doctor collapses to bool for the JSON
/// envelope.
pub fn probe_fda() -> FdaState {
    let mut saw_enoent = false;
    let mut saw_eperm = false;
    for p in fda_probe_paths() {
        match std::fs::metadata(&p) {
            Ok(_) => return FdaState::Granted,
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => saw_eperm = true,
                std::io::ErrorKind::NotFound => saw_enoent = true,
                _ => {}
            },
        }
    }
    if saw_eperm {
        FdaState::Denied
    } else if saw_enoent {
        FdaState::Indeterminate
    } else {
        // No path resolved at all — HOME unset?
        FdaState::Indeterminate
    }
}

// ─────────────────────────────────────────────────────────────────────
// Codesign verification
// ─────────────────────────────────────────────────────────────────────

/// Locate the helper binary on disk. Mirrors `linux::find_helper_bin`
/// — tries `target/release/shit-helper`, `target/debug/shit-helper`,
/// `/usr/local/libexec/shit-helper`, then `which shit-helper`.
fn find_helper_bin() -> Option<PathBuf> {
    let candidates = ["target/release/shit-helper", "target/debug/shit-helper"];
    for rel in candidates {
        let p = PathBuf::from(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    for abs in ["/usr/local/libexec/shit-helper", "/opt/homebrew/bin/shit-helper"] {
        let p = PathBuf::from(abs);
        if p.is_file() {
            return Some(p);
        }
    }
    let out = Command::new("which").arg("shit-helper").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Parse `codesign -dvv` stderr output for the `TeamIdentifier=`
/// line. The output is undocumented but stable since macOS 10.10.
fn parse_team_id(dvv_stderr: &str) -> Option<String> {
    for line in dvv_stderr.lines() {
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            let t = rest.trim();
            if !t.is_empty() && t != "not set" {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Parse `codesign -dvv` stderr for the `Authority=...Developer ID
/// Application: ...` line that distinguishes a Developer-ID-signed
/// binary from an ad-hoc or unsigned one.
fn parse_signature_kind(dvv_stderr: &str, verify_ok: bool) -> &'static str {
    if !verify_ok {
        // Verify failed → either unsigned or signature broken. Treat
        // as unsigned for the M02 envelope; broken signatures land in
        // the doctor's remediation notes.
        return "unsigned";
    }
    let mut saw_dev_id = false;
    let mut saw_apple_dev = false;
    for line in dvv_stderr.lines() {
        if line.contains("Authority=Developer ID Application:") {
            saw_dev_id = true;
        }
        if line.contains("Authority=Apple Development:") {
            saw_apple_dev = true;
        }
    }
    if saw_dev_id {
        "developer-id-application"
    } else if saw_apple_dev {
        "apple-development"
    } else {
        // verify passed but no Authority line — ad-hoc signed
        // (Signature=adhoc on the `codesign -dv` output).
        "ad-hoc"
    }
}

/// Check whether the binary's notary ticket is stapled. The probe
/// is `stapler validate`; non-zero exit (including exit 65 / "no
/// ticket") means not stapled.
fn probe_stapled(bin: &Path) -> bool {
    Command::new("stapler")
        .arg("validate")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Verify the helper binary's codesign + extract signature metadata.
pub fn probe_codesign_self() -> CodesignReport {
    let Some(bin) = find_helper_bin() else {
        return CodesignReport {
            signature_kind: "unknown".into(),
            ..Default::default()
        };
    };

    let verify = Command::new("codesign")
        .args(["--verify", "--strict", "--deep"])
        .arg(&bin)
        .output();
    let verify_ok = matches!(&verify, Ok(o) if o.status.success());

    // `codesign -dvv` writes to stderr; non-zero exit is possible
    // on unsigned binaries. Capture output regardless.
    let dvv = Command::new("codesign").args(["-d", "-vv"]).arg(&bin).output();
    let dvv_stderr = match &dvv {
        Ok(o) => String::from_utf8_lossy(&o.stderr).into_owned(),
        Err(_) => String::new(),
    };

    let team_id = parse_team_id(&dvv_stderr);
    let signature_kind = parse_signature_kind(&dvv_stderr, verify_ok).to_string();
    let stapled = probe_stapled(&bin);
    // Notarized iff stapled (or notarized-but-unstapled which we
    // can't cheaply distinguish without hitting Apple's notary API).
    // Surface stapled as the source of truth for M02.
    let notarized = stapled;

    CodesignReport {
        team_id,
        signature_kind,
        notarized,
        stapled,
    }
}

// ─────────────────────────────────────────────────────────────────────
// SIP (System Integrity Protection) state
// ─────────────────────────────────────────────────────────────────────

/// Parse `csrutil status` output. The output is one of:
/// - `System Integrity Protection status: enabled.`
/// - `System Integrity Protection status: disabled.`
/// - `System Integrity Protection status: enabled (Custom Configuration).`
/// - On some macOS versions in Recovery, root-only output prefixed
///   with config details — we surface "unknown" for those.
pub fn parse_csrutil_status(out: &str) -> &'static str {
    let lower = out.to_lowercase();
    if lower.contains("status: enabled (custom") {
        "custom"
    } else if lower.contains("status: enabled") {
        "enabled"
    } else if lower.contains("status: disabled") {
        "disabled"
    } else {
        "unknown"
    }
}

pub fn probe_sip_state() -> SipReport {
    let out = Command::new("csrutil").arg("status").output();
    let stdout = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return SipReport { state: "unknown".into() },
    };
    SipReport {
        state: parse_csrutil_status(&stdout).into(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Sandbox profile loaded
// ─────────────────────────────────────────────────────────────────────

// `int sandbox_check(pid_t pid, const char *operation, sandbox_filter_type type, ...);`
// Undocumented but stable. Returns 1 if the operation would be denied
// by the active sandbox profile, 0 if allowed, -1 on error.
//
// The `type` flag bit `SANDBOX_CHECK_NO_REPORT (0x1)` suppresses TCC
// prompts (we want this — the probe must be silent).
unsafe extern "C" {
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, ty: u64) -> i32;
}

const SANDBOX_CHECK_NO_REPORT: u64 = 0x1;

pub fn probe_sandbox_profile_loaded() -> SandboxReport {
    let op = CString::new("file-write*").expect("operation literal has no NUL");
    let pid = std::process::id() as libc::pid_t;
    // The doctor caller (shit CLI) isn't sandboxed, so we expect 0
    // here. The real probe-the-helper-profile path goes via the
    // handshake-probe IPC and is M02 follow-up territory.
    let rc = unsafe { sandbox_check(pid, op.as_ptr(), SANDBOX_CHECK_NO_REPORT) };
    SandboxReport {
        // CLI being unsandboxed is normal — `profile_loaded` here
        // refers to the caller, not the helper. M02 surfaces this
        // honestly via the table renderer (doctor/mod.rs).
        profile_loaded: rc == 1,
        write_allowed_outside_state_dir: rc == 0,
    }
}

// ─────────────────────────────────────────────────────────────────────
// FSEvents functional probe
// ─────────────────────────────────────────────────────────────────────
//
// Minimal inline FSEvents binding. The full library lives in
// `shit-helper::fsevents` (M01.7); we vendor a subset here because
// the doctor CLI runs in a separate process and can't link the
// helper's [[bin]] crate. M03 may move both to a shared crate.

use core_foundation_sys::array::{CFArrayCreate, CFArrayRef, kCFTypeArrayCallBacks};
use core_foundation_sys::base::{CFRelease, kCFAllocatorDefault};
use core_foundation_sys::runloop::{
    CFRunLoopGetCurrent, CFRunLoopRef, CFRunLoopRun, CFRunLoopStop, kCFRunLoopDefaultMode,
};
use core_foundation_sys::string::{
    CFStringCreateWithCString, CFStringRef, kCFStringEncodingUTF8,
};

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
const K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x10;
const K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER: u32 = 0x02;

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

/// Probe context the FSEvents callback receives. Atomics so the
/// callback (worker thread) and the probe (caller thread) can
/// touch them without a Mutex.
struct ProbeContext {
    seen: AtomicBool,
}

extern "C" fn probe_callback(
    _stream: FSEventStreamRef,
    info: *mut c_void,
    num_events: usize,
    _paths: *const c_void,
    _flags: *const FSEventStreamEventFlags,
    _ids: *const FSEventStreamEventId,
) {
    if info.is_null() || num_events == 0 {
        return;
    }
    let ctx = unsafe { &*(info as *const ProbeContext) };
    ctx.seen.store(true, Ordering::Relaxed);
}

/// `FSEvents` functional probe. Subscribes to a tempdir, writes a
/// file, waits up to 500ms for an event, tears down. Reports
/// functional=true + measured latency on success; functional=false
/// otherwise.
pub fn probe_fsevents_functional() -> FsEventsProbeReport {
    let started = Instant::now();
    // Manual unique-path tempdir — `tempfile` is dev-dep only.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("shit-doctor-fsevents-{pid}-{nanos}"));
    if std::fs::create_dir_all(&dir).is_err() {
        return FsEventsProbeReport::default();
    }
    let _cleanup = TmpDirGuard(dir.clone());
    let root = match std::fs::canonicalize(&dir) {
        Ok(p) => p,
        Err(_) => return FsEventsProbeReport::default(),
    };

    let ctx = Box::new(ProbeContext {
        seen: AtomicBool::new(false),
    });
    let ctx_ptr: *mut ProbeContext = Box::as_ref(&ctx) as *const _ as *mut _;

    // Worker thread runs CFRunLoopRun; main thread polls `seen` then
    // stops the runloop.
    let runloop_holder: Arc<RunloopSlot> = Arc::new(RunloopSlot::default());
    let stream_holder: Arc<StreamSlot> = Arc::new(StreamSlot::default());
    let (ready_tx, ready_rx) = channel::<bool>();

    let rl_for_worker = Arc::clone(&runloop_holder);
    let st_for_worker = Arc::clone(&stream_holder);
    let root_for_worker = root.clone();
    let ctx_for_worker = SendableUsize(ctx_ptr as usize);

    let worker = thread::Builder::new()
        .name("shit-doctor-fsevents-probe".into())
        .spawn(move || worker_main(root_for_worker, ctx_for_worker, rl_for_worker, st_for_worker, ready_tx));

    let worker = match worker {
        Ok(j) => j,
        Err(_) => return FsEventsProbeReport::default(),
    };

    // Wait for stream setup.
    let setup_ok = ready_rx
        .recv_timeout(Duration::from_millis(500))
        .unwrap_or(false);
    if !setup_ok {
        // Try to wind down the worker even if it never signaled.
        if let Some(rl) = runloop_holder.take() {
            unsafe { CFRunLoopStop(rl as CFRunLoopRef) };
        }
        let _ = worker.join();
        return FsEventsProbeReport::default();
    }

    // Touch a file and poll for the callback.
    let target = root.join("doctor-probe.txt");
    let _ = std::fs::write(&target, b"x");

    let deadline = Instant::now() + Duration::from_millis(500);
    let mut seen = false;
    while Instant::now() < deadline {
        if ctx.seen.load(Ordering::Relaxed) {
            seen = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let latency_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    // Tear down.
    if let Some(stream) = stream_holder.take() {
        unsafe {
            let s = stream as FSEventStreamRef;
            FSEventStreamStop(s);
            FSEventStreamInvalidate(s);
            FSEventStreamRelease(s);
        }
    }
    if let Some(rl) = runloop_holder.take() {
        unsafe { CFRunLoopStop(rl as CFRunLoopRef) };
    }
    let _ = worker.join();
    // ctx outlives the FSEvents stream — drop it last so any late
    // callback (post-Stop, pre-Release) doesn't dangle. The Box
    // drops here at scope exit; the FSEvents stream is already
    // Invalidated+Released so no further callback can fire.
    drop(ctx);

    FsEventsProbeReport {
        functional: seen,
        latency_probe_ms: if seen { latency_ms } else { 0 },
    }
}

#[derive(Default)]
struct RunloopSlot(AtomicU64);
#[derive(Default)]
struct StreamSlot(AtomicU64);

impl RunloopSlot {
    fn store(&self, ptr: usize) {
        self.0.store(ptr as u64, Ordering::Release);
    }
    fn take(&self) -> Option<usize> {
        let raw = self.0.swap(0, Ordering::AcqRel);
        if raw == 0 { None } else { Some(raw as usize) }
    }
}
impl StreamSlot {
    fn store(&self, ptr: usize) {
        self.0.store(ptr as u64, Ordering::Release);
    }
    fn take(&self) -> Option<usize> {
        let raw = self.0.swap(0, Ordering::AcqRel);
        if raw == 0 { None } else { Some(raw as usize) }
    }
}

/// Send-safe wrapper for the callback-context pointer crossing into
/// the worker thread closure.
#[derive(Clone, Copy)]
struct SendableUsize(usize);
unsafe impl Send for SendableUsize {}

fn worker_main(
    root: PathBuf,
    ctx_ptr: SendableUsize,
    runloop_slot: Arc<RunloopSlot>,
    stream_slot: Arc<StreamSlot>,
    ready_tx: Sender<bool>,
) {
    let s = match root.to_str() {
        Some(s) => s,
        None => {
            let _ = ready_tx.send(false);
            return;
        }
    };
    let Ok(cs) = CString::new(s) else {
        let _ = ready_tx.send(false);
        return;
    };
    let cf_string = unsafe {
        CFStringCreateWithCString(kCFAllocatorDefault, cs.as_ptr(), kCFStringEncodingUTF8)
    };
    if cf_string.is_null() {
        let _ = ready_tx.send(false);
        return;
    }
    let array_items: [CFStringRef; 1] = [cf_string];
    let cf_array = unsafe {
        CFArrayCreate(
            kCFAllocatorDefault,
            array_items.as_ptr() as *const _,
            1,
            &kCFTypeArrayCallBacks,
        )
    };
    unsafe { CFRelease(cf_string as *const _) };
    if cf_array.is_null() {
        let _ = ready_tx.send(false);
        return;
    }

    let stream_ctx = FSEventStreamContext {
        version: 0,
        info: ctx_ptr.0 as *mut c_void,
        retain: None,
        release: None,
        copy_description: None,
    };
    let stream = unsafe {
        FSEventStreamCreate(
            ptr::null(),
            probe_callback,
            &stream_ctx,
            cf_array,
            K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW,
            0.0,
            K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS | K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER,
        )
    };
    unsafe { CFRelease(cf_array as *const _) };
    if stream.is_null() {
        let _ = ready_tx.send(false);
        return;
    }

    let rl = unsafe { CFRunLoopGetCurrent() };
    runloop_slot.store(rl as usize);
    stream_slot.store(stream as usize);

    unsafe {
        FSEventStreamScheduleWithRunLoop(stream, rl, kCFRunLoopDefaultMode);
        if !FSEventStreamStart(stream) {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            stream_slot.take();
            runloop_slot.take();
            let _ = ready_tx.send(false);
            return;
        }
    }

    let _ = ready_tx.send(true);
    unsafe { CFRunLoopRun() };
    // CFRunLoopRun returned (the main thread called CFRunLoopStop).
    // Stream cleanup happens on the main thread.
}

// ─────────────────────────────────────────────────────────────────────
// EndpointSecurity (M02 stub)
// ─────────────────────────────────────────────────────────────────────

/// EndpointSecurity probe. M02 stages this — the real probe lands
/// in M03's first commit when the ES FFI bindings ship in
/// `shit-helper`. Until then we return a clearly-marked
/// "not yet implemented" report so the doctor can render an honest
/// remediation line.
pub fn probe_endpoint_security() -> EndpointSecurityReport {
    EndpointSecurityReport {
        entitlement_present: false,
        fda_granted: false, // overwritten by the doctor with the FDA probe's result
        client_can_subscribe: false,
        subscribed_event_kinds: vec![],
        notes: vec!["ES probe not yet implemented (M03)".into()],
    }
}

// ─────────────────────────────────────────────────────────────────────
// Cleanup helpers
// ─────────────────────────────────────────────────────────────────────

/// RAII guard that recursively removes a probe tempdir on drop.
struct TmpDirGuard(PathBuf);
impl Drop for TmpDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrutil_parser_enabled() {
        assert_eq!(
            parse_csrutil_status("System Integrity Protection status: enabled.\n"),
            "enabled"
        );
    }

    #[test]
    fn csrutil_parser_disabled() {
        assert_eq!(
            parse_csrutil_status("System Integrity Protection status: disabled.\n"),
            "disabled"
        );
    }

    #[test]
    fn csrutil_parser_custom() {
        assert_eq!(
            parse_csrutil_status(
                "System Integrity Protection status: enabled (Custom Configuration).\n\
                 Configuration:\n\
                 \tApple Internal: disabled\n"
            ),
            "custom"
        );
    }

    #[test]
    fn csrutil_parser_unknown() {
        assert_eq!(parse_csrutil_status(""), "unknown");
        assert_eq!(parse_csrutil_status("garbage output\n"), "unknown");
    }

    #[test]
    fn team_id_parser_extracts_id() {
        let dvv = "Executable=/path/to/bin\n\
                   Identifier=com.tenseleyflow.shit-helper\n\
                   TeamIdentifier=Q6JHJ53S9C\n\
                   Authority=Developer ID Application: Matthew Wolffe (Q6JHJ53S9C)\n";
        assert_eq!(parse_team_id(dvv), Some("Q6JHJ53S9C".into()));
    }

    #[test]
    fn team_id_parser_returns_none_when_not_set() {
        let dvv = "Identifier=anonymous\nTeamIdentifier=not set\n";
        assert_eq!(parse_team_id(dvv), None);
        assert_eq!(parse_team_id("no team id line at all\n"), None);
    }

    #[test]
    fn signature_kind_parser_developer_id() {
        let dvv = "Identifier=com.tenseleyflow.shit-helper\n\
                   Authority=Developer ID Application: Matthew Wolffe (Q6JHJ53S9C)\n\
                   Authority=Developer ID Certification Authority\n";
        assert_eq!(parse_signature_kind(dvv, true), "developer-id-application");
    }

    #[test]
    fn signature_kind_parser_apple_dev() {
        let dvv = "Identifier=com.example.tool\n\
                   Authority=Apple Development: dev@example.com (TEAMID)\n";
        assert_eq!(parse_signature_kind(dvv, true), "apple-development");
    }

    #[test]
    fn signature_kind_parser_adhoc() {
        let dvv = "Identifier=adhoc-bin\nSignature=adhoc\n";
        assert_eq!(parse_signature_kind(dvv, true), "ad-hoc");
    }

    #[test]
    fn signature_kind_parser_unsigned_when_verify_failed() {
        let dvv = "Identifier=com.example.tool\n\
                   Authority=Developer ID Application: Matthew Wolffe (Q6JHJ53S9C)\n";
        assert_eq!(parse_signature_kind(dvv, false), "unsigned");
    }

    #[test]
    fn fda_probe_paths_includes_mail_when_home_set() {
        let saved = std::env::var_os("HOME");
        // SAFETY: we restore HOME after the test.
        unsafe { std::env::set_var("HOME", "/tmp/m02-fda-probe-home") };
        let paths = fda_probe_paths();
        assert!(paths.iter().any(|p| p.ends_with("Library/Mail")));
        if let Some(s) = saved {
            unsafe { std::env::set_var("HOME", s) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
    }

    #[test]
    fn endpoint_security_stub_returns_m03_pending() {
        let r = probe_endpoint_security();
        assert!(!r.entitlement_present);
        assert!(!r.client_can_subscribe);
        assert!(r.notes.iter().any(|n| n.contains("M03")));
    }

    #[test]
    fn sip_probe_returns_one_of_known_states() {
        // Running locally; csrutil should respond. On CI runners
        // it's also reachable. Tolerate "unknown" so the test
        // doesn't flake on a stripped image.
        let r = probe_sip_state();
        assert!(
            matches!(r.state.as_str(), "enabled" | "disabled" | "custom" | "unknown"),
            "unexpected SIP state: {}",
            r.state
        );
    }
}
