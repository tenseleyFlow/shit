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

// Module-level `#[cfg(target_os = "macos")]` lives on `pub mod macos;`
// in `super::mod`; the inner `#![cfg(...)]` is redundant and trips
// `clippy::duplicated_attributes` on newer rustc.

use crate::doctor::json::{
    CodesignReport, DyldShimRcFile, DyldShimReport, EndpointSecurityReport, EsBlocker,
    FsEventsProbeReport, SandboxReport, SipReport,
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
    for abs in [
        "/usr/local/libexec/shit-helper",
        "/opt/homebrew/bin/shit-helper",
    ] {
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
    let dvv = Command::new("codesign")
        .args(["-d", "-vv"])
        .arg(&bin)
        .output();
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
    let sip_out = Command::new("csrutil").arg("status").output();
    let state = match sip_out {
        Ok(o) => parse_csrutil_status(&String::from_utf8_lossy(&o.stdout)).into(),
        Err(_) => "unknown".to_string(),
    };
    SipReport {
        state,
        authenticated_root: probe_authenticated_root(),
        amfi_bypass: probe_amfi_bypass(),
    }
}

/// Parse `csrutil authenticated-root status`. Apple Silicon machines
/// have a System volume seal that's independent of SIP itself. The
/// AMFI-bypass install path needs BOTH disabled.
///
/// Output forms (macOS 11+):
/// - `Authenticated Root status: enabled`
/// - `Authenticated Root status: disabled`
/// - Plus a trailing newline.
///
/// Returns `"enabled"` / `"disabled"` / `"unknown"`.
pub fn parse_csrutil_authenticated_root(out: &str) -> &'static str {
    let lower = out.to_lowercase();
    if lower.contains("authenticated root status: enabled") {
        "enabled"
    } else if lower.contains("authenticated root status: disabled") {
        "disabled"
    } else {
        "unknown"
    }
}

fn probe_authenticated_root() -> String {
    // `csrutil authenticated-root status` returns 0 on success on
    // macOS where the command is supported, non-zero on older
    // Intel Macs where the auth-root feature doesn't exist. Treat
    // unknown either way; the doctor surfaces it.
    let out = Command::new("csrutil")
        .arg("authenticated-root")
        .arg("status")
        .output();
    match out {
        Ok(o) => parse_csrutil_authenticated_root(&String::from_utf8_lossy(&o.stdout)).into(),
        Err(_) => "unknown".into(),
    }
}

/// Parse `nvram boot-args` output for the AMFI bypass flag. nvram
/// emits `boot-args\t<value>` (tab-separated). The bypass flag is
/// `amfi_get_out_of_my_way=0x1` (or `=1`); we match the key
/// substring rather than the exact value so a future Apple change
/// to "=0x3" or similar still surfaces as bypass-active.
///
/// Returns true iff the bypass flag is present in the boot-args.
pub fn parse_nvram_amfi_bypass(out: &str) -> bool {
    let lower = out.to_lowercase();
    lower.contains("amfi_get_out_of_my_way")
}

fn probe_amfi_bypass() -> bool {
    let out = Command::new("nvram").arg("boot-args").output();
    match out {
        Ok(o) => parse_nvram_amfi_bypass(&String::from_utf8_lossy(&o.stdout)),
        // nvram returns non-zero when the variable isn't set at all.
        // That's the default state on every stock Mac — bypass=false.
        Err(_) => false,
    }
}

/// Parse `codesign -d --entitlements - <bin>` output for the ES
/// entitlement key. The output is a Property List (binary or XML
/// depending on macOS rev); we substring-match the key name rather
/// than parse the plist — sufficient for a yes/no surface.
///
/// Apple's tool also prefixes a blob header line we ignore; the
/// substring match is on the entitlement key itself, which is
/// stable across formats.
pub fn parse_codesign_entitlements_has_es(out: &str) -> bool {
    out.contains("com.apple.developer.endpoint-security.client")
}

/// Read the installed helper's codesigned entitlements and report
/// whether the ES key is present. The helper path is resolved the
/// same way the daemon resolves it for spawning:
/// `SHIT_HELPER_BIN` env override → `target/release/shit-helper` →
/// `/usr/local/bin/shit-helper` → `/opt/homebrew/bin/shit-helper`.
///
/// Returns false on any failure (helper not found, codesign not
/// installed, helper unsigned, etc.) — power-user mode requires the
/// helper to be explicitly codesigned with the entitlement plist;
/// missing = needs to run the codesign-on-install script.
pub fn probe_helper_has_es_entitlement(helper_path: Option<&Path>) -> bool {
    let helper = match helper_path {
        Some(p) => p.to_path_buf(),
        None => {
            // Resolve like the daemon does. Cheap because we don't
            // execute the helper — just check codesign metadata.
            let env_override = std::env::var_os("SHIT_HELPER_BIN").map(PathBuf::from);
            let candidates = [
                env_override,
                Some(PathBuf::from("target/release/shit-helper")),
                Some(PathBuf::from("/usr/local/bin/shit-helper")),
                Some(PathBuf::from("/opt/homebrew/bin/shit-helper")),
            ];
            let mut found = None;
            for c in candidates.into_iter().flatten() {
                if c.exists() {
                    found = Some(c);
                    break;
                }
            }
            match found {
                Some(p) => p,
                None => return false,
            }
        }
    };
    let out = Command::new("codesign")
        .arg("-d")
        .arg("--entitlements")
        .arg("-")
        .arg(&helper)
        .output();
    match out {
        Ok(o) => {
            // codesign writes the entitlement blob to stderr in
            // older macOS revs and stdout in newer ones; check both.
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            parse_codesign_entitlements_has_es(&stdout)
                || parse_codesign_entitlements_has_es(&stderr)
        }
        Err(_) => false,
    }
}

/// Compose `(es_capable, es_blockers)` from the four prereq probes.
/// Pure function for unit-test friendliness; the caller wires in the
/// already-collected reports + the EndpointSecurityReport so this
/// function does no I/O.
///
/// `es_capable = true` iff:
/// - `sip.state` is `"disabled"` OR `"custom"` (custom may keep SIP
///   off for the filesystem-protection bit even with kext-signing on,
///   which is enough for our purposes; if it's still blocking we'd
///   see the next probe report blockers anyway)
/// - `sip.authenticated_root == "disabled"`
/// - `sip.amfi_bypass == true`
/// - `endpoint_security.helper_has_es_entitlement == true`
///
/// When any prereq fails, the returned `Vec<EsBlocker>` enumerates
/// each missing piece with a remediation command.
pub fn compose_es_capable(sip: &SipReport, es: &EndpointSecurityReport) -> (bool, Vec<EsBlocker>) {
    let mut blockers: Vec<EsBlocker> = Vec::new();

    if !matches!(sip.state.as_str(), "disabled" | "custom") {
        blockers.push(EsBlocker {
            component: "sip".into(),
            reason: format!(
                "System Integrity Protection is {}; ES entitlement is rejected by AMFI unless SIP is off",
                sip.state
            ),
            fix_command: Some("csrutil disable".into()),
            recovery_mode: true,
        });
    }
    if sip.authenticated_root != "disabled" {
        blockers.push(EsBlocker {
            component: "authenticated_root".into(),
            reason: format!(
                "Authenticated Root is {}; required to be disabled on Apple Silicon for AMFI bypass to take effect",
                if sip.authenticated_root.is_empty() {
                    "unknown"
                } else {
                    sip.authenticated_root.as_str()
                }
            ),
            fix_command: Some("csrutil authenticated-root disable".into()),
            recovery_mode: true,
        });
    }
    if !sip.amfi_bypass {
        blockers.push(EsBlocker {
            component: "amfi_bypass".into(),
            reason: "AMFI bypass boot-arg not set; AMFI will reject the helper's ES entitlement claim even with SIP off"
                .into(),
            fix_command: Some(
                "sudo nvram boot-args=\"amfi_get_out_of_my_way=0x1\" && sudo reboot".into(),
            ),
            recovery_mode: false,
        });
    }
    if !es.helper_has_es_entitlement {
        blockers.push(EsBlocker {
            component: "helper_entitlement".into(),
            reason: "Installed shit-helper is not codesigned with the EndpointSecurity entitlement; run the install-time codesign script"
                .into(),
            fix_command: Some(
                "sudo /usr/local/bin/shit-setup-es-mode || sudo /opt/homebrew/bin/shit-setup-es-mode"
                    .into(),
            ),
            recovery_mode: false,
        });
    }

    let capable = blockers.is_empty();
    (capable, blockers)
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
use core_foundation_sys::string::{CFStringCreateWithCString, CFStringRef, kCFStringEncodingUTF8};

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
        .spawn(move || {
            worker_main(
                root_for_worker,
                ctx_for_worker,
                rl_for_worker,
                st_for_worker,
                ready_tx,
            )
        });

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
// EndpointSecurity (M03.1.C — wired)
// ─────────────────────────────────────────────────────────────────────

/// EndpointSecurity probe. Spawns the helper's `es-probe`
/// subcommand (M03.1.C), parses the one-line JSON it prints, and
/// maps to [`EndpointSecurityReport`].
///
/// The helper actually attempts `es_new_client` with a no-op
/// handler and reports the kernel verdict. Doctor caller runs as
/// the user (not root); the helper subprocess inherits user
/// privileges. On a stock SIP-on macOS without entitlement that
/// means we'll get `NotPrivileged` or `NotEntitled` depending on
/// host check ordering — both are reported honestly via the
/// `notes` field.
///
/// To get a Success result from the probe, the helper must run in
/// a context where ES is unlocked:
/// - SIP off + AMFI bypass (Tart VM dev), OR
/// - Signed + notarized binary with the entitlement (M04 +
///   Apple paperwork), OR
/// - Running as root WITH one of the above.
pub fn probe_endpoint_security() -> EndpointSecurityReport {
    let Some(bin) = find_helper_bin() else {
        return EndpointSecurityReport {
            entitlement_present: false,
            fda_granted: false,
            client_can_subscribe: false,
            subscribed_event_kinds: vec![],
            notes: vec![
                "no helper binary found on disk — build via `cargo build -p shit-helper` \
                 or install the release artifact"
                    .into(),
            ],
            helper_has_es_entitlement: false,
        };
    };

    let out = Command::new(&bin).arg("es-probe").output();
    let stdout = match &out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            return EndpointSecurityReport {
                notes: vec![format!(
                    "shit-helper es-probe exited {} (stderr: {})",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                )],
                ..Default::default()
            };
        }
        Err(e) => {
            return EndpointSecurityReport {
                notes: vec![format!("spawn shit-helper es-probe failed: {e}")],
                ..Default::default()
            };
        }
    };

    let line = stdout.lines().next().unwrap_or("").trim();
    parse_es_probe_line(line)
}

/// Parse the one-line JSON the helper's `es-probe` emits. Hand-rolled
/// (no serde_json import needed for one field) and tolerant of the
/// `UnknownResult,"raw":<u32>` two-field shape.
fn parse_es_probe_line(line: &str) -> EndpointSecurityReport {
    let result = line.split('"').nth(3).unwrap_or("").to_string();
    let (entitlement_present, client_can_subscribe, note) = match result.as_str() {
        "Success" => (
            true,
            true,
            "ES client created successfully (kernel SUCCESS)".to_string(),
        ),
        "NotEntitled" => (
            false,
            false,
            "ES returned NOT_ENTITLED — missing entitlement on signed binary, \
             OR running ad-hoc on a system without AMFI bypass"
                .to_string(),
        ),
        "NotPermitted" => (
            true, // entitlement check passed; TCC is the gate
            false,
            "ES returned NOT_PERMITTED — entitlement OK but Full Disk Access \
             not granted; remediate via System Settings → Privacy → Full Disk Access"
                .to_string(),
        ),
        "NotPrivileged" => (
            false,
            false,
            "ES returned NOT_PRIVILEGED — helper not running as root. \
             Production helpers run as root via shitd; the doctor's user-context \
             probe correctly reports this gap"
                .to_string(),
        ),
        "InvalidArgument" => (
            false,
            false,
            "ES returned INVALID_ARGUMENT (probe bug)".into(),
        ),
        "InternalError" => (
            false,
            false,
            "ES returned INTERNAL_ERROR (host-side ES issue)".into(),
        ),
        "TooManyClients" => (
            false,
            false,
            "ES returned TOO_MANY_CLIENTS — host saturated; close other ES clients".into(),
        ),
        "NotSupportedOnThisOs" => (
            false,
            false,
            "ES not supported on this OS (probe ran on non-macOS helper)".into(),
        ),
        other => (
            false,
            false,
            format!("unknown es-probe result '{other}' (line: '{line}')"),
        ),
    };
    EndpointSecurityReport {
        entitlement_present,
        fda_granted: false, // overwritten by the doctor with the FDA probe's result
        client_can_subscribe,
        subscribed_event_kinds: vec![],
        notes: vec![note],
        // overwritten by the doctor's dispatch with `probe_helper_has_es_entitlement`
        helper_has_es_entitlement: false,
    }
}

// ─────────────────────────────────────────────────────────────────────
// M07-doctor — dyld-shim install state
// ─────────────────────────────────────────────────────────────────────

/// Marker pair the `shit dyld-hooks install` snippet wraps its
/// rc-file content in. Kept in sync with the constants in
/// `cmd::dyld_hooks`; duplicated here rather than referenced
/// because importing from `cmd` into `doctor::probes` would
/// invert the dep direction.
const DYLD_HOOKS_SNIPPET_BEGIN: &str = "# >>> shit dyld-hooks (begin) >>>";

/// Resolve the shim dylib path. Mirrors the resolution chain in
/// `cmd::dyld_hooks::resolve_shim_path` (env var → Homebrew prefix
/// arm64 → Homebrew prefix x86_64 → repo target/release → repo
/// target/debug). Duplicated rather than imported to keep the
/// `doctor` → `cmd` boundary clean.
fn resolve_shim_dylib_path() -> Option<PathBuf> {
    if let Some(env) = std::env::var_os("SHIT_PRELOAD_SHIM") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in [
        "/usr/local/lib/libshit_preload_shim.dylib",
        "/opt/homebrew/lib/libshit_preload_shim.dylib",
        "target/release/libshit_preload_shim.dylib",
        "target/debug/libshit_preload_shim.dylib",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Per-rc-file probe: is the shim snippet's begin-marker present?
/// Cheaper than the full begin+end span check; if the begin marker
/// is there we trust the install routine wrote a complete section.
fn rc_file_snippet_state(path: &Path) -> DyldShimRcFile {
    let exists = path.exists();
    let snippet_installed = if exists {
        std::fs::read_to_string(path)
            .map(|c| c.contains(DYLD_HOOKS_SNIPPET_BEGIN))
            .unwrap_or(false)
    } else {
        false
    };
    DyldShimRcFile {
        path: path.display().to_string(),
        exists,
        snippet_installed,
    }
}

/// M07-doctor probe entry point. Resolves the shim dylib + checks
/// the user's shell rc files for the `shit dyld-hooks install`
/// snippet. No external commands; pure filesystem reads.
pub fn probe_dyld_shim() -> DyldShimReport {
    let dylib = resolve_shim_dylib_path();
    let mut rc_files_checked = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for rc in [".zshrc", ".bashrc"] {
            rc_files_checked.push(rc_file_snippet_state(&home.join(rc)));
        }
    }
    let rc_snippet_installed = rc_files_checked.iter().any(|e| e.snippet_installed);
    DyldShimReport {
        shim_dylib_present: dylib.is_some(),
        shim_dylib_path: dylib.as_ref().map(|p| p.display().to_string()),
        rc_snippet_installed,
        rc_files_checked,
    }
}

#[cfg(test)]
mod dyld_shim_tests {
    use super::*;

    #[test]
    fn rc_file_snippet_state_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join("nonexistent_rc");
        let e = rc_file_snippet_state(&rc);
        assert!(!e.exists);
        assert!(!e.snippet_installed);
        assert_eq!(e.path, rc.display().to_string());
    }

    #[test]
    fn rc_file_snippet_state_present_without_snippet() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        std::fs::write(&rc, "alias ll='ls -l'\n").unwrap();
        let e = rc_file_snippet_state(&rc);
        assert!(e.exists);
        assert!(!e.snippet_installed);
    }

    #[test]
    fn rc_file_snippet_state_with_snippet() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        let body = format!("alias ll='ls -l'\n{DYLD_HOOKS_SNIPPET_BEGIN}\n# stuff\n");
        std::fs::write(&rc, body).unwrap();
        let e = rc_file_snippet_state(&rc);
        assert!(e.exists);
        assert!(e.snippet_installed);
    }

    #[test]
    fn probe_dyld_shim_returns_well_formed_report() {
        // Report shape must be populated even on a stock host
        // where nothing is installed. Don't assert specific values
        // because the test box may or may not have the shim.
        let report = probe_dyld_shim();
        if report.shim_dylib_present {
            assert!(report.shim_dylib_path.is_some());
        } else {
            assert!(report.shim_dylib_path.is_none());
        }
        // rc_files_checked is populated as long as $HOME is set
        // (which it is during cargo test).
        if std::env::var_os("HOME").is_some() {
            assert_eq!(report.rc_files_checked.len(), 2);
        }
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
    fn es_probe_parser_success() {
        let r = parse_es_probe_line(r#"{"result":"Success"}"#);
        assert!(r.entitlement_present);
        assert!(r.client_can_subscribe);
        assert!(r.notes.iter().any(|n| n.contains("SUCCESS")));
    }

    #[test]
    fn es_probe_parser_not_entitled() {
        let r = parse_es_probe_line(r#"{"result":"NotEntitled"}"#);
        assert!(!r.entitlement_present);
        assert!(!r.client_can_subscribe);
        assert!(r.notes.iter().any(|n| n.contains("NOT_ENTITLED")));
    }

    #[test]
    fn es_probe_parser_not_permitted_keeps_entitlement_true() {
        // NOT_PERMITTED means entitlement check passed but TCC denied.
        let r = parse_es_probe_line(r#"{"result":"NotPermitted"}"#);
        assert!(r.entitlement_present);
        assert!(!r.client_can_subscribe);
        assert!(r.notes.iter().any(|n| n.contains("Full Disk Access")));
    }

    #[test]
    fn es_probe_parser_not_privileged() {
        let r = parse_es_probe_line(r#"{"result":"NotPrivileged"}"#);
        assert!(!r.entitlement_present);
        assert!(!r.client_can_subscribe);
        assert!(r.notes.iter().any(|n| n.contains("root")));
    }

    #[test]
    fn es_probe_parser_unknown_result_carried_verbatim() {
        let r = parse_es_probe_line(r#"{"result":"SomethingNew","raw":99}"#);
        assert!(!r.entitlement_present);
        assert!(r.notes.iter().any(|n| n.contains("SomethingNew")));
    }

    #[test]
    fn es_probe_parser_garbage_input_is_safe() {
        let r = parse_es_probe_line("");
        assert!(!r.entitlement_present);
        // Empty input → result string is empty → falls into the
        // "unknown" arm with an empty token.
    }

    #[test]
    fn sip_probe_returns_one_of_known_states() {
        // Running locally; csrutil should respond. On CI runners
        // it's also reachable. Tolerate "unknown" so the test
        // doesn't flake on a stripped image.
        let r = probe_sip_state();
        assert!(
            matches!(
                r.state.as_str(),
                "enabled" | "disabled" | "custom" | "unknown"
            ),
            "unexpected SIP state: {}",
            r.state
        );
    }

    // ─── M03.x.POWER-USER.1 parsers + composition ────────────────

    #[test]
    fn auth_root_parser_disabled() {
        assert_eq!(
            parse_csrutil_authenticated_root("Authenticated Root status: disabled\n"),
            "disabled"
        );
    }

    #[test]
    fn auth_root_parser_enabled() {
        assert_eq!(
            parse_csrutil_authenticated_root("Authenticated Root status: enabled\n"),
            "enabled"
        );
    }

    #[test]
    fn auth_root_parser_garbage_is_unknown() {
        assert_eq!(parse_csrutil_authenticated_root(""), "unknown");
        assert_eq!(
            parse_csrutil_authenticated_root("csrutil: invalid subcommand\n"),
            "unknown"
        );
    }

    #[test]
    fn amfi_parser_detects_bypass_flag() {
        assert!(parse_nvram_amfi_bypass(
            "boot-args\tamfi_get_out_of_my_way=0x1\n"
        ));
        assert!(parse_nvram_amfi_bypass(
            "boot-args\t-v amfi_get_out_of_my_way=1 keepsyms=1\n"
        ));
    }

    #[test]
    fn amfi_parser_empty_or_missing_is_false() {
        assert!(!parse_nvram_amfi_bypass(""));
        assert!(!parse_nvram_amfi_bypass("boot-args\t\n"));
        assert!(!parse_nvram_amfi_bypass("boot-args\t-v keepsyms=1\n"));
    }

    #[test]
    fn codesign_entitlements_parser_detects_es_key() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC ...>
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>"#;
        assert!(parse_codesign_entitlements_has_es(xml));
    }

    #[test]
    fn codesign_entitlements_parser_no_es_key_returns_false() {
        let xml = r#"<plist version="1.0"><dict><key>some.other.key</key><true/></dict></plist>"#;
        assert!(!parse_codesign_entitlements_has_es(xml));
        assert!(!parse_codesign_entitlements_has_es(""));
    }

    #[test]
    fn compose_es_capable_fully_green() {
        let sip = SipReport {
            state: "disabled".into(),
            authenticated_root: "disabled".into(),
            amfi_bypass: true,
        };
        let es = EndpointSecurityReport {
            helper_has_es_entitlement: true,
            ..Default::default()
        };
        let (capable, blockers) = compose_es_capable(&sip, &es);
        assert!(capable);
        assert!(blockers.is_empty());
    }

    #[test]
    fn compose_es_capable_stock_mac_lists_all_four_blockers() {
        let sip = SipReport {
            state: "enabled".into(),
            authenticated_root: "enabled".into(),
            amfi_bypass: false,
        };
        let es = EndpointSecurityReport {
            helper_has_es_entitlement: false,
            ..Default::default()
        };
        let (capable, blockers) = compose_es_capable(&sip, &es);
        assert!(!capable);
        let names: Vec<&str> = blockers.iter().map(|b| b.component.as_str()).collect();
        assert!(names.contains(&"sip"));
        assert!(names.contains(&"authenticated_root"));
        assert!(names.contains(&"amfi_bypass"));
        assert!(names.contains(&"helper_entitlement"));
        // Recovery-mode flags set correctly on the SIP/auth-root blockers.
        for b in &blockers {
            match b.component.as_str() {
                "sip" | "authenticated_root" => assert!(b.recovery_mode),
                _ => assert!(!b.recovery_mode),
            }
        }
    }

    #[test]
    fn compose_es_capable_accepts_custom_sip() {
        // `csrutil enable --without fs` leaves SIP "custom" with FS
        // protection off — that's the same effective posture as
        // fully disabled for AMFI's purposes.
        let sip = SipReport {
            state: "custom".into(),
            authenticated_root: "disabled".into(),
            amfi_bypass: true,
        };
        let es = EndpointSecurityReport {
            helper_has_es_entitlement: true,
            ..Default::default()
        };
        let (capable, blockers) = compose_es_capable(&sip, &es);
        assert!(capable, "custom SIP should pass: blockers={blockers:?}");
    }

    #[test]
    fn compose_es_capable_partial_block_only_lists_failing_components() {
        // SIP off + auth-root off + AMFI on, but helper unsigned.
        let sip = SipReport {
            state: "disabled".into(),
            authenticated_root: "disabled".into(),
            amfi_bypass: true,
        };
        let es = EndpointSecurityReport {
            helper_has_es_entitlement: false,
            ..Default::default()
        };
        let (capable, blockers) = compose_es_capable(&sip, &es);
        assert!(!capable);
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].component, "helper_entitlement");
    }
}
