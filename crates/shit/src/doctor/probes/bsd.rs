// SPDX-License-Identifier: AGPL-3.0-or-later

//! BSD-family runtime probes (B03).
//!
//! Each function here is invoked exactly once per `shit doctor`
//! invocation and populates one field of [`super::super::json::BsdReport`].
//! All probes must:
//!
//! - complete in <100ms (so total `shit doctor --json` overhead
//!   stays under 2s — important for CI pre-flight use).
//! - be idempotent and side-effect-free (no kernel state changes,
//!   no daemon spawns that outlive the probe).
//! - gracefully report failure rather than panic. A probe that
//!   can't determine its answer returns the "neutral" value
//!   (`false`, empty Vec, `None`) so doctor's JSON envelope still
//!   serializes cleanly.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
// `helper_handshake_probe` + `find_helper_bin` are dev-tool functions
// kept for direct testing of the `shit-helper handshake-probe`
// subcommand (they spawn it and parse the JSON reply). After the
// ctl-Metrics pivot in B03, doctor's main path doesn't call them —
// it goes through `crate::doctor::mod.rs::probe_helper_handshake`
// against the daemon's persistent ctl socket. The functions stay
// because (a) the dev-side handshake-probe subcommand is still
// shipped on the helper, (b) the tests below exercise them, and
// (c) a future doctor option (e.g. `--fresh-helper-probe`) could
// wire them back into the main path. Without this allow, the
// FreeBSD bin-target dead-code lint trips `-D warnings` even
// though the items are exercised by tests.
#![allow(dead_code)]

use crate::doctor::json::HelperHandshakeReport;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Open a kqueue, register EVFILT_VNODE NOTE_WRITE on a fresh
/// tempfile, mutate the file, drain one event. Returns true iff
/// the event was observed within 100ms.
///
/// This is the load-bearing "does the kernel actually deliver
/// vnode events to userspace" check. The kqueue feature-flag
/// probe at `shit_capture::bsd_probe::probe_bsd` can lie if the
/// kernel was built with kqueue but the EVFILT_VNODE path is
/// broken (rare but happens after kernel-debug experiments).
pub fn kqueue_functional() -> bool {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // Manual tempfile in /tmp — tempfile crate is a dev-dep only,
    // not available at runtime. Path is per-pid + nanos for uniqueness.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("shit-doctor-kq-{pid}-{nanos}"));
    let mut f = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // Best-effort cleanup on drop via a scoped guard.
    let _cleanup = scopeguard(path.clone());

    // SAFETY: kqueue() returns a fresh fd we own.
    let kq_fd = unsafe { libc::kqueue() };
    if kq_fd < 0 {
        return false;
    }
    // SAFETY: kq_fd is a valid fresh fd we own.
    let _kq_guard = unsafe { OwnedFd::from_raw_fd(kq_fd) };

    // Use mem::zeroed() to initialize all kevent fields portably —
    // FreeBSD adds an `ext: [i64; 4]` field that NetBSD/OpenBSD/
    // DragonFly lack; zeroed-then-override avoids the per-OS literal.
    // SAFETY: libc::kevent is `#[repr(C)]` with primitive fields;
    // an all-zeros bit pattern is a valid kevent (zeroed udata is
    // a null ptr, which is what we want anyway).
    let mut change: libc::kevent = unsafe { std::mem::zeroed() };
    change.ident = f.as_raw_fd() as usize;
    change.filter = libc::EVFILT_VNODE;
    change.flags = libc::EV_ADD | libc::EV_CLEAR;
    change.fflags = libc::NOTE_WRITE;
    let mut changes = [change];

    // SAFETY: kq_fd is open, changes points to one valid kevent.
    let r = unsafe {
        libc::kevent(
            kq_fd,
            changes.as_mut_ptr(),
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if r < 0 {
        return false;
    }

    // Mutate the file so the kqueue should fire.
    if writeln!(f, "probe").is_err() {
        return false;
    }
    // Force the write to hit the vnode (some FSes batch).
    let _ = f.sync_data();

    // Drain one event with a 100ms timeout.
    let mut events = [unsafe { std::mem::zeroed::<libc::kevent>() }; 1];
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    // SAFETY: kq_fd open, events points to one valid kevent slot,
    // ts is a valid timespec.
    let n = unsafe { libc::kevent(kq_fd, std::ptr::null(), 0, events.as_mut_ptr(), 1, &ts) };
    n >= 1 && (events[0].fflags & libc::NOTE_WRITE) != 0
}

/// Tiny scoped-guard helper for unlinking a temp file on drop.
/// Avoids pulling in `scopeguard` or `tempfile` (both dev-deps).
fn scopeguard(path: std::path::PathBuf) -> impl Drop {
    struct G(std::path::PathBuf);
    impl Drop for G {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    G(path)
}

/// True iff `cap_getmode(2)` returns 0 (the capsicum syscall is
/// wired in the kernel). Doesn't actually enter capability mode —
/// just verifies the syscall is reachable. FreeBSD-only;
/// NetBSD/OpenBSD/DragonFly lack capsicum entirely so this is
/// always false there.
#[cfg(target_os = "freebsd")]
pub fn capsicum_available() -> bool {
    let mut mode: libc::c_uint = 0;
    // SAFETY: cap_getmode is a getter with no side effects; passing
    // a valid out-param pointer is the documented call shape.
    let r = unsafe { libc::cap_getmode(&mut mode) };
    r == 0
}

#[cfg(not(target_os = "freebsd"))]
pub fn capsicum_available() -> bool {
    false
}

/// True iff the helper will enter `cap_enter(2)` on startup with
/// the current environment. B05: capsicum-default-on means
/// `available && SHIT_CAPSICUM != "0"`. Pure-function on top of
/// the kernel probe — does NOT spawn the helper.
pub fn capsicum_default_on(available: bool) -> bool {
    if !available {
        return false;
    }
    !matches!(std::env::var("SHIT_CAPSICUM").as_deref(), Ok("0"))
}

/// Enumerate ZFS datasets via `/sbin/zfs list -H -o name`. Empty
/// Vec if zfs is not installed or no pools are imported. Uses
/// absolute path to be robust against SSH-non-interactive PATH
/// (same caveat as the pkg/service inspectors).
pub fn zfs_datasets() -> Vec<String> {
    let zfs = ["/sbin/zfs", "/usr/sbin/zfs"]
        .iter()
        .find(|p| Path::new(p).is_file());
    let Some(zfs) = zfs else {
        return Vec::new();
    };
    let out = Command::new(zfs)
        .args(["list", "-H", "-o", "name"])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// True iff the LD_PRELOAD shim is installed at the conventional
/// path. Matches the shipped `shit hooks install --preload` target.
pub fn preload_shim_installed() -> bool {
    Path::new("/usr/local/lib/shit/libshit_preload.so").is_file()
}

/// Pick the runtime-capture tier label. Mirrors
/// `helper::main::pick_bsd_tier()` so doctor and the helper agree.
/// Returns one of `"kqueue+preload"`, `"kqueue-only"`, `"degraded"`.
pub fn runtime_capture_label() -> String {
    let probe = shit_capture::bsd_probe::probe_bsd();
    if !probe.kqueue.evfilt_vnode {
        return "degraded".to_string();
    }
    if preload_shim_installed() {
        "kqueue+preload".to_string()
    } else {
        "kqueue-only".to_string()
    }
}

/// Spawn `shit-helper handshake-probe --daemon-sock <path>` and
/// parse its one-line JSON reply. If no daemon is running we still
/// return a populated report with `ok=false` and the error string.
///
/// Looks up the helper binary in this order:
/// 1. `$SHIT_HELPER_BIN` env var (used by tests + the smoke harness)
/// 2. `/usr/local/bin/shit-helper` (cargo install default)
/// 3. `/usr/local/libexec/shit-helper` (packaging convention)
/// 4. `shit-helper` on `$PATH`
pub fn helper_handshake_probe(daemon_sock: &Path) -> HelperHandshakeReport {
    let bin = find_helper_bin();
    let Some(bin) = bin else {
        return HelperHandshakeReport {
            ok: false,
            latency_ms: 0,
            helper_version: None,
            kernel_tier: None,
            error: Some("shit-helper binary not found".into()),
        };
    };

    let started = std::time::Instant::now();
    let output = Command::new(&bin)
        .args([
            "handshake-probe",
            "--daemon-sock",
            daemon_sock.to_str().unwrap_or(""),
        ])
        .output();
    let elapsed_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            return HelperHandshakeReport {
                ok: false,
                latency_ms: 0,
                helper_version: None,
                kernel_tier: None,
                error: Some(format!("spawn {}: {e}", bin.display())),
            };
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return HelperHandshakeReport {
            ok: false,
            latency_ms: elapsed_ms,
            helper_version: None,
            kernel_tier: None,
            error: Some(if stderr.is_empty() {
                format!("helper exited {:?}", output.status.code())
            } else {
                stderr
            }),
        };
    }

    // The helper writes one JSON line to stdout on success. Parse it.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("").trim();
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return HelperHandshakeReport {
                ok: false,
                latency_ms: elapsed_ms,
                helper_version: None,
                kernel_tier: None,
                error: Some(format!("helper output not JSON: {e}")),
            };
        }
    };

    HelperHandshakeReport {
        ok: v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
        latency_ms: v
            .get("latency_ms")
            .and_then(|x| x.as_u64())
            .map(|m| m.min(u32::MAX as u64) as u32)
            .unwrap_or(elapsed_ms),
        helper_version: v
            .get("helper_version")
            .and_then(|x| x.as_str())
            .map(String::from),
        kernel_tier: v
            .get("kernel_tier")
            .and_then(|x| x.as_str())
            .map(String::from),
        error: v.get("error").and_then(|x| x.as_str()).map(String::from),
    }
}

fn find_helper_bin() -> Option<std::path::PathBuf> {
    if let Some(bin) = std::env::var_os("SHIT_HELPER_BIN") {
        let p = std::path::PathBuf::from(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    for cand in [
        "/usr/local/bin/shit-helper",
        "/usr/local/libexec/shit-helper",
    ] {
        if Path::new(cand).is_file() {
            return Some(std::path::PathBuf::from(cand));
        }
    }
    // $PATH lookup.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join("shit-helper");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// Bound on how long the helper handshake probe is allowed to take.
/// If the helper hangs (rare; would indicate daemon-side bug), the
/// caller can use this to wall-clock the spawn.
#[allow(dead_code)]
pub const HELPER_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kqueue_functional_on_host() {
        // The host running this test is a BSD (cfg-gated), so the
        // probe should succeed. If it doesn't, kqueue itself is
        // broken on this kernel.
        assert!(kqueue_functional(), "kqueue probe failed on BSD host");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn capsicum_default_on_respects_env() {
        // SAFETY: process-wide; tests in this binary run serially per
        // module-level state to avoid env races. We snapshot+restore.
        let prev = std::env::var("SHIT_CAPSICUM").ok();
        unsafe { std::env::set_var("SHIT_CAPSICUM", "0") };
        assert!(
            !super::capsicum_default_on(true),
            "SHIT_CAPSICUM=0 must opt out"
        );
        unsafe { std::env::remove_var("SHIT_CAPSICUM") };
        assert!(
            super::capsicum_default_on(true),
            "default is on when env unset"
        );
        unsafe { std::env::set_var("SHIT_CAPSICUM", "1") };
        assert!(super::capsicum_default_on(true), "SHIT_CAPSICUM=1 stays on");
        match prev {
            Some(v) => unsafe { std::env::set_var("SHIT_CAPSICUM", v) },
            None => unsafe { std::env::remove_var("SHIT_CAPSICUM") },
        }
    }

    #[test]
    fn capsicum_default_on_false_when_unavailable() {
        assert!(!super::capsicum_default_on(false));
    }

    #[test]
    fn capsicum_available_on_freebsd() {
        assert!(capsicum_available(), "cap_getmode syscall absent");
    }

    #[test]
    fn runtime_capture_label_known() {
        let label = runtime_capture_label();
        assert!(
            matches!(
                label.as_str(),
                "kqueue+preload" | "kqueue-only" | "degraded"
            ),
            "unexpected label: {label}"
        );
    }

    #[test]
    fn find_helper_bin_via_env() {
        // Set a non-existent path; should return None.
        unsafe {
            std::env::set_var("SHIT_HELPER_BIN", "/definitely/not/a/real/path");
        }
        let result = find_helper_bin();
        unsafe {
            std::env::remove_var("SHIT_HELPER_BIN");
        }
        // Either None (path doesn't exist and no default install)
        // or Some from a real install on the test box — both are fine.
        // We only assert the function doesn't panic.
        let _ = result;
    }

    #[test]
    fn handshake_probe_no_daemon_reports_error() {
        // Point at a definitely-nonexistent socket. The helper
        // should fail to connect and we should get ok=false with
        // an error string. If the helper binary isn't installed
        // we get a different error — both are acceptable; we just
        // verify ok=false and no panic.
        let report = helper_handshake_probe(Path::new("/nonexistent/shit/sock"));
        assert!(!report.ok);
        assert!(report.error.is_some(), "expected error message");
    }
}
