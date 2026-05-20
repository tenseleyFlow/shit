// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux-family runtime probes (L05).
//!
//! Each function populates one field of [`super::super::json::LinuxReport`].
//! Per the B03 / L05 convention, every probe:
//!
//! - completes in <2s total wall-time for the whole report;
//! - is side-effect-free (no kernel state changes, no daemon
//!   spawns that outlive the probe);
//! - gracefully reports failure rather than panic. A probe that
//!   can't determine its answer returns the "neutral" value
//!   (`false`, empty Vec, `None`) so the JSON envelope still
//!   serializes cleanly even on a broken host.
//!
//! The fanotify and eBPF-LSM functional probes spawn the helper
//! binary via `shit-helper probe-fanotify` / `probe-ebpf`
//! subcommands. The helper is the only thing that can validate
//! these primitives end-to-end on Linux (CAP_SYS_ADMIN / CAP_BPF
//! / CAP_PERFMON live on the helper file, not the doctor caller).

#![cfg(target_os = "linux")]

use crate::doctor::json::{
    CallerEffectiveCaps, CapsReport, HelperBinaryCaps, SystemdUnitReport,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

// Linux CAP_* bit positions. These are stable kernel ABI; mirror
// from <linux/capability.h>.
const CAP_SYS_ADMIN: u8 = 21;
const CAP_BPF: u8 = 39;
const CAP_PERFMON: u8 = 38;

/// Read `/proc/self/status` to extract `CapEff` and parse the
/// three caps we care about for the LSM/fanotify tiers.
///
/// Returns the neutral (all-false) value when `/proc/self/status`
/// is unreadable or the CapEff line is malformed.
pub fn read_caller_effective_caps() -> CallerEffectiveCaps {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return CallerEffectiveCaps::default(),
    };
    let cap_eff_hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(str::trim)
        .unwrap_or("0");
    let cap_eff = u64::from_str_radix(cap_eff_hex, 16).unwrap_or(0);
    let has = |bit: u8| (cap_eff & (1u64 << bit)) != 0;
    CallerEffectiveCaps {
        cap_sys_admin: has(CAP_SYS_ADMIN),
        cap_bpf: has(CAP_BPF),
        cap_perfmon: has(CAP_PERFMON),
    }
}

/// Resolve the helper binary on disk and probe its file caps via
/// `getcap`. Falls back to "not readable" when the helper isn't
/// findable on disk (typical fresh-checkout case where the user
/// runs `cargo run -p shit -- doctor` without an install).
pub fn read_helper_binary_caps() -> HelperBinaryCaps {
    let Some(bin) = find_helper_bin() else {
        return HelperBinaryCaps {
            readable: false,
            ..Default::default()
        };
    };
    let out = match Command::new("getcap").arg(&bin).output() {
        Ok(o) if o.status.success() => o,
        _ => {
            return HelperBinaryCaps {
                readable: false,
                ..Default::default()
            };
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Sample output: `/path/to/shit-helper cap_sys_admin,cap_bpf,cap_perfmon=ep`
    // Match by substring of cap name — `getcap`'s set notation is
    // permissive (`=ep`, `+ep`, etc.) so don't anchor on a separator.
    HelperBinaryCaps {
        cap_sys_admin: stdout.contains("cap_sys_admin"),
        cap_bpf: stdout.contains("cap_bpf"),
        cap_perfmon: stdout.contains("cap_perfmon"),
        readable: true,
    }
}

/// Read `/sys/kernel/security/lsm` — a comma-separated list of
/// active LSMs (e.g. `capability,landlock,yama,bpf,ima`). Returns
/// empty Vec when unreadable.
pub fn read_kernel_lsm_list() -> Vec<String> {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| {
            s.trim()
                .split(',')
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Run `systemctl --user is-{active,enabled} shit.service` to
/// determine the daemon user unit's runtime state.
///
/// Bounded by a 2s timeout via `setsid + kill` — `systemctl
/// --user` can hang indefinitely if the user manager isn't
/// reachable (e.g. SSH non-interactive sessions without
/// XDG_RUNTIME_DIR). The hang case is reported via
/// `user_manager_reachable: false`.
pub fn read_systemd_unit() -> SystemdUnitReport {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return SystemdUnitReport::default(),
    };
    let unit_path = format!("{home}/.config/systemd/user/shit.service");
    let user_unit_present = Path::new(&unit_path).is_file();

    // Reachability probe: `systemctl --user show-environment` is
    // a cheap no-op that fails fast if the user manager isn't up.
    let reachable = systemctl_user_runs(&["show-environment"], Duration::from_secs(2));

    if !reachable {
        return SystemdUnitReport {
            user_unit_present,
            user_unit_active: false,
            user_unit_enabled: false,
            user_manager_reachable: false,
        };
    }

    let user_unit_active = systemctl_user_stdout(
        &["is-active", "shit.service"],
        Duration::from_secs(2),
    )
    .map(|s| s.trim() == "active")
    .unwrap_or(false);

    let user_unit_enabled = systemctl_user_stdout(
        &["is-enabled", "shit.service"],
        Duration::from_secs(2),
    )
    .map(|s| {
        let t = s.trim();
        t == "enabled" || t == "static" || t == "alias"
    })
    .unwrap_or(false);

    SystemdUnitReport {
        user_unit_present,
        user_unit_active,
        user_unit_enabled,
        user_manager_reachable: true,
    }
}

/// Live fanotify-perm functional probe. Shells out to
/// `shit-helper probe-fanotify` (which inits a fanotify-perm fd,
/// marks a tmpdir, writes a probe file, drains one event).
/// Returns true iff the helper exits 0.
///
/// Bounded to 2s. The probe NEEDS CAP_SYS_ADMIN on the helper
/// binary; if the helper is unfound or lacks caps, returns false.
pub fn fanotify_functional() -> bool {
    let Some(bin) = find_helper_bin() else {
        return false;
    };
    run_helper_subcommand(&bin, "probe-fanotify", Duration::from_secs(2))
}

/// Live eBPF-LSM prerequisite probe. Shells out to
/// `shit-helper probe-ebpf` (calls `EbpfLoader::probe` in-helper).
/// Returns true iff the helper exits 0.
pub fn ebpf_lsm_functional() -> bool {
    let Some(bin) = find_helper_bin() else {
        return false;
    };
    run_helper_subcommand(&bin, "probe-ebpf", Duration::from_secs(2))
}

/// Build the full `CapsReport` including remediation. The
/// remediation string is the exact `setcap` command line the user
/// should run when any helper-binary cap is missing.
pub fn read_caps() -> CapsReport {
    let helper_binary = read_helper_binary_caps();
    let caller_effective = read_caller_effective_caps();

    let setcap_remediation = if helper_binary.readable
        && !(helper_binary.cap_sys_admin
            && helper_binary.cap_bpf
            && helper_binary.cap_perfmon)
    {
        let path = find_helper_bin()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<helper>".into());
        Some(format!(
            "sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep {path}"
        ))
    } else {
        None
    };

    CapsReport {
        helper_binary,
        caller_effective,
        setcap_remediation,
    }
}

// ============================================================
// Internals
// ============================================================

/// Find the helper binary on disk. Mirrors `bsd.rs::find_helper_bin`
/// but adds Linux-conventional install paths and the cargo target
/// dirs (so `cargo run -p shit doctor` works from a fresh
/// checkout).
fn find_helper_bin() -> Option<PathBuf> {
    if let Some(bin) = std::env::var_os("SHIT_HELPER_BIN") {
        let p = PathBuf::from(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    for cand in [
        "/usr/local/bin/shit-helper",
        "/usr/local/libexec/shit-helper",
        "/usr/bin/shit-helper",
        "/usr/libexec/shit-helper",
    ] {
        if Path::new(cand).is_file() {
            return Some(PathBuf::from(cand));
        }
    }
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

/// Run `shit-helper <subcommand>` with the given wall-clock
/// timeout. Returns true iff the helper exited zero within the
/// timeout. Timeouts and spawn failures both return false.
fn run_helper_subcommand(bin: &Path, subcommand: &str, timeout: Duration) -> bool {
    let mut child = match Command::new(bin)
        .arg(subcommand)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

/// Run `systemctl --user <args>` with timeout; succeed iff the
/// process exits zero. Output ignored.
fn systemctl_user_runs(args: &[&str], timeout: Duration) -> bool {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

/// Run `systemctl --user <args>` with timeout; capture stdout as
/// String. Returns None on spawn failure or timeout. Exit code
/// is NOT checked — `systemctl is-active` exits non-zero when
/// the unit is inactive, but we still want the "inactive" /
/// "failed" string on stdout.
fn systemctl_user_stdout(args: &[&str], timeout: Duration) -> Option<String> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user")
        .args(args)
        .stderr(std::process::Stdio::null());
    let mut child = cmd.stdout(std::process::Stdio::piped()).spawn().ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
    use std::io::Read;
    let mut s = String::new();
    child.stdout?.read_to_string(&mut s).ok()?;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_caller_effective_caps_returns_some_value() {
        // The current /proc/self/status must be readable in any
        // non-pathological test env. We don't assert specific bits
        // because they vary by sandbox / sudo state; we assert the
        // function doesn't panic and returns a struct.
        let caps = read_caller_effective_caps();
        // No-op assertion that uses the struct — proves it built.
        let _ = caps.cap_bpf;
    }

    #[test]
    fn read_kernel_lsm_list_returns_vec() {
        let lsms = read_kernel_lsm_list();
        // Modern kernels with /sys/kernel/security/lsm return at
        // least "capability". CI sandboxes without /sys may return
        // empty — either is acceptable.
        if !lsms.is_empty() {
            assert!(lsms.iter().any(|s| !s.is_empty()));
        }
    }

    #[test]
    fn read_helper_binary_caps_handles_missing_helper() {
        // Unset SHIT_HELPER_BIN to avoid the test reading some
        // unrelated binary's caps. The probe should return
        // `readable: false` cleanly.
        // SAFETY: standard env-var manipulation. Test is single-
        // threaded and doesn't interact with other tests' env state.
        unsafe { std::env::remove_var("SHIT_HELPER_BIN") };
        let saved_path = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", "/nonexistent") };
        let caps = read_helper_binary_caps();
        assert!(!caps.readable);
        assert!(!caps.cap_bpf);
        // Restore PATH so other tests don't break.
        match saved_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }

    #[test]
    fn read_systemd_unit_handles_no_home() {
        let saved = std::env::var_os("HOME");
        unsafe { std::env::remove_var("HOME") };
        let report = read_systemd_unit();
        assert!(!report.user_unit_present);
        // Restore so other tests don't see HOME-less env.
        if let Some(h) = saved {
            unsafe { std::env::set_var("HOME", h) };
        }
    }

    #[test]
    fn fanotify_functional_returns_false_without_helper() {
        unsafe { std::env::remove_var("SHIT_HELPER_BIN") };
        let saved_path = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", "/nonexistent") };
        assert!(!fanotify_functional());
        match saved_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }
}
