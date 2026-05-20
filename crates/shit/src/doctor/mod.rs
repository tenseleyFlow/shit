// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit doctor` — walk likely-to-matter mount points, run runtime
//! probes against the host's kernel + helper, and report.
//!
//! ## Output modes
//!
//! - Default: human-readable table (the long-standing behavior;
//!   preserved byte-for-byte for the BSD path so CI doesn't notice
//!   the refactor).
//! - `--json`: machine-readable [`json::DoctorReport`] for CI gates
//!   and external tooling consumption (B03). Schema is versioned;
//!   see [`json::SCHEMA_VERSION`] and `.docs/audits/doctor-json-schema.md`.
//!
//! The two modes are produced from the same [`json::DoctorReport`]
//! struct so the human and machine outputs always agree.

pub mod json;
pub mod probes;

use shit_capture::{CaptureOpts, CowTier, FsKind, detect_fs, supported_tiers, would_pick};
use std::path::{Path, PathBuf};

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
use crate::doctor::json::HelperHandshakeReport;
use crate::doctor::json::{DoctorReport, HostInfo, MountReport, SCHEMA_VERSION};

const CANDIDATE_PATHS: &[&str] = &["$HOME", "/etc", "/usr/local", "/opt", "/tmp", "/var/tmp"];

#[derive(Debug)]
struct Row {
    path: PathBuf,
    fs: FsKind,
    picked: Option<CowTier>,
    caveats: Vec<String>,
}

/// Top-level entry. `json=true` emits the serialized envelope on
/// stdout; `json=false` preserves the long-standing human table.
pub fn run(json: bool) -> anyhow::Result<()> {
    let (rows, report) = collect();
    if json {
        let s = serde_json::to_string_pretty(&report)?;
        println!("{s}");
    } else {
        render_table(&rows, &report);
    }
    Ok(())
}

/// Build the full report. Side-effect-free except for the probes
/// in [`probes::bsd`] (which do small kqueue + sysctl + subprocess
/// I/O — all documented to be <2s total).
fn collect() -> (Vec<Row>, DoctorReport) {
    let mut rows: Vec<Row> = Vec::new();
    for raw in CANDIDATE_PATHS {
        let resolved = resolve_path(raw);
        let Some(path) = resolved else { continue };
        if !path.exists() {
            continue;
        }
        let fs = detect_fs(&path).unwrap_or(FsKind::Other("unknown".into()));
        let picked = would_pick(&path, &path, CaptureOpts::default());
        let caveats = caveats_for(&fs, picked.as_ref());
        rows.push(Row {
            path,
            fs,
            picked,
            caveats,
        });
    }

    let mounts: Vec<MountReport> = rows
        .iter()
        .map(|r| MountReport {
            path: r.path.display().to_string(),
            fs_kind: r.fs.as_str().to_string(),
            picked_cow_tier: r.picked.map(|t| t.as_str().to_string()),
            caveats: r.caveats.clone(),
        })
        .collect();

    let report = DoctorReport {
        schema_version: SCHEMA_VERSION,
        host: host_info(),
        bsd: collect_bsd(),
        linux: None,
        macos: None,
        mounts,
    };

    (rows, report)
}

fn host_info() -> HostInfo {
    HostInfo {
        os: std::env::consts::OS.to_string(),
        os_release: read_os_release(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

/// Best-effort kernel/OS release string. Linux: kernel release via
/// `uname -r`. BSD: `uname -r` equivalent. macOS: Darwin version.
/// Returns empty string when `uname(3)` fails (extremely rare).
fn read_os_release() -> String {
    // SAFETY: uname() takes a pointer to a buffer it fills in;
    // libc::utsname is zeroable.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::uname(&mut u) };
    if r != 0 {
        return String::new();
    }
    // SAFETY: the kernel guarantees release is NUL-terminated.
    let cstr = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) };
    cstr.to_string_lossy().into_owned()
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn collect_bsd() -> Option<json::BsdReport> {
    use crate::doctor::probes::bsd;

    let cap_available = bsd::capsicum_available();
    let cap_default_on = bsd::capsicum_default_on(cap_available);
    Some(json::BsdReport {
        runtime_capture: bsd::runtime_capture_label(),
        kqueue_functional: bsd::kqueue_functional(),
        capsicum_available: cap_available,
        capsicum_default_on: cap_default_on,
        zfs_datasets: bsd::zfs_datasets(),
        helper_handshake: probe_helper_handshake(),
        preload_shim_installed: bsd::preload_shim_installed(),
    })
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
)))]
fn collect_bsd() -> Option<json::BsdReport> {
    None
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn probe_helper_handshake() -> HelperHandshakeReport {
    use shit_proto::{CtlRequest, CtlResponse};

    let ctl_path = crate::paths::default_ctl_socket_path();
    let started = std::time::Instant::now();
    let resp = crate::cmd::ctl_client::call(&ctl_path, &CtlRequest::Metrics);
    let latency_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    match resp {
        Ok(CtlResponse::Metrics(m)) => {
            let tier_empty = m.kernel_tier.is_empty();
            HelperHandshakeReport {
                ok: !tier_empty,
                latency_ms,
                helper_version: None,
                kernel_tier: if tier_empty {
                    None
                } else {
                    Some(m.kernel_tier)
                },
                error: if tier_empty {
                    Some(
                        "daemon reachable but kernel_tier empty — helper handshake not completed"
                            .into(),
                    )
                } else {
                    None
                },
            }
        }
        Ok(other) => HelperHandshakeReport {
            ok: false,
            latency_ms,
            helper_version: None,
            kernel_tier: None,
            error: Some(format!("unexpected ctl response: {other:?}")),
        },
        Err(e) => HelperHandshakeReport {
            ok: false,
            latency_ms,
            helper_version: None,
            kernel_tier: None,
            error: Some(e.to_string()),
        },
    }
}

/// Render the table-mode output. Designed to match the pre-B03
/// byte stream for the BSD / Linux per-platform sections so the
/// table-mode UX doesn't regress.
fn render_table(rows: &[Row], _report: &DoctorReport) {
    #[cfg(target_os = "linux")]
    print_linux_kernel_tier();
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    if let Some(bsd) = _report.bsd.as_ref() {
        print_bsd_tier(bsd);
    }
    print_mount_table(rows);
}

fn resolve_path(raw: &str) -> Option<PathBuf> {
    if raw == "$HOME" {
        std::env::var_os("HOME").map(PathBuf::from)
    } else {
        Some(PathBuf::from(raw))
    }
}

fn caveats_for(fs: &FsKind, picked: Option<&CowTier>) -> Vec<String> {
    let mut out = Vec::new();
    if fs.is_synthetic() {
        out.push("synthetic fs — capture refused, hard-fail".to_string());
    }
    if fs.is_network() {
        out.push("network fs — capture pays per-read RTT; default streaming only".to_string());
    }
    match (fs, picked) {
        (FsKind::Xfs, Some(CowTier::Reflink)) => {
            out.push("XFS: reflink requires the volume to have been made with reflink=1; if FICLONE returns EOPNOTSUPP at runtime we fall through to copy_file_range".to_string());
        }
        (FsKind::Zfs, _) => {
            out.push("ZFS: per-file zfs clone is not used in v1 (snapshot-granularity only); see snapper-style integration in a later sprint".to_string());
        }
        (FsKind::Overlayfs, _) => {
            out.push("overlayfs (likely a container): tier detection is best-effort; streaming fallback always works".to_string());
        }
        _ => {}
    }
    if !supported_tiers(fs).is_empty() && picked.is_none() {
        out.push("no viable tier for this fs (hard-fail when default-on)".to_string());
    }
    out
}

fn print_mount_table(rows: &[Row]) {
    println!("{:<22}  {:<10}  {:<16}  caveats", "path", "fs", "tier");
    println!("{}", "-".repeat(72));
    for r in rows {
        let tier = r.picked.map(|t| t.as_str()).unwrap_or("<none>");
        println!(
            "{:<22}  {:<10}  {:<16}  {}",
            truncate(&r.path.display().to_string(), 22),
            r.fs.as_str(),
            tier,
            r.caveats.join("; ")
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let cut = max.saturating_sub(1);
        let mut t = String::with_capacity(max);
        t.push_str(&s[..cut]);
        t.push('…');
        t
    }
}

#[cfg(target_os = "linux")]
fn print_linux_kernel_tier() {
    match shit_capture::linux_kernel::probe() {
        Ok((version, features)) => {
            println!("kernel:   {version}  ({})", features.tier_label());
        }
        Err(e) => {
            println!("kernel:   probe failed ({e})");
        }
    }

    let bpf = shit_capture::linux_kernel::probe_bpf_lsm();
    println!("bpf-lsm:  {}", bpf.diagnose());
    println!(
        "  btf={}  active-lsm-includes-bpf={}  CONFIG_BPF_LSM={}",
        bpf.btf_available,
        bpf.bpf_in_active_lsm,
        match bpf.config_bpf_lsm {
            Some(true) => "y",
            Some(false) => "n",
            None => "unknown",
        }
    );
    if let Some(hint) = bpf.cmdline_remediation_hint() {
        println!();
        println!("To enable BPF-LSM:");
        for line in hint.lines() {
            println!("  {line}");
        }
    }
    println!();
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn print_bsd_tier(bsd: &json::BsdReport) {
    let probe = shit_capture::bsd_probe::probe_bsd();
    println!(
        "os:       {} ({})",
        probe.family.label(),
        if probe.family.is_primary() {
            "primary"
        } else {
            "best-effort"
        }
    );
    println!("kqueue:   {}", kqueue_features_line(&probe.kqueue));
    println!(
        "kqueue-functional: {}",
        if bsd.kqueue_functional { "yes" } else { "NO" }
    );
    println!(
        "capsicum: {}",
        match (bsd.capsicum_available, bsd.capsicum_default_on) {
            (true, true) => "syscall available; helper enters by default",
            (true, false) => "syscall available; SHIT_CAPSICUM=0 disables helper sandbox",
            (false, _) => "not available",
        }
    );
    print!("zfs:      ");
    if bsd.zfs_datasets.is_empty() && !probe.zfs.binary_present {
        println!("not installed");
    } else if bsd.zfs_datasets.is_empty() {
        println!("binary present, no datasets enumerated");
    } else {
        println!(
            "{} dataset(s): {}",
            bsd.zfs_datasets.len(),
            bsd.zfs_datasets.join(", ")
        );
    }
    println!(
        "preload:  {}",
        if bsd.preload_shim_installed {
            "installed at /usr/local/lib/shit/libshit_preload.so"
        } else {
            "not installed — kqueue-only coverage; see `shit hooks install`"
        }
    );
    print!("helper:   ");
    if bsd.helper_handshake.ok {
        println!(
            "ok ({} ms, {})",
            bsd.helper_handshake.latency_ms,
            bsd.helper_handshake
                .helper_version
                .as_deref()
                .unwrap_or("version unknown"),
        );
    } else {
        println!(
            "FAILED: {}",
            bsd.helper_handshake
                .error
                .as_deref()
                .unwrap_or("(no error message)")
        );
    }
    println!();
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn kqueue_features_line(k: &shit_capture::bsd_probe::KqueueFeatures) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if k.evfilt_vnode {
        parts.push("vnode");
    }
    if k.evfilt_proc {
        parts.push("proc");
    }
    if k.note_exec {
        parts.push("note_exec");
    }
    if k.note_truncate {
        parts.push("note_truncate");
    }
    parts.join(" + ")
}

/// Walk a path and print the doctor row for it. Useful from tests.
#[allow(dead_code)]
pub fn print_row(path: &Path) {
    let fs = detect_fs(path).unwrap_or(FsKind::Other("unknown".into()));
    let picked = would_pick(path, path, CaptureOpts::default());
    let row = Row {
        path: path.to_path_buf(),
        fs: fs.clone(),
        picked,
        caveats: caveats_for(&fs, picked.as_ref()),
    };
    print_mount_table(std::slice::from_ref(&row));
}
