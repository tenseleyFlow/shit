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
pub mod snippet;

use shit_capture::{CaptureOpts, CowTier, FsKind, detect_fs, supported_tiers, would_pick};
use std::path::{Path, PathBuf};

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
    target_os = "macos",
))]
use crate::doctor::json::HelperHandshakeReport;
use crate::doctor::json::{
    ArbitraryUndoCoverage, DoctorReport, HostInfo, MountReport, SCHEMA_VERSION,
};

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

/// AU08 — automatic remediation entry point (`shit doctor --fix`).
///
/// Today's scope is narrow: Linux helper file capabilities. The
/// existing report already computes a `setcap_remediation` string;
/// `--fix` attempts that string with `sudo -n`. On success, prints a
/// confirmation. On failure (no NOPASSWD, no sudo, non-Linux),
/// prints the manual command + a pointer to
/// `--emit-sudoers-snippet`. Exits non-zero when remediation is
/// needed but couldn't be applied; zero when nothing was wrong or
/// the apply succeeded.
///
/// Other platforms: no-op success today. AU07 (BSD shim default-on)
/// is expected to extend this with shim-install remediation.
pub fn run_fix() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        fix_linux_caps()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "shit doctor --fix: no auto-remediation is currently implemented for this platform"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn fix_linux_caps() -> anyhow::Result<()> {
    use std::process::Command;

    let caps = probes::linux::read_caps();
    // Distinguish "helper not findable" from "helper found with all
    // caps". Without this, an unresolvable helper produces the
    // misleading "caps satisfy the runtime requirement" message.
    if !caps.helper_binary.readable {
        eprintln!(
            "shit doctor --fix: helper binary not found on disk.\n  \
             Build it (`cargo build --release -p shit-helper`) or set\n  \
             SHIT_HELPER_BIN to the binary path before re-running."
        );
        anyhow::bail!("helper binary not found");
    }
    let Some(cmd_str) = caps.setcap_remediation.as_deref() else {
        println!("shit doctor --fix: helper caps already satisfy the runtime requirement.");
        return Ok(());
    };

    // The remediation string is shaped `sudo setcap <CAPS> <PATH>`.
    // For `--fix` we want a non-interactive variant: replace the
    // leading `sudo` with `sudo -n`. If the string ever changes
    // shape, fall back to printing it verbatim.
    let argv: Vec<&str> = cmd_str.split_whitespace().collect();
    if argv.first() != Some(&"sudo") || argv.len() < 4 {
        eprintln!("shit doctor --fix: unexpected remediation shape; run manually:");
        eprintln!("  {cmd_str}");
        anyhow::bail!("remediation shape unrecognized");
    }
    let rest = &argv[1..]; // setcap CAPS PATH

    if caps.helper_binary.caps_stale {
        eprintln!("shit doctor --fix: caps stripped by a rebuild since last apply.");
    } else {
        eprintln!("shit doctor --fix: helper caps missing; attempting setcap.");
    }
    eprintln!("  sudo -n {}", rest.join(" "));

    let status = Command::new("sudo").arg("-n").args(rest).status();
    match status {
        Ok(s) if s.success() => {
            println!("shit doctor --fix: caps applied successfully.");
            Ok(())
        }
        Ok(s) => {
            eprintln!(
                "shit doctor --fix: sudo -n exited {}; NOPASSWD likely not configured.",
                s.code().unwrap_or(-1)
            );
            eprintln!("  Run manually:");
            eprintln!("    {cmd_str}");
            eprintln!("  Or paste a NOPASSWD block once with:");
            eprintln!("    shit doctor --emit-sudoers-snippet           # generic sudoers");
            eprintln!("    shit doctor --emit-sudoers-snippet --target nixos  # NixOS");
            anyhow::bail!("setcap not applied")
        }
        Err(e) => {
            eprintln!("shit doctor --fix: failed to spawn sudo: {e}");
            eprintln!("  Run manually:");
            eprintln!("    {cmd_str}");
            anyhow::bail!("could not invoke sudo")
        }
    }
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
        linux: collect_linux(),
        macos: collect_macos(),
        mounts,
        arbitrary_undo_coverage: collect_arbitrary_undo_coverage(),
    };

    (rows, report)
}

/// AR07.3 — populate the `arbitrary_undo_coverage` block. The
/// `refused_classes` list is enumerated from the planner's
/// refuse-list catalog so it can never drift from the code.
/// `covered_classes` is a hand-curated inventory sourced from
/// the AR08.1 audit; future sprints may derive it programmatically
/// from per-class smoke status. `last_validated_at` is intentionally
/// empty here — CI writes a fresh snapshot when it stamps the
/// coverage matrix.
fn collect_arbitrary_undo_coverage() -> ArbitraryUndoCoverage {
    let refused_classes: Vec<String> = shit_planner::refuse::catalog_classes()
        .into_iter()
        .map(str::to_string)
        .collect();
    // The covered-classes list mirrors the AR08.1 audit's
    // 'covered + smoke' + 'covered, smoke-gap' entries grouped by
    // their tier-level identifier. Order is alphabetical-by-tier so
    // a diff against the AR08.1 doc is easy to eyeball.
    let covered_classes: Vec<String> = [
        "container-rm",       // AR03.1 / AR10.9 — docker/podman rm
        "container-rmi",      // AR03.2 — docker rmi
        "container-volume",   // AR03.3 — docker volume rm
        "container-network",  // AR03.4 — docker network rm
        "container-compose",  // AR03.6 — docker compose down
        "fs-content-restore", // kernel-tier FilePreImage → RestoreContent
        "fs-metadata",        // kernel-tier MetadataChange → RestoreMetadata
        "fs-rename",          // kernel-tier TreeOp::Rename → Rename
        "fs-tree",            // kernel-tier TreeOp Create/Unlink/Symlink
        "kubectl-delete",     // AR04.3
        "package-apt",        // AR02.1 / AR02.5
        "package-dnf",        // AR02.2
        "package-brew",       // DR-22
        "preload-install",    // AR05.1/.2/.3 — LD_PRELOAD shim install path
        "process-note",       // S18 — kill/pkill/killall informational
        "redirect-truncate",  // AR06.5 — shell redirect pre-stash
        "service-systemctl",  // S16
        "tool-gh",            // AR04.4 — gh release delete
        "tool-network",       // S17 — iptables/nft/ufw/ip
        "tool-terraform",     // AR04.1/.2
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let covered = covered_classes.len() as u32;
    let refused = refused_classes.len() as u32;
    let total = covered + refused;
    let coverage_pct = if total == 0 {
        0
    } else {
        ((covered as f64 / total as f64) * 100.0).round() as u32
    };
    ArbitraryUndoCoverage {
        covered_classes,
        refused_classes,
        coverage_pct,
        last_validated_at: String::new(),
    }
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

#[cfg(target_os = "linux")]
fn collect_linux() -> Option<json::LinuxReport> {
    use crate::doctor::probes::linux;

    let kernel_lsm_list = linux::read_kernel_lsm_list();
    let capabilities = linux::read_caps();
    let systemd_user_unit = linux::read_systemd_unit();
    let fanotify_functional = linux::fanotify_functional();
    let ebpf_lsm_functional = linux::ebpf_lsm_functional();

    // Stable tier label — picks the highest-functioning tier the
    // host can sustain. Matches the strings emitted by the helper's
    // `pick_linux_tier`.
    let runtime_capture = if ebpf_lsm_functional {
        "ebpf-lsm".to_string()
    } else if fanotify_functional {
        "fanotify-perm".to_string()
    } else {
        "degraded".to_string()
    };

    Some(json::LinuxReport {
        runtime_capture,
        fanotify_functional,
        ebpf_lsm_functional,
        capabilities,
        systemd_user_unit,
        kernel_lsm_list,
        helper_handshake: probe_helper_handshake(),
    })
}

#[cfg(not(target_os = "linux"))]
fn collect_linux() -> Option<json::LinuxReport> {
    None
}

#[cfg(target_os = "macos")]
fn collect_macos() -> Option<json::MacReport> {
    use crate::doctor::probes::macos;

    let fda = macos::probe_fda();
    let codesign = macos::probe_codesign_self();
    let sip = macos::probe_sip_state();
    let sandbox = macos::probe_sandbox_profile_loaded();
    let fsevents = macos::probe_fsevents_functional();
    let mut es = macos::probe_endpoint_security();
    // Mirror the FDA bool into the ES sub-report so the JSON shape
    // is consistent for consumers that only look at .macos.endpoint_security.
    es.fda_granted = matches!(fda, macos::FdaState::Granted);
    if matches!(fda, macos::FdaState::Indeterminate) {
        es.notes.push(
            "FDA indeterminate — Mail.app never used and TCC.db not readable; \
             grant Full Disk Access to confirm"
                .to_string(),
        );
    }

    // Stable tier label — fsevents-degraded baseline today. M03 will
    // flip to "endpoint-security" when entitlement_present +
    // fda_granted + client_can_subscribe all become true.
    let runtime_capture = if es.entitlement_present && es.fda_granted && es.client_can_subscribe {
        "endpoint-security".to_string()
    } else if fsevents.functional {
        "fsevents-degraded".to_string()
    } else {
        "degraded".to_string()
    };

    Some(json::MacReport {
        runtime_capture,
        endpoint_security: es,
        fsevents,
        codesign,
        sip,
        sandbox,
        helper_handshake: probe_helper_handshake(),
    })
}

#[cfg(not(target_os = "macos"))]
fn collect_macos() -> Option<json::MacReport> {
    None
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
    target_os = "macos",
))]
fn probe_helper_handshake() -> HelperHandshakeReport {
    use shit_proto::{CtlRequest, CtlResponse};

    let ctl_path = crate::paths::default_ctl_socket_path();
    let started = std::time::Instant::now();
    let resp = crate::cmd::ctl_client::call(&ctl_path, &CtlRequest::Metrics);
    let latency_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    match resp {
        Ok(CtlResponse::Metrics(m)) => {
            // B03.A — `helper_link_state` is the load-bearing
            // signal. `kernel_tier` is sticky-once-set, so a
            // crashed helper still leaves a non-empty tier and
            // would make `ok=true` lie. Fall back to the
            // tier-empty heuristic only when the daemon is so old
            // that `#[serde(default)]` left the state at
            // `NeverConnected` despite a populated `kernel_tier`.
            use shit_proto::HelperLinkState;
            let tier_empty = m.kernel_tier.is_empty();
            let (ok, error_msg) = match m.helper_link_state {
                HelperLinkState::Connected => (true, None),
                HelperLinkState::Disconnected => (
                    false,
                    Some(
                        "helper handshook then exited — capture coverage lost \
                         until the daemon restarts"
                            .into(),
                    ),
                ),
                HelperLinkState::NeverConnected => {
                    if tier_empty {
                        (
                            false,
                            Some("daemon reachable but helper handshake not completed".into()),
                        )
                    } else {
                        // Old-daemon compat: pre-B03.A daemons don't
                        // emit the state field. Trust kernel_tier.
                        (true, None)
                    }
                }
            };
            HelperHandshakeReport {
                ok,
                latency_ms,
                helper_version: None,
                kernel_tier: if tier_empty {
                    None
                } else {
                    Some(m.kernel_tier)
                },
                error: error_msg,
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
fn render_table(rows: &[Row], report: &DoctorReport) {
    #[cfg(target_os = "linux")]
    if let Some(linux) = report.linux.as_ref() {
        print_linux_kernel_tier(linux);
    }
    // Silence the unused-variable warning on hosts without a
    // per-OS table renderer.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "macos",
    )))]
    let _ = report;
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    if let Some(bsd) = report.bsd.as_ref() {
        print_bsd_tier(bsd);
    }
    #[cfg(target_os = "macos")]
    if let Some(mac) = report.macos.as_ref() {
        print_macos_tier(mac);
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
fn print_linux_kernel_tier(linux: &json::LinuxReport) {
    let ok = |b: bool| if b { "✓" } else { "✗" };

    match shit_capture::linux_kernel::probe() {
        Ok((version, features)) => {
            println!("kernel:   {version}  ({})", features.tier_label());
        }
        Err(e) => {
            println!("kernel:   probe failed ({e})");
        }
    }

    println!("tier:     {}", linux.runtime_capture);
    println!(
        "fanotify: {}  ebpf-lsm: {}",
        ok(linux.fanotify_functional),
        ok(linux.ebpf_lsm_functional)
    );

    // Caps — helper binary on disk vs caller's effective.
    let h = &linux.capabilities.helper_binary;
    if h.readable {
        println!(
            "helper-caps: cap_sys_admin={} cap_bpf={} cap_perfmon={}",
            ok(h.cap_sys_admin),
            ok(h.cap_bpf),
            ok(h.cap_perfmon)
        );
    } else {
        println!(
            "helper-caps: ? (helper binary not found via SHIT_HELPER_BIN, FHS paths, or $PATH)"
        );
    }
    let c = &linux.capabilities.caller_effective;
    println!(
        "caller-caps: cap_sys_admin={} cap_bpf={} cap_perfmon={}",
        ok(c.cap_sys_admin),
        ok(c.cap_bpf),
        ok(c.cap_perfmon)
    );

    // LSM active list.
    if linux.kernel_lsm_list.is_empty() {
        println!("active-lsms: (unreadable; /sys/kernel/security/lsm missing)");
    } else {
        println!("active-lsms: {}", linux.kernel_lsm_list.join(","));
    }

    // systemd user unit.
    let u = &linux.systemd_user_unit;
    if !u.user_manager_reachable {
        println!("shit.service (user): manager unreachable (XDG_RUNTIME_DIR unset?)");
    } else {
        println!(
            "shit.service (user): present={} active={} enabled={}",
            ok(u.user_unit_present),
            ok(u.user_unit_active),
            ok(u.user_unit_enabled)
        );
    }

    // Remediation hints.
    if let Some(setcap) = &linux.capabilities.setcap_remediation {
        println!();
        println!("To grant helper caps:");
        println!("  {setcap}");
    }
    let bpf = shit_capture::linux_kernel::probe_bpf_lsm();
    if let Some(hint) = bpf.cmdline_remediation_hint() {
        println!();
        println!("To enable BPF-LSM:");
        for line in hint.lines() {
            println!("  {line}");
        }
    }
    if u.user_manager_reachable && !u.user_unit_active {
        println!();
        println!("To activate the daemon user unit:");
        println!("  systemctl --user start shit.service");
        if !u.user_unit_enabled {
            println!("  systemctl --user enable shit.service");
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

#[cfg(target_os = "macos")]
fn print_macos_tier(mac: &json::MacReport) {
    println!("os:       macos ({})", std::env::consts::ARCH);
    println!("tier:     {}", mac.runtime_capture);
    if mac.runtime_capture == "fsevents-degraded" {
        // Per M02 DoD: warn loudly when degraded.
        println!(
            "          WARN: running in degraded mode — no pre-image capture. \
             Full ES coverage gated on Apple paperwork (see \
             .docs/audits/apple-entitlement.md)."
        );
    }
    println!(
        "es:       entitlement={}  fda={}  can_subscribe={}",
        if mac.endpoint_security.entitlement_present {
            "yes"
        } else {
            "no"
        },
        if mac.endpoint_security.fda_granted {
            "yes"
        } else {
            "no"
        },
        if mac.endpoint_security.client_can_subscribe {
            "yes"
        } else {
            "no"
        },
    );
    for note in &mac.endpoint_security.notes {
        println!("          {note}");
    }
    if !mac.endpoint_security.entitlement_present {
        println!(
            "          remediation: install the notarized release build, OR \
             boot a SIP-disabled dev VM and use an ad-hoc-signed helper for \
             pre-image capture (see M03 in .docs/sprints/macos/)."
        );
    } else if !mac.endpoint_security.fda_granted {
        println!(
            "          remediation: System Settings → Privacy & Security → \
             Full Disk Access → drag `shit-helper` in."
        );
        println!(
            "          open: x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
        );
    }
    println!(
        "fsevents: {}",
        if mac.fsevents.functional {
            format!(
                "functional ({} ms first-event latency)",
                mac.fsevents.latency_probe_ms
            )
        } else {
            "FAILED".to_string()
        }
    );
    print!("codesign: {}", mac.codesign.signature_kind);
    if let Some(team_id) = &mac.codesign.team_id {
        print!(" team_id={team_id}");
    }
    if mac.codesign.notarized {
        print!(" notarized");
    }
    if mac.codesign.stapled {
        print!(" stapled");
    }
    println!();
    if mac.codesign.signature_kind == "unsigned" {
        println!(
            "          remediation: `make dev-sign` (ad-hoc sign for local dev), \
             OR `brew install shit` for a notarized release build."
        );
    }
    println!("sip:      {}", mac.sip.state);
    println!(
        "sandbox:  {}",
        if mac.sandbox.profile_loaded {
            "loaded (doctor caller sandboxed)"
        } else {
            "not loaded (doctor caller is the shit CLI — unsandboxed by design; \
             helper-side check is M02 follow-up via handshake-probe)"
        }
    );
    print_helper_handshake(&mac.helper_handshake);
    println!();
}

#[cfg(target_os = "macos")]
fn print_helper_handshake(h: &json::HelperHandshakeReport) {
    print!("helper:   ");
    if h.ok {
        println!(
            "ok ({} ms, tier={})",
            h.latency_ms,
            h.kernel_tier.as_deref().unwrap_or("?"),
        );
    } else {
        println!(
            "FAILED: {}",
            h.error.as_deref().unwrap_or("(no error message)")
        );
    }
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
