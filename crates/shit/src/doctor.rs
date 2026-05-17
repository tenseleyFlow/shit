// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit doctor` — walk likely-to-matter mount points, print the
//! detected FS kind, the COW tier we'd pick, and any caveats.

use shit_capture::{CaptureOpts, CowTier, FsKind, detect_fs, supported_tiers, would_pick};
use std::path::{Path, PathBuf};

const CANDIDATE_PATHS: &[&str] = &["$HOME", "/etc", "/usr/local", "/opt", "/tmp", "/var/tmp"];

#[derive(Debug)]
struct Row {
    path: PathBuf,
    fs: FsKind,
    picked: Option<CowTier>,
    caveats: Vec<String>,
}

pub fn run() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    print_linux_kernel_tier();

    let mut rows: Vec<Row> = Vec::new();
    for raw in CANDIDATE_PATHS {
        let resolved = resolve_path(raw);
        let Some(path) = resolved else {
            continue;
        };
        if !path.exists() {
            continue;
        }
        let fs = detect_fs(&path).unwrap_or(FsKind::Other("unknown".into()));
        // Pick assuming same destination (the typical case for shit's
        // own blob store under $XDG_STATE_HOME).
        let picked = would_pick(&path, &path, CaptureOpts::default());
        let caveats = caveats_for(&fs, picked.as_ref());
        rows.push(Row {
            path,
            fs,
            picked,
            caveats,
        });
    }

    print_table(&rows);
    Ok(())
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

fn print_table(rows: &[Row]) {
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
    print_table(std::slice::from_ref(&row));
}
