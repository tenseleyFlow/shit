// SPDX-License-Identifier: AGPL-3.0-or-later

//! BSD OS-family + ZFS feature probe (S10 stage 1).
//!
//! Unlike Linux where the kernel version unlocks fanotify tiers, BSD
//! has roughly two axes:
//!
//! 1. **OS family** — FreeBSD (primary), NetBSD, OpenBSD, DragonFly
//!    (best-effort). Identified at compile time via `cfg(target_os)`;
//!    there is no runtime "which BSD am I?" probe needed.
//! 2. **Storage substrate** — ZFS or UFS / FFS / etc. ZFS unlocks
//!    snapshot-based coarse capture which is dramatically cheaper than
//!    the kqueue + LD_PRELOAD path. Detected at runtime by shelling
//!    out to `zfs(8)` because that's the boundary between OS and pool.
//!
//! Strategy mirrors `linux_kernel.rs`: a struct describing what we
//! found, plus `diagnose()` for `shit doctor` to render.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::path::Path;
use std::process::Command;

/// Which BSD we built for. Determined at compile time — no runtime
/// detection needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsdFamily {
    FreeBsd,
    NetBsd,
    OpenBsd,
    DragonFly,
}

impl BsdFamily {
    pub const CURRENT: BsdFamily = {
        #[cfg(target_os = "freebsd")]
        {
            BsdFamily::FreeBsd
        }
        #[cfg(target_os = "netbsd")]
        {
            BsdFamily::NetBsd
        }
        #[cfg(target_os = "openbsd")]
        {
            BsdFamily::OpenBsd
        }
        #[cfg(target_os = "dragonfly")]
        {
            BsdFamily::DragonFly
        }
    };

    pub fn label(&self) -> &'static str {
        match self {
            BsdFamily::FreeBsd => "freebsd",
            BsdFamily::NetBsd => "netbsd",
            BsdFamily::OpenBsd => "openbsd",
            BsdFamily::DragonFly => "dragonfly",
        }
    }

    /// True when this BSD is the primary-supported target. NetBSD /
    /// OpenBSD / DragonFly compile but don't get the same level of
    /// integration testing.
    pub fn is_primary(&self) -> bool {
        matches!(self, BsdFamily::FreeBsd)
    }
}

/// What kqueue notes/filters this BSD exposes. The relevant subset:
/// EVFILT_VNODE (file events) and EVFILT_PROC (process lifecycle).
/// Both exist on all four BSDs but the set of NOTE_* sub-flags
/// differs — most notably OpenBSD doesn't have NOTE_EXEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KqueueFeatures {
    pub evfilt_vnode: bool,
    pub evfilt_proc: bool,
    /// NOTE_EXEC delivered via EVFILT_PROC. Absent on OpenBSD.
    pub note_exec: bool,
    /// NOTE_TRUNCATE delivered via EVFILT_VNODE. Absent on OpenBSD.
    pub note_truncate: bool,
}

impl KqueueFeatures {
    /// What the *built* binary can expect at runtime, based on the
    /// compile-time BSD family. No kernel-runtime probe needed —
    /// these flags are baked into the kernel's syscall ABI.
    pub fn for_family(f: BsdFamily) -> Self {
        match f {
            BsdFamily::FreeBsd | BsdFamily::DragonFly => Self {
                evfilt_vnode: true,
                evfilt_proc: true,
                note_exec: true,
                note_truncate: true,
            },
            BsdFamily::NetBsd => Self {
                evfilt_vnode: true,
                evfilt_proc: true,
                note_exec: true,
                note_truncate: true,
            },
            BsdFamily::OpenBsd => Self {
                evfilt_vnode: true,
                evfilt_proc: true,
                note_exec: false,
                note_truncate: false,
            },
        }
    }
}

/// Result of probing for ZFS. ZFS dramatically improves the BSD
/// capture story by replacing per-file capture with constant-time
/// dataset snapshots, so it's the recommended setup on FreeBSD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsProbe {
    /// `zfs(8)` is on `$PATH`. Doesn't guarantee a pool exists.
    pub binary_present: bool,
    /// Best-effort count of imported pools. None when we couldn't
    /// run `zpool list` (no binary, perm denied, etc.).
    pub pool_count: Option<u32>,
    /// `zfs --version` output, trimmed. None when we couldn't run it.
    pub version: Option<String>,
}

impl ZfsProbe {
    /// All-negative probe — used when the syscalls in this module
    /// are unavailable or we're running unprivileged in a test.
    pub const fn none() -> Self {
        Self {
            binary_present: false,
            pool_count: None,
            version: None,
        }
    }

    /// True when ZFS is a viable storage tier (binary present AND
    /// at least one pool imported).
    pub fn usable(&self) -> bool {
        self.binary_present && self.pool_count.unwrap_or(0) > 0
    }
}

/// Aggregate BSD probe — the single thing the helper queries at
/// startup. Cheap; safe to call from any context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsdProbe {
    pub family: BsdFamily,
    pub kqueue: KqueueFeatures,
    pub zfs: ZfsProbe,
}

impl BsdProbe {
    /// Render a one-line diagnosis for `shit doctor`.
    pub fn diagnose(&self) -> String {
        let zfs_bit = if self.zfs.usable() {
            format!(
                "zfs (pools={})",
                self.zfs.pool_count.unwrap_or(0)
            )
        } else if self.zfs.binary_present {
            "zfs binary present, no pools".to_string()
        } else {
            "no zfs".to_string()
        };
        format!(
            "{} kqueue (vnode+proc{}); {}",
            self.family.label(),
            if self.kqueue.note_exec { "+exec" } else { "" },
            zfs_bit,
        )
    }
}

/// Probe entry point.
pub fn probe_bsd() -> BsdProbe {
    let family = BsdFamily::CURRENT;
    BsdProbe {
        family,
        kqueue: KqueueFeatures::for_family(family),
        zfs: probe_zfs(),
    }
}

/// Shell-out probe for ZFS availability. We deliberately do this via
/// `zfs(8)` rather than `libzfs` because libzfs's ABI changes across
/// OpenZFS versions and we don't want to pin against any specific one
/// just to find out whether it exists.
pub fn probe_zfs() -> ZfsProbe {
    let binary_present = which_zfs().is_some();
    if !binary_present {
        return ZfsProbe::none();
    }
    ZfsProbe {
        binary_present: true,
        pool_count: count_pools(),
        version: read_zfs_version(),
    }
}

/// Pure helper: is there a `zfs` binary on `$PATH`?
fn which_zfs() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("zfs");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn count_pools() -> Option<u32> {
    let out = Command::new("zpool").args(["list", "-H", "-o", "name"]).output().ok()?;
    if !out.status.success() {
        return Some(0);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Some(s.lines().filter(|l| !l.trim().is_empty()).count() as u32)
}

fn read_zfs_version() -> Option<String> {
    let out = Command::new("zfs").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|s| s.trim().to_string())?;
    if v.is_empty() { None } else { Some(v) }
}

/// Resolve a path to its containing ZFS dataset, by walking up the
/// path until `zfs list -H -o name <path>` succeeds. Returns None on
/// non-ZFS paths or when `zfs` isn't on PATH.
///
/// We do *not* use `statfs` to detect "is this a ZFS mount" because
/// the ZFS mount fstype string differs across BSDs and across OpenZFS
/// versions — `zfs list` is the authoritative answer.
pub fn dataset_for_path(path: &Path) -> Option<String> {
    let _ = which_zfs()?;
    let out = Command::new("zfs")
        .args(["list", "-H", "-o", "name"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_string();
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zfs_probe_is_callable() {
        let _ = probe_zfs();
    }

    #[test]
    fn bsd_probe_diagnose_is_nonempty() {
        let p = probe_bsd();
        assert!(!p.diagnose().is_empty());
        assert!(p.diagnose().contains(p.family.label()));
    }

    #[test]
    fn zfs_none_is_not_usable() {
        assert!(!ZfsProbe::none().usable());
    }

    #[test]
    fn kqueue_features_for_openbsd_lack_note_exec() {
        let f = KqueueFeatures::for_family(BsdFamily::OpenBsd);
        assert!(!f.note_exec);
        assert!(f.evfilt_vnode);
        assert!(f.evfilt_proc);
    }
}
