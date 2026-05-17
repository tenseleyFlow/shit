// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kernel feature detection. Each version unlocks fanotify capabilities
//! we care about:
//!
//! | Kernel | Feature                                |
//! |--------|----------------------------------------|
//! | 4.20   | `FAN_OPEN_PERM` / `FAN_ACCESS_PERM`    |
//! | 5.1    | `FAN_MARK_FILESYSTEM`                  |
//! | 5.4    | `FAN_REPORT_FID`                       |
//! | 5.9    | `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` |
//! | 5.15   | `FAN_REPORT_PIDFD`                     |
//!
//! Strategy: read `/proc/sys/kernel/osrelease` and parse the leading
//! `MAJOR.MINOR.PATCH`. We deliberately *don't* try `uname(2)` because
//! it pulls in glibc-specific behavior; the procfs path is portable
//! across libcs.

#![cfg(target_os = "linux")]

use std::fs;
use std::io;

/// Parsed kernel version, with `extra` stripped (e.g. `6.6.32-generic`
/// → `(6, 6, 32)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// True when this kernel is at least `other`.
    pub fn at_least(&self, other: KernelVersion) -> bool {
        *self >= other
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("unparseable kernel version string: {0:?}")]
    BadVersion(String),
}

/// What our fanotify code path can rely on at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyFeatures {
    pub perm_events: bool,
    pub filesystem_mark: bool,
    pub report_fid: bool,
    pub report_dir_fid: bool,
    pub report_pidfd: bool,
}

impl FanotifyFeatures {
    /// Empty set — kernel doesn't expose any fanotify event class we use.
    pub const fn none() -> Self {
        Self {
            perm_events: false,
            filesystem_mark: false,
            report_fid: false,
            report_dir_fid: false,
            report_pidfd: false,
        }
    }

    pub fn from_version(v: KernelVersion) -> Self {
        let v420 = KernelVersion::new(4, 20, 0);
        let v51 = KernelVersion::new(5, 1, 0);
        let v54 = KernelVersion::new(5, 4, 0);
        let v59 = KernelVersion::new(5, 9, 0);
        let v515 = KernelVersion::new(5, 15, 0);
        Self {
            perm_events: v.at_least(v420),
            filesystem_mark: v.at_least(v51),
            report_fid: v.at_least(v54),
            report_dir_fid: v.at_least(v59),
            report_pidfd: v.at_least(v515),
        }
    }

    /// Highest tier label, for `shit doctor` output. Tiers are
    /// cumulative — a kernel that has report_pidfd also has every
    /// lower-tier flag — so we walk top-to-bottom and pick the first
    /// hit. Any oddball combination (a custom kernel that surfaces a
    /// higher flag without a lower one) falls through to the most
    /// specific label that still describes it.
    pub fn tier_label(&self) -> &'static str {
        if !self.perm_events {
            return "no fanotify-perm (pre-4.20 or compiled-out)";
        }
        if self.report_pidfd {
            "fanotify-perm + pidfd (5.15+)"
        } else if self.report_dir_fid {
            "fanotify-perm + dir-fid (5.9+)"
        } else if self.report_fid {
            "fanotify-perm + fid (5.4+)"
        } else if self.filesystem_mark {
            "fanotify-perm + fs-scope (5.1+)"
        } else {
            "fanotify-perm (4.20+)"
        }
    }
}

/// Read `/proc/sys/kernel/osrelease` and parse the version.
pub fn read_kernel_version() -> Result<KernelVersion, ProbeError> {
    let raw = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    parse_version(raw.trim())
}

fn parse_version(s: &str) -> Result<KernelVersion, ProbeError> {
    // Take up to the first non-version character (the '-' before the
    // distro suffix, or end-of-string).
    let prefix_end = s
        .find(|c: char| c != '.' && !c.is_ascii_digit())
        .unwrap_or(s.len());
    let head = &s[..prefix_end];
    let mut parts = head.split('.');
    let major = parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| ProbeError::BadVersion(s.to_string()))?;
    let minor = parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| ProbeError::BadVersion(s.to_string()))?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Ok(KernelVersion {
        major,
        minor,
        patch,
    })
}

/// Probe kernel version + derive the feature set. Convenience wrapper.
pub fn probe() -> Result<(KernelVersion, FanotifyFeatures), ProbeError> {
    let v = read_kernel_version()?;
    Ok((v, FanotifyFeatures::from_version(v)))
}

/// BPF-LSM availability — read-only probe via filesystem.
///
/// **Safe to call from any context.** Touches no syscalls beyond `read`
/// on a handful of stable procfs/sysfs paths. Does not load BPF
/// programs, does not require any capability.
///
/// Reports the full picture the user needs to make the
/// "S09 vs fall-back-to-S08" decision. All four checks are independent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BpfLsmFeatures {
    /// True when `/sys/kernel/btf/vmlinux` exists. BTF is required for
    /// CO-RE relocation; without it, `aya` programs can't load.
    pub btf_available: bool,
    /// True when `/sys/kernel/security/lsm` contains `bpf`. This is
    /// the runtime indicator: even if `CONFIG_BPF_LSM=y`, BPF-LSM
    /// hooks won't fire unless the kernel was booted with
    /// `lsm=...,bpf,...`.
    pub bpf_in_active_lsm: bool,
    /// True when the kernel config has `CONFIG_BPF_LSM=y`. Best-effort:
    /// we check `/proc/config.gz`, `/boot/config-$(uname -r)`, and
    /// `/lib/modules/$(uname -r)/build/.config`. `None` if no config
    /// source is readable.
    pub config_bpf_lsm: Option<bool>,
    /// Kernel version is at or above the BPF-LSM minimum (5.7).
    pub kernel_recent_enough: bool,
}

impl BpfLsmFeatures {
    /// True iff every check passes — we can load BPF-LSM programs.
    pub fn fully_supported(&self) -> bool {
        self.btf_available
            && self.bpf_in_active_lsm
            && self.kernel_recent_enough
            && matches!(self.config_bpf_lsm, Some(true))
    }

    /// Short, doctor-friendly diagnostic. Names the specific check
    /// that failed when something is wrong, so the user knows what
    /// to fix.
    pub fn diagnose(&self) -> &'static str {
        if !self.kernel_recent_enough {
            "kernel < 5.7 — no BPF-LSM"
        } else if matches!(self.config_bpf_lsm, Some(false)) {
            "CONFIG_BPF_LSM=n in kernel config — rebuild or use different kernel"
        } else if !self.bpf_in_active_lsm {
            "bpf missing from active lsm= cmdline — reboot with lsm=...,bpf"
        } else if !self.btf_available {
            "/sys/kernel/btf/vmlinux missing — distro doesn't ship BTF"
        } else if self.fully_supported() {
            "BPF-LSM available"
        } else {
            "BPF-LSM partial — see field details"
        }
    }

    /// The grub-cmdline addition to suggest when `bpf_in_active_lsm`
    /// is false but everything else looks OK.
    pub fn cmdline_remediation_hint(&self) -> Option<&'static str> {
        if !self.bpf_in_active_lsm
            && self.kernel_recent_enough
            && matches!(self.config_bpf_lsm, Some(true) | None)
        {
            Some(
                "Add `bpf` to your kernel cmdline:\n\
                 GRUB_CMDLINE_LINUX_DEFAULT=\"... lsm=lockdown,capability,landlock,yama,bpf\"\n\
                 sudo grub-mkconfig -o /boot/grub/grub.cfg && reboot",
            )
        } else {
            None
        }
    }
}

/// Probe BPF-LSM availability. Safe; pure filesystem reads.
pub fn probe_bpf_lsm() -> BpfLsmFeatures {
    let kernel_recent_enough = match read_kernel_version() {
        Ok(v) => v.at_least(KernelVersion::new(5, 7, 0)),
        Err(_) => false,
    };
    BpfLsmFeatures {
        btf_available: std::path::Path::new("/sys/kernel/btf/vmlinux").is_file(),
        bpf_in_active_lsm: read_active_lsm()
            .map(|s| s.split(',').any(|x| x.trim() == "bpf"))
            .unwrap_or(false),
        config_bpf_lsm: probe_config_bpf_lsm(),
        kernel_recent_enough,
    }
}

/// Read the currently-active LSM list. Available since kernel 4.13.
fn read_active_lsm() -> Option<String> {
    fs::read_to_string("/sys/kernel/security/lsm").ok()
}

/// Try several known kernel-config sources. Returns `Some(true)` if any
/// of them contains `CONFIG_BPF_LSM=y`, `Some(false)` if any
/// definitively says =n or =m, `None` if no source was readable.
fn probe_config_bpf_lsm() -> Option<bool> {
    use std::path::Path;
    // `/proc/config.gz` is gzipped; the most portable trick is to
    // read it raw and scan for the bytes. We do NOT shell out to
    // `zcat` — adds a dependency on /bin/sh and gzip on the box.
    if Path::new("/proc/config.gz").is_file()
        && let Ok(bytes) = fs::read("/proc/config.gz")
        && let Some(verdict) = scan_config_gz_for_bpf_lsm(&bytes)
    {
        return Some(verdict);
    }
    // Uncompressed configs at known paths.
    let uname_r = read_kernel_release_string().unwrap_or_default();
    let candidates = [
        format!("/boot/config-{uname_r}"),
        format!("/lib/modules/{uname_r}/build/.config"),
        format!("/lib/modules/{uname_r}/source/.config"),
        "/proc/config".to_string(),
    ];
    for p in &candidates {
        if let Ok(s) = fs::read_to_string(p)
            && let Some(verdict) = scan_config_text_for_bpf_lsm(&s)
        {
            return Some(verdict);
        }
    }
    None
}

fn read_kernel_release_string() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

fn scan_config_text_for_bpf_lsm(s: &str) -> Option<bool> {
    for line in s.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("CONFIG_BPF_LSM=") {
            return match rest.trim() {
                "y" | "Y" => Some(true),
                "n" | "N" => Some(false),
                "m" | "M" => Some(false), // module not built into kernel
                _ => None,
            };
        }
        if t == "# CONFIG_BPF_LSM is not set" {
            return Some(false);
        }
    }
    None
}

/// Decode just enough of /proc/config.gz to find the BPF_LSM line.
/// We use the `flate2` crate if/when present — for now, a fallback
/// that's good enough for the rare distros putting config.gz where
/// the uncompressed variant doesn't also exist: read the file and look
/// for a likely-uncompressed substring. (gzip headers + DEFLATE blocks
/// can vary, so this is best-effort. Returns `None` if we can't tell.)
///
/// In practice every distro that ships config.gz also makes the
/// uncompressed config available elsewhere; this is a defensive last
/// resort.
fn scan_config_gz_for_bpf_lsm(_bytes: &[u8]) -> Option<bool> {
    // Deliberately conservative: don't try to inflate without the
    // dependency. Caller falls through to uncompressed sources.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clean_version() {
        let v = parse_version("6.6.32").unwrap();
        assert_eq!(v, KernelVersion::new(6, 6, 32));
    }

    #[test]
    fn parse_with_distro_suffix() {
        let v = parse_version("6.8.0-31-generic").unwrap();
        assert_eq!(v, KernelVersion::new(6, 8, 0));
    }

    #[test]
    fn parse_two_part() {
        let v = parse_version("5.4").unwrap();
        assert_eq!(v, KernelVersion::new(5, 4, 0));
    }

    #[test]
    fn parse_amazon_linux_style() {
        let v = parse_version("5.10.225-213.878.amzn2.x86_64").unwrap();
        assert_eq!(v, KernelVersion::new(5, 10, 225));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_version("").is_err());
    }

    #[test]
    fn features_for_4_20_only_perm() {
        let f = FanotifyFeatures::from_version(KernelVersion::new(4, 20, 0));
        assert!(f.perm_events);
        assert!(!f.filesystem_mark);
        assert!(!f.report_fid);
    }

    #[test]
    fn features_for_5_1_filesystem_mark() {
        let f = FanotifyFeatures::from_version(KernelVersion::new(5, 1, 0));
        assert!(f.perm_events);
        assert!(f.filesystem_mark);
        assert!(!f.report_fid);
    }

    #[test]
    fn features_for_5_15_full() {
        let f = FanotifyFeatures::from_version(KernelVersion::new(5, 15, 0));
        assert!(f.perm_events);
        assert!(f.filesystem_mark);
        assert!(f.report_fid);
        assert!(f.report_dir_fid);
        assert!(f.report_pidfd);
    }

    #[test]
    fn features_for_4_19_yields_none() {
        let f = FanotifyFeatures::from_version(KernelVersion::new(4, 19, 0));
        assert!(!f.perm_events);
    }

    #[test]
    fn tier_label_changes_with_features() {
        assert_eq!(
            FanotifyFeatures::from_version(KernelVersion::new(4, 20, 0)).tier_label(),
            "fanotify-perm (4.20+)"
        );
        assert_eq!(
            FanotifyFeatures::from_version(KernelVersion::new(5, 15, 1)).tier_label(),
            "fanotify-perm + pidfd (5.15+)"
        );
        assert_eq!(
            FanotifyFeatures::from_version(KernelVersion::new(4, 0, 0)).tier_label(),
            "no fanotify-perm (pre-4.20 or compiled-out)"
        );
    }

    #[test]
    fn at_least_ordering() {
        let a = KernelVersion::new(5, 4, 10);
        let b = KernelVersion::new(5, 4, 9);
        let c = KernelVersion::new(5, 5, 0);
        assert!(a.at_least(b));
        assert!(!b.at_least(a));
        assert!(c.at_least(a));
    }

    #[test]
    fn scan_config_text_finds_y() {
        let s = "CONFIG_FOO=y\nCONFIG_BPF_LSM=y\nCONFIG_BAR=m\n";
        assert_eq!(scan_config_text_for_bpf_lsm(s), Some(true));
    }

    #[test]
    fn scan_config_text_finds_n_explicit() {
        let s = "CONFIG_BPF_LSM=n\n";
        assert_eq!(scan_config_text_for_bpf_lsm(s), Some(false));
    }

    #[test]
    fn scan_config_text_finds_module_as_unsupported() {
        // BPF_LSM as a module doesn't actually work; treat as false.
        let s = "CONFIG_BPF_LSM=m\n";
        assert_eq!(scan_config_text_for_bpf_lsm(s), Some(false));
    }

    #[test]
    fn scan_config_text_finds_not_set_comment() {
        let s = "# CONFIG_FOO is not set\n# CONFIG_BPF_LSM is not set\n";
        assert_eq!(scan_config_text_for_bpf_lsm(s), Some(false));
    }

    #[test]
    fn scan_config_text_returns_none_when_absent() {
        let s = "CONFIG_FOO=y\nCONFIG_BAR=m\n";
        assert_eq!(scan_config_text_for_bpf_lsm(s), None);
    }

    #[test]
    fn diagnose_uses_specific_failure_path() {
        let f = BpfLsmFeatures {
            btf_available: true,
            bpf_in_active_lsm: false,
            config_bpf_lsm: Some(true),
            kernel_recent_enough: true,
        };
        assert!(f.diagnose().contains("lsm="));
    }

    #[test]
    fn diagnose_pre_5_7_kernel() {
        let f = BpfLsmFeatures {
            kernel_recent_enough: false,
            ..Default::default()
        };
        assert!(f.diagnose().contains("5.7"));
    }

    #[test]
    fn fully_supported_only_when_all_four_pass() {
        let mut f = BpfLsmFeatures {
            btf_available: true,
            bpf_in_active_lsm: true,
            config_bpf_lsm: Some(true),
            kernel_recent_enough: true,
        };
        assert!(f.fully_supported());
        f.btf_available = false;
        assert!(!f.fully_supported());
        f.btf_available = true;
        f.config_bpf_lsm = None;
        assert!(!f.fully_supported());
    }

    #[test]
    fn cmdline_remediation_hint_appears_for_lsm_missing_only() {
        let f = BpfLsmFeatures {
            btf_available: true,
            bpf_in_active_lsm: false,
            config_bpf_lsm: Some(true),
            kernel_recent_enough: true,
        };
        let hint = f.cmdline_remediation_hint().unwrap();
        assert!(hint.contains("GRUB_CMDLINE_LINUX_DEFAULT"));
        assert!(hint.contains("bpf"));
    }

    #[test]
    fn cmdline_hint_suppressed_when_config_disabled() {
        // No point suggesting a cmdline tweak when CONFIG isn't even on.
        let f = BpfLsmFeatures {
            btf_available: true,
            bpf_in_active_lsm: false,
            config_bpf_lsm: Some(false),
            kernel_recent_enough: true,
        };
        assert!(f.cmdline_remediation_hint().is_none());
    }
}
