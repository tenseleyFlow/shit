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

    /// Highest tier label, for `shit doctor` output.
    pub fn tier_label(&self) -> &'static str {
        match (
            self.perm_events,
            self.filesystem_mark,
            self.report_fid,
            self.report_dir_fid,
            self.report_pidfd,
        ) {
            (true, true, true, true, true) => "fanotify-perm + pidfd (5.15+)",
            (true, true, true, true, false) => "fanotify-perm + dir-fid (5.9+)",
            (true, true, true, false, false) => "fanotify-perm + fid (5.4+)",
            (true, true, false, false, false) => "fanotify-perm + fs-scope (5.1+)",
            (true, false, false, false, false) => "fanotify-perm (4.20+)",
            (false, _, _, _, _) => "no fanotify-perm (pre-4.20 or compiled-out)",
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
}
