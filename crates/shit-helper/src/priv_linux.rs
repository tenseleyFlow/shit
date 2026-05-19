// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux privilege dropping.
//!
//! Helper runs with `cap_sys_admin,cap_bpf,cap_perfmon=ep` (file
//! capabilities preferred over setuid root — see S06 open questions).
//! At startup we keep exactly the caps we need and drop everything
//! else. If we somehow inherited *full* root (UID 0 with all caps),
//! refuse to run — that's not the configured posture.
//!
//! Order: this runs *before* `sandbox::enter`. After sandbox entry the
//! seccomp filter would itself block `capset(2)`.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum PrivError {
    #[error("refusing to run with full root inherited (uid 0 + all caps)")]
    FullRootInherited,
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("capability syscall failed: {0}")]
    Capset(String),
}

/// Drop everything but the capabilities the helper needs for its
/// kernel-tier setup (`cap_sys_admin`, `cap_bpf`, `cap_perfmon`).
///
/// On systems where the helper was installed via file capabilities,
/// the inherited set is already the minimum; this is then a no-op safety
/// net. On systems installed setuid-root (degraded mode), we drop
/// everything we won't use.
pub fn drop_to_minimum() -> Result<(), PrivError> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 && full_capset() {
        return Err(PrivError::FullRootInherited);
    }

    // Walk the cap range; drop everything except the keep-list.
    // CAP_LAST_CAP varies by kernel; we probe by trying CAP_DROP up to
    // a known-safe ceiling. Capabilities above the real CAP_LAST_CAP
    // return EINVAL which we ignore.
    // Numeric values from <linux/capability.h> — libc on stable doesn't
    // expose CAP_SYS_ADMIN / CAP_BPF / CAP_PERFMON as constants. Pinning
    // the numbers explicitly here is the standard portable pattern and
    // is what `man capabilities` documents.
    const KEEP: &[u32] = &[
        21, // CAP_SYS_ADMIN
        39, // CAP_BPF
        38, // CAP_PERFMON
    ];

    for cap in 0..=63u32 {
        if KEEP.contains(&cap) {
            continue;
        }
        // PR_CAPBSET_DROP removes the capability from the bounding set.
        // It also requires we have the cap itself; ignore EPERM/EINVAL.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::EPERM)) {
                continue;
            }
            return Err(PrivError::Capset(format!("PR_CAPBSET_DROP cap={cap}: {e}")));
        }
    }

    // Set NO_NEW_PRIVS — required for the unprivileged seccomp install
    // later, and prevents any future setuid binary from regaining caps.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
    if rc != 0 {
        return Err(PrivError::Capset(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            io::Error::last_os_error()
        )));
    }

    tracing::info!(
        kept_caps = ?KEEP,
        "capabilities dropped to minimum"
    );
    Ok(())
}

/// Best-effort detection of "full root inherited" — UID 0 *and* the
/// process holds CAP_SYS_RAWIO (a capability we don't ask for; if it's
/// present we likely inherited the full set). This is heuristic; the
/// real test is "did the operator launch us via sudo without our
/// file-cap install path".
fn full_capset() -> bool {
    use std::io::Read;
    let mut s = String::new();
    if std::fs::File::open("/proc/self/status")
        .and_then(|mut f| f.read_to_string(&mut s))
        .is_err()
    {
        return false;
    }
    // CapEff is a hex mask; if it equals "ffffffffffffffff" we have
    // (essentially) every capability.
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let trimmed = rest.trim();
            return trimmed == "0000003fffffffff"
                || trimmed == "00000000ffffffff"
                || trimmed.starts_with("ffffffff");
        }
    }
    false
}

/// Numeric capability constants we need but libc on stable doesn't
/// export. Values are pinned by the kernel ABI; see
/// `include/uapi/linux/capability.h`.
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;

/// Which capabilities the current process holds in its effective set.
/// Reads `/proc/self/status:CapEff` and tests bit `(1 << cap)`.
///
/// Returns `None` if the status file is unreadable (synthetic procfs
/// builds, restrictive sandboxes).
pub fn effective_caps_contain(cap: u32) -> Option<bool> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hex = rest.trim();
            let mask = u64::from_str_radix(hex, 16).ok()?;
            return Some((mask & (1u64 << cap)) != 0);
        }
    }
    None
}

/// Snapshot of the BPF-LSM-relevant capabilities. Used by the helper
/// during startup probe + `shit doctor` reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BpfCapState {
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub cap_sys_admin: bool,
}

impl BpfCapState {
    /// True when we have what `aya::Bpf::load` would need to load an
    /// LSM program on a modern kernel: either `CAP_BPF + CAP_PERFMON`
    /// (preferred, 5.8+) or `CAP_SYS_ADMIN` (legacy fallback).
    pub fn can_load_lsm(&self) -> bool {
        (self.cap_bpf && self.cap_perfmon) || self.cap_sys_admin
    }
}

pub fn probe_bpf_caps() -> BpfCapState {
    BpfCapState {
        cap_bpf: effective_caps_contain(CAP_BPF).unwrap_or(false),
        cap_perfmon: effective_caps_contain(CAP_PERFMON).unwrap_or(false),
        cap_sys_admin: effective_caps_contain(CAP_SYS_ADMIN).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_bpf_caps_returns_a_state() {
        // Tests don't run privileged. All three should be false. If
        // the test runner DOES have any of these, that's outside our
        // control — we just sanity-check the call doesn't panic.
        let c = probe_bpf_caps();
        let _ = c.can_load_lsm();
    }

    #[test]
    fn empty_cap_state_cannot_load() {
        let c = BpfCapState::default();
        assert!(!c.can_load_lsm());
    }

    #[test]
    fn cap_bpf_plus_perfmon_can_load() {
        let c = BpfCapState {
            cap_bpf: true,
            cap_perfmon: true,
            cap_sys_admin: false,
        };
        assert!(c.can_load_lsm());
    }

    #[test]
    fn cap_sys_admin_alone_can_load_legacy() {
        let c = BpfCapState {
            cap_bpf: false,
            cap_perfmon: false,
            cap_sys_admin: true,
        };
        assert!(c.can_load_lsm());
    }

    #[test]
    fn cap_bpf_alone_cannot_load_on_modern() {
        // 5.8+ split CAP_BPF from CAP_PERFMON; both required for
        // perf-attached LSM programs.
        let c = BpfCapState {
            cap_bpf: true,
            cap_perfmon: false,
            cap_sys_admin: false,
        };
        assert!(!c.can_load_lsm());
    }

    #[test]
    fn full_capset_is_false_in_normal_test_run() {
        // Tests don't run as root or with all caps. (If you're running
        // tests as root with all caps inherited, this would fail —
        // please don't.)
        assert!(!full_capset());
    }
}
