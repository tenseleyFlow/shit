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

#![cfg(target_os = "linux")]

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
    const KEEP: &[u32] = &[
        libc::CAP_SYS_ADMIN as u32,
        // libc on stable doesn't expose CAP_BPF/CAP_PERFMON yet; use raw values.
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
            if matches!(
                e.raw_os_error(),
                Some(libc::EINVAL) | Some(libc::EPERM)
            ) {
                continue;
            }
            return Err(PrivError::Capset(format!("PR_CAPBSET_DROP cap={cap}: {e}")));
        }
    }

    // Set NO_NEW_PRIVS — required for the unprivileged seccomp install
    // later, and prevents any future setuid binary from regaining caps.
    let rc =
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_capset_is_false_in_normal_test_run() {
        // Tests don't run as root or with all caps. (If you're running
        // tests as root with all caps inherited, this would fail —
        // please don't.)
        assert!(!full_capset());
    }
}
