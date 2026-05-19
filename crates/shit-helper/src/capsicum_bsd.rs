// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeBSD Capsicum sandbox (S10 stage 1).
//!
//! Capsicum is FreeBSD's capability-mode sandbox: once a process
//! calls `cap_enter(2)`, it can no longer use global namespaces
//! (open by absolute path, kill arbitrary pids, etc.) and is
//! restricted to operations on file descriptors it already holds.
//! This is the FreeBSD analog of:
//! - Linux: seccomp + the cap-drop in `priv_linux::drop_to_minimum`
//! - macOS: the helper's sandbox profile (S07)
//!
//! ## Why FreeBSD-only (not the other BSDs)
//!
//! Capsicum originated on FreeBSD and ships there by default. NetBSD,
//! OpenBSD, and DragonFly do not have a comparable API. On those the
//! helper relies on filesystem ACLs + the kqueue tier's narrower
//! attack surface (no LSM-like deny path); revisit in a follow-up
//! sprint paired with audit work.
//!
//! ## Stage 1 contract
//!
//! Exposes `enter_capability_mode()` returning a `CapsicumError`
//! variant. Stage 1 always returns `NotImplemented` so wiring it into
//! `privileged_setup` is a no-op. Real `cap_enter(2)` call lands
//! once we have a FreeBSD VM target — same prerequisite as the kqueue
//! runtime work.

#[derive(Debug, thiserror::Error)]
pub enum CapsicumError {
    #[error("cap_enter(2): {0}")]
    CapEnter(std::io::Error),
    #[error("not implemented in stage 1: {0}")]
    NotImplemented(&'static str),
}

/// Enter Capsicum capability mode. **One-way:** after this returns
/// Ok, the process can no longer use global namespace operations.
///
/// Stage 1 always returns `NotImplemented`; the cap-mode entry is
/// gated on a FreeBSD VM-paired validation pass (same prerequisite as
/// the kqueue runtime path).
pub fn enter_capability_mode() -> Result<(), CapsicumError> {
    Err(CapsicumError::NotImplemented(
        "cap_enter(2) wiring lands once a FreeBSD VM target is in CI",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage1_returns_not_implemented() {
        match enter_capability_mode() {
            Err(CapsicumError::NotImplemented(_)) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
}
