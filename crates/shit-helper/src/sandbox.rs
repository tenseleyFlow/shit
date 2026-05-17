// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-OS sandbox entry. Full policies land in their respective
//! platform sprints (S07 macOS, S08/S09 Linux, S10 BSD). This module
//! is the structural carve-out.

use std::path::Path;

/// Enter the platform sandbox. After this returns successfully, the
/// helper is restricted to the allowed syscall set / sandbox profile.
/// There is no way back: code paths that need privileged setup must
/// run *before* this call.
pub fn enter(_state_dir: &Path) -> anyhow::Result<()> {
    enter_platform(_state_dir)?;
    tracing::info!("sandbox entered");
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_platform(_state_dir: &Path) -> anyhow::Result<()> {
    // S06.6 swaps in seccomp policy installation here.
    tracing::debug!("linux sandbox stub (S06.6 fills in seccomp)");
    Ok(())
}

#[cfg(target_os = "macos")]
fn enter_platform(_state_dir: &Path) -> anyhow::Result<()> {
    // S07 swaps in `sandbox_init_with_parameters` profile.
    tracing::debug!("macos sandbox stub (S07 fills in sandbox_init)");
    Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
fn enter_platform(_state_dir: &Path) -> anyhow::Result<()> {
    // S10 swaps in capsicum `cap_enter`.
    tracing::debug!("bsd sandbox stub (S10 fills in capsicum)");
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
fn enter_platform(_state_dir: &Path) -> anyhow::Result<()> {
    tracing::warn!("no sandbox on this platform");
    Ok(())
}
