// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-OS sandbox entry. After [`enter`] returns successfully, the
//! helper is restricted to the platform sandbox profile. There is no
//! way back: privileged setup must run before this call.
//!
//! Full policies land in platform sprints:
//! - macOS: S07 (sandbox_init_with_parameters)
//! - Linux: S06.6 (seccomp), S08 (fanotify), S09 (eBPF-LSM)
//! - BSD: S10 (capsicum cap_enter)

use std::path::Path;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
mod bsd;

/// Enter the platform sandbox.
pub fn enter(state_dir: &Path) -> anyhow::Result<()> {
    enter_platform(state_dir)?;
    tracing::info!("sandbox entered");
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_platform(state_dir: &Path) -> anyhow::Result<()> {
    linux::enter(state_dir)
}

#[cfg(target_os = "macos")]
fn enter_platform(state_dir: &Path) -> anyhow::Result<()> {
    macos::enter(state_dir)
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
fn enter_platform(state_dir: &Path) -> anyhow::Result<()> {
    bsd::enter(state_dir)
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
