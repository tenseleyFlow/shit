// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime probes invoked by `shit doctor` to validate the host
//! tier end-to-end.
//!
//! Per-platform submodules behind `cfg(target_os = "…")` gates.
//! Each populates one of the per-platform sub-reports defined in
//! [`super::json`]:
//!
//! - [`bsd`] → [`super::json::BsdReport`] (FreeBSD-focused; B03)
//! - [`linux`] → [`super::json::LinuxReport`] (L05)
//! - [`macos`] → [`super::json::MacReport`] (M02)

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod bsd;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;
