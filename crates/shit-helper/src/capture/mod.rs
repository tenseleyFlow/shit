// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side capture producers (S24.B+).
//!
//! Each platform has its own producer module that consumes kernel-tier
//! events (kqueue / fanotify / ES) and ships `HelperResponse::CapturedPreImage`
//! to the daemon. The wire format is shared (see `shit-proto`); the
//! producer logic is platform-specific because the syscalls are.
//!
//! S24.B lands the FreeBSD/kqueue producer ([`bsd`]). L01 lands the
//! Linux/fanotify producer ([`linux`]). macOS ES producer is S27.

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod bsd;

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod cwd;

#[cfg(target_os = "linux")]
pub mod linux;
