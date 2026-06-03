// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side capture producers (S24.B+).
//!
//! Each platform has its own producer module that consumes kernel-tier
//! events (kqueue / fanotify / ES) and ships `HelperResponse::CapturedPreImage`
//! to the daemon. The wire format is shared (see `shit-proto`); the
//! producer logic is platform-specific because the syscalls are.
//!
//! S24.B lands the FreeBSD/kqueue producer ([`bsd`]). L01 lands the
//! Linux/fanotify producer ([`linux`]). M01.A lands the macOS/FSEvents
//! degraded-tier producer ([`macos`]); M03.1.I layers the ES producer
//! ([`macos_es`]) alongside it (both run in parallel per the M03.1.I
//! design's defense-in-depth posture).

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

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub mod macos_es;

// xattr capture is consumed by the BSD, Linux, and macOS producers
// (macOS via M03.x.XATTR — reads off the staging fd post-clonefile).
pub mod xattr;

// Streaming pre-image primitives shared between BSD/kqueue and
// Linux/LSM (AU25). macOS has its own streaming impl in
// `macos_es.rs` (M03.x.STREAMING) — a future sprint may consolidate
// onto this module. The `pread(2)` + `openat(2)` + blake3 dance is
// portable; the module is cfg-gated only because macOS doesn't use
// it today.
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod streaming;
