// SPDX-License-Identifier: AGPL-3.0-or-later

//! Copy-on-write capture engine and filesystem-watcher abstractions for `shit`.
//!
//! Spec lives in `.docs/sprints/S05-cow-engine.md`. Per-OS watcher implementations
//! land in S07 (macOS EndpointSecurity), S08 (Linux fanotify), S09 (Linux eBPF-LSM),
//! and S10 (BSD kqueue).

pub mod cow;
pub mod fs_matrix;
#[cfg(target_os = "linux")]
pub mod linux_kernel;
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod bsd_probe;

pub use cow::{
    CaptureOpts, CaptureOutcome, CowEngine, CowError, CowTier, DefaultEngine, would_pick,
};
pub use fs_matrix::{FsKind, detect_fs, pick_tier, supported_tiers};
