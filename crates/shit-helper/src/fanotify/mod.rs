// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux fanotify integration. Kernel hooks live in the helper; the
//! daemon never speaks fanotify directly.
//!
//! Module layout:
//! - `init` — `fanotify_init(2)` wrapper, returns an owned `FanotifyFd`.
//! - `mark` — `fanotify_mark(2)` wrapper for add/remove watches.
//! - (later sub-tasks) `parse`, `event_loop`, `respond`, `tree`, `queue`.
//!
//! Spec: `.docs/sprints/S08-linux-fanotify-perm.md`.
//!
//! **Visibility:** the entire module is gated by `cfg(target_os = "linux")`
//! at the parent (`crate::main`). Non-Linux builds see an empty module
//! and never link against fanotify symbols.

pub mod event_loop;
pub mod init;
pub mod mark;
pub mod parse;
pub mod queue;
pub mod runtime;
pub mod tree;

// kernel_probe lives in `shit-capture::linux_kernel` so the `shit doctor`
// CLI can use it without depending on the helper binary crate.
pub use shit_capture::linux_kernel::{FanotifyFeatures, KernelVersion, probe, read_kernel_version};

pub use init::{FanotifyFd, InitError, init, init_pre_content};
pub use mark::{MarkError, MarkFlags, mark_filesystem, mark_mount, unmark_filesystem};
pub use parse::{Event, EventIter, ParseError};
