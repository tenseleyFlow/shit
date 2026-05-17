// SPDX-License-Identifier: AGPL-3.0-or-later

//! BSD kqueue integration (S10 stage 1).
//!
//! Module layout mirrors `fanotify/` on Linux:
//! - `init`  — `kqueue(2)` wrapper, returns an owned `KqueueFd`.
//! - `vnode` — `EVFILT_VNODE` registration on directory/file fds.
//! - `proc`  — `EVFILT_PROC` registration on pids (NOTE_FORK/EXEC/EXIT).
//! - `event_loop` — kevent(2) drain loop.
//! - `error` — shared error type.
//!
//! Spec: `.docs/sprints/S10-bsd-tier.md`.
//!
//! **Stage 1**: only the skeleton + init wrapper are real; vnode/proc
//! registration are stubs that compile cleanly but don't yet wire up
//! to the daemon's tree-tracking. Runtime validation deferred until
//! a FreeBSD VM target is ready, paired with S20's security audit.
//!
//! **Visibility:** the entire module is gated to BSD targets at the
//! parent (`crate::main`). Non-BSD builds see no kqueue symbols.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

pub mod error;
pub mod event_loop;
pub mod init;
pub mod proc;
pub mod tree;
pub mod vnode;

pub use error::KqueueError;
pub use init::{KqueueFd, init};
pub use proc::{ProcEventKind, watch_pid};
pub use tree::TrackedTree;
pub use vnode::{VnodeEventKind, watch_path};
