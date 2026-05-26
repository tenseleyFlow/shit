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
//! **S23.1 (DR-05)**: vnode subtree registration is real; proc and the
//! drain loop are still stubs that land in S23.2 + S23.3. Runtime is
//! validated on the FreeBSD VM under `tools/freebsd-vm/`.
//!
//! **Visibility:** the entire module is gated to BSD targets at the
//! parent (`crate::main`). Non-BSD builds see no kqueue symbols.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
// Stage-1: kqueue/* exposes the public API DR-05..DR-11 will wire up
// (vnode/proc watchers, kevent drain loop). Until then there are no
// in-crate callers, which trips dead_code / unused_imports under
// `-D warnings` on FreeBSD CI. Drop the allow when the runtime path
// lights up (paired with the FreeBSD VM tooling).
#![allow(dead_code, unused_imports)]

pub mod capture;
#[cfg(test)]
mod capture_tests;
pub mod drain;
pub mod error;
pub mod event_loop;
pub mod init;
pub mod proc;
pub mod tree;
pub mod vnode;

pub use capture::{
    CaptureError, PRE_IMAGE_INLINE_CAP, STREAM_COPY_CAP, read_pre_image, stream_copy_to_staging,
};
pub use drain::{
    DEFAULT_CAPACITY, DrainError, DrainEvent, DrainHandle, DrainSession, spawn as spawn_drain,
    spawn_default as spawn_drain_default,
};
pub use error::KqueueError;
pub use init::{KqueueFd, init};
pub use proc::{
    PROC_FFLAGS_DESCENDANTS, PROC_FFLAGS_SINGLE, ProcEventKind, TrackedPid, track_descendants,
    track_pid,
};
pub use tree::TrackedTree;
pub use vnode::{
    DEFAULT_DEPTH_LIMIT, TrackedSubtree, VNODE_FFLAGS, VnodeEventKind, register_subtree,
    register_subtree_at, watch_path,
};
