// SPDX-License-Identifier: AGPL-3.0-or-later

//! kevent(2) drain loop — pulls registered events off the kqueue
//! and routes them to the daemon. Stage 1 stub.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use super::error::KqueueError;
use super::init::KqueueFd;

/// Drain pending events. Stage 1 stub.
pub fn drain_once(_kq: &KqueueFd) -> Result<usize, KqueueError> {
    Err(KqueueError::NotImplemented(
        "event_loop::drain_once lands in S10 stage 2",
    ))
}
