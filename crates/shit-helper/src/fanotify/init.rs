// SPDX-License-Identifier: AGPL-3.0-or-later

//! `fanotify_init(2)` wrapper. Returns an owned fd that closes on drop.
//!
//! The fanotify fd is the helper's privileged handle to the kernel
//! pre-mutation event stream. We open two clients in the steady state
//! (S08.4): one in `FAN_CLASS_CONTENT` for permission events, one in
//! `FAN_CLASS_NOTIF` for post-hoc metadata events.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("fanotify_init failed: {0}")]
    Syscall(#[from] io::Error),
    #[error("fanotify requires CAP_SYS_ADMIN; helper is unprivileged (errno = EPERM)")]
    Unprivileged,
    #[error("fanotify not supported by this kernel (errno = ENOSYS)")]
    Unsupported,
}

/// Wrapper around an owned `fanotify` fd. Closes on drop.
#[derive(Debug)]
pub struct FanotifyFd {
    fd: OwnedFd,
}

impl FanotifyFd {
    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.fd.as_raw_fd()
    }

    /// Take ownership of the fd. Caller closes.
    pub fn into_owned(self) -> OwnedFd {
        self.fd
    }
}

/// Open a fanotify fd with the requested flags. Most callers prefer the
/// convenience constructors below.
pub fn init(flags: u32, event_f_flags: u32) -> Result<FanotifyFd, InitError> {
    // SAFETY: libc::fanotify_init is a straight wrapper around the
    // syscall; no unsafe-precondition contract beyond passing valid
    // flag bits.
    let rc = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM) => InitError::Unprivileged,
            Some(libc::ENOSYS) => InitError::Unsupported,
            _ => InitError::Syscall(err),
        });
    }
    // SAFETY: fanotify_init returned non-negative on success → fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(rc) };
    Ok(FanotifyFd { fd })
}

/// Open a `FAN_CLASS_CONTENT` client suitable for pre-content
/// permission events on kernels >= 4.20.
///
/// Flags:
/// - `FAN_CLOEXEC` so we don't leak the fd across exec.
/// - `FAN_NONBLOCK` so the read loop never blocks the worker.
/// - `FAN_CLASS_PRE_CONTENT` to receive `FAN_OPEN_PERM` /
///   `FAN_ACCESS_PERM` before kernel grants the syscall.
///
/// `event_f_flags` = `O_RDONLY | O_LARGEFILE` — read-only fds, no
/// truncation under us.
pub fn init_pre_content() -> Result<FanotifyFd, InitError> {
    init(
        libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_CLASS_PRE_CONTENT,
        (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
    )
}

/// Open a `FAN_CLASS_NOTIF` client for post-hoc events that don't need
/// a permission decision. Used in parallel with the pre-content client
/// to avoid head-of-line blocking between the two event classes.
#[allow(dead_code)]
pub fn init_notif() -> Result<FanotifyFd, InitError> {
    init(
        libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_CLASS_NOTIF,
        (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
    )
}
