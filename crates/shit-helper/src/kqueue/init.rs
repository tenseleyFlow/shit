// SPDX-License-Identifier: AGPL-3.0-or-later

//! `kqueue(2)` wrapper. Returns an owned `KqueueFd` whose Drop closes
//! the descriptor — the only correct way to release a kqueue, since
//! Linux-style "the helper exit closes the fd" doesn't apply to BSDs
//! the same way (the kernel does close it on exit, but we keep the
//! RAII contract so unit tests stay clean).

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::error::KqueueError;

/// Owned kqueue file descriptor. Closes on drop.
#[derive(Debug)]
pub struct KqueueFd(OwnedFd);

impl KqueueFd {
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Create a fresh kqueue. The descriptor is set CLOEXEC by the BSDs
/// automatically (unlike the Linux fanotify path).
pub fn init() -> Result<KqueueFd, KqueueError> {
    // SAFETY: kqueue takes no arguments and returns a fresh fd or -1.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(KqueueError::Kqueue(std::io::Error::last_os_error()));
    }
    // SAFETY: raw is a fresh kernel-allocated fd we now own.
    let owned = unsafe { OwnedFd::from_raw_fd_owned(raw) };
    Ok(KqueueFd(owned))
}

/// Tiny shim so the unsafe is localized; mirrors the BorrowedFd
/// pattern used elsewhere in the codebase.
trait FromRawFdOwned {
    unsafe fn from_raw_fd_owned(fd: RawFd) -> Self;
}
impl FromRawFdOwned for OwnedFd {
    unsafe fn from_raw_fd_owned(fd: RawFd) -> Self {
        use std::os::fd::FromRawFd;
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_returns_a_valid_fd() {
        let kq = init().expect("kqueue init");
        assert!(kq.as_raw_fd() >= 0);
    }
}
