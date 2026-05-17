// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EVFILT_VNODE` — per-fd file-system event subscription.
//!
//! Stage 1 stub: returns `NotImplemented`. The full implementation
//! opens the target read-only, registers a kevent with the union of
//! `NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK
//! | NOTE_RENAME | NOTE_REVOKE` (the FreeBSD set), and surfaces
//! deliveries through the event_loop.
//!
//! **Key constraint** noted in the S10 sprint plan: EVFILT_VNODE only
//! delivers events for fds we *explicitly* registered. Watching a
//! whole subtree requires walking it and opening every directory.
//! We'll do this with a depth limit (default 8) and lazy expansion
//! triggered by directory events on parent dirs.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::path::Path;

use super::error::KqueueError;
use super::init::KqueueFd;

/// What a vnode event tells us about the affected inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VnodeEventKind {
    Delete,
    Write,
    Extend,
    Attrib,
    Link,
    Rename,
    Revoke,
}

/// Register a vnode watch on the given path. Stage 1 is a stub.
pub fn watch_path(_kq: &KqueueFd, _path: &Path) -> Result<(), KqueueError> {
    Err(KqueueError::NotImplemented(
        "vnode::watch_path lands in S10 stage 2",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kqueue::init;

    #[test]
    fn watch_path_is_not_implemented_yet() {
        let kq = init().expect("kqueue");
        let r = watch_path(&kq, Path::new("/tmp"));
        assert!(matches!(r, Err(KqueueError::NotImplemented(_))));
    }
}
