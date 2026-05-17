// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EVFILT_PROC` — process-lifecycle event subscription.
//!
//! Stage 1 stub. The full implementation registers
//! `NOTE_FORK | NOTE_EXEC | NOTE_EXIT` on a pid (and on a fresh
//! follow-up registration for each fork-child) so we can maintain
//! the same process-tree view as Linux's fanotify pid tracking
//! without polling `/proc`.
//!
//! OpenBSD does not deliver NOTE_EXEC — see `BsdProbe.kqueue.note_exec`.
//! Code paths that depend on it must check the probe before relying
//! on exec-driven tree expansion.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use super::error::KqueueError;
use super::init::KqueueFd;

/// Process-lifecycle event kind delivered by EVFILT_PROC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEventKind {
    Fork,
    Exec,
    Exit,
}

/// Subscribe to NOTE_FORK | NOTE_EXEC | NOTE_EXIT for a given pid.
/// Stage 1 stub.
pub fn watch_pid(_kq: &KqueueFd, _pid: i32) -> Result<(), KqueueError> {
    Err(KqueueError::NotImplemented(
        "proc::watch_pid lands in S10 stage 2",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kqueue::init;

    #[test]
    fn watch_pid_is_not_implemented_yet() {
        let kq = init().expect("kqueue");
        let r = watch_pid(&kq, 1);
        assert!(matches!(r, Err(KqueueError::NotImplemented(_))));
    }
}
