// SPDX-License-Identifier: AGPL-3.0-or-later

//! inotify supplement for events fanotify-perm can't observe.
//!
//! fanotify in `FAN_CLASS_PRE_CONTENT` mode catches write-intent
//! open/access/exec but **not** metadata-only changes: chmod, chown,
//! setxattr, removexattr. inotify catches those (`IN_ATTRIB`) — but
//! only post-hoc, with no chance to snapshot the pre-state. We
//! therefore mark these `CaptureEvent`s as `partial = true` so the
//! planner knows it can't reverse them perfectly (we have the new
//! metadata, not the old).
//!
//! eBPF-LSM (S09) replaces this with proper pre-mutation hooks; this
//! module is the degraded-but-portable fallback for pre-eBPF kernels.
//!
//! Stage-1 surface: `read_events` / `as_raw_fd` are the API DR-01..04
//! will call once the watcher loop wires up; until then there are no
//! in-crate callers. Module-level allow keeps the surface ready.

#![allow(dead_code)]

use std::io;
use std::path::Path;

use inotify::{Inotify, WatchDescriptor, WatchMask};

#[derive(Debug, thiserror::Error)]
pub enum InotifyError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Wrapper around `inotify-rs`'s `Inotify` with the event mask we
/// actually care about pre-set. Owns the inotify fd; closes on drop.
pub struct InotifySupplement {
    inner: Inotify,
}

impl InotifySupplement {
    pub fn open() -> Result<Self, InotifyError> {
        Ok(Self {
            inner: Inotify::init()?,
        })
    }

    /// Add a recursive-style watch on `path`. inotify itself doesn't
    /// recurse — the caller is responsible for walking the tree and
    /// adding a watch per directory. For S08 we watch only `path`
    /// itself; S09's eBPF tier handles tree-wide coverage.
    ///
    /// Mask covers metadata events fanotify-perm can't see:
    /// `IN_ATTRIB` (chmod/chown/setxattr), `IN_MOVE_SELF` /
    /// `IN_DELETE_SELF` (the watched path itself moves/disappears).
    pub fn watch(&mut self, path: &Path) -> Result<WatchDescriptor, InotifyError> {
        let mask =
            WatchMask::ATTRIB | WatchMask::MOVE_SELF | WatchMask::DELETE_SELF | WatchMask::MODIFY;
        Ok(self.inner.watches().add(path, mask)?)
    }

    /// Drop a previously added watch.
    #[allow(dead_code)]
    pub fn unwatch(&mut self, wd: WatchDescriptor) -> Result<(), InotifyError> {
        self.inner.watches().remove(wd)?;
        Ok(())
    }

    /// Read the next batch of events into the caller's buffer.
    /// Returns the count read. Non-blocking — callers should
    /// `poll`/`epoll` on `as_raw_fd()` first.
    pub fn read_events<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<inotify::Events<'a>, InotifyError> {
        Ok(self.inner.read_events(buf)?)
    }

    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.inner.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_drop_doesnt_panic() {
        // inotify_init may fail in some restricted environments (no
        // CAP_SYS_ADMIN needed, just /proc/sys/fs/inotify quotas); if
        // it does, just skip rather than fail the test.
        match InotifySupplement::open() {
            Ok(s) => drop(s),
            Err(e) => eprintln!("inotify init failed; skipping: {e}"),
        }
    }

    #[test]
    fn watch_then_unwatch_on_tempdir() {
        let mut sup = match InotifySupplement::open() {
            Ok(s) => s,
            Err(_) => return,
        };
        let tmp = tempfile::tempdir().unwrap();
        let wd = sup.watch(tmp.path()).unwrap();
        sup.unwatch(wd).unwrap();
    }
}
