// SPDX-License-Identifier: AGPL-3.0-or-later

//! `fanotify_mark(2)` wrapper. `libc` does not expose this directly so
//! we go via `libc::syscall(SYS_fanotify_mark, ...)`.
//!
//! Mark scopes (mutually exclusive):
//! - **filesystem** (`FAN_MARK_FILESYSTEM`, kernel >= 5.1): watch every
//!   inode on the filesystem containing `dirfd/pathname`. Cheapest for
//!   "watch all of $HOME".
//! - **mount** (`FAN_MARK_MOUNT`): watch every inode under a mount.
//! - per-inode (the default): watch one inode. Fine-grained but
//!   creates marks proportional to watched paths.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::init::FanotifyFd;

#[derive(Debug, thiserror::Error)]
pub enum MarkError {
    #[error("fanotify_mark failed: {0}")]
    Syscall(#[from] io::Error),
    #[error("path contains a NUL byte: {0:?}")]
    BadPath(std::path::PathBuf),
    #[error("kernel does not support FAN_MARK_FILESYSTEM (requires >= 5.1)")]
    FilesystemScopeUnsupported,
}

bitflags::bitflags! {
    /// Re-export of the kernel's FAN_MARK_* bits as a typed flag set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MarkFlags: u32 {
        const ADD = libc::FAN_MARK_ADD;
        const REMOVE = libc::FAN_MARK_REMOVE;
        const DONT_FOLLOW = libc::FAN_MARK_DONT_FOLLOW;
        const ONLYDIR = libc::FAN_MARK_ONLYDIR;
        const MOUNT = libc::FAN_MARK_MOUNT;
        const FILESYSTEM = libc::FAN_MARK_FILESYSTEM;
        const IGNORED_MASK = libc::FAN_MARK_IGNORED_MASK;
        const IGNORED_SURV_MODIFY = libc::FAN_MARK_IGNORED_SURV_MODIFY;
        const FLUSH = libc::FAN_MARK_FLUSH;
    }
}

/// Raw wrapper around `fanotify_mark(2)`.
pub fn mark(
    fd: &FanotifyFd,
    flags: MarkFlags,
    event_mask: u64,
    dirfd: i32,
    pathname: &Path,
) -> Result<(), MarkError> {
    let c_path = CString::new(pathname.as_os_str().as_bytes())
        .map_err(|_| MarkError::BadPath(pathname.to_path_buf()))?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fd.as_raw_fd(),
            flags.bits() as libc::c_uint,
            event_mask,
            dirfd as libc::c_int,
            c_path.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(MarkError::Syscall(io::Error::last_os_error()));
    }
    Ok(())
}

/// Convenience: add a filesystem-scope watch for the standard
/// write-intent event set. Requires kernel >= 5.1; surfaces a typed
/// error otherwise.
pub fn mark_filesystem(fd: &FanotifyFd, path: &Path) -> Result<(), MarkError> {
    let mask = libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM | libc::FAN_EVENT_ON_CHILD;
    let res = mark(
        fd,
        MarkFlags::ADD | MarkFlags::FILESYSTEM,
        mask,
        libc::AT_FDCWD,
        path,
    );
    if let Err(MarkError::Syscall(e)) = &res
        && e.raw_os_error() == Some(libc::EINVAL)
    {
        return Err(MarkError::FilesystemScopeUnsupported);
    }
    res
}

/// Add a per-mount watch.
pub fn mark_mount(fd: &FanotifyFd, mount_path: &Path) -> Result<(), MarkError> {
    let mask = libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM | libc::FAN_EVENT_ON_CHILD;
    mark(
        fd,
        MarkFlags::ADD | MarkFlags::MOUNT,
        mask,
        libc::AT_FDCWD,
        mount_path,
    )
}

/// Remove a filesystem-scope mark previously added by [`mark_filesystem`].
pub fn unmark_filesystem(fd: &FanotifyFd, path: &Path) -> Result<(), MarkError> {
    let mask = libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM | libc::FAN_EVENT_ON_CHILD;
    mark(
        fd,
        MarkFlags::REMOVE | MarkFlags::FILESYSTEM,
        mask,
        libc::AT_FDCWD,
        path,
    )
}
