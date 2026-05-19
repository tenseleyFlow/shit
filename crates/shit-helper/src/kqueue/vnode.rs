// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EVFILT_VNODE` — per-fd file-system event subscription.
//!
//! S23.1 (DR-05): registers every dir + regular file under a tracked
//! subtree with `EVFILT_VNODE`. EVFILT_VNODE only delivers events for
//! fds we explicitly opened, so we walk the tree, open every entry
//! `O_RDONLY|O_CLOEXEC`, and submit one kevent per fd. The returned
//! [`TrackedSubtree`] owns the fds — Drop closes them, which is also
//! how kqueue learns to unregister (per `kevent(2)` semantics on
//! FreeBSD: the filter is removed when the descriptor is closed).
//!
//! Subtree walks are depth-limited (default
//! [`DEFAULT_DEPTH_LIMIT`] = 8). Lazy expansion on parent-dir
//! NOTE_WRITE events is the drain loop's responsibility (S23.3),
//! not this module's.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::error::KqueueError;
use super::init::KqueueFd;

/// Decoded fflags from a kevent delivery.
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

impl VnodeEventKind {
    /// Map a kevent's fflags bitfield to the most-specific event kind
    /// it represents. A single delivery can carry multiple bits (e.g.
    /// NOTE_WRITE|NOTE_EXTEND on an append); we return the strongest
    /// signal (Delete > Rename > Revoke > Write > Extend > Attrib >
    /// Link) so the drain loop has a single canonical event to route.
    pub fn from_fflags(fflags: u32) -> Option<Self> {
        if fflags & libc::NOTE_DELETE != 0 {
            Some(Self::Delete)
        } else if fflags & libc::NOTE_RENAME != 0 {
            Some(Self::Rename)
        } else if fflags & libc::NOTE_REVOKE != 0 {
            Some(Self::Revoke)
        } else if fflags & libc::NOTE_WRITE != 0 {
            Some(Self::Write)
        } else if fflags & libc::NOTE_EXTEND != 0 {
            Some(Self::Extend)
        } else if fflags & libc::NOTE_ATTRIB != 0 {
            Some(Self::Attrib)
        } else if fflags & libc::NOTE_LINK != 0 {
            Some(Self::Link)
        } else {
            None
        }
    }
}

/// Default subtree depth when the caller doesn't override. Eight is
/// the S10 design's working limit — deeper trees get lazy expansion
/// driven by directory NOTE_WRITE events in the drain loop.
pub const DEFAULT_DEPTH_LIMIT: usize = 8;

/// Union of fflags every tracked fd subscribes to. Exposed so the
/// drain loop can re-register with the same set if a child fd needs
/// to be added after a NOTE_WRITE on its parent.
pub const VNODE_FFLAGS: u32 = libc::NOTE_DELETE
    | libc::NOTE_WRITE
    | libc::NOTE_EXTEND
    | libc::NOTE_ATTRIB
    | libc::NOTE_LINK
    | libc::NOTE_RENAME
    | libc::NOTE_REVOKE;

/// One watched entry — an owned fd plus the path we opened it as.
/// The path is needed because EVFILT_VNODE events identify the fd,
/// not the path, and the daemon wants pathnames in its journal.
#[derive(Debug)]
struct TrackedEntry {
    fd: OwnedFd,
    path: PathBuf,
}

/// A subtree of fds registered with EVFILT_VNODE on a kqueue.
///
/// Dropping this value closes every fd, which is how kqueue learns
/// to remove the filters (per FreeBSD's kevent(2) man page: "If the
/// descriptor associated with an event is closed, the event is
/// automatically deleted"). No explicit EV_DELETE needed.
#[derive(Debug)]
pub struct TrackedSubtree {
    entries: Vec<TrackedEntry>,
}

impl TrackedSubtree {
    /// How many fds the subtree currently holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve a kevent ident (which carries a RawFd cast to uintptr)
    /// back to the path we registered it against. None if the fd
    /// isn't currently tracked.
    pub fn path_for_fd(&self, fd: RawFd) -> Option<&Path> {
        self.entries
            .iter()
            .find(|e| e.fd.as_raw_fd() == fd)
            .map(|e| e.path.as_path())
    }
}

/// Walk `root` to `depth_limit`, open every directory and regular
/// file `O_RDONLY|O_CLOEXEC`, and register each fd with
/// `EVFILT_VNODE` on `kq` for [`VNODE_FFLAGS`].
///
/// Symlinks are not followed — we track real inodes only. Permission-
/// denied entries are silently skipped so a partial tree still
/// produces a usable subtree. Other I/O errors abort the walk.
pub fn register_subtree(
    kq: &KqueueFd,
    root: &Path,
    depth_limit: usize,
) -> Result<TrackedSubtree, KqueueError> {
    let mut entries = Vec::new();
    walk(root, depth_limit, &mut entries)?;
    register_entries(kq, &entries)?;
    Ok(TrackedSubtree { entries })
}

fn walk(
    path: &Path,
    depth_remaining: usize,
    out: &mut Vec<TrackedEntry>,
) -> Result<(), KqueueError> {
    let fd = open_for_watch(path)?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| KqueueError::Open {
        path: path.to_path_buf(),
        source: e,
    })?;
    let is_dir = meta.is_dir();
    out.push(TrackedEntry {
        fd,
        path: path.to_path_buf(),
    });
    if !is_dir || depth_remaining == 0 {
        return Ok(());
    }
    let read_dir = match std::fs::read_dir(path) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
        Err(e) => {
            return Err(KqueueError::Open {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    for entry in read_dir.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        // Errors on individual children don't abort the whole walk —
        // a single permission-denied file in a deep tree shouldn't
        // wipe out everything we've registered above it.
        let _ = walk(&entry.path(), depth_remaining - 1, out);
    }
    Ok(())
}

fn open_for_watch(path: &Path) -> Result<OwnedFd, KqueueError> {
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| KqueueError::Open {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL byte"),
    })?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC;
    // SAFETY: cpath is a valid NUL-terminated C string for the call
    // duration; open returns -1 with errno on failure.
    let raw = unsafe { libc::open(cpath.as_ptr(), flags, 0) };
    if raw < 0 {
        return Err(KqueueError::Open {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: raw is a fresh kernel-allocated fd we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn register_entries(kq: &KqueueFd, entries: &[TrackedEntry]) -> Result<(), KqueueError> {
    if entries.is_empty() {
        return Ok(());
    }
    let changes: Vec<libc::kevent> = entries
        .iter()
        .map(|e| libc::kevent {
            ident: e.fd.as_raw_fd() as libc::uintptr_t,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: VNODE_FFLAGS,
            data: 0,
            udata: std::ptr::null_mut(),
            ext: [0; 4],
        })
        .collect();
    // SAFETY: kq is owned for the duration; `changes` ptr/len describe
    // the changelist; eventlist=NULL, nevents=0 means "register only".
    let rc = unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            changes.as_ptr(),
            changes.len() as libc::c_int,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(KqueueError::Kevent(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Back-compat stub from S10 stage 1. The real entry point is
/// [`register_subtree`]; this returns `NotImplemented` deliberately so
/// any caller still hitting it surfaces.
pub fn watch_path(_kq: &KqueueFd, _path: &Path) -> Result<(), KqueueError> {
    Err(KqueueError::NotImplemented(
        "watch_path is superseded by register_subtree (S23.1)",
    ))
}

impl TrackedSubtree {
    /// S29.2 — add an incremental watch on a single path that wasn't
    /// known at `register_subtree` time. Used when the dir-diff in
    /// `capture::bsd::handle_dir_change` sees a new entry appear and
    /// we want subsequent NOTE_WRITE/NOTE_DELETE on that entry to
    /// fire on a tracked fd. Returns the new fd on success, or
    /// `None` if the open failed (permission-denied, race-deleted,
    /// etc. — non-fatal; the watch silently drops that entry).
    pub fn add_path(&mut self, kq: &KqueueFd, path: &Path) -> Option<RawFd> {
        let fd = match open_for_watch(path) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::trace!(path = %path.display(), error = ?e, "add_path open failed");
                return None;
            }
        };
        let raw = fd.as_raw_fd();
        let entry = TrackedEntry {
            fd,
            path: path.to_path_buf(),
        };
        // Register one filter against the new fd. We re-use
        // `register_entries` with a single-element slice to keep the
        // changelist construction in one place.
        let single = std::slice::from_ref(&entry);
        if let Err(e) = register_entries(kq, single) {
            tracing::warn!(path = %path.display(), error = %e, "add_path kevent register failed");
            return None;
        }
        self.entries.push(entry);
        Some(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kqueue::init;
    use std::time::Duration;

    #[test]
    fn from_fflags_picks_most_specific() {
        assert_eq!(
            VnodeEventKind::from_fflags(libc::NOTE_WRITE),
            Some(VnodeEventKind::Write)
        );
        // NOTE_WRITE|NOTE_EXTEND on an append — Write wins.
        assert_eq!(
            VnodeEventKind::from_fflags(libc::NOTE_WRITE | libc::NOTE_EXTEND),
            Some(VnodeEventKind::Write)
        );
        // NOTE_DELETE outranks NOTE_WRITE.
        assert_eq!(
            VnodeEventKind::from_fflags(libc::NOTE_DELETE | libc::NOTE_WRITE),
            Some(VnodeEventKind::Delete)
        );
        assert_eq!(VnodeEventKind::from_fflags(0), None);
    }

    #[test]
    fn register_subtree_returns_owned_fds() {
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("foo"), b"a").unwrap();
        std::fs::write(dir.path().join("bar"), b"b").unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        // root dir + 2 files = 3 fds.
        assert_eq!(tree.len(), 3);
        let foo = dir.path().join("foo");
        let foo_fd = tree
            .entries
            .iter()
            .find(|e| e.path == foo)
            .map(|e| e.fd.as_raw_fd())
            .expect("foo tracked");
        assert!(foo_fd >= 0);
        assert_eq!(tree.path_for_fd(foo_fd), Some(foo.as_path()));
    }

    #[test]
    fn register_subtree_surfaces_note_write() {
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        let foo = dir.path().join("foo");
        std::fs::write(&foo, b"initial").unwrap();
        let _tree = register_subtree(&kq, dir.path(), 4).expect("register");
        // The mutation must happen *after* registration — kqueue
        // only sees events delivered while the filter is attached.
        std::fs::write(&foo, b"modified-content-larger").unwrap();
        // Drain with a 100ms deadline.
        let mut events: [libc::kevent; 8] = unsafe { std::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: Duration::from_millis(100).subsec_nanos() as libc::c_long,
        };
        // SAFETY: kq is owned for the duration; events is a writable
        // buffer of len 8; no changelist (NULL/0).
        let n = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                &timeout,
            )
        };
        assert!(n > 0, "expected at least one kevent, got {n}");
        let mut saw_write = false;
        for ev in events.iter().take(n as usize) {
            if ev.filter == libc::EVFILT_VNODE && (ev.fflags & libc::NOTE_WRITE) != 0 {
                saw_write = true;
            }
        }
        assert!(saw_write, "expected NOTE_WRITE on foo");
    }

    #[test]
    fn register_subtree_respects_depth_limit() {
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        // dir/a/b/c.txt
        let deep = dir.path().join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("c.txt"), b"x").unwrap();
        // depth_limit=1 should register: root + root/a (depth 1
        // remaining at root means we recurse one level into a, but
        // don't recurse into b's contents).
        let tree = register_subtree(&kq, dir.path(), 1).expect("register");
        // Expect: root, a → 2 entries.
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn register_subtree_skips_symlinks() {
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("real"), b"a").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        // root + "real" only; "link" is skipped.
        assert_eq!(tree.len(), 2);
    }
}
