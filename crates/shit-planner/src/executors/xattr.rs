// SPDX-License-Identifier: AGPL-3.0-or-later

//! User-namespace xattr restore (W09.21).
//!
//! Diffs the captured `target` xattr map against what's live on disk
//! and converges via descriptor-bound set/delete calls on FreeBSD and macOS.
//! Linux replay is deliberately disabled, and an empty FreeBSD target is
//! treated as non-authoritative, until capture records whether its xattr
//! snapshot is complete. Treating today's stubbed/ambiguous empty maps as
//! authoritative would delete genuine attributes.
//!
//! ## Why "user namespace" only
//!
//! The capture side reads `user.*` only ([`crate::capture::xattr`]).
//! Restoring outside the user namespace would require helper-routed
//! privileged calls, which we don't ship yet. Most tools that set
//! xattrs (setfattr, setextattr, rsync `--xattrs`, tar `--xattrs`)
//! default to `user.*` so this covers the realistic round-trip
//! cases.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

/// Drive xattrs on `path` to exactly match `target`. Adds missing,
/// updates differing, removes orphans. Returns the count of changed
/// attrs (mostly for tracing).
///
/// Errors are returned as strings and must be propagated by the caller. Once
/// a snapshot is treated as authoritative, silently ignoring list/get/set or
/// delete failures would falsely report a complete metadata restore.
pub fn restore_user_xattrs(
    path: &Path,
    target: &BTreeMap<String, Vec<u8>>,
) -> Result<usize, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("open {path:?} for xattr restore: {e}"))?;
    restore_user_xattrs_fd(file.as_raw_fd(), path, target)
}

/// Descriptor-bound form used by metadata replay. The caller owns `fd` and
/// must keep it open for the duration of this call. `path` is diagnostic-only;
/// no xattr operation resolves it again.
pub(crate) fn restore_user_xattrs_fd(
    fd: RawFd,
    path: &Path,
    target: &BTreeMap<String, Vec<u8>>,
) -> Result<usize, String> {
    #[cfg(target_os = "linux")]
    {
        let _ = (fd, path, target);
        tracing::warn!(
            path = %path.display(),
            "skipping Linux xattr replay: capture does not yet record snapshot completeness"
        );
        Ok(0)
    }
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        #[cfg(target_os = "freebsd")]
        if target.is_empty() {
            let _ = fd;
            tracing::warn!(
                path = %path.display(),
                "skipping empty FreeBSD xattr replay: capture does not yet record snapshot completeness"
            );
            return Ok(0);
        }
        platform::restore_fd(fd, path, target)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "linux", target_os = "macos")))]
    {
        let _ = (fd, path, target);
        Ok(0)
    }
}

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
mod platform {
    use super::*;
    use std::ffi::CString;

    pub fn restore_fd(
        fd: RawFd,
        path: &Path,
        target: &BTreeMap<String, Vec<u8>>,
    ) -> Result<usize, String> {
        let current = read(fd)?;
        let mut changed = 0usize;

        // Set adds + updates.
        for (k, v) in target {
            if should_skip_restore(k) {
                continue;
            }
            if current.get(k).map(|cv| cv == v).unwrap_or(false) {
                continue;
            }
            let cname = cname_for(k)
                .map_err(|e| format!("xattr {k:?} on {path:?} is unrepresentable: {e}"))?;
            set(fd, &cname, v).map_err(|e| format!("set xattr {k:?} on {path:?}: {e}"))?;
            changed += 1;
        }

        // Delete orphans (in current but not in target).
        for k in current.keys() {
            if target.contains_key(k) || should_skip_restore(k) {
                continue;
            }
            let cname = cname_for(k)
                .map_err(|e| format!("xattr {k:?} on {path:?} is unrepresentable: {e}"))?;
            delete(fd, &cname).map_err(|e| format!("delete xattr {k:?} on {path:?}: {e}"))?;
            changed += 1;
        }

        Ok(changed)
    }

    #[cfg(target_os = "freebsd")]
    fn cname_for(name: &str) -> Result<CString, String> {
        CString::new(name).map_err(|e| format!("xattr name has interior NUL: {e}"))
    }

    #[cfg(target_os = "macos")]
    fn cname_for(name: &str) -> Result<CString, String> {
        // macOS xattrs use their full name verbatim (no namespace
        // prefix logic). `com.apple.*` flows through identically.
        CString::new(name).map_err(|e| format!("xattr name has interior NUL: {e}"))
    }

    /// macOS-only filter for xattrs we should NEVER write back during
    /// restore — they're either system-managed (kernel auto-stamps a
    /// fresh value on the restored file; clobbering with an old value
    /// breaks the system tracking) or otherwise unsafe to forge.
    ///
    /// `com.apple.provenance` is stamped by the kernel on file
    /// creation on macOS 14+. Restoring our captured-old value would
    /// pin the file to a stale provenance record.
    ///
    /// Everything else, including `com.apple.quarantine`,
    /// `com.apple.metadata:*`, `com.apple.FinderInfo`, ACLs, and
    /// codesign signatures, is user-meaningful and we DO restore.
    #[cfg(target_os = "macos")]
    fn should_skip_restore(name: &str) -> bool {
        matches!(name, "com.apple.provenance")
    }
    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    fn should_skip_restore(_name: &str) -> bool {
        false
    }

    #[cfg(target_os = "freebsd")]
    fn read(fd: std::os::fd::RawFd) -> Result<BTreeMap<String, Vec<u8>>, String> {
        // Same logic as capture-side; duplicated locally to avoid a
        // helper-crate dep on planner.
        let ns = libc::EXTATTR_NAMESPACE_USER;
        let size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(format!(
                "extattr_list_fd size query: {}",
                std::io::Error::last_os_error()
            ));
        }
        if size == 0 {
            return Ok(BTreeMap::new());
        }
        let mut buf = vec![0u8; size as usize];
        let n = unsafe { libc::extattr_list_fd(fd, ns, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(format!(
                "extattr_list_fd: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut out = BTreeMap::new();
        let mut i = 0usize;
        let end = n as usize;
        while i < end {
            let len = buf[i] as usize;
            i += 1;
            if i + len > end {
                return Err("extattr_list_fd returned a malformed name list".into());
            }
            let name_bytes = &buf[i..i + len];
            i += len;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|e| format!("live xattr name is not UTF-8: {e}"))?;
            let cname =
                CString::new(name).map_err(|e| format!("live xattr name contains NUL: {e}"))?;
            let val_size =
                unsafe { libc::extattr_get_fd(fd, ns, cname.as_ptr(), std::ptr::null_mut(), 0) };
            if val_size < 0 {
                return Err(format!(
                    "extattr_get_fd size query for {name:?}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut val = vec![0u8; val_size as usize];
            let m = unsafe {
                libc::extattr_get_fd(fd, ns, cname.as_ptr(), val.as_mut_ptr().cast(), val.len())
            };
            if m < 0 {
                return Err(format!(
                    "extattr_get_fd for {name:?}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            val.truncate(m as usize);
            out.insert(name.to_string(), val);
        }
        Ok(out)
    }

    #[cfg(target_os = "freebsd")]
    fn set(fd: std::os::fd::RawFd, name: &CString, value: &[u8]) -> Result<(), String> {
        let rc = unsafe {
            libc::extattr_set_fd(
                fd,
                libc::EXTATTR_NAMESPACE_USER,
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "freebsd")]
    fn delete(fd: std::os::fd::RawFd, name: &CString) -> Result<(), String> {
        let rc =
            unsafe { libc::extattr_delete_fd(fd, libc::EXTATTR_NAMESPACE_USER, name.as_ptr()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    // ─── macOS xattr ops ─────────────────────────────────────────
    //
    // Apple's signatures take extra `position` (for resource-fork
    // segmentation; always 0 for normal xattrs) + `options` (0 means
    // follow symlinks + normal namespace; XATTR_NOFOLLOW=0x0001 to
    // not follow). We always operate on the open fd directly, so
    // symlink semantics are moot — pass 0.

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn flistxattr(
            fd: libc::c_int,
            namebuf: *mut libc::c_char,
            size: libc::size_t,
            options: libc::c_int,
        ) -> libc::ssize_t;

        fn fgetxattr(
            fd: libc::c_int,
            name: *const libc::c_char,
            value: *mut libc::c_void,
            size: libc::size_t,
            position: u32,
            options: libc::c_int,
        ) -> libc::ssize_t;

        fn fsetxattr(
            fd: libc::c_int,
            name: *const libc::c_char,
            value: *const libc::c_void,
            size: libc::size_t,
            position: u32,
            options: libc::c_int,
        ) -> libc::c_int;

        fn fremovexattr(
            fd: libc::c_int,
            name: *const libc::c_char,
            options: libc::c_int,
        ) -> libc::c_int;
    }

    #[cfg(target_os = "macos")]
    fn read(fd: std::os::fd::RawFd) -> Result<BTreeMap<String, Vec<u8>>, String> {
        // SAFETY: size-query form per Apple's docs.
        let size = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
        if size < 0 {
            return Err(format!(
                "flistxattr size query: {}",
                std::io::Error::last_os_error()
            ));
        }
        if size == 0 {
            return Ok(BTreeMap::new());
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf has size bytes; fd is borrowed-valid.
        let n = unsafe { flistxattr(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(format!("flistxattr: {}", std::io::Error::last_os_error()));
        }
        let mut out = BTreeMap::new();
        for name_bytes in buf[..n as usize]
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
        {
            let name = std::str::from_utf8(name_bytes)
                .map_err(|e| format!("live xattr name is not UTF-8: {e}"))?;
            let cname =
                CString::new(name).map_err(|e| format!("live xattr name contains NUL: {e}"))?;
            // SAFETY: cname NUL-terminated, fd borrowed-valid.
            let val_size = unsafe { fgetxattr(fd, cname.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
            if val_size < 0 {
                return Err(format!(
                    "fgetxattr size query for {name:?}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut val = vec![0u8; val_size as usize];
            let m =
                unsafe { fgetxattr(fd, cname.as_ptr(), val.as_mut_ptr().cast(), val.len(), 0, 0) };
            if m < 0 {
                return Err(format!(
                    "fgetxattr for {name:?}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            val.truncate(m as usize);
            out.insert(name.to_string(), val);
        }
        Ok(out)
    }

    #[cfg(target_os = "macos")]
    fn set(fd: std::os::fd::RawFd, name: &CString, value: &[u8]) -> Result<(), String> {
        // SAFETY: name NUL-terminated; value valid for value.len() bytes; fd borrowed.
        let rc = unsafe { fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0, 0) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn delete(fd: std::os::fd::RawFd, name: &CString) -> Result<(), String> {
        // SAFETY: name NUL-terminated; fd borrowed.
        let rc = unsafe { fremovexattr(fd, name.as_ptr(), 0) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(all(
    test,
    any(target_os = "freebsd", target_os = "linux", target_os = "macos")
))]
mod tests {
    use super::*;

    #[test]
    fn empty_target_on_empty_file_is_noop() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let n = restore_user_xattrs(f.path(), &BTreeMap::new()).unwrap();
        assert_eq!(n, 0);
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    #[test]
    fn invalid_descriptor_read_is_an_error() {
        let mut target = BTreeMap::new();
        target.insert("probe".to_string(), b"value".to_vec());
        let err = restore_user_xattrs_fd(-1, Path::new("/diagnostic-only"), &target)
            .expect_err("invalid descriptor must not look like an empty xattr set");
        assert!(err.contains("list") || err.contains("EBADF"), "{err}");
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    #[test]
    fn unrepresentable_target_name_is_an_error() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut target = BTreeMap::new();
        target.insert("bad\0name".to_string(), b"value".to_vec());
        let err = restore_user_xattrs(f.path(), &target)
            .expect_err("an invalid name must not be silently skipped");
        assert!(err.contains("unrepresentable"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_incomplete_snapshot_never_deletes_live_user_xattrs() {
        use std::ffi::CString;

        let f = tempfile::NamedTempFile::new().unwrap();
        let name = CString::new("user.shit.keep").unwrap();
        let value = b"must survive";
        // SAFETY: descriptor/name/value are valid for the syscall.
        let rc = unsafe {
            libc::fsetxattr(
                f.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if rc != 0 {
            // The test filesystem has xattrs disabled; there is no live attr
            // with which to exercise the preservation invariant.
            return;
        }

        assert_eq!(
            restore_user_xattrs_fd(f.as_raw_fd(), f.path(), &BTreeMap::new()).unwrap(),
            0
        );
        let mut got = vec![0u8; value.len()];
        // SAFETY: descriptor/name/buffer are valid for the syscall.
        let n = unsafe {
            libc::fgetxattr(
                f.as_raw_fd(),
                name.as_ptr(),
                got.as_mut_ptr().cast(),
                got.len(),
            )
        };
        assert_eq!(n, value.len() as isize);
        assert_eq!(got, value);
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn freebsd_ambiguous_empty_snapshot_never_deletes_live_user_xattrs() {
        use std::ffi::CString;

        let f = tempfile::NamedTempFile::new().unwrap();
        let name = CString::new("shit.keep").unwrap();
        let value = b"must survive";
        // SAFETY: descriptor/name/value are valid for the syscall.
        let rc = unsafe {
            libc::extattr_set_fd(
                f.as_raw_fd(),
                libc::EXTATTR_NAMESPACE_USER,
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
            )
        };
        if rc < 0 {
            return;
        }

        assert_eq!(
            restore_user_xattrs_fd(f.as_raw_fd(), f.path(), &BTreeMap::new()).unwrap(),
            0
        );
        let mut got = vec![0u8; value.len()];
        // SAFETY: descriptor/name/buffer are valid for the syscall.
        let n = unsafe {
            libc::extattr_get_fd(
                f.as_raw_fd(),
                libc::EXTATTR_NAMESPACE_USER,
                name.as_ptr(),
                got.as_mut_ptr().cast(),
                got.len(),
            )
        };
        assert_eq!(n, value.len() as isize);
        assert_eq!(got, value);
    }
}
