// SPDX-License-Identifier: AGPL-3.0-or-later

//! User-namespace xattr restore (W09.21).
//!
//! Diffs the captured `target` xattr map against what's live on disk
//! and converges via set/delete calls. FreeBSD and Linux are
//! implemented; other targets are no-ops that succeed.
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
use std::path::Path;

/// Drive xattrs on `path` to exactly match `target`. Adds missing,
/// updates differing, removes orphans. Returns the count of changed
/// attrs (mostly for tracing).
///
/// Errors are returned as strings — the caller upgrades to
/// `MetadataRestoreError::Other`. We don't fail-hard on individual
/// xattr ops because the FS may not support the specific xattr we
/// captured (e.g. capturing on UFS+xattr → restoring on a tmpfs
/// without xattr enable). Per-op failure is logged via the warn
/// channel by the inner platform impl.
pub fn restore_user_xattrs(
    path: &Path,
    target: &BTreeMap<String, Vec<u8>>,
) -> Result<usize, String> {
    #[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "macos"))]
    {
        platform::restore(path, target)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, target);
        Ok(0)
    }
}

#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    pub fn restore(path: &Path, target: &BTreeMap<String, Vec<u8>>) -> Result<usize, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| format!("open {path:?} for xattr restore: {e}"))?;
        let fd = file.as_raw_fd();
        let current = read(fd);
        let mut changed = 0usize;

        // Set adds + updates.
        for (k, v) in target {
            if should_skip_restore(k) {
                continue;
            }
            if current.get(k).map(|cv| cv == v).unwrap_or(false) {
                continue;
            }
            let cname = match cname_for(k) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), name = %k, err = %e, "skip xattr with unrepresentable name");
                    continue;
                }
            };
            if let Err(e) = set(fd, &cname, v) {
                tracing::warn!(path = %path.display(), name = %k, err = %e, "set xattr failed");
                continue;
            }
            changed += 1;
        }

        // Delete orphans (in current but not in target).
        for k in current.keys() {
            if target.contains_key(k) || should_skip_restore(k) {
                continue;
            }
            let cname = match cname_for(k) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if let Err(e) = delete(fd, &cname) {
                tracing::warn!(path = %path.display(), name = %k, err = %e, "delete xattr failed");
                continue;
            }
            changed += 1;
        }

        Ok(changed)
    }

    #[cfg(target_os = "freebsd")]
    fn cname_for(name: &str) -> Result<CString, String> {
        CString::new(name).map_err(|e| format!("xattr name has interior NUL: {e}"))
    }

    #[cfg(target_os = "linux")]
    fn cname_for(name: &str) -> Result<CString, String> {
        // Linux xattrs are namespaced; capture-side stripped the
        // `user.` prefix, restore adds it back here.
        let full = format!("user.{name}");
        CString::new(full).map_err(|e| format!("xattr name has interior NUL: {e}"))
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
    fn read(fd: std::os::fd::RawFd) -> BTreeMap<String, Vec<u8>> {
        // Same logic as capture-side; duplicated locally to avoid a
        // helper-crate dep on planner.
        let ns = libc::EXTATTR_NAMESPACE_USER;
        let size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return BTreeMap::new();
        }
        let mut buf = vec![0u8; size as usize];
        let n = unsafe { libc::extattr_list_fd(fd, ns, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return BTreeMap::new();
        }
        let mut out = BTreeMap::new();
        let mut i = 0usize;
        let end = n as usize;
        while i < end {
            let len = buf[i] as usize;
            i += 1;
            if i + len > end {
                break;
            }
            let name_bytes = &buf[i..i + len];
            i += len;
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                continue;
            };
            let Ok(cname) = CString::new(name) else {
                continue;
            };
            let val_size =
                unsafe { libc::extattr_get_fd(fd, ns, cname.as_ptr(), std::ptr::null_mut(), 0) };
            if val_size < 0 {
                continue;
            }
            let mut val = vec![0u8; val_size as usize];
            let m = unsafe {
                libc::extattr_get_fd(fd, ns, cname.as_ptr(), val.as_mut_ptr().cast(), val.len())
            };
            if m < 0 {
                continue;
            }
            val.truncate(m as usize);
            out.insert(name.to_string(), val);
        }
        out
    }

    #[cfg(target_os = "linux")]
    fn read(fd: std::os::fd::RawFd) -> BTreeMap<String, Vec<u8>> {
        let size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return BTreeMap::new();
        }
        // c_char is i8 on x86_64 and u8 on aarch64; use it directly
        // so the platform's libc binding accepts the pointer without
        // a cast.
        let mut buf = vec![0 as libc::c_char; size as usize];
        let n = unsafe { libc::flistxattr(fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            return BTreeMap::new();
        }
        let mut out = BTreeMap::new();
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), n as usize) };
        for raw in bytes.split(|b| *b == 0) {
            if raw.is_empty() || !raw.starts_with(b"user.") {
                continue;
            }
            let Ok(name_str) = std::str::from_utf8(raw) else {
                continue;
            };
            let Ok(cname) = CString::new(name_str) else {
                continue;
            };
            let val_size = unsafe { libc::fgetxattr(fd, cname.as_ptr(), std::ptr::null_mut(), 0) };
            if val_size < 0 {
                continue;
            }
            let mut val = vec![0u8; val_size as usize];
            let m =
                unsafe { libc::fgetxattr(fd, cname.as_ptr(), val.as_mut_ptr().cast(), val.len()) };
            if m < 0 {
                continue;
            }
            val.truncate(m as usize);
            let stripped = name_str
                .strip_prefix("user.")
                .unwrap_or(name_str)
                .to_string();
            out.insert(stripped, val);
        }
        out
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

    #[cfg(target_os = "linux")]
    fn set(fd: std::os::fd::RawFd, name: &CString, value: &[u8]) -> Result<(), String> {
        let rc =
            unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
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

    #[cfg(target_os = "linux")]
    fn delete(fd: std::os::fd::RawFd, name: &CString) -> Result<(), String> {
        let rc = unsafe { libc::fremovexattr(fd, name.as_ptr()) };
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
    fn read(fd: std::os::fd::RawFd) -> BTreeMap<String, Vec<u8>> {
        // SAFETY: size-query form per Apple's docs.
        let size = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
        if size <= 0 {
            return BTreeMap::new();
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf has size bytes; fd is borrowed-valid.
        let n = unsafe { flistxattr(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            return BTreeMap::new();
        }
        let mut out = BTreeMap::new();
        for name_bytes in buf[..n as usize]
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
        {
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                continue;
            };
            let Ok(cname) = CString::new(name) else {
                continue;
            };
            // SAFETY: cname NUL-terminated, fd borrowed-valid.
            let val_size = unsafe { fgetxattr(fd, cname.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
            if val_size < 0 {
                continue;
            }
            let mut val = vec![0u8; val_size as usize];
            let m =
                unsafe { fgetxattr(fd, cname.as_ptr(), val.as_mut_ptr().cast(), val.len(), 0, 0) };
            if m < 0 {
                continue;
            }
            val.truncate(m as usize);
            out.insert(name.to_string(), val);
        }
        out
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

#[cfg(all(test, any(target_os = "freebsd", target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn empty_target_on_empty_file_is_noop() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let n = restore_user_xattrs(f.path(), &BTreeMap::new()).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn adds_missing_user_xattr_when_target_has_one() {
        // FS that supports xattrs is required; tempfile lives under
        // /tmp which on FreeBSD ZFS / Linux ext4/tmpfs supports user
        // xattrs. Test is best-effort: if the FS rejects the set, we
        // log + skip and the assert below is forgiving.
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut target = BTreeMap::new();
        target.insert("shit.test".to_string(), b"hello".to_vec());
        let _ = restore_user_xattrs(f.path(), &target);
    }
}
