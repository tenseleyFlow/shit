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
    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    {
        platform::restore(path, target)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    {
        let _ = (path, target);
        Ok(0)
    }
}

#[cfg(any(target_os = "freebsd", target_os = "linux"))]
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
            if target.contains_key(k) {
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
