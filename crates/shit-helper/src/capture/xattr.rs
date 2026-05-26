// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extended-attribute capture (W09.21).
//!
//! Reads all user-namespace xattrs off a file descriptor into a
//! `BTreeMap<String, Vec<u8>>` (ordered for stable hashing). FreeBSD
//! uses `extattr_list_fd(2)` / `extattr_get_fd(2)` with
//! `EXTATTR_NAMESPACE_USER`; Linux uses `flistxattr(2)` /
//! `fgetxattr(2)` restricted to the `user.` prefix. Other targets
//! return an empty map.
//!
//! ## Why user namespace only
//!
//! `EXTATTR_NAMESPACE_SYSTEM` (FreeBSD) and `security.*` /
//! `trusted.*` (Linux) require root. The helper *might* be privileged,
//! but the planner-side restore would also need root — and most tools
//! that set xattrs (setfattr, setextattr, rsync, tar with `--xattrs`)
//! default to the user namespace. We can extend coverage later if a
//! concrete tool needs it.

use std::collections::BTreeMap;
use std::os::fd::RawFd;

/// Best-effort xattr read off `fd`. Errors are swallowed: missing
/// xattr support on the filesystem (UFS without UFS2, tmpfs without
/// xattr enable) yields an empty map rather than a capture failure.
pub fn read_user_xattrs(fd: RawFd) -> BTreeMap<String, Vec<u8>> {
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read(fd)
    }
    #[cfg(target_os = "linux")]
    {
        linux::read(fd)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    {
        let _ = fd;
        BTreeMap::new()
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::fd::RawFd;

    /// FreeBSD's extattr list format: `<u8 namelen><name…>` repeating,
    /// no terminator. Names are NOT null-terminated. Parsing requires
    /// reading the leading length byte and advancing exactly that
    /// many bytes.
    pub fn read(fd: RawFd) -> BTreeMap<String, Vec<u8>> {
        let ns = libc::EXTATTR_NAMESPACE_USER;
        // First call with NULL/0 returns the size needed.
        let list_size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if list_size <= 0 {
            return BTreeMap::new();
        }
        let mut buf = vec![0u8; list_size as usize];
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
            let cname = match CString::new(name) {
                Ok(c) => c,
                Err(_) => continue,
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
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::ffi::{CStr, CString};
    use std::os::fd::RawFd;

    pub fn read(fd: RawFd) -> BTreeMap<String, Vec<u8>> {
        let list_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if list_size <= 0 {
            return BTreeMap::new();
        }
        let mut buf = vec![0i8; list_size as usize];
        let n = unsafe { libc::flistxattr(fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            return BTreeMap::new();
        }
        let mut out = BTreeMap::new();
        // Linux returns a `\0`-separated, `\0`-terminated list.
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), n as usize) };
        for raw in bytes.split(|b| *b == 0) {
            if raw.is_empty() {
                continue;
            }
            // Restrict to the `user.` namespace — see module docs.
            if !raw.starts_with(b"user.") {
                continue;
            }
            let Ok(name_str) = std::str::from_utf8(raw) else {
                continue;
            };
            let cname = match CString::new(name_str) {
                Ok(c) => c,
                Err(_) => continue,
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
            // Store WITHOUT the `user.` prefix to match the FreeBSD
            // namespace-scoped key shape. The restore side adds the
            // prefix back on Linux.
            let stripped = name_str
                .strip_prefix("user.")
                .unwrap_or(name_str)
                .to_string();
            // Use `_` to silence unused on non-Linux; CStr ref keeps cname alive.
            let _ = CStr::from_bytes_with_nul(cname.to_bytes_with_nul());
            out.insert(stripped, val);
        }
        out
    }
}

#[cfg(all(test, any(target_os = "freebsd", target_os = "linux")))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn empty_file_has_no_xattrs() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let got = read_user_xattrs(f.as_file().as_raw_fd());
        assert!(
            got.is_empty(),
            "unexpected xattrs on fresh tempfile: {got:?}"
        );
    }
}
