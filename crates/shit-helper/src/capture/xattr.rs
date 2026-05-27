// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extended-attribute capture (W09.21 / M03.x.XATTR on macOS).
//!
//! Reads xattrs off a file descriptor into a
//! `BTreeMap<String, Vec<u8>>` (ordered for stable hashing). Per-OS:
//!
//! - **FreeBSD:** `extattr_list_fd(2)` / `extattr_get_fd(2)` with
//!   `EXTATTR_NAMESPACE_USER` only. System namespace requires root +
//!   the planner-side restore would also need root.
//! - **macOS:** `flistxattr(2)` / `fgetxattr(2)` — captures the FULL
//!   xattr set including `com.apple.*` (Gatekeeper quarantine,
//!   Spotlight metadata, FinderInfo, ACLs, codesign signatures).
//!   Restoring a file without its xattrs leaves it broken in
//!   user-visible ways (signed binaries unsigned, quarantined
//!   apps un-quarantined, etc.).
//! - **Linux:** stubbed pending the L04 pre_open_tree integration —
//!   adding flistxattr to that hot path crashed the runner; see
//!   note below.

use std::collections::BTreeMap;
use std::os::fd::RawFd;

/// Best-effort xattr read off `fd`. Errors are swallowed: missing
/// xattr support on the filesystem (UFS without UFS2, tmpfs without
/// xattr enable) yields an empty map rather than a capture failure.
pub fn read_user_xattrs(fd: RawFd) -> BTreeMap<String, Vec<u8>> {
    // NOTE (W09.21 / capsicum-default-on interaction): on FreeBSD with
    // cap_enter active (B05 default), `extattr_*_fd` returns no
    // attributes on tracked fds even when the file has them — capsicum
    // does not include CAP_EXTATTR_* in the implicit rights of an
    // O_RDONLY-opened fd. Fix path is to cap_rights_limit each
    // subtree fd with CAP_EXTATTR_GET|LIST|SET|DELETE, or to open
    // fds before cap_enter with rights explicitly carried in. Until
    // then xattr capture is a no-op when capsicum is active; the
    // smoke validates the round-trip with SHIT_CAPSICUM=0.
    //
    // NOTE (W09.21 / Linux pre_open_tree interaction): on the L04
    // tier, pre_open_tree opens every regular file under root_pid's
    // cwd at PreExec and calls fstat_meta on each fd. Adding
    // flistxattr to that hot path triggered a helper crash on the
    // AR00 runner — reproducible "UnwatchTree dispatch failed: EPIPE"
    // pattern that timed out wait-watch-ready and broke the
    // edit/rm/chmod/mv-undo-linux smokes. Linux xattr capture
    // doesn't have a validating smoke yet, and the platform target
    // for W09.21 is FreeBSD; punt the Linux read to a follow-up.
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read(fd)
    }
    #[cfg(target_os = "macos")]
    {
        macos::read(fd)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "macos")))]
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

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::fd::RawFd;

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
    }

    /// Apple's xattr list format: NUL-terminated names concatenated.
    /// Different from FreeBSD's length-prefixed form. Empty value
    /// list returns 0 with success (no xattrs).
    ///
    /// Capture the FULL xattr set on macOS — `com.apple.quarantine`,
    /// codesign signatures, Spotlight metadata, ACLs, FinderInfo —
    /// all need restoration during undo or the file ends up
    /// user-visibly broken (signed binaries unsigned, etc.).
    pub fn read(fd: RawFd) -> BTreeMap<String, Vec<u8>> {
        // First call with NULL/0 → returns the size needed.
        // SAFETY: passing 0/NULL is the documented size-query form;
        // fd is borrowed-valid for this call.
        let list_size = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
        if list_size <= 0 {
            return BTreeMap::new();
        }
        let mut buf = vec![0u8; list_size as usize];
        // SAFETY: buf has list_size bytes; fd borrowed-valid.
        let n = unsafe { flistxattr(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            return BTreeMap::new();
        }
        let mut out = BTreeMap::new();
        // Split on NUL; skip the trailing empty slice the split
        // produces when the buffer ends with a NUL.
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
            // SAFETY: cname NUL-terminated; fd borrowed-valid;
            // value=NULL/size=0 is the size-query form.
            let val_size = unsafe { fgetxattr(fd, cname.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
            if val_size < 0 {
                continue;
            }
            let mut val = vec![0u8; val_size as usize];
            // SAFETY: val has val_size bytes; fd + cname still valid.
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
}

#[cfg(all(test, target_os = "freebsd"))]
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

#[cfg(all(test, target_os = "macos"))]
mod tests_macos {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    // NOTE: macOS Sonoma+ auto-stamps `com.apple.provenance` on every
    // newly-created file, so we can't assert "fresh file has no
    // xattrs". The smoke gate is "we can read xattrs and round-trip
    // a user-set one without corrupting it".

    #[test]
    fn round_trips_a_user_xattr() {
        // Set an xattr via shell `xattr -w` (Apple's CLI) on a real
        // file in tempdir, then read it via our binding. Skips if
        // `xattr` is unavailable (CI image quirk).
        let xattr = match std::process::Command::new("xattr").arg("-h").output() {
            Ok(o) if o.status.success() => "xattr",
            _ => {
                eprintln!("skip: `xattr` CLI not present");
                return;
            }
        };
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("xattr-target.txt");
        std::fs::File::create(&p).unwrap().write_all(b"x").unwrap();
        let set = std::process::Command::new(xattr)
            .args(["-w", "com.example.shit-test", "the-value"])
            .arg(&p)
            .status()
            .expect("xattr -w");
        if !set.success() {
            eprintln!("skip: xattr -w returned non-success — fs likely lacks xattr support");
            return;
        }
        let f = std::fs::File::open(&p).unwrap();
        let got = read_user_xattrs(f.as_raw_fd());
        let val = got
            .get("com.example.shit-test")
            .expect("xattr key not captured");
        assert_eq!(val, b"the-value", "captured xattr value mismatch");
    }
}
