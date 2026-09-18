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
//! - **Linux:** `flistxattr(2)` / `fgetxattr(2)`, limited to the
//!   restorable `user.*` namespace.

use std::collections::BTreeMap;
use std::os::fd::RawFd;

/// Best-effort compatibility wrapper. Capture paths that treat the returned
/// map as authoritative MUST use [`try_read_user_xattrs`] instead: an empty
/// map after a read error would make undo delete attributes it never saw.
#[allow(dead_code)] // FreeBSD's Capsicum capture still needs the non-authoritative fallback.
pub fn read_user_xattrs(fd: RawFd) -> BTreeMap<String, Vec<u8>> {
    try_read_user_xattrs(fd).unwrap_or_default()
}

/// Strict xattr snapshot off an already-open descriptor.
///
/// `Ok(empty)` means the filesystem positively reported no restorable
/// attributes. List/read/encoding/race/cap failures remain errors so the
/// caller can emit `CaptureRefused` rather than authoritative empty state.
pub fn try_read_user_xattrs(fd: RawFd) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    // NOTE (W09.21 / capsicum-default-on interaction): on FreeBSD with
    // cap_enter active (B05 default), `extattr_*_fd` returns no
    // attributes on tracked fds even when the file has them — capsicum
    // does not include CAP_EXTATTR_* in the implicit rights of an
    // O_RDONLY-opened fd. Fix path is to cap_rights_limit each
    // subtree fd with CAP_EXTATTR_GET|LIST|SET|DELETE, or to open
    // fds before cap_enter with rights explicitly carried in. Until
    // then xattr capture is a no-op when capsicum is active; the
    // smoke validates the round-trip with SHIT_CAPSICUM=0.
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read(fd)
    }
    #[cfg(target_os = "macos")]
    {
        macos::read(fd)
    }
    #[cfg(target_os = "linux")]
    {
        linux::read(fd)
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "descriptor xattr capture is unsupported on this platform",
        ))
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
    pub fn read(fd: RawFd) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
        const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;
        let ns = libc::EXTATTR_NAMESPACE_USER;
        // First call with NULL/0 returns the size needed.
        let list_size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if list_size == 0 {
            return Ok(BTreeMap::new());
        }
        let list_size = usize::try_from(list_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name-list length does not fit usize",
            )
        })?;
        if list_size > XATTR_CAPTURE_CAP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "xattr name list is {list_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
                ),
            ));
        }
        let mut buf = vec![0u8; list_size];
        let n = unsafe { libc::extattr_list_fd(fd, ns, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n as usize != list_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("xattr name list changed during capture (expected {list_size}, read {n})"),
            ));
        }
        let mut out = BTreeMap::new();
        let mut total = list_size;
        let mut i = 0usize;
        let end = n as usize;
        while i < end {
            let len = buf[i] as usize;
            i += 1;
            if i + len > end {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed FreeBSD xattr name list",
                ));
            }
            let name_bytes = &buf[i..i + len];
            i += len;
            let name = std::str::from_utf8(name_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            let cname = CString::new(name).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr name contains NUL: {e}"),
                )
            })?;
            let val_size =
                unsafe { libc::extattr_get_fd(fd, ns, cname.as_ptr(), std::ptr::null_mut(), 0) };
            if val_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let val_size = usize::try_from(val_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {name:?} length does not fit usize"),
                )
            })?;
            total = total.checked_add(val_size).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr capture length overflow",
                )
            })?;
            if total > XATTR_CAPTURE_CAP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr capture exceeds the {XATTR_CAPTURE_CAP}-byte aggregate cap"),
                ));
            }
            let mut val = vec![0u8; val_size];
            let m = unsafe {
                libc::extattr_get_fd(fd, ns, cname.as_ptr(), val.as_mut_ptr().cast(), val.len())
            };
            if m < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if m as usize != val_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xattr {name:?} changed during capture (expected {val_size}, read {m})"
                    ),
                ));
            }
            out.insert(name.to_string(), val);
        }
        Ok(out)
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
    pub fn read(fd: RawFd) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
        const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;
        // First call with NULL/0 → returns the size needed.
        // SAFETY: passing 0/NULL is the documented size-query form;
        // fd is borrowed-valid for this call.
        let list_size = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if list_size == 0 {
            return Ok(BTreeMap::new());
        }
        let list_size = usize::try_from(list_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name-list length does not fit usize",
            )
        })?;
        if list_size > XATTR_CAPTURE_CAP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "xattr name list is {list_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
                ),
            ));
        }
        let mut buf = vec![0u8; list_size];
        // SAFETY: buf has list_size bytes; fd borrowed-valid.
        let n = unsafe { flistxattr(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n as usize != list_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("xattr name list changed during capture (expected {list_size}, read {n})"),
            ));
        }
        let mut out = BTreeMap::new();
        let mut total = list_size;
        // Split on NUL; skip the trailing empty slice the split
        // produces when the buffer ends with a NUL.
        for name_bytes in buf[..n as usize]
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
        {
            let name = std::str::from_utf8(name_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            let cname = CString::new(name).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr name contains NUL: {e}"),
                )
            })?;
            // SAFETY: cname NUL-terminated; fd borrowed-valid;
            // value=NULL/size=0 is the size-query form.
            let val_size = unsafe { fgetxattr(fd, cname.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
            if val_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let val_size = usize::try_from(val_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {name:?} length does not fit usize"),
                )
            })?;
            total = total.checked_add(val_size).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr capture length overflow",
                )
            })?;
            if total > XATTR_CAPTURE_CAP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr capture exceeds the {XATTR_CAPTURE_CAP}-byte aggregate cap"),
                ));
            }
            let mut val = vec![0u8; val_size];
            // SAFETY: val has val_size bytes; fd + cname still valid.
            let m =
                unsafe { fgetxattr(fd, cname.as_ptr(), val.as_mut_ptr().cast(), val.len(), 0, 0) };
            if m < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if m as usize != val_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xattr {name:?} changed during capture (expected {val_size}, read {m})"
                    ),
                ));
            }
            out.insert(name.to_string(), val);
        }
        Ok(out)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::fd::RawFd;

    pub fn read(fd: RawFd) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
        const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;

        let list_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if list_size == 0 {
            return Ok(BTreeMap::new());
        }
        let list_size = usize::try_from(list_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name-list length does not fit usize",
            )
        })?;
        if list_size > XATTR_CAPTURE_CAP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "xattr name list is {list_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
                ),
            ));
        }
        let mut names = vec![0 as libc::c_char; list_size];
        let got = unsafe { libc::flistxattr(fd, names.as_mut_ptr(), names.len()) };
        if got < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if got as usize != list_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "xattr name list changed during capture (expected {list_size}, read {got})"
                ),
            ));
        }

        let name_bytes =
            unsafe { std::slice::from_raw_parts(names.as_ptr().cast::<u8>(), names.len()) };
        let mut out = BTreeMap::new();
        let mut total = list_size;
        for raw in name_bytes
            .split(|byte| *byte == 0)
            .filter(|raw| !raw.is_empty())
        {
            let full = std::str::from_utf8(raw).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            let Some(name) = full.strip_prefix("user.") else {
                continue;
            };
            let c_name = CString::new(full).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr name contains NUL: {e}"),
                )
            })?;
            let value_size =
                unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
            if value_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let value_size = usize::try_from(value_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {full:?} length does not fit usize"),
                )
            })?;
            total = total.checked_add(value_size).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr capture length overflow",
                )
            })?;
            if total > XATTR_CAPTURE_CAP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr capture exceeds the {XATTR_CAPTURE_CAP}-byte aggregate cap"),
                ));
            }
            let mut value = vec![0u8; value_size];
            let read = unsafe {
                libc::fgetxattr(fd, c_name.as_ptr(), value.as_mut_ptr().cast(), value.len())
            };
            if read < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if read as usize != value_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xattr {full:?} changed during capture (expected {value_size}, read {read})"
                    ),
                ));
            }
            out.insert(name.to_string(), value);
        }
        Ok(out)
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
