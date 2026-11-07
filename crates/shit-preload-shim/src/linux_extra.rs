// SPDX-License-Identifier: AGPL-3.0-or-later

//! L5 — Linux interposers for the symbols glibc programs reach instead
//! of `open`/`openat`, and for directory creation and removal.
//!
//! Anything built with `_FILE_OFFSET_BITS=64` (CPython and Rust's std
//! among them) calls `open64`/`openat64`, and with `_FORTIFY_SOURCE` the
//! two-argument forms become `__open64_2`/`__openat64_2`. `os.makedirs`
//! is `mkdir`, and `shutil.rmtree` removes its top directory with a plain
//! `rmdir`. None of these reached the shim, so pip's new tree and the top
//! of its stash were unjournaled.
//!
//! The open family uses the same policy as `open`/`openat`
//! ([`policy::write_open_begin`]): a Create only for a path that was
//! absent before a call that succeeded, the bytes of an existing file,
//! or a capture-gap marker when they could not be read. `mkdir`/`mkdirat`
//! resolve their target before the syscall and notify only after it
//! succeeds, so a `mkdir -p` step that returns EEXIST journals no Create.

use super::interposers::cstr_to_string;
use super::{next, policy};
use libc::{O_CREAT, O_TRUNC, O_WRONLY, c_char, c_int, c_uint, mode_t};
use std::sync::OnceLock;

/// The next definition of `$name`, typed `$ty`, or `None`.
macro_rules! real {
    ($name:literal, $ty:ty) => {{
        static SYM: OnceLock<usize> = OnceLock::new();
        match next::lookup(&SYM, concat!($name, "\0").as_bytes()) {
            0 => None,
            // SAFETY: dlsym returned the next definition of this libc
            // symbol, whose C signature is `$ty`.
            addr => Some(unsafe { std::mem::transmute::<usize, $ty>(addr) }),
        }
    }};
}

type OpenFn = unsafe extern "C" fn(*const c_char, c_int, c_uint) -> c_int;
type OpenAtFn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_uint) -> c_int;
type Open2Fn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type OpenAt2Fn = unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int;
type CreatFn = unsafe extern "C" fn(*const c_char, mode_t) -> c_int;
type MkdirFn = unsafe extern "C" fn(*const c_char, mode_t) -> c_int;
type MkdirAtFn = unsafe extern "C" fn(c_int, *const c_char, mode_t) -> c_int;
type RmdirFn = unsafe extern "C" fn(*const c_char) -> c_int;

fn enosys() -> c_int {
    // SAFETY: errno is a valid thread-local lvalue.
    unsafe { policy::set_errno(libc::ENOSYS) };
    -1
}

/// Run a path open under the shared write-open policy.
fn path_open(path: *const c_char, flags: c_int, call: impl FnOnce() -> c_int) -> c_int {
    let pending = policy::write_open_begin(
        "open",
        policy::OpenTarget::Path(&cstr_to_string(path)),
        flags,
    );
    let rc = call();
    policy::write_open_end(pending, rc);
    rc
}

/// Run a dirfd-relative open under the shared write-open policy.
fn at_open(dirfd: c_int, path: *const c_char, flags: c_int, call: impl FnOnce() -> c_int) -> c_int {
    let pending = policy::write_open_begin(
        "openat",
        policy::OpenTarget::At(dirfd, &cstr_to_string(path)),
        flags,
    );
    let rc = call();
    policy::write_open_end(pending, rc);
    rc
}

/// `open64(2)`.
///
/// # Safety
/// libc `open64` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    path_open(path, flags, || match real!("open64", OpenFn) {
        Some(f) => unsafe { f(path, flags, mode) },
        None => enosys(),
    })
}

/// `openat64(2)`.
///
/// # Safety
/// libc `openat64` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_uint,
) -> c_int {
    at_open(dirfd, path, flags, || match real!("openat64", OpenAtFn) {
        Some(f) => unsafe { f(dirfd, path, flags, mode) },
        None => enosys(),
    })
}

/// glibc's `_FORTIFY_SOURCE` entry for a two-argument `open`.
///
/// # Safety
/// glibc `__open_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    path_open(path, flags, || match real!("__open_2", Open2Fn) {
        Some(f) => unsafe { f(path, flags) },
        None => enosys(),
    })
}

/// glibc's `_FORTIFY_SOURCE` entry for a two-argument `open64`.
///
/// # Safety
/// glibc `__open64_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    path_open(path, flags, || match real!("__open64_2", Open2Fn) {
        Some(f) => unsafe { f(path, flags) },
        None => enosys(),
    })
}

/// glibc's `_FORTIFY_SOURCE` entry for a two-argument `openat`.
///
/// # Safety
/// glibc `__openat_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    at_open(dirfd, path, flags, || {
        match real!("__openat_2", OpenAt2Fn) {
            Some(f) => unsafe { f(dirfd, path, flags) },
            None => enosys(),
        }
    })
}

/// glibc's `_FORTIFY_SOURCE` entry for a two-argument `openat64`.
///
/// # Safety
/// glibc `__openat64_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    at_open(dirfd, path, flags, || {
        match real!("__openat64_2", OpenAt2Fn) {
            Some(f) => unsafe { f(dirfd, path, flags) },
            None => enosys(),
        }
    })
}

/// `creat(2)`, which is `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
///
/// # Safety
/// libc `creat` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat(path: *const c_char, mode: mode_t) -> c_int {
    path_open(path, O_CREAT | O_WRONLY | O_TRUNC, || {
        match real!("creat", CreatFn) {
            Some(f) => unsafe { f(path, mode) },
            None => enosys(),
        }
    })
}

/// `creat64(2)`.
///
/// # Safety
/// libc `creat64` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat64(path: *const c_char, mode: mode_t) -> c_int {
    path_open(path, O_CREAT | O_WRONLY | O_TRUNC, || {
        match real!("creat64", CreatFn) {
            Some(f) => unsafe { f(path, mode) },
            None => enosys(),
        }
    })
}
/// `mkdir(2)`: resolve first, notify after success only.
///
/// # Safety
/// libc `mkdir` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
    let (resolved, failure) = policy::canonicalize_or_raw(&cstr_to_string(path), "path");
    let rc = match real!("mkdir", MkdirFn) {
        Some(f) => unsafe { f(path, mode) },
        None => enosys(),
    };
    if rc == 0 {
        policy::notify_create_resolved("mkdir", &resolved, failure);
    }
    rc
}

/// `mkdirat(2)`: resolve against the dirfd first, notify after success.
///
/// # Safety
/// libc `mkdirat` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
    let target = policy::resolve_at_for_notify(dirfd, &cstr_to_string(path), "path");
    let rc = match real!("mkdirat", MkdirAtFn) {
        Some(f) => unsafe { f(dirfd, path, mode) },
        None => enosys(),
    };
    if rc == 0 {
        match target {
            policy::AtResolution::Resolved(abs) => {
                policy::notify_create_resolved("mkdirat", &abs, None)
            }
            policy::AtResolution::Failed(raw, failure) => {
                policy::notify_create_resolved("mkdirat", &raw, Some(failure))
            }
            // The parent was missing before the call; it cannot have
            // succeeded, but there is nothing to key either way.
            policy::AtResolution::Nothing => {}
        }
    }
    rc
}

/// `rmdir(2)`: notify before the syscall, as an unlink of a directory.
///
/// # Safety
/// libc `rmdir` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    let pending = policy::removal_begin("rmdir", &cstr_to_string(path));
    let rc = match real!("rmdir", RmdirFn) {
        Some(f) => unsafe { f(path) },
        None => enosys(),
    };
    policy::removal_end(pending, rc);
    rc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::test_capture;
    use std::ffi::CString;
    use std::os::unix::io::AsRawFd;

    fn c(p: &std::path::Path) -> CString {
        CString::new(p.to_str().unwrap()).unwrap()
    }

    #[test]
    fn open64_create_is_notified_after_success() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = dir.join("new.txt");
        let cp = c(&p);
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o644) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "open_create");
        assert_eq!(notes[0].arg, p.to_str().unwrap());
        assert!(notes[0].pre_image.is_none());
    }

    #[test]
    fn open64_read_only_sends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("r");
        std::fs::write(&p, b"r").unwrap();
        let cp = c(&p);
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), libc::O_RDONLY, 0) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert!(notes.is_empty(), "{notes:#?}");
    }

    #[test]
    fn openat64_over_existing_file_carries_its_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::write(dir.join("f"), b"old").unwrap();
        let d = std::fs::File::open(&dir).unwrap();
        let name = CString::new("f").unwrap();
        let notes = test_capture::capture(|| {
            let fd = unsafe { openat64(d.as_raw_fd(), name.as_ptr(), O_WRONLY | O_TRUNC, 0) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "openat");
        let pre = notes[0].pre_image.as_ref().expect("pre-image");
        assert_eq!(pre.path, dir.join("f").to_str().unwrap());
        assert_eq!(pre.bytes, b"old");
    }

    #[test]
    fn mkdir_notifies_after_success_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = c(&dir.join("d"));
        let notes = test_capture::capture(|| {
            assert_eq!(unsafe { mkdir(p.as_ptr(), 0o755) }, 0);
            // EEXIST: no second Create.
            assert_eq!(unsafe { mkdir(p.as_ptr(), 0o755) }, -1);
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "mkdir");
        assert_eq!(notes[0].arg, dir.join("d").to_str().unwrap());
    }

    #[test]
    fn mkdirat_resolves_against_the_dirfd() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let d = std::fs::File::open(&dir).unwrap();
        let name = CString::new("sub").unwrap();
        let notes = test_capture::capture(|| {
            assert_eq!(unsafe { mkdirat(d.as_raw_fd(), name.as_ptr(), 0o700) }, 0);
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "mkdirat");
        assert_eq!(notes[0].arg, dir.join("sub").to_str().unwrap());
    }

    #[test]
    fn rmdir_notifies_after_success_with_its_pre_call_stat() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(dir.join("gone")).unwrap();
        std::fs::set_permissions(dir.join("gone"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = c(&dir.join("gone"));
        let notes = test_capture::capture(|| {
            assert_eq!(unsafe { rmdir(p.as_ptr()) }, 0);
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "rmdir");
        assert_eq!(notes[0].arg, dir.join("gone").to_str().unwrap());
        assert!(notes[0].failure.is_none());
        assert_eq!(notes[0].pre_stat.map(|s| s.mode), Some(0o040700));
        assert!(!dir.join("gone").exists());
    }

    /// Review item 1: an existing file the shim cannot read must not look
    /// like a fresh create (the daemon would journal a Create and undo
    /// would unlink the user's file).
    #[test]
    fn open64_of_an_unreadable_existing_file_sends_a_gap_marker() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = dir.join("wo");
        std::fs::write(&p, b"keep me").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o200)).unwrap();
        if std::fs::read(&p).is_ok() {
            return; // running as root: the file is readable anyway
        }
        let cp = c(&p);
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), O_WRONLY, 0) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert!(notes[0].pre_image.is_none());
        assert!(
            matches!(
                notes[0].failure,
                Some(shit_proto::ShimFailure::PreImageUncaptured { .. })
            ),
            "{notes:#?}"
        );
        assert_ne!(notes[0].syscall, "open_create");
    }

    #[test]
    fn open64_of_a_file_over_the_cap_sends_a_gap_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = dir.join("big");
        std::fs::File::create(&p)
            .unwrap()
            .set_len(shit_proto::SHIM_INLINE_PREIMAGE_CAP + 1)
            .unwrap();
        let cp = c(&p);
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), O_WRONLY | O_TRUNC, 0) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert!(
            matches!(
                notes[0].failure,
                Some(shit_proto::ShimFailure::PreImageUncaptured { .. })
            ),
            "{notes:#?}"
        );
    }

    /// Review item 4: `O_TMPFILE` names nothing.
    #[test]
    fn open64_with_o_tmpfile_sends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let cp = c(&tmp.path().canonicalize().unwrap());
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), libc::O_TMPFILE | O_WRONLY, 0o600) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        });
        assert!(notes.is_empty(), "{notes:#?}");
    }

    /// A failed create journals nothing.
    #[test]
    fn open64_create_that_fails_sends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let cp = c(&tmp.path().join("missing/x"));
        let notes = test_capture::capture(|| {
            assert!(unsafe { open64(cp.as_ptr(), O_WRONLY | O_CREAT, 0o644) } < 0);
        });
        assert!(notes.is_empty(), "{notes:#?}");
    }

    /// Review item 3: `rmdir --ignore-fail-on-non-empty`, `os.removedirs`.
    /// A refused rmdir removed nothing and must journal nothing.
    #[test]
    fn rmdir_of_a_non_empty_dir_sends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(dir.join("full")).unwrap();
        std::fs::write(dir.join("full/f"), b"f").unwrap();
        let p = c(&dir.join("full"));
        let notes = test_capture::capture(|| {
            assert_eq!(unsafe { rmdir(p.as_ptr()) }, -1);
        });
        assert!(notes.is_empty(), "{notes:#?}");
        assert!(dir.join("full/f").exists());
    }

    #[test]
    fn creat_over_existing_file_carries_its_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::write(dir.join("f"), b"old").unwrap();
        let p = c(&dir.join("f"));
        let notes = test_capture::capture(|| {
            let fd = unsafe { creat(p.as_ptr(), 0o644) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].pre_image.as_ref().unwrap().bytes, b"old");
    }
}
