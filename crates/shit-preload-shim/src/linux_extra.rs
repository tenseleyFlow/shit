// SPDX-License-Identifier: AGPL-3.0-or-later

//! L5 — Linux interposers for the symbols glibc programs reach instead
//! of `open`/`openat`, and for directory creation and removal.
//!
//! Anything built with `_FILE_OFFSET_BITS=64` (CPython among them)
//! calls `open64`/`openat64`, and with `_FORTIFY_SOURCE` the two-argument
//! forms become `__open64_2`/`__openat64_2`. `os.makedirs` is `mkdir`,
//! and `shutil.rmtree` removes its top directory with a plain `rmdir`.
//! None of these reached the shim, so pip's new tree and the top of its
//! stash were unjournaled.
//!
//! The open family keeps `open`'s policy exactly: notify before the
//! syscall on any write-capable open, with the pre-image when the target
//! exists. `mkdir`/`mkdirat` resolve their target before the syscall and
//! notify only after it succeeds, so a `mkdir -p` step that returns
//! EEXIST journals no Create. `rmdir` notifies before the syscall, while
//! the directory still exists for the daemon's kind and mode read.

use super::policy;
use libc::{O_CREAT, O_RDWR, O_TRUNC, O_WRONLY, c_char, c_int, c_uint, mode_t};
use std::sync::OnceLock;

fn cstr_to_string(path: *const c_char) -> String {
    if path.is_null() {
        return String::new();
    }
    // SAFETY: libc contract: non-null `path` is NUL-terminated.
    unsafe { std::ffi::CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned()
}

fn writes(flags: c_int) -> bool {
    (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0
}

/// `dlsym(RTLD_NEXT, name)`, cached; 0 when the symbol is absent.
fn next_sym(cache: &'static OnceLock<usize>, name: &'static [u8]) -> usize {
    *cache.get_or_init(|| {
        debug_assert!(name.last() == Some(&0));
        // SAFETY: NUL-terminated name, RTLD_NEXT pseudo-handle.
        unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast::<c_char>()) as usize }
    })
}

macro_rules! real {
    ($name:literal, $ty:ty) => {{
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = next_sym(&SYM, concat!($name, "\0").as_bytes());
        if addr == 0 {
            None
        } else {
            // SAFETY: dlsym returned the next definition of this libc
            // symbol, whose C signature is `$ty`.
            Some(unsafe { std::mem::transmute::<usize, $ty>(addr) })
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
    // SAFETY: errno location is thread-local and always valid.
    unsafe { *libc::__errno_location() = libc::ENOSYS };
    -1
}

fn notify_open(flags: c_int, path: *const c_char) {
    if writes(flags) {
        policy::notify_pre_mutation_with_content("open", &cstr_to_string(path));
    }
}

fn notify_openat(dirfd: c_int, flags: c_int, path: *const c_char) {
    if writes(flags) {
        policy::notify_pre_mutation_with_content_at("openat", dirfd, &cstr_to_string(path));
    }
}

/// `open64(2)`: same policy as the `open` interposer.
///
/// # Safety
/// libc `open64` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    notify_open(flags, path);
    match real!("open64", OpenFn) {
        Some(f) => unsafe { f(path, flags, mode) },
        None => enosys(),
    }
}

/// `openat64(2)`: same policy as the `openat` interposer.
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
    notify_openat(dirfd, flags, path);
    match real!("openat64", OpenAtFn) {
        Some(f) => unsafe { f(dirfd, path, flags, mode) },
        None => enosys(),
    }
}

/// glibc's `_FORTIFY_SOURCE` entry for a two-argument `open`.
///
/// # Safety
/// glibc `__open_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    notify_open(flags, path);
    match real!("__open_2", Open2Fn) {
        Some(f) => unsafe { f(path, flags) },
        None => enosys(),
    }
}

/// glibc's `_FORTIFY_SOURCE` entry for a two-argument `open64`.
///
/// # Safety
/// glibc `__open64_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    notify_open(flags, path);
    match real!("__open64_2", Open2Fn) {
        Some(f) => unsafe { f(path, flags) },
        None => enosys(),
    }
}

/// glibc's `_FORTIFY_SOURCE` entry for a three-argument-less `openat`.
///
/// # Safety
/// glibc `__openat_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    notify_openat(dirfd, flags, path);
    match real!("__openat_2", OpenAt2Fn) {
        Some(f) => unsafe { f(dirfd, path, flags) },
        None => enosys(),
    }
}

/// glibc's `_FORTIFY_SOURCE` entry for a three-argument-less `openat64`.
///
/// # Safety
/// glibc `__openat64_2` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    notify_openat(dirfd, flags, path);
    match real!("__openat64_2", OpenAt2Fn) {
        Some(f) => unsafe { f(dirfd, path, flags) },
        None => enosys(),
    }
}

/// `creat(2)`, which is `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
///
/// # Safety
/// libc `creat` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat(path: *const c_char, mode: mode_t) -> c_int {
    notify_open(O_CREAT | O_WRONLY | O_TRUNC, path);
    match real!("creat", CreatFn) {
        Some(f) => unsafe { f(path, mode) },
        None => enosys(),
    }
}

/// `creat64(2)`.
///
/// # Safety
/// libc `creat64` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat64(path: *const c_char, mode: mode_t) -> c_int {
    notify_open(O_CREAT | O_WRONLY | O_TRUNC, path);
    match real!("creat64", CreatFn) {
        Some(f) => unsafe { f(path, mode) },
        None => enosys(),
    }
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
    policy::notify_removal("rmdir", &cstr_to_string(path));
    match real!("rmdir", RmdirFn) {
        Some(f) => unsafe { f(path) },
        None => enosys(),
    }
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
    fn open64_create_journals_like_open() {
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
        assert_eq!(notes[0].syscall, "open");
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
    fn rmdir_notifies_before_with_the_canonical_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(dir.join("gone")).unwrap();
        let p = c(&dir.join("gone"));
        let notes = test_capture::capture(|| {
            assert_eq!(unsafe { rmdir(p.as_ptr()) }, 0);
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "rmdir");
        assert_eq!(notes[0].arg, dir.join("gone").to_str().unwrap());
        assert!(notes[0].failure.is_none());
        assert!(!dir.join("gone").exists());
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
