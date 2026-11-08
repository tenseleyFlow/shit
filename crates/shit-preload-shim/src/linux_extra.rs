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
//! ([`policy::write_open`]): a Create only for a path that was
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
    (@ident $name:ident, $ty:ty) => {
        real!(@sym concat!(stringify!($name), "\0"), $ty)
    };
    ($name:literal, $ty:ty) => {
        real!(@sym concat!($name, "\0"), $ty)
    };
    (@sym $sym:expr, $ty:ty) => {{
        static SYM: OnceLock<usize> = OnceLock::new();
        match next::lookup(&SYM, $sym.as_bytes()) {
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

/// Review round 2, item 5: when `dlsym(RTLD_NEXT)` finds no next
/// definition the call still runs, as the kernel syscall, the way the
/// `open`/`openat` interposers fall back. Never fail the user's call
/// because the shim could not find a symbol.
mod sys {
    use libc::{c_char, c_int, c_uint, mode_t};

    pub fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
        // SAFETY: the caller's open contract; raw openat(2).
        unsafe { libc::syscall(libc::SYS_openat, dirfd, path, flags, mode) as c_int }
    }

    pub fn mkdirat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
        // SAFETY: the caller's mkdir contract; raw mkdirat(2).
        unsafe { libc::syscall(libc::SYS_mkdirat, dirfd, path, mode) as c_int }
    }

    pub fn rmdir(path: *const c_char) -> c_int {
        // SAFETY: the caller's rmdir contract; raw unlinkat(2).
        unsafe {
            libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path, libc::AT_REMOVEDIR) as c_int
        }
    }
}

/// Run a path open under the shared write-open policy. `call` gets the
/// flags to use (the policy may add `O_EXCL`; see [`policy::write_open`]).
fn path_open(path: *const c_char, flags: c_int, call: impl Fn(c_int) -> c_int) -> c_int {
    policy::write_open(
        "open",
        flags,
        || policy::OpenTarget::Path(cstr_to_string(path)),
        call,
    )
}

/// Run a dirfd-relative open under the shared write-open policy.
fn at_open(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    call: impl Fn(c_int) -> c_int,
) -> c_int {
    policy::write_open(
        "openat",
        flags,
        || policy::OpenTarget::At(dirfd, cstr_to_string(path)),
        call,
    )
}

/// `open64(2)`.
///
/// # Safety
/// libc `open64` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    path_open(path, flags, |f| match real!("open64", OpenFn) {
        Some(open) => unsafe { open(path, f, mode) },
        None => sys::openat(libc::AT_FDCWD, path, f, mode),
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
    at_open(dirfd, path, flags, |f| match real!("openat64", OpenAtFn) {
        Some(open) => unsafe { open(dirfd, path, f, mode) },
        None => sys::openat(dirfd, path, f, mode),
    })
}

/// glibc's `_FORTIFY_SOURCE` entries for a two-argument open. glibc
/// aborts in these on `O_CREAT`, so the policy never adds `O_EXCL` here;
/// any other flags go to the raw syscall.
macro_rules! fortify_open {
    ($name:ident) => {
        #[doc = concat!("glibc's `", stringify!($name), "`.")]
        ///
        /// # Safety
        /// The glibc contract of the same name.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(path: *const c_char, flags: c_int) -> c_int {
            path_open(path, flags, |f| match real!(@ident $name, Open2Fn) {
                Some(open) if f == flags => unsafe { open(path, f) },
                _ => sys::openat(libc::AT_FDCWD, path, f, 0),
            })
        }
    };
    ($name:ident, at) => {
        #[doc = concat!("glibc's `", stringify!($name), "`.")]
        ///
        /// # Safety
        /// The glibc contract of the same name.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
            at_open(dirfd, path, flags, |f| {
                match real!(@ident $name, OpenAt2Fn) {
                    Some(open) if f == flags => unsafe { open(dirfd, path, f) },
                    _ => sys::openat(dirfd, path, f, 0),
                }
            })
        }
    };
}

fortify_open!(__open_2);
fortify_open!(__open64_2);
fortify_open!(__openat_2, at);
fortify_open!(__openat64_2, at);

/// `creat(2)` and `creat64(2)`, which are `open(path,
/// O_CREAT|O_WRONLY|O_TRUNC, mode)`. When the policy adds `O_EXCL` the
/// call is made as that open.
macro_rules! creat_open {
    ($name:ident) => {
        #[doc = concat!("`", stringify!($name), "(2)`.")]
        ///
        /// # Safety
        /// The libc contract of the same name.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(path: *const c_char, mode: mode_t) -> c_int {
            const FLAGS: c_int = O_CREAT | O_WRONLY | O_TRUNC;
            path_open(path, FLAGS, |f| match real!(@ident $name, CreatFn) {
                Some(creat) if f == FLAGS => unsafe { creat(path, mode) },
                _ => sys::openat(libc::AT_FDCWD, path, f, mode as c_uint),
            })
        }
    };
}

creat_open!(creat);
creat_open!(creat64);

/// `mkdir(2)`: resolve first, notify after success only.
///
/// # Safety
/// libc `mkdir` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
    let raw = cstr_to_string(path);
    let target = (!policy::idle(&raw)).then(|| policy::canonicalize_or_raw(&raw, "path"));
    let rc = match real!("mkdir", MkdirFn) {
        Some(f) => unsafe { f(path, mode) },
        None => sys::mkdirat(libc::AT_FDCWD, path, mode),
    };
    if rc == 0
        && let Some((resolved, failure)) = target
    {
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
    let raw = cstr_to_string(path);
    let target = if policy::idle(&raw) {
        policy::AtResolution::Nothing
    } else {
        policy::resolve_at_for_notify(dirfd, &raw, "path")
    };
    let rc = match real!("mkdirat", MkdirAtFn) {
        Some(f) => unsafe { f(dirfd, path, mode) },
        None => sys::mkdirat(dirfd, path, mode),
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
        None => sys::rmdir(path),
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
        assert_eq!(notes[0].pre_stat.as_ref().map(|s| s.mode), Some(0o040700));
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

    /// Review round 2, item 6: a read-only open can still create the file.
    #[test]
    fn read_only_open_with_o_creat_journals_the_create() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = dir.join("lock");
        let cp = c(&p);
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), libc::O_RDONLY | O_CREAT, 0o644) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "open_create");
        assert_eq!(notes[0].arg, p.to_str().unwrap());
    }

    #[test]
    fn read_only_open_with_o_creat_of_an_existing_file_sends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("lock");
        std::fs::write(&p, b"held").unwrap();
        let cp = c(&p);
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(cp.as_ptr(), libc::O_RDONLY | O_CREAT, 0o644) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert!(notes.is_empty(), "{notes:#?}");
    }

    /// Review round 2, item 5: when `dlsym(RTLD_NEXT)` finds nothing the
    /// call still happens, through the syscall.
    #[test]
    fn syscall_fallbacks_do_the_call() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let f = c(&dir.join("f"));
        let fd = sys::openat(libc::AT_FDCWD, f.as_ptr(), O_WRONLY | O_CREAT, 0o600);
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        unsafe { libc::close(fd) };
        assert!(dir.join("f").exists());
        let d = c(&dir.join("d"));
        assert_eq!(sys::mkdirat(libc::AT_FDCWD, d.as_ptr(), 0o700), 0);
        assert!(dir.join("d").is_dir());
        assert_eq!(sys::rmdir(d.as_ptr()), 0);
        assert!(!dir.join("d").exists());
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

    /// Review round 5, item 5: another process creates the path between
    /// the shim's lstat and the open. This call did not create it: no
    /// Create (undo would unlink the other process's file); its bytes are
    /// captured as an existing file's.
    #[test]
    fn racing_creator_is_not_journaled_as_this_calls_create() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = dir.join("raced");
        let cp = c(&p);
        let theirs = cp.clone();
        let notes = test_capture::capture(|| {
            // The other process: the raw syscall, which the shim does
            // not see.
            test_capture::before_create(move || {
                let fd = sys::openat(libc::AT_FDCWD, theirs.as_ptr(), O_WRONLY | O_CREAT, 0o644);
                assert!(fd >= 0);
                assert_eq!(unsafe { libc::write(fd, b"theirs".as_ptr().cast(), 6) }, 6);
                unsafe { libc::close(fd) };
            });
            let fd = unsafe { open64(cp.as_ptr(), O_WRONLY | O_CREAT, 0o644) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert!(
            notes.iter().all(|n| n.syscall != "open_create"),
            "{notes:#?}"
        );
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].pre_image.as_ref().unwrap().bytes, b"theirs");
    }

    /// The `O_EXCL` first attempt is invisible to a caller that creates
    /// the file, and creat's own flags still apply.
    #[test]
    fn creat_of_a_new_path_is_one_create() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let p = c(&dir.join("n"));
        let notes = test_capture::capture(|| {
            let fd = unsafe { creat(p.as_ptr(), 0o600) };
            assert!(fd >= 0);
            assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert_eq!(notes[0].syscall, "open_create");
        assert_eq!(std::fs::read(dir.join("n")).unwrap(), b"x");
    }

    /// #223 / D-22: a write-open follows the final symlink, so the note
    /// and its pre-image name the target `echo > link` writes.
    #[test]
    fn write_open_through_a_symlink_captures_the_target() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::write(dir.join("target"), b"old").unwrap();
        std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
        let p = c(&dir.join("link"));
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(p.as_ptr(), O_WRONLY | O_TRUNC, 0) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
        assert_eq!(notes.len(), 1, "{notes:#?}");
        let pre = notes[0].pre_image.as_ref().expect("pre-image");
        assert_eq!(pre.path, dir.join("target").to_str().unwrap());
        assert_eq!(pre.bytes, b"old");
    }

    /// With `O_NOFOLLOW` the open of a symlink fails (ELOOP) and writes
    /// nothing: no note, and the target's bytes are not claimed.
    #[test]
    fn nofollow_write_open_of_a_symlink_sends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::write(dir.join("target"), b"old").unwrap();
        std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
        let p = c(&dir.join("link"));
        let notes = test_capture::capture(|| {
            let fd = unsafe { open64(p.as_ptr(), O_WRONLY | O_TRUNC | libc::O_NOFOLLOW, 0) };
            assert_eq!(fd, -1);
        });
        assert!(notes.is_empty(), "{notes:#?}");
        assert_eq!(std::fs::read(dir.join("target")).unwrap(), b"old");
    }
}
