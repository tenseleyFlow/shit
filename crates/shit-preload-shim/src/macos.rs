// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS interposition surface (M07.A).
//!
//! macOS strips `DYLD_INSERT_LIBRARIES` from SIP-protected binaries
//! by design (Apple platform binaries in `/System` / `/usr/bin`).
//! Coverage on a stock Mac is everything else: Homebrew-installed
//! `coreutils`, `git`, `cargo`, `npm`, user-scope Python tooling,
//! plus the user's own builds. That's ~90% of real workflow surface
//! per the M07 sprint estimate.
//!
//! Why `__DATA,__interpose` instead of `dlsym(RTLD_NEXT, ...)`:
//! Apple's preferred interposition mechanism is a static
//! `(replacement, target)` table in a magic Mach-O section. The
//! dynamic linker walks the table at image-load time and rewrites
//! lazy-binding stubs to route through our replacement. Benefits
//! over the BSD/Linux `dlsym(RTLD_NEXT)` pattern:
//!
//! - No per-call dlsym cost or cache.
//! - The interposer's address is captured at load time, not at
//!   first-call time — eliminates a race window where a tool
//!   could call the libc symbol before the cache is populated.
//! - Apple-blessed; future macOS revs are unlikely to break it.
//!
//! Layout: for each interposed symbol `foo`, we define `my_foo`
//! (the replacement) and emit a 2-pointer entry into the
//! `__DATA,__interpose` section: `(my_foo as *const c_void,
//! libc::foo as *const c_void)`. The dynamic linker does the rest.

use super::policy;
use libc::{O_RDWR, O_TRUNC, O_WRONLY, c_char, c_int, c_uint, c_void, mode_t};

/// Materialize a NUL-terminated C string into an owned `String` for
/// the policy notification. Returns empty on NULL or invalid UTF-8
/// (the policy module is lossy-tolerant on its `arg` field — it's
/// for logging / pre-image keying, not source-of-truth restoration).
fn cstr_to_string(path: *const c_char) -> String {
    if path.is_null() {
        return String::new();
    }
    // SAFETY: caller's libc-contract guarantees `path` is a valid
    // NUL-terminated C string when non-null.
    let bytes = unsafe { std::ffi::CStr::from_ptr(path) };
    bytes.to_string_lossy().into_owned()
}

// Interposer set for M07.A: install-event coverage. Each replacement
// notifies `policy` (fail-open: socket missing / daemon down / 50ms
// ack timeout all swallow silently) then forwards to the libc symbol.
// Filter logic for open/openat (write-mode only) mirrors the BSD/Linux
// interposers' policy choices.

/// Replacement for `unlink(2)`.
///
/// # Safety
/// Same contract as `libc::unlink` — `pathname` must point to a
/// valid NUL-terminated C string for the duration of the call.
unsafe extern "C" fn my_unlink(pathname: *const c_char) -> c_int {
    policy::notify_pre_mutation_with_content("unlink", &cstr_to_string(pathname));
    // SAFETY: caller upholds libc::unlink's contract on pathname.
    unsafe { libc::unlink(pathname) }
}

/// Replacement for `unlinkat(2)`. Modern coreutils (`rm`, `find`,
/// `git`'s clean path) prefer the dirfd-relative variant over bare
/// `unlink`; missing the interposer would leave `rm -r` silently
/// uncovered.
///
/// # Safety
/// Same contract as `libc::unlinkat` — `pathname` must point to a
/// valid NUL-terminated C string; `dirfd` must be `AT_FDCWD` or
/// an open dirfd; `flags` is `0` or `AT_REMOVEDIR`.
unsafe extern "C" fn my_unlinkat(dirfd: c_int, pathname: *const c_char, flags: c_int) -> c_int {
    policy::notify_pre_mutation_with_content("unlinkat", &cstr_to_string(pathname));
    unsafe { libc::unlinkat(dirfd, pathname, flags) }
}

/// Replacement for `rename(2)`. The atomic-move syscall behind
/// `mv`, `install`'s temp-then-rename pattern, and most "save
/// atomically" editor paths (`vim :wq`).
///
/// # Safety
/// Same contract as `libc::rename` — both args must be valid
/// NUL-terminated C strings for the duration of the call.
unsafe extern "C" fn my_rename(from: *const c_char, to: *const c_char) -> c_int {
    policy::notify_rename_with_dst_preimage("rename", &cstr_to_string(from), &cstr_to_string(to));
    unsafe { libc::rename(from, to) }
}

/// Replacement for `renameat(2)`. Dirfd-relative variant; modern
/// coreutils prefer this over bare `rename`.
///
/// # Safety
/// Same contract as `libc::renameat` — both pathnames must be
/// valid NUL-terminated C strings; dirfds are `AT_FDCWD` or open.
unsafe extern "C" fn my_renameat(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
) -> c_int {
    policy::notify_rename_with_dst_preimage("renameat", &cstr_to_string(from), &cstr_to_string(to));
    unsafe { libc::renameat(fromfd, from, tofd, to) }
}

// Open/openat replacements live in the C trampoline (`macos_shim.c`)
// because Apple's AArch64 variadic ABI is incompatible with a
// Rust-side fixed-arity interpose function (mode arg gets read from
// the wrong place — a register instead of the va_arg stack slot —
// silently corrupting file modes). The C trampoline does
// `va_arg(ap, int)` correctly and forwards to `rust_shim_open` /
// `rust_shim_openat` below for the notify + libc passthrough.
//
// The interpose entries point at the C-side `macos_shim_open` /
// `macos_shim_openat` symbols as replacements, and at libsystem_c's
// `_open` / `_openat` as targets (resolved via the `addr` module's
// fixed-arity aliases — see below).
unsafe extern "C" {
    fn macos_shim_open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
    fn macos_shim_openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
}

// Address-only aliases for libsystem_c's `_open` / `_openat`. We
// need fixed-arity signatures so Rust can do the `as *const c_void`
// coercion for the interpose target — the dynamic linker resolves
// `link_name = "open"` to the same symbol regardless of the Rust
// signature.
#[allow(dead_code)]
mod addr {
    use libc::{c_char, c_int, c_uint};
    unsafe extern "C" {
        #[link_name = "open"]
        pub fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
        #[link_name = "openat"]
        pub fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
    }
}

/// Rust target of the C trampoline for `open(2)`. The trampoline
/// has already done `va_arg` for `mode` and is calling us with a
/// proper fixed-arity 3-arg form. We notify on write flags then
/// re-dispatch to libc's variadic `open` (Rust's variadic-out
/// codegen handles the ABI back to libsystem_c correctly).
///
/// `#[no_mangle]` because the C trampoline links against this
/// symbol by name.
///
/// # Safety
/// Same contract as libc `open(2)` — `path` must be a valid
/// NUL-terminated C string; `mode` only meaningful when `O_CREAT`
/// is in `flags`.
#[unsafe(no_mangle)]
unsafe extern "C" fn rust_shim_open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    let writes = (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0;
    if writes {
        policy::notify_pre_mutation_with_content("open", &cstr_to_string(path));
    }
    unsafe { libc::open(path, flags, mode as c_int) }
}

/// Rust target of the C trampoline for `openat(2)`.
///
/// # Safety
/// Same contract as libc `openat(2)`.
#[unsafe(no_mangle)]
unsafe extern "C" fn rust_shim_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_uint,
) -> c_int {
    let writes = (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0;
    if writes {
        policy::notify_pre_mutation_with_content("openat", &cstr_to_string(path));
    }
    unsafe { libc::openat(dirfd, path, flags, mode as c_int) }
}

/// Replacement for `mkdir(2)`. Captures directory-create
/// events; the future undo path removes the directory if it
/// was empty at creation time.
///
/// # Safety
/// Same contract as `libc::mkdir`.
unsafe extern "C" fn my_mkdir(path: *const c_char, mode: mode_t) -> c_int {
    // `notify_create` carries the new path without a pre-image (the
    // path doesn't exist pre-syscall). Daemon journals a TreeOp::Create
    // whose inverse is `rmdir` (or `unlink` on the planner side).
    policy::notify_create("mkdir", &cstr_to_string(path));
    unsafe { libc::mkdir(path, mode) }
}

/// Replacement for `chmod(2)`. M07.B.1.
///
/// Captures the path + pre-image so the planner can record the
/// old mode and restore on undo. The `_with_content` notify also
/// reads file bytes — wasteful for chmod-only mutations, but
/// harmless (the planner picks `ChmodMetadata` inverse based on
/// the event type, ignoring the bytes payload). Future tightening:
/// a metadata-only notify variant that skips the read.
///
/// # Safety
/// Same contract as `libc::chmod` — `path` must be a valid
/// NUL-terminated C string.
unsafe extern "C" fn my_chmod(path: *const c_char, mode: mode_t) -> c_int {
    policy::notify_pre_mutation_with_content("chmod", &cstr_to_string(path));
    unsafe { libc::chmod(path, mode) }
}

/// Replacement for `fchmod(2)`. Resolves the fd → path via
/// `fcntl(F_GETPATH)` so the daemon receives a path-based event
/// like every other interposer. Skip-notifies if F_GETPATH fails
/// (typical for pipe / socket / anon-mmap fds, which aren't
/// chmod targets anyway).
///
/// # Safety
/// Same contract as `libc::fchmod` — `fd` must be a valid file
/// descriptor.
unsafe extern "C" fn my_fchmod(fd: c_int, mode: mode_t) -> c_int {
    if let Some(path) = fd_to_path(fd) {
        policy::notify_pre_mutation_with_content("fchmod", &path);
    }
    unsafe { libc::fchmod(fd, mode) }
}

/// Replacement for `fchmodat(2)` (M07.B.5). This is the syscall
/// GNU coreutils' `chmod`/`gchmod` actually issues — `nm -u
/// /opt/homebrew/bin/gchmod` shows `_fchmodat` and nothing else
/// from the chmod family. Without this interposer the M07.B
/// shim coverage was silently inert against the most common
/// invocation path.
///
/// # Safety
/// Same contract as `libc::fchmodat`.
unsafe extern "C" fn my_fchmodat(
    dirfd: c_int,
    pathname: *const c_char,
    mode: mode_t,
    flags: c_int,
) -> c_int {
    policy::notify_pre_mutation_with_content("fchmodat", &cstr_to_string(pathname));
    unsafe { libc::fchmodat(dirfd, pathname, mode, flags) }
}

/// Replacement for `chown(2)`. Captures path + metadata so the
/// planner can restore the old uid/gid on undo.
///
/// # Safety
/// Same contract as `libc::chown` — `path` must be a valid
/// NUL-terminated C string.
unsafe extern "C" fn my_chown(path: *const c_char, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    policy::notify_pre_mutation_with_content("chown", &cstr_to_string(path));
    unsafe { libc::chown(path, uid, gid) }
}

/// Replacement for `fchown(2)`. Resolves fd→path; skip-notifies
/// if F_GETPATH fails.
///
/// # Safety
/// Same contract as `libc::fchown`.
unsafe extern "C" fn my_fchown(fd: c_int, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    if let Some(path) = fd_to_path(fd) {
        policy::notify_pre_mutation_with_content("fchown", &path);
    }
    unsafe { libc::fchown(fd, uid, gid) }
}

/// Replacement for `fchownat(2)` (M07.B.5). GNU coreutils'
/// `chown`/`gchown` uses this instead of bare `chown` — same
/// rationale as `fchmodat`.
///
/// # Safety
/// Same contract as `libc::fchownat`.
unsafe extern "C" fn my_fchownat(
    dirfd: c_int,
    pathname: *const c_char,
    owner: libc::uid_t,
    group: libc::gid_t,
    flags: c_int,
) -> c_int {
    policy::notify_pre_mutation_with_content("fchownat", &cstr_to_string(pathname));
    unsafe { libc::fchownat(dirfd, pathname, owner, group, flags) }
}

/// Replacement for `lchown(2)`. Variant that operates on the
/// symlink itself, not the target. Notification path is the
/// same — daemon discriminates on the syscall name.
///
/// # Safety
/// Same contract as `libc::lchown`.
unsafe extern "C" fn my_lchown(path: *const c_char, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    policy::notify_pre_mutation_with_content("lchown", &cstr_to_string(path));
    unsafe { libc::lchown(path, uid, gid) }
}

/// Replacement for `utimes(2)`. Captures path + metadata so the
/// planner can restore the old atime/mtime on undo.
///
/// # Safety
/// Same contract as `libc::utimes` — `path` valid C string; `times`
/// either NULL (set to current time) or pointer to 2 timevals.
unsafe extern "C" fn my_utimes(path: *const c_char, times: *const libc::timeval) -> c_int {
    policy::notify_pre_mutation_with_content("utimes", &cstr_to_string(path));
    unsafe { libc::utimes(path, times) }
}

/// Replacement for `futimens(2)`. fd → path via F_GETPATH; skip-
/// notifies if resolution fails.
///
/// # Safety
/// Same contract as `libc::futimens`.
unsafe extern "C" fn my_futimens(fd: c_int, times: *const libc::timespec) -> c_int {
    if let Some(path) = fd_to_path(fd) {
        policy::notify_pre_mutation_with_content("futimens", &path);
    }
    unsafe { libc::futimens(fd, times) }
}

/// Replacement for `utimensat(2)` (M07.B.5). GNU coreutils'
/// `touch`/`gtouch` uses this — `nm -u /opt/homebrew/bin/gtouch`
/// shows utimensat alongside utimes/futimens/futimes. macOS Apple
/// /usr/bin/touch is SIP-stripped anyway; the gtouch path is what
/// the dyld-hooks user PATH wraps in practice.
///
/// # Safety
/// Same contract as `libc::utimensat`.
unsafe extern "C" fn my_utimensat(
    dirfd: c_int,
    pathname: *const c_char,
    times: *const libc::timespec,
    flag: c_int,
) -> c_int {
    policy::notify_pre_mutation_with_content("utimensat", &cstr_to_string(pathname));
    unsafe { libc::utimensat(dirfd, pathname, times, flag) }
}

/// Replacement for `futimes(2)` (M07.B.5). fd-only variant; same
/// fd→path resolver as fchmod/fchown.
///
/// # Safety
/// Same contract as `libc::futimes`.
unsafe extern "C" fn my_futimes(fd: c_int, times: *const libc::timeval) -> c_int {
    if let Some(path) = fd_to_path(fd) {
        policy::notify_pre_mutation_with_content("futimes", &path);
    }
    unsafe { libc::futimes(fd, times) }
}

// macOS xattr signatures diverge from Linux: extra `position` arg
// (legacy resource-fork offset, near-universally 0) and `flags` arg
// (XATTR_NOFOLLOW etc).
//
// M07.B.4.1 — pre-syscall xattr value capture. Before the libc
// passthrough, we call `getxattr(path, name, ...)` to read the
// current value (if any). The shim ships it on the wire so the
// daemon's planner can drive a byte-identical undo:
//   setxattr undo:   removexattr (if absent before) OR setxattr-with-old-value (if present)
//   removexattr undo: setxattr-with-old-value (if present) OR no-op (if absent)

/// Read the current value of `name` on `path`. Returns
/// `Some(bytes)` when present, `None` when the xattr doesn't
/// exist or the read fails. macOS uses non-zero `position` only
/// for legacy resource-fork access; modern xattrs always use 0.
unsafe fn read_xattr_value(path: *const c_char, name: *const c_char) -> Option<Vec<u8>> {
    if path.is_null() || name.is_null() {
        return None;
    }
    // First call sizes the value. Pass NULL buffer + 0 size; if
    // the xattr exists, return is its byte count. ENOATTR (= 93
    // on Darwin) means absent.
    let sz = unsafe { libc::getxattr(path, name, std::ptr::null_mut(), 0, 0, 0) };
    if sz < 0 {
        return None;
    }
    if sz == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; sz as usize];
    let got =
        unsafe { libc::getxattr(path, name, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, 0) };
    if got < 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

/// fd-based variant of [`read_xattr_value`] using `fgetxattr`.
unsafe fn read_xattr_value_fd(fd: c_int, name: *const c_char) -> Option<Vec<u8>> {
    if name.is_null() {
        return None;
    }
    let sz = unsafe { libc::fgetxattr(fd, name, std::ptr::null_mut(), 0, 0, 0) };
    if sz < 0 {
        return None;
    }
    if sz == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; sz as usize];
    let got =
        unsafe { libc::fgetxattr(fd, name, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, 0) };
    if got < 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

/// Build the [`shit_proto::XattrPreImage`] payload from a captured
/// pre-value. `name` must be a valid C string.
unsafe fn build_xattr_pre(
    name: *const c_char,
    pre_value: Option<Vec<u8>>,
) -> shit_proto::XattrPreImage {
    let name_str = if name.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned()
    };
    shit_proto::XattrPreImage {
        name: name_str,
        value: pre_value,
    }
}

/// Replacement for `setxattr(2)`.
///
/// # Safety
/// Same contract as `libc::setxattr`.
unsafe extern "C" fn my_setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: libc::size_t,
    position: u32,
    flags: c_int,
) -> c_int {
    // M07.B.4.1: capture pre-value first.
    let pre_value = unsafe { read_xattr_value(path, name) };
    let xattr_pre = unsafe { build_xattr_pre(name, pre_value) };
    policy::notify_xattr_mutation("setxattr", &cstr_to_string(path), xattr_pre);
    unsafe { libc::setxattr(path, name, value, size, position, flags) }
}

/// Replacement for `fsetxattr(2)`. fd → path via F_GETPATH.
///
/// # Safety
/// Same contract as `libc::fsetxattr`.
unsafe extern "C" fn my_fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: libc::size_t,
    position: u32,
    flags: c_int,
) -> c_int {
    if let Some(path) = fd_to_path(fd) {
        let pre_value = unsafe { read_xattr_value_fd(fd, name) };
        let xattr_pre = unsafe { build_xattr_pre(name, pre_value) };
        policy::notify_xattr_mutation("fsetxattr", &path, xattr_pre);
    }
    unsafe { libc::fsetxattr(fd, name, value, size, position, flags) }
}

/// Replacement for `removexattr(2)`.
///
/// # Safety
/// Same contract as `libc::removexattr`.
unsafe extern "C" fn my_removexattr(
    path: *const c_char,
    name: *const c_char,
    flags: c_int,
) -> c_int {
    let pre_value = unsafe { read_xattr_value(path, name) };
    let xattr_pre = unsafe { build_xattr_pre(name, pre_value) };
    policy::notify_xattr_mutation("removexattr", &cstr_to_string(path), xattr_pre);
    unsafe { libc::removexattr(path, name, flags) }
}

/// Replacement for `fremovexattr(2)`. fd → path via F_GETPATH.
///
/// # Safety
/// Same contract as `libc::fremovexattr`.
unsafe extern "C" fn my_fremovexattr(fd: c_int, name: *const c_char, flags: c_int) -> c_int {
    if let Some(path) = fd_to_path(fd) {
        let pre_value = unsafe { read_xattr_value_fd(fd, name) };
        let xattr_pre = unsafe { build_xattr_pre(name, pre_value) };
        policy::notify_xattr_mutation("fremovexattr", &path, xattr_pre);
    }
    unsafe { libc::fremovexattr(fd, name, flags) }
}

/// Best-effort fd → path via `fcntl(F_GETPATH)`. Returns `None`
/// if the fd isn't backed by a path (anon fds, pipes, sockets)
/// or if the call fails. macOS-specific: `F_GETPATH` writes up
/// to `MAXPATHLEN` (1024) bytes into the user buffer.
fn fd_to_path(fd: c_int) -> Option<String> {
    use libc::{F_GETPATH, MAXPATHLEN, fcntl};
    let mut buf = [0u8; MAXPATHLEN as usize];
    // SAFETY: buf is large enough for F_GETPATH; fcntl writes a
    // NUL-terminated path into it on success.
    let rc = unsafe { fcntl(fd, F_GETPATH, buf.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let nul = buf.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&buf[..nul]).ok().map(str::to_string)
}

/// Replacement for `mkdirat(2)`. Dirfd-relative variant.
///
/// # Safety
/// Same contract as `libc::mkdirat`.
unsafe extern "C" fn my_mkdirat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
    policy::notify_create("mkdirat", &cstr_to_string(path));
    unsafe { libc::mkdirat(dirfd, path, mode) }
}

/// `__DATA,__interpose` table entry for `unlink`. The dynamic
/// linker reads this at image-load time and rewrites the
/// lazy-binding stubs for `unlink` in the host process to point
/// at `my_unlink`.
///
/// `#[used]` keeps the static from being dead-code-eliminated;
/// without it rustc would (correctly) observe that nothing in
/// Rust source references the entry and strip it before the
/// linker ever sees it.
#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_UNLINK: InterposeEntry = InterposeEntry {
    replacement: my_unlink as *const c_void,
    target: libc::unlink as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_UNLINKAT: InterposeEntry = InterposeEntry {
    replacement: my_unlinkat as *const c_void,
    target: libc::unlinkat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_RENAME: InterposeEntry = InterposeEntry {
    replacement: my_rename as *const c_void,
    target: libc::rename as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_RENAMEAT: InterposeEntry = InterposeEntry {
    replacement: my_renameat as *const c_void,
    target: libc::renameat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_OPEN: InterposeEntry = InterposeEntry {
    replacement: macos_shim_open as *const c_void,
    target: addr::open as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_OPENAT: InterposeEntry = InterposeEntry {
    replacement: macos_shim_openat as *const c_void,
    target: addr::openat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_MKDIR: InterposeEntry = InterposeEntry {
    replacement: my_mkdir as *const c_void,
    target: libc::mkdir as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_MKDIRAT: InterposeEntry = InterposeEntry {
    replacement: my_mkdirat as *const c_void,
    target: libc::mkdirat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_CHMOD: InterposeEntry = InterposeEntry {
    replacement: my_chmod as *const c_void,
    target: libc::chmod as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FCHMOD: InterposeEntry = InterposeEntry {
    replacement: my_fchmod as *const c_void,
    target: libc::fchmod as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FCHMODAT: InterposeEntry = InterposeEntry {
    replacement: my_fchmodat as *const c_void,
    target: libc::fchmodat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_CHOWN: InterposeEntry = InterposeEntry {
    replacement: my_chown as *const c_void,
    target: libc::chown as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FCHOWN: InterposeEntry = InterposeEntry {
    replacement: my_fchown as *const c_void,
    target: libc::fchown as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_LCHOWN: InterposeEntry = InterposeEntry {
    replacement: my_lchown as *const c_void,
    target: libc::lchown as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FCHOWNAT: InterposeEntry = InterposeEntry {
    replacement: my_fchownat as *const c_void,
    target: libc::fchownat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_UTIMES: InterposeEntry = InterposeEntry {
    replacement: my_utimes as *const c_void,
    target: libc::utimes as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FUTIMENS: InterposeEntry = InterposeEntry {
    replacement: my_futimens as *const c_void,
    target: libc::futimens as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_UTIMENSAT: InterposeEntry = InterposeEntry {
    replacement: my_utimensat as *const c_void,
    target: libc::utimensat as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FUTIMES: InterposeEntry = InterposeEntry {
    replacement: my_futimes as *const c_void,
    target: libc::futimes as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_SETXATTR: InterposeEntry = InterposeEntry {
    replacement: my_setxattr as *const c_void,
    target: libc::setxattr as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FSETXATTR: InterposeEntry = InterposeEntry {
    replacement: my_fsetxattr as *const c_void,
    target: libc::fsetxattr as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_REMOVEXATTR: InterposeEntry = InterposeEntry {
    replacement: my_removexattr as *const c_void,
    target: libc::removexattr as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FREMOVEXATTR: InterposeEntry = InterposeEntry {
    replacement: my_fremovexattr as *const c_void,
    target: libc::fremovexattr as *const c_void,
};

/// `(replacement, target)` pair the dynamic linker expects in
/// `__DATA,__interpose`. Two `*const c_void`s, naturally aligned,
/// equivalent to Apple's C `DYLD_INTERPOSE` macro output.
#[repr(C)]
struct InterposeEntry {
    replacement: *const c_void,
    target: *const c_void,
}

// SAFETY: function pointers are inherently thread-safe; the static
// is read-only after image load. Required because `*const c_void`
// doesn't auto-implement Sync.
unsafe impl Sync for InterposeEntry {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpose_entry_has_two_pointers() {
        assert_eq!(
            std::mem::size_of::<InterposeEntry>(),
            2 * std::mem::size_of::<*const c_void>(),
            "__DATA,__interpose entries must be exactly two pointer-sized fields"
        );
    }

    #[test]
    fn unlink_interposer_pair_is_populated() {
        assert!(!INTERPOSE_UNLINK.replacement.is_null());
        assert!(!INTERPOSE_UNLINK.target.is_null());
        assert_ne!(
            INTERPOSE_UNLINK.replacement, INTERPOSE_UNLINK.target,
            "replacement and target must be distinct function addresses"
        );
    }

    #[test]
    fn unlinkat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_UNLINKAT.replacement.is_null());
        assert!(!INTERPOSE_UNLINKAT.target.is_null());
        assert_ne!(INTERPOSE_UNLINKAT.replacement, INTERPOSE_UNLINKAT.target);
    }

    #[test]
    fn rename_interposer_pair_is_populated() {
        assert!(!INTERPOSE_RENAME.replacement.is_null());
        assert!(!INTERPOSE_RENAME.target.is_null());
        assert_ne!(INTERPOSE_RENAME.replacement, INTERPOSE_RENAME.target);
    }

    #[test]
    fn renameat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_RENAMEAT.replacement.is_null());
        assert!(!INTERPOSE_RENAMEAT.target.is_null());
        assert_ne!(INTERPOSE_RENAMEAT.replacement, INTERPOSE_RENAMEAT.target);
    }

    #[test]
    fn open_interposer_pair_is_populated() {
        assert!(!INTERPOSE_OPEN.replacement.is_null());
        assert!(!INTERPOSE_OPEN.target.is_null());
        assert_ne!(INTERPOSE_OPEN.replacement, INTERPOSE_OPEN.target);
    }

    #[test]
    fn openat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_OPENAT.replacement.is_null());
        assert!(!INTERPOSE_OPENAT.target.is_null());
        assert_ne!(INTERPOSE_OPENAT.replacement, INTERPOSE_OPENAT.target);
    }

    #[test]
    fn mkdir_interposer_pair_is_populated() {
        assert!(!INTERPOSE_MKDIR.replacement.is_null());
        assert!(!INTERPOSE_MKDIR.target.is_null());
        assert_ne!(INTERPOSE_MKDIR.replacement, INTERPOSE_MKDIR.target);
    }

    #[test]
    fn mkdirat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_MKDIRAT.replacement.is_null());
        assert!(!INTERPOSE_MKDIRAT.target.is_null());
        assert_ne!(INTERPOSE_MKDIRAT.replacement, INTERPOSE_MKDIRAT.target);
    }

    #[test]
    fn chmod_interposer_pair_is_populated() {
        assert!(!INTERPOSE_CHMOD.replacement.is_null());
        assert!(!INTERPOSE_CHMOD.target.is_null());
        assert_ne!(INTERPOSE_CHMOD.replacement, INTERPOSE_CHMOD.target);
    }

    #[test]
    fn fchmod_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FCHMOD.replacement.is_null());
        assert!(!INTERPOSE_FCHMOD.target.is_null());
        assert_ne!(INTERPOSE_FCHMOD.replacement, INTERPOSE_FCHMOD.target);
    }

    #[test]
    fn chown_interposer_pair_is_populated() {
        assert!(!INTERPOSE_CHOWN.replacement.is_null());
        assert!(!INTERPOSE_CHOWN.target.is_null());
        assert_ne!(INTERPOSE_CHOWN.replacement, INTERPOSE_CHOWN.target);
    }

    #[test]
    fn fchown_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FCHOWN.replacement.is_null());
        assert!(!INTERPOSE_FCHOWN.target.is_null());
        assert_ne!(INTERPOSE_FCHOWN.replacement, INTERPOSE_FCHOWN.target);
    }

    #[test]
    fn lchown_interposer_pair_is_populated() {
        assert!(!INTERPOSE_LCHOWN.replacement.is_null());
        assert!(!INTERPOSE_LCHOWN.target.is_null());
        assert_ne!(INTERPOSE_LCHOWN.replacement, INTERPOSE_LCHOWN.target);
    }

    #[test]
    fn utimes_interposer_pair_is_populated() {
        assert!(!INTERPOSE_UTIMES.replacement.is_null());
        assert!(!INTERPOSE_UTIMES.target.is_null());
        assert_ne!(INTERPOSE_UTIMES.replacement, INTERPOSE_UTIMES.target);
    }

    #[test]
    fn futimens_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FUTIMENS.replacement.is_null());
        assert!(!INTERPOSE_FUTIMENS.target.is_null());
        assert_ne!(INTERPOSE_FUTIMENS.replacement, INTERPOSE_FUTIMENS.target);
    }

    #[test]
    fn setxattr_interposer_pair_is_populated() {
        assert!(!INTERPOSE_SETXATTR.replacement.is_null());
        assert!(!INTERPOSE_SETXATTR.target.is_null());
        assert_ne!(INTERPOSE_SETXATTR.replacement, INTERPOSE_SETXATTR.target);
    }

    #[test]
    fn fsetxattr_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FSETXATTR.replacement.is_null());
        assert!(!INTERPOSE_FSETXATTR.target.is_null());
        assert_ne!(INTERPOSE_FSETXATTR.replacement, INTERPOSE_FSETXATTR.target);
    }

    #[test]
    fn removexattr_interposer_pair_is_populated() {
        assert!(!INTERPOSE_REMOVEXATTR.replacement.is_null());
        assert!(!INTERPOSE_REMOVEXATTR.target.is_null());
        assert_ne!(
            INTERPOSE_REMOVEXATTR.replacement,
            INTERPOSE_REMOVEXATTR.target
        );
    }

    #[test]
    fn fremovexattr_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FREMOVEXATTR.replacement.is_null());
        assert!(!INTERPOSE_FREMOVEXATTR.target.is_null());
        assert_ne!(
            INTERPOSE_FREMOVEXATTR.replacement,
            INTERPOSE_FREMOVEXATTR.target
        );
    }

    // M07.B.5: *at variants GNU coreutils actually use.
    #[test]
    fn fchmodat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FCHMODAT.replacement.is_null());
        assert!(!INTERPOSE_FCHMODAT.target.is_null());
        assert_ne!(INTERPOSE_FCHMODAT.replacement, INTERPOSE_FCHMODAT.target);
    }

    #[test]
    fn fchownat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FCHOWNAT.replacement.is_null());
        assert!(!INTERPOSE_FCHOWNAT.target.is_null());
        assert_ne!(INTERPOSE_FCHOWNAT.replacement, INTERPOSE_FCHOWNAT.target);
    }

    #[test]
    fn utimensat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_UTIMENSAT.replacement.is_null());
        assert!(!INTERPOSE_UTIMENSAT.target.is_null());
        assert_ne!(INTERPOSE_UTIMENSAT.replacement, INTERPOSE_UTIMENSAT.target);
    }

    #[test]
    fn futimes_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FUTIMES.replacement.is_null());
        assert!(!INTERPOSE_FUTIMES.target.is_null());
        assert_ne!(INTERPOSE_FUTIMES.replacement, INTERPOSE_FUTIMES.target);
    }

    #[test]
    fn fd_to_path_returns_none_for_bad_fd() {
        // fd -1 is never valid; F_GETPATH returns -1, our helper None.
        assert!(fd_to_path(-1).is_none());
    }

    #[test]
    fn fd_to_path_resolves_open_file_to_its_path() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "hi").unwrap();
        let p = tmp.path().to_path_buf();
        // Open via libc::open to mirror what an interposed caller has.
        let path_c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0, "open of temp file should succeed");
        let resolved = fd_to_path(fd);
        unsafe { libc::close(fd) };
        let resolved = resolved.expect("F_GETPATH should resolve a real file fd");
        // macOS canonicalizes /tmp to /private/tmp; compare via canonicalize.
        let want = std::fs::canonicalize(&p).unwrap();
        let got = std::fs::canonicalize(&resolved).unwrap();
        assert_eq!(got, want);
    }

    /// Cross-cutting: count of expected interpose entries.
    /// Regression gate — if someone adds a static without bumping
    /// the assertion, the test points to the omission in code
    /// review. (Open/openat replacements live in the C trampoline
    /// `macos_shim.c`; their interpose entries still appear in
    /// this list, with the replacement field pointing at the C
    /// symbol rather than a Rust function.)
    #[test]
    fn all_m07a2_entries_present() {
        let entries: &[&InterposeEntry] = &[
            &INTERPOSE_UNLINK,
            &INTERPOSE_UNLINKAT,
            &INTERPOSE_RENAME,
            &INTERPOSE_RENAMEAT,
            &INTERPOSE_OPEN,
            &INTERPOSE_OPENAT,
            &INTERPOSE_MKDIR,
            &INTERPOSE_MKDIRAT,
            // M07.B.1: chmod family
            &INTERPOSE_CHMOD,
            &INTERPOSE_FCHMOD,
            // M07.B.2: chown family
            &INTERPOSE_CHOWN,
            &INTERPOSE_FCHOWN,
            &INTERPOSE_LCHOWN,
            // M07.B.3: utimes family
            &INTERPOSE_UTIMES,
            &INTERPOSE_FUTIMENS,
            // M07.B.4: xattr family
            &INTERPOSE_SETXATTR,
            &INTERPOSE_FSETXATTR,
            &INTERPOSE_REMOVEXATTR,
            &INTERPOSE_FREMOVEXATTR,
            // M07.B.5: *at variants GNU coreutils actually use
            &INTERPOSE_FCHMODAT,
            &INTERPOSE_FCHOWNAT,
            &INTERPOSE_UTIMENSAT,
            &INTERPOSE_FUTIMES,
        ];
        assert_eq!(entries.len(), 23, "M07.A.2 + M07.B.1..5 interposer count");
        for e in entries {
            assert!(!e.replacement.is_null());
            assert!(!e.target.is_null());
            assert_ne!(e.replacement, e.target);
        }
    }
}
