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
use std::path::{Path, PathBuf};

/// Materialize a NUL-terminated C string into an owned wire string. The
/// protocol cannot yet carry arbitrary POSIX bytes, so invalid UTF-8 becomes
/// an impossible NUL-containing sentinel. Policy resolution turns that into a
/// structured refusal; it must never become a lossy replay target.
fn cstr_to_string(path: *const c_char) -> String {
    if path.is_null() {
        return "\0shit:null-path".to_string();
    }
    // SAFETY: caller's libc-contract guarantees `path` is a valid
    // NUL-terminated C string when non-null.
    let bytes = unsafe { std::ffi::CStr::from_ptr(path) };
    bytes
        .to_str()
        .map(str::to_owned)
        .unwrap_or_else(|_| "\0shit:non-utf8-path".to_string())
}

/// Resolve a path-taking `*at` call's target against its dirfd.
///
/// The destination is resolved before the syscall by canonicalizing its
/// existing parent and appending the final basename lexically. Resolving the
/// final name after success would introduce a race: another thread could
/// replace it with a symlink before `canonicalize`, misattributing the Create.
///
/// For a relative path with a real dirfd, interpreting it relative to the
/// shimmed process's cwd is wrong: `mkdirat(fd, "child", ...)` targets
/// `<fd>/child`, regardless of cwd. `F_GETPATH` supplies that missing base.
///
/// Resolution failures preserve the best available path and attach AU10's
/// structured failure marker. The daemon journals that successful mutation as
/// a refusal instead of guessing an inverse from an unsafe path.
fn resolve_created_path_at(dirfd: c_int, path: &str) -> (String, Option<shit_proto::ShimFailure>) {
    let path = Path::new(path);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if dirfd == libc::AT_FDCWD {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(error) => {
                return create_path_base_failure(path, format!("getcwd failed: {error}"));
            }
        }
    } else {
        match fd_to_path(dirfd) {
            Some(base) => PathBuf::from(base).join(path),
            None => {
                return create_path_base_failure(
                    path,
                    format!("F_GETPATH failed for dirfd {dirfd}"),
                );
            }
        }
    };

    // Run AU10's canonical-parent + lexical-basename resolution before the
    // syscall. If canonicalization fails, this returns the absolute candidate
    // plus ShimFailure::CanonicalizeFailed rather than dropping the event.
    let candidate = candidate.to_string_lossy().into_owned();
    policy::canonicalize_parent_or_raw(&candidate, "path")
}

fn create_path_base_failure(
    path: &Path,
    detail: String,
) -> (String, Option<shit_proto::ShimFailure>) {
    let attempted_path = path.to_string_lossy().into_owned();
    let failure = shit_proto::ShimFailure::CanonicalizeFailed {
        which_arg: "path".to_string(),
        attempted_path: attempted_path.clone(),
        error_chain: detail,
    };
    (attempted_path, Some(failure))
}

/// Run a create-like syscall, then notify only when it actually succeeded.
///
/// `create`, `resolve_path`, and `notify` are parameters so unit tests can pin
/// the ordering and failure gate without opening the daemon socket. Production
/// wrappers all route through [`call_path_create`] below.
fn call_create_and_notify_with<Create, Resolve, Notify>(
    syscall: &'static str,
    create: Create,
    resolve_path: Resolve,
    notify: Notify,
) -> c_int
where
    Create: FnOnce() -> c_int,
    Resolve: FnOnce() -> (String, Option<shit_proto::ShimFailure>),
    Notify: FnOnce(&'static str, &str, Option<shit_proto::ShimFailure>),
{
    call_mutation_and_notify_with(
        // Resolve before mutation. In addition to avoiding final-name races,
        // this captures AT_FDCWD before another thread can change cwd.
        resolve_path,
        create,
        |result| *result == 0,
        |(resolved_path, failure)| notify(syscall, &resolved_path, failure),
    )
}

/// Testable adapter for create-only path syscalls.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string during path resolution and
/// remain valid until `create` returns, matching the wrapped libc contract.
unsafe fn call_path_create_with<Create, Notify>(
    syscall: &'static str,
    dirfd: c_int,
    path: *const c_char,
    create: Create,
    notify: Notify,
) -> c_int
where
    Create: FnOnce() -> c_int,
    Notify: FnOnce(&'static str, &str, Option<shit_proto::ShimFailure>),
{
    call_create_and_notify_with(
        syscall,
        create,
        || resolve_created_path_at(dirfd, &cstr_to_string(path)),
        notify,
    )
}

/// Production form of [`call_path_create_with`].
///
/// # Safety
/// Same pointer-lifetime requirement as [`call_path_create_with`].
unsafe fn call_path_create<Create>(
    syscall: &'static str,
    dirfd: c_int,
    path: *const c_char,
    create: Create,
) -> c_int
where
    Create: FnOnce() -> c_int,
{
    unsafe { call_path_create_with(syscall, dirfd, path, create, policy::notify_create_resolved) }
}

/// Capture before libc, but commit the captured notification only when the
/// wrapped operation reports success. `success` is supplied by the caller so
/// the same helper preserves both zero-on-success syscall returns and
/// nonnegative file descriptors from open(2).
fn current_errno() -> c_int {
    // SAFETY: Darwin's __error returns a valid pointer to this thread's errno.
    unsafe { *libc::__error() }
}

fn set_errno(value: c_int) {
    // SAFETY: Darwin's __error returns a valid pointer to this thread's errno.
    unsafe { *libc::__error() = value };
}

fn call_mutation_and_notify_with<Capture, Call, Success, Notify, Captured, Result>(
    capture: Capture,
    call: Call,
    success: Success,
    notify: Notify,
) -> Result
where
    Capture: FnOnce() -> Captured,
    Call: FnOnce() -> Result,
    Success: FnOnce(&Result) -> bool,
    Notify: FnOnce(Captured),
{
    let incoming_errno = current_errno();
    let captured = capture();
    // Pre-image capture performs filesystem I/O and must not leak its errno
    // into a successful libc call whose contract leaves errno unchanged.
    set_errno(incoming_errno);
    let result = call();
    let result_errno = current_errno();
    if success(&result) {
        notify(captured);
    } else {
        // Drop potentially allocated pre-images before restoring errno: Rust
        // deallocation is outside libc's error contract.
        drop(captured);
    }
    // Socket delivery is best-effort and may set errno; callers must observe
    // exactly the errno left by the wrapped libc operation.
    set_errno(result_errno);
    result
}

/// Production adapter for libc calls returning `0` on success.
fn call_zero_success<Prepare, Call>(prepare: Prepare, call: Call) -> c_int
where
    Prepare: FnOnce() -> Option<policy::PreparedNotification>,
    Call: FnOnce() -> c_int,
{
    call_mutation_and_notify_with(
        prepare,
        call,
        |result| *result == 0,
        |prepared| {
            if let Some(prepared) = prepared {
                prepared.send();
            }
        },
    )
}

/// Resolve an fd-backed mutation before libc. If F_GETPATH cannot provide a
/// replayable path, retain a success-gated refusal using a diagnostic-only
/// synthetic basename instead of silently dropping a successful mutation.
fn prepare_fd_path_mutation<Prepare>(
    syscall: &'static str,
    fd: c_int,
    prepare: Prepare,
) -> Option<policy::PreparedNotification>
where
    Prepare: FnOnce(&str) -> Option<policy::PreparedNotification>,
{
    let Some(path) = fd_to_path(fd) else {
        return policy::prepare_unsupported_path_mutation(
            syscall,
            &format!("shit-unresolved-fd-{fd}"),
            false,
            format!("F_GETPATH failed for fd {fd}"),
        );
    };
    match fd_is_symlink(fd) {
        Ok(false) => prepare(&path),
        Ok(true) => policy::prepare_unsupported_path_mutation(
            syscall,
            &path,
            true,
            "fd refers to a symlink whose nofollow replay is not modeled".to_string(),
        ),
        Err(error) => policy::prepare_unsupported_path_mutation(
            syscall,
            &path,
            false,
            format!("fstat failed for fd {fd}: {error}"),
        ),
    }
}

fn fd_is_symlink(fd: c_int) -> std::io::Result<bool> {
    // SAFETY: `stat` is plain-old-data and zero is a valid initial state.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is writable for the duration of fstat.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFLNK)
}

// Interposer set for M07.A: install-event coverage. Destructive replacements
// capture before mutation and send only after libc succeeds. Create-only
// replacements call libc first and notify only on success; otherwise a failed
// operation would journal a false inverse. Notifications remain fail-open
// (socket missing / daemon down / timeout are swallowed).

/// Replacement for `unlink(2)`.
///
/// # Safety
/// Same contract as `libc::unlink` — `pathname` must point to a
/// valid NUL-terminated C string for the duration of the call.
unsafe extern "C" fn my_unlink(pathname: *const c_char) -> c_int {
    let path = cstr_to_string(pathname);
    call_zero_success(
        || policy::prepare_pre_mutation_with_content("unlink", &path),
        // SAFETY: caller upholds libc::unlink's contract on pathname.
        || unsafe { libc::unlink(pathname) },
    )
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
    let path = cstr_to_string(pathname);
    call_zero_success(
        || policy::prepare_pre_mutation_at_with_content("unlinkat", dirfd, &path, true),
        || unsafe { libc::unlinkat(dirfd, pathname, flags) },
    )
}

/// Replacement for `rmdir(2)`. Directory removal needs the same
/// capture-before/success-gated-send contract as unlink; the policy layer
/// records a directory marker rather than attempting to read file bytes.
///
/// # Safety
/// Same contract as `libc::rmdir`.
unsafe extern "C" fn my_rmdir(path: *const c_char) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || {
            policy::prepare_pre_mutation_at_with_content(
                "rmdir",
                libc::AT_FDCWD,
                &path_string,
                true,
            )
        },
        || unsafe { libc::rmdir(path) },
    )
}

/// Replacement for C `remove(3)`, which may remove either a non-directory
/// entry or an empty directory. Preserve the lexical leaf so removing a
/// symlink never captures or journals its referent.
///
/// # Safety
/// Same contract as `libc::remove`.
unsafe extern "C" fn my_remove(path: *const c_char) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || {
            policy::prepare_pre_mutation_at_with_content(
                "remove",
                libc::AT_FDCWD,
                &path_string,
                true,
            )
        },
        || unsafe { libc::remove(path) },
    )
}

/// Replacement for `rename(2)`. The atomic-move syscall behind
/// `mv`, `install`'s temp-then-rename pattern, and most "save
/// atomically" editor paths (`vim :wq`).
///
/// # Safety
/// Same contract as `libc::rename` — both args must be valid
/// NUL-terminated C strings for the duration of the call.
unsafe extern "C" fn my_rename(from: *const c_char, to: *const c_char) -> c_int {
    let from_path = cstr_to_string(from);
    let to_path = cstr_to_string(to);
    call_zero_success(
        || policy::prepare_rename_with_dst_preimage("rename", &from_path, &to_path),
        || unsafe { libc::rename(from, to) },
    )
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
    let from_path = cstr_to_string(from);
    let to_path = cstr_to_string(to);
    call_zero_success(
        || {
            policy::prepare_rename_at_with_dst_preimage(
                "renameat", fromfd, &from_path, tofd, &to_path,
            )
        },
        || unsafe { libc::renameat(fromfd, from, tofd, to) },
    )
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
    let path_string = cstr_to_string(path);
    call_mutation_and_notify_with(
        || {
            writes
                .then(|| policy::prepare_pre_mutation_with_content("open", &path_string))
                .flatten()
        },
        || unsafe { libc::open(path, flags, mode as c_int) },
        |fd| *fd >= 0,
        |prepared| {
            if let Some(prepared) = prepared {
                prepared.send();
            }
        },
    )
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
    let path_string = cstr_to_string(path);
    call_mutation_and_notify_with(
        || {
            writes
                .then(|| {
                    policy::prepare_pre_mutation_at_with_content(
                        "openat",
                        dirfd,
                        &path_string,
                        false,
                    )
                })
                .flatten()
        },
        || unsafe { libc::openat(dirfd, path, flags, mode as c_int) },
        |fd| *fd >= 0,
        |prepared| {
            if let Some(prepared) = prepared {
                prepared.send();
            }
        },
    )
}

/// Replacement for `mkdir(2)`. Captures directory-create
/// events; the future undo path removes the directory if it
/// was empty at creation time.
///
/// # Safety
/// Same contract as `libc::mkdir`.
unsafe extern "C" fn my_mkdir(path: *const c_char, mode: mode_t) -> c_int {
    // Notify after success: mkdir commonly returns EEXIST while recursively
    // ensuring a parent tree, and that is not evidence the command created it.
    unsafe { call_path_create("mkdir", libc::AT_FDCWD, path, || libc::mkdir(path, mode)) }
}

/// Replacement for `mkfifo(3)` (M03.x.CREATE). Creates a FIFO
/// special file at `path`. The shim notifies a Create event so
/// the daemon journals TreeOp::Create; inverse is `unlink(path)`.
/// mkfifo(3) is a libc wrapper around `mknod(2)` with S_IFIFO
/// mode bits, but on macOS it exists as a discrete libc symbol
/// that gets dispatched separately from mknod.
///
/// # Safety
/// Same contract as `libc::mkfifo` — `path` must be a valid
/// NUL-terminated C string.
unsafe extern "C" fn my_mkfifo(path: *const c_char, mode: mode_t) -> c_int {
    unsafe { call_path_create("mkfifo", libc::AT_FDCWD, path, || libc::mkfifo(path, mode)) }
}

/// Replacement for `mkfifoat(2)` (M03.x.CREATE). The *at variant
/// — same semantics as `mkfifo` but with a `dirfd` for relative
/// path resolution.
///
/// # Safety
/// Same contract as `libc::mkfifoat`.
unsafe extern "C" fn my_mkfifoat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
    unsafe {
        call_path_create("mkfifoat", dirfd, path, || {
            libc::mkfifoat(dirfd, path, mode)
        })
    }
}

/// Replacement for `link(2)` (M03.x.LINK). Creates a hardlink:
/// `dst` becomes a new path aliasing `src`'s inode. The src
/// persists; only the new dst path needs undoing via unlink.
///
/// We notify on dst (the new path), not src — src is unchanged
/// by the syscall. The wire shape is the same as mkdir's: a
/// `TreeOp::Create` whose inverse is `unlink(dst)`.
///
/// # Safety
/// Same contract as `libc::link` — both paths must be valid
/// NUL-terminated C strings.
unsafe extern "C" fn my_link(src: *const c_char, dst: *const c_char) -> c_int {
    unsafe { call_path_create("link", libc::AT_FDCWD, dst, || libc::link(src, dst)) }
}

/// Replacement for `linkat(2)` (M03.x.LINK). The *at variant
/// `linkat(srcfd, src, dstfd, dst, flags)` resolves both paths
/// relative to their respective fds (or AT_FDCWD). We notify on
/// the dst path only — same semantics as `my_link`.
///
/// AT_SYMLINK_FOLLOW vs AT_SYMLINK_NOFOLLOW affects whether src
/// follows symlinks; doesn't change the dst-create shape.
///
/// # Safety
/// Same contract as `libc::linkat`.
unsafe extern "C" fn my_linkat(
    srcfd: c_int,
    src: *const c_char,
    dstfd: c_int,
    dst: *const c_char,
    flags: c_int,
) -> c_int {
    unsafe {
        call_path_create("linkat", dstfd, dst, || {
            libc::linkat(srcfd, src, dstfd, dst, flags)
        })
    }
}

/// Replacement for `chmod(2)`. M07.B.1.
///
/// Captures the path + metadata pre-image so the planner can record the
/// old mode and restore on undo without reading or rewriting file content.
///
/// # Safety
/// Same contract as `libc::chmod` — `path` must be a valid
/// NUL-terminated C string.
unsafe extern "C" fn my_chmod(path: *const c_char, mode: mode_t) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || policy::prepare_metadata_mutation("chmod", &path_string, false),
        || unsafe { libc::chmod(path, mode) },
    )
}

/// Replacement for `fchmod(2)`. Resolves the fd → path via
/// `fcntl(F_GETPATH)` so the daemon receives a path-based event
/// like every other interposer. A successful mutation whose fd
/// cannot be resolved emits a refusal instead of disappearing.
///
/// # Safety
/// Same contract as `libc::fchmod` — `fd` must be a valid file
/// descriptor.
unsafe extern "C" fn my_fchmod(fd: c_int, mode: mode_t) -> c_int {
    call_zero_success(
        || {
            prepare_fd_path_mutation("fchmod", fd, |path| {
                policy::prepare_metadata_mutation("fchmod", path, false)
            })
        },
        || unsafe { libc::fchmod(fd, mode) },
    )
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
    let path = cstr_to_string(pathname);
    call_zero_success(
        || {
            if (flags & libc::AT_SYMLINK_NOFOLLOW) != 0 {
                policy::prepare_unsupported_at_mutation(
                    "fchmodat",
                    dirfd,
                    &path,
                    true,
                    "symlink metadata restore with nofollow semantics is not modeled".to_string(),
                )
            } else {
                policy::prepare_metadata_at_mutation("fchmodat", dirfd, &path, false)
            }
        },
        || unsafe { libc::fchmodat(dirfd, pathname, mode, flags) },
    )
}

/// Replacement for `chflags(2)` (M03.x.SETATTR). chflags mutates the
/// BSD/macOS `st_flags` bitmap — UF_IMMUTABLE, UF_HIDDEN, UF_NOUNLINK,
/// SF_IMMUTABLE, etc. Apple keeps flags in a separate syscall and kernel
/// field from mode/ownership, so they need a dedicated capture and inverse.
///
/// The prepared notification captures current st_flags before the chflags
/// call, sends only on success, and the planner restores it through the
/// dedicated flags inverse.
///
/// Apple's libc signature: `chflags(path: *const c_char, flags: c_uint)`.
/// (FreeBSD widens to c_ulong; macOS keeps c_uint.)
///
/// # Safety
/// Same contract as `libc::chflags` — `path` must be a valid
/// NUL-terminated C string.
unsafe extern "C" fn my_chflags(path: *const c_char, flags: c_uint) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || policy::prepare_flags_mutation("chflags", &path_string),
        || unsafe { libc::chflags(path, flags) },
    )
}

/// Replacement for `fchflags(2)` (M03.x.SETATTR). Fd-based variant.
/// Resolves fd→path via `fcntl(F_GETPATH)`; successful operations on
/// unresolvable fds become explicit refusals.
///
/// # Safety
/// Same contract as `libc::fchflags`.
unsafe extern "C" fn my_fchflags(fd: c_int, flags: c_uint) -> c_int {
    call_zero_success(
        || {
            prepare_fd_path_mutation("fchflags", fd, |path| {
                policy::prepare_flags_mutation("fchflags", path)
            })
        },
        || unsafe { libc::fchflags(fd, flags) },
    )
}

/// Replacement for `chown(2)`. Captures path + metadata so the
/// planner can restore the old uid/gid on undo.
///
/// # Safety
/// Same contract as `libc::chown` — `path` must be a valid
/// NUL-terminated C string.
unsafe extern "C" fn my_chown(path: *const c_char, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || policy::prepare_metadata_mutation("chown", &path_string, false),
        || unsafe { libc::chown(path, uid, gid) },
    )
}

/// Replacement for `fchown(2)`. Resolves fd→path; successful operations
/// with no resolvable path become explicit refusals.
///
/// # Safety
/// Same contract as `libc::fchown`.
unsafe extern "C" fn my_fchown(fd: c_int, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    call_zero_success(
        || {
            prepare_fd_path_mutation("fchown", fd, |path| {
                policy::prepare_metadata_mutation("fchown", path, false)
            })
        },
        || unsafe { libc::fchown(fd, uid, gid) },
    )
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
    let path = cstr_to_string(pathname);
    call_zero_success(
        || {
            if (flags & libc::AT_SYMLINK_NOFOLLOW) != 0 {
                policy::prepare_unsupported_at_mutation(
                    "fchownat",
                    dirfd,
                    &path,
                    true,
                    "symlink metadata restore with nofollow semantics is not modeled".to_string(),
                )
            } else {
                policy::prepare_metadata_at_mutation("fchownat", dirfd, &path, false)
            }
        },
        || unsafe { libc::fchownat(dirfd, pathname, owner, group, flags) },
    )
}

/// Replacement for `lchown(2)`. RestoreMetadata currently follows paths, so
/// it cannot safely replay metadata onto the symlink itself. Successful calls
/// are journaled as explicit refusals until the executor gains nofollow
/// metadata support.
///
/// # Safety
/// Same contract as `libc::lchown`.
unsafe extern "C" fn my_lchown(path: *const c_char, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || {
            policy::prepare_unsupported_path_mutation(
                "lchown",
                &path_string,
                true,
                "symlink metadata restore with nofollow semantics is not modeled".to_string(),
            )
        },
        || unsafe { libc::lchown(path, uid, gid) },
    )
}

/// Replacement for `utimes(2)`. `FileMetadata` does not yet carry atime, so
/// pretending its mtime-only snapshot is complete would leave half of this
/// syscall behind. Journal a success-gated refusal until timestamp replay
/// models both values.
///
/// # Safety
/// Same contract as `libc::utimes` — `path` valid C string; `times`
/// either NULL (set to current time) or pointer to 2 timevals.
unsafe extern "C" fn my_utimes(path: *const c_char, times: *const libc::timeval) -> c_int {
    let path_string = cstr_to_string(path);
    call_zero_success(
        || {
            policy::prepare_unsupported_path_mutation(
                "utimes",
                &path_string,
                false,
                "timestamp restore does not yet capture atime".to_string(),
            )
        },
        || unsafe { libc::utimes(path, times) },
    )
}

/// Replacement for `futimens(2)`. fd → path via F_GETPATH; successful
/// operations with no resolvable path become explicit refusals.
///
/// # Safety
/// Same contract as `libc::futimens`.
unsafe extern "C" fn my_futimens(fd: c_int, times: *const libc::timespec) -> c_int {
    call_zero_success(
        || {
            prepare_fd_path_mutation("futimens", fd, |path| {
                policy::prepare_unsupported_path_mutation(
                    "futimens",
                    path,
                    false,
                    "timestamp restore does not yet capture atime".to_string(),
                )
            })
        },
        || unsafe { libc::futimens(fd, times) },
    )
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
    let path = cstr_to_string(pathname);
    call_zero_success(
        || {
            if (flag & libc::AT_SYMLINK_NOFOLLOW) != 0 {
                policy::prepare_unsupported_at_mutation(
                    "utimensat",
                    dirfd,
                    &path,
                    true,
                    "timestamp restore does not capture atime and nofollow replay is not modeled"
                        .to_string(),
                )
            } else {
                policy::prepare_unsupported_at_mutation(
                    "utimensat",
                    dirfd,
                    &path,
                    false,
                    "timestamp restore does not yet capture atime".to_string(),
                )
            }
        },
        || unsafe { libc::utimensat(dirfd, pathname, times, flag) },
    )
}

/// Replacement for `futimes(2)` (M07.B.5). fd-only variant; same
/// fd→path resolver as fchmod/fchown.
///
/// # Safety
/// Same contract as `libc::futimes`.
unsafe extern "C" fn my_futimes(fd: c_int, times: *const libc::timeval) -> c_int {
    call_zero_success(
        || {
            prepare_fd_path_mutation("futimes", fd, |path| {
                policy::prepare_unsupported_path_mutation(
                    "futimes",
                    path,
                    false,
                    "timestamp restore does not yet capture atime".to_string(),
                )
            })
        },
        || unsafe { libc::futimes(fd, times) },
    )
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

/// Read the current value of `name` on `path`. `Ok(None)` means the
/// attribute was genuinely absent (`ENOATTR`); every other read error is
/// preserved so a successful mutation can be journaled as a refusal instead
/// of pretending the attribute did not exist.
unsafe fn read_xattr_value(
    path: *const c_char,
    name: *const c_char,
) -> std::io::Result<Option<Vec<u8>>> {
    if path.is_null() || name.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "null path or xattr name",
        ));
    }
    // First call sizes the value. Pass NULL buffer + 0 size; if
    // the xattr exists, return is its byte count. ENOATTR (= 93
    // on Darwin) means absent.
    let sz = unsafe { libc::getxattr(path, name, std::ptr::null_mut(), 0, 0, 0) };
    if sz < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOATTR) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if sz == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut buf = vec![0u8; sz as usize];
    let got =
        unsafe { libc::getxattr(path, name, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, 0) };
    if got < 0 {
        // An ENOATTR here is a race (the attribute existed during the size
        // probe and vanished before the read), not a trustworthy "absent"
        // pre-state.
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(Some(buf))
}

/// fd-based variant of [`read_xattr_value`] using `fgetxattr`.
unsafe fn read_xattr_value_fd(fd: c_int, name: *const c_char) -> std::io::Result<Option<Vec<u8>>> {
    if name.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "null xattr name",
        ));
    }
    let sz = unsafe { libc::fgetxattr(fd, name, std::ptr::null_mut(), 0, 0, 0) };
    if sz < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOATTR) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if sz == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut buf = vec![0u8; sz as usize];
    let got =
        unsafe { libc::fgetxattr(fd, name, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, 0) };
    if got < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(Some(buf))
}

/// Build the [`shit_proto::XattrPreImage`] payload from a captured
/// pre-value. `name` must be a valid C string.
unsafe fn build_xattr_pre(
    name: *const c_char,
    pre_value: Option<Vec<u8>>,
) -> shit_proto::XattrPreImage {
    let name_str = if name.is_null() {
        "\0shit:null-xattr-name".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str()
            .map(str::to_owned)
            .unwrap_or_else(|_| "\0shit:non-utf8-xattr-name".to_string())
    };
    shit_proto::XattrPreImage {
        name: name_str,
        value: pre_value,
    }
}

/// Convert a pre-read into either a normal xattr notification or a
/// refusal-only notification. Capture failures must remain distinct from
/// ENOATTR: treating an unreadable pre-state as absent would make undo remove
/// an attribute whose prior value was merely unavailable to the shim.
unsafe fn prepare_xattr_path_mutation(
    syscall: &'static str,
    path: *const c_char,
    name: *const c_char,
    flags: c_int,
    position: u32,
) -> Option<policy::PreparedNotification> {
    let path_string = cstr_to_string(path);
    if (flags & libc::XATTR_NOFOLLOW) != 0 {
        return policy::prepare_unsupported_path_mutation(
            syscall,
            &path_string,
            true,
            "XATTR_NOFOLLOW symlink pre-state is not safely modeled".to_string(),
        );
    }
    if position != 0 {
        return policy::prepare_unsupported_path_mutation(
            syscall,
            &path_string,
            false,
            format!("non-zero xattr resource-fork position {position} is not modeled"),
        );
    }
    match unsafe { read_xattr_value(path, name) } {
        Ok(pre_value) => {
            let xattr_pre = unsafe { build_xattr_pre(name, pre_value) };
            policy::prepare_xattr_mutation(syscall, &path_string, xattr_pre)
        }
        Err(error) => policy::prepare_unsupported_path_mutation(
            syscall,
            &path_string,
            false,
            format!("could not capture pre-mutation xattr value: {error}"),
        ),
    }
}

/// fd counterpart of [`prepare_xattr_path_mutation`]. A failed F_GETPATH is
/// represented by a diagnostic-only synthetic basename carried alongside an
/// UnsupportedOperation marker; the daemon must never replay that path.
unsafe fn prepare_xattr_fd_mutation(
    syscall: &'static str,
    fd: c_int,
    name: *const c_char,
    position: u32,
) -> Option<policy::PreparedNotification> {
    let Some(path) = fd_to_path(fd) else {
        return policy::prepare_unsupported_path_mutation(
            syscall,
            &format!("shit-unresolved-fd-{fd}"),
            false,
            format!("F_GETPATH failed for fd {fd}"),
        );
    };
    match fd_is_symlink(fd) {
        Ok(false) => {}
        Ok(true) => {
            return policy::prepare_unsupported_path_mutation(
                syscall,
                &path,
                true,
                "fd refers to a symlink whose xattr replay is not modeled".to_string(),
            );
        }
        Err(error) => {
            return policy::prepare_unsupported_path_mutation(
                syscall,
                &path,
                false,
                format!("fstat failed for fd {fd}: {error}"),
            );
        }
    }
    if position != 0 {
        return policy::prepare_unsupported_path_mutation(
            syscall,
            &path,
            false,
            format!("non-zero xattr resource-fork position {position} is not modeled"),
        );
    }
    match unsafe { read_xattr_value_fd(fd, name) } {
        Ok(pre_value) => {
            let xattr_pre = unsafe { build_xattr_pre(name, pre_value) };
            policy::prepare_xattr_fd_mutation(syscall, &path, fd, xattr_pre)
        }
        Err(error) => policy::prepare_unsupported_path_mutation(
            syscall,
            &path,
            false,
            format!("could not capture pre-mutation xattr value: {error}"),
        ),
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
    call_zero_success(
        || unsafe { prepare_xattr_path_mutation("setxattr", path, name, flags, position) },
        || unsafe { libc::setxattr(path, name, value, size, position, flags) },
    )
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
    call_zero_success(
        || unsafe { prepare_xattr_fd_mutation("fsetxattr", fd, name, position) },
        || unsafe { libc::fsetxattr(fd, name, value, size, position, flags) },
    )
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
    call_zero_success(
        || unsafe { prepare_xattr_path_mutation("removexattr", path, name, flags, 0) },
        || unsafe { libc::removexattr(path, name, flags) },
    )
}

/// Replacement for `fremovexattr(2)`. fd → path via F_GETPATH.
///
/// # Safety
/// Same contract as `libc::fremovexattr`.
unsafe extern "C" fn my_fremovexattr(fd: c_int, name: *const c_char, flags: c_int) -> c_int {
    call_zero_success(
        || unsafe { prepare_xattr_fd_mutation("fremovexattr", fd, name, 0) },
        || unsafe { libc::fremovexattr(fd, name, flags) },
    )
}

/// Best-effort fd → path via `fcntl(F_GETPATH)`. Returns `None`
/// if the fd isn't backed by a path (anon fds, pipes, sockets)
/// or if the call fails. macOS-specific: `F_GETPATH` writes up
/// to `MAXPATHLEN` (1024) bytes into the user buffer.
pub(super) fn fd_to_path(fd: c_int) -> Option<String> {
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
    unsafe { call_path_create("mkdirat", dirfd, path, || libc::mkdirat(dirfd, path, mode)) }
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
static INTERPOSE_RMDIR: InterposeEntry = InterposeEntry {
    replacement: my_rmdir as *const c_void,
    target: libc::rmdir as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_REMOVE: InterposeEntry = InterposeEntry {
    replacement: my_remove as *const c_void,
    target: libc::remove as *const c_void,
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

// M03.x.CREATE — mkfifo family. FIFO-creating syscalls; daemon
// already classifies "mkfifo"/"mkfifoat" → TreeOp::Create. Just
// needed shim coverage.
#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_MKFIFO: InterposeEntry = InterposeEntry {
    replacement: my_mkfifo as *const c_void,
    target: libc::mkfifo as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_MKFIFOAT: InterposeEntry = InterposeEntry {
    replacement: my_mkfifoat as *const c_void,
    target: libc::mkfifoat as *const c_void,
};

// M03.x.LINK — hardlink family. Inverse is unlink(dst) (same shape
// as TreeOp::Create); src is unchanged so no pre-image needed.
#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_LINK: InterposeEntry = InterposeEntry {
    replacement: my_link as *const c_void,
    target: libc::link as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_LINKAT: InterposeEntry = InterposeEntry {
    replacement: my_linkat as *const c_void,
    target: libc::linkat as *const c_void,
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

// M03.x.SETATTR — chflags/fchflags. Macros wrap path+fd variants of
// the BSD-only st_flags mutation syscall (UF_IMMUTABLE, UF_HIDDEN,
// etc.). Apple does NOT have `chflagsat`; only chflags + fchflags
// are real symbols.
#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_CHFLAGS: InterposeEntry = InterposeEntry {
    replacement: my_chflags as *const c_void,
    target: libc::chflags as *const c_void,
};

#[used]
#[unsafe(link_section = "__DATA,__interpose")]
static INTERPOSE_FCHFLAGS: InterposeEntry = InterposeEntry {
    replacement: my_fchflags as *const c_void,
    target: libc::fchflags as *const c_void,
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
    fn rmdir_interposer_pair_is_populated() {
        assert!(!INTERPOSE_RMDIR.replacement.is_null());
        assert!(!INTERPOSE_RMDIR.target.is_null());
        assert_ne!(INTERPOSE_RMDIR.replacement, INTERPOSE_RMDIR.target);
    }

    #[test]
    fn remove_interposer_pair_is_populated() {
        assert!(!INTERPOSE_REMOVE.replacement.is_null());
        assert!(!INTERPOSE_REMOVE.target.is_null());
        assert_ne!(INTERPOSE_REMOVE.replacement, INTERPOSE_REMOVE.target);
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
    fn chflags_interposer_pair_is_populated() {
        assert!(!INTERPOSE_CHFLAGS.replacement.is_null());
        assert!(!INTERPOSE_CHFLAGS.target.is_null());
        assert_ne!(INTERPOSE_CHFLAGS.replacement, INTERPOSE_CHFLAGS.target);
    }

    #[test]
    fn fchflags_interposer_pair_is_populated() {
        assert!(!INTERPOSE_FCHFLAGS.replacement.is_null());
        assert!(!INTERPOSE_FCHFLAGS.target.is_null());
        assert_ne!(INTERPOSE_FCHFLAGS.replacement, INTERPOSE_FCHFLAGS.target);
    }

    #[test]
    fn mkfifo_interposer_pair_is_populated() {
        assert!(!INTERPOSE_MKFIFO.replacement.is_null());
        assert!(!INTERPOSE_MKFIFO.target.is_null());
        assert_ne!(INTERPOSE_MKFIFO.replacement, INTERPOSE_MKFIFO.target);
    }

    #[test]
    fn mkfifoat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_MKFIFOAT.replacement.is_null());
        assert!(!INTERPOSE_MKFIFOAT.target.is_null());
        assert_ne!(INTERPOSE_MKFIFOAT.replacement, INTERPOSE_MKFIFOAT.target);
    }

    #[test]
    fn link_interposer_pair_is_populated() {
        assert!(!INTERPOSE_LINK.replacement.is_null());
        assert!(!INTERPOSE_LINK.target.is_null());
        assert_ne!(INTERPOSE_LINK.replacement, INTERPOSE_LINK.target);
    }

    #[test]
    fn linkat_interposer_pair_is_populated() {
        assert!(!INTERPOSE_LINKAT.replacement.is_null());
        assert!(!INTERPOSE_LINKAT.target.is_null());
        assert_ne!(INTERPOSE_LINKAT.replacement, INTERPOSE_LINKAT.target);
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

    #[test]
    fn mutation_helper_captures_before_call_and_notifies_after_success() {
        use std::cell::RefCell;

        let order = RefCell::new(Vec::new());
        let result = call_mutation_and_notify_with(
            || {
                order.borrow_mut().push("capture");
                "pre-image"
            },
            || {
                order.borrow_mut().push("libc");
                41
            },
            |result| *result >= 0,
            |captured| {
                assert_eq!(captured, "pre-image");
                order.borrow_mut().push("notify");
            },
        );

        assert_eq!(result, 41, "open-like return values must be preserved");
        assert_eq!(*order.borrow(), ["capture", "libc", "notify"]);
    }

    #[test]
    fn mutation_helper_drops_capture_when_libc_fails() {
        use std::cell::RefCell;

        let order = RefCell::new(Vec::new());
        let result = call_mutation_and_notify_with(
            || {
                order.borrow_mut().push("capture");
                "pre-image"
            },
            || {
                order.borrow_mut().push("libc");
                -1
            },
            |result| *result == 0,
            |_| order.borrow_mut().push("notify"),
        );

        assert_eq!(result, -1);
        assert_eq!(*order.borrow(), ["capture", "libc"]);
    }

    #[test]
    fn mutation_helper_preserves_errno_across_capture_and_delivery() {
        set_errno(libc::EBUSY);
        let result = call_mutation_and_notify_with(
            || {
                set_errno(libc::EACCES);
                "pre-image"
            },
            || {
                assert_eq!(
                    current_errno(),
                    libc::EBUSY,
                    "libc must see the caller's incoming errno"
                );
                set_errno(libc::EAGAIN);
                -1
            },
            |result| *result == 0,
            |_| set_errno(libc::EPIPE),
        );

        assert_eq!(result, -1);
        assert_eq!(current_errno(), libc::EAGAIN);

        set_errno(libc::EDOM);
        let result = call_mutation_and_notify_with(
            || (),
            || {
                set_errno(libc::ERANGE);
                7
            },
            |result| *result >= 0,
            |_| set_errno(libc::ECONNREFUSED),
        );
        assert_eq!(result, 7);
        assert_eq!(current_errno(), libc::ERANGE);
    }

    #[test]
    fn xattr_reader_distinguishes_absent_from_capture_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = std::ffi::CString::new(file.path().to_str().unwrap()).unwrap();
        let name = std::ffi::CString::new("com.shit.preimage-missing").unwrap();

        assert_eq!(
            unsafe { read_xattr_value(path.as_ptr(), name.as_ptr()) }.unwrap(),
            None,
            "ENOATTR must mean a genuine absent pre-state"
        );

        let missing = std::ffi::CString::new(
            file.path()
                .with_file_name("missing-xattr-target")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let error = unsafe { read_xattr_value(missing.as_ptr(), name.as_ptr()) }
            .expect_err("ENOENT must not collapse into absent xattr");
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn failed_mkdir_existing_emits_no_create_notification() {
        let tmp = tempfile::tempdir().unwrap();
        let path = std::ffi::CString::new(tmp.path().to_str().unwrap()).unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "mkdir",
                libc::AT_FDCWD,
                path.as_ptr(),
                || libc::mkdir(path.as_ptr(), 0o755),
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();

        assert_eq!(result, -1);
        assert_eq!(errno, Some(libc::EEXIST));
        assert!(
            notifications.is_empty(),
            "mkdir(existing) must not journal a Create"
        );
    }

    #[test]
    fn failed_mkdirat_existing_emits_no_create_notification() {
        use std::os::fd::AsRawFd;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("existing")).unwrap();
        let dir = std::fs::File::open(tmp.path()).unwrap();
        let path = std::ffi::CString::new("existing").unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "mkdirat",
                dir.as_raw_fd(),
                path.as_ptr(),
                || libc::mkdirat(dir.as_raw_fd(), path.as_ptr(), 0o755),
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();

        assert_eq!(result, -1);
        assert_eq!(errno, Some(libc::EEXIST));
        assert!(
            notifications.is_empty(),
            "mkdirat(existing) must not journal a Create"
        );
    }

    #[test]
    fn failed_mkfifo_existing_emits_no_create_notification() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = std::ffi::CString::new(tmp.path().to_str().unwrap()).unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "mkfifo",
                libc::AT_FDCWD,
                path.as_ptr(),
                || libc::mkfifo(path.as_ptr(), 0o600),
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };

        assert_eq!(result, -1);
        assert!(
            notifications.is_empty(),
            "mkfifo(existing) must not journal a Create"
        );
    }

    #[test]
    fn failed_link_existing_destination_emits_no_create_notification() {
        let tmp = tempfile::tempdir().unwrap();
        let source_path = tmp.path().join("source");
        let destination_path = tmp.path().join("destination");
        std::fs::write(&source_path, b"source").unwrap();
        std::fs::write(&destination_path, b"destination").unwrap();
        let source = std::ffi::CString::new(source_path.to_str().unwrap()).unwrap();
        let destination = std::ffi::CString::new(destination_path.to_str().unwrap()).unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "link",
                libc::AT_FDCWD,
                destination.as_ptr(),
                || libc::link(source.as_ptr(), destination.as_ptr()),
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };

        assert_eq!(result, -1);
        assert!(
            notifications.is_empty(),
            "link(existing-destination) must not journal a Create"
        );
    }

    #[test]
    fn successful_mkdirat_notification_uses_dirfd_path() {
        use std::os::fd::AsRawFd;

        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::File::open(tmp.path()).unwrap();
        let path = std::ffi::CString::new("created-via-dirfd").unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "mkdirat",
                dir.as_raw_fd(),
                path.as_ptr(),
                || libc::mkdirat(dir.as_raw_fd(), path.as_ptr(), 0o755),
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };

        assert_eq!(result, 0);
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].0, "mkdirat");
        let expected = std::fs::canonicalize(tmp.path().join("created-via-dirfd")).unwrap();
        assert_eq!(Path::new(&notifications[0].1), expected);
        assert!(notifications[0].2.is_none());
    }

    #[test]
    fn successful_linkat_notification_uses_destination_dirfd() {
        use std::os::fd::AsRawFd;

        let tmp = tempfile::tempdir().unwrap();
        let source_dir_path = tmp.path().join("source-dir");
        let destination_dir_path = tmp.path().join("destination-dir");
        std::fs::create_dir(&source_dir_path).unwrap();
        std::fs::create_dir(&destination_dir_path).unwrap();
        std::fs::write(source_dir_path.join("source"), b"content").unwrap();
        let source_dir = std::fs::File::open(&source_dir_path).unwrap();
        let destination_dir = std::fs::File::open(&destination_dir_path).unwrap();
        let source = std::ffi::CString::new("source").unwrap();
        let destination = std::ffi::CString::new("destination").unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "linkat",
                destination_dir.as_raw_fd(),
                destination.as_ptr(),
                || {
                    libc::linkat(
                        source_dir.as_raw_fd(),
                        source.as_ptr(),
                        destination_dir.as_raw_fd(),
                        destination.as_ptr(),
                        0,
                    )
                },
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };

        assert_eq!(result, 0);
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].0, "linkat");
        let expected = std::fs::canonicalize(destination_dir_path.join("destination")).unwrap();
        assert_eq!(Path::new(&notifications[0].1), expected);
        assert!(notifications[0].2.is_none());
    }

    #[test]
    fn successful_create_notification_preserves_absolute_fallback_and_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let candidate = tmp.path().join("missing-parent").join("child");
        let path = std::ffi::CString::new(candidate.to_str().unwrap()).unwrap();
        let mut notifications = Vec::new();

        let result = unsafe {
            call_path_create_with(
                "mkdir",
                libc::AT_FDCWD,
                path.as_ptr(),
                || 0,
                |syscall, path, failure| {
                    notifications.push((syscall.to_string(), path.to_string(), failure));
                },
            )
        };

        assert_eq!(result, 0);
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].0, "mkdir");
        assert_eq!(Path::new(&notifications[0].1), candidate);
        match notifications[0]
            .2
            .as_ref()
            .expect("failed canonicalization must remain observable")
        {
            shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg,
                attempted_path,
                ..
            } => {
                assert_eq!(which_arg, "path");
                assert_eq!(Path::new(attempted_path), candidate);
            }
            other => panic!("expected CanonicalizeFailed, got {other:?}"),
        }
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
            &INTERPOSE_RMDIR,
            &INTERPOSE_REMOVE,
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
            // M03.x.SETATTR: chflags family
            &INTERPOSE_CHFLAGS,
            &INTERPOSE_FCHFLAGS,
            // M03.x.LINK: hardlink family
            &INTERPOSE_LINK,
            &INTERPOSE_LINKAT,
            // M03.x.CREATE: mkfifo family
            &INTERPOSE_MKFIFO,
            &INTERPOSE_MKFIFOAT,
        ];
        assert_eq!(
            entries.len(),
            31,
            "M07.A.2 + M07.B.1..5 + M03.x.SETATTR + M03.x.LINK + M03.x.CREATE interposer count"
        );
        for e in entries {
            assert!(!e.replacement.is_null());
            assert!(!e.target.is_null());
            assert_ne!(e.replacement, e.target);
        }
    }
}
