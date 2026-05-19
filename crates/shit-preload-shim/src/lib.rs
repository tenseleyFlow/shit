// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-preload-shim` — userspace libc-interposition library for the
//! BSD capture tier (S10 / S24.D).
//!
//! ## What this is
//!
//! A `cdylib` loaded into user processes via `LD_PRELOAD` (BSD/Linux)
//! or `DYLD_INSERT_LIBRARIES` (macOS, not used in v1). It interposes
//! a small set of libc calls that mutate file-system state and emits
//! a pre-mutation notification to `shit-helper` (via the daemon's
//! shim socket) before calling through to the real libc symbol.
//!
//! ## Interposed syscalls (S24.D)
//!
//! - `unlink`, `unlinkat` — explicit removal.
//! - `truncate`, `ftruncate` — size mutation.
//! - `open` / `openat` (when `O_TRUNC` or write modes) — truncate-on-open.
//! - `pwrite` — random-access write (covers `dd conv=notrunc` style).
//! - `mmap` (when `PROT_WRITE` and `MAP_SHARED`) — page-table write window.
//!
//! Each interposer:
//! 1. Resolves the real libc symbol via `dlsym(RTLD_NEXT, ...)`
//!    (cached in a `OnceLock`).
//! 2. Optionally sends a pre-mutation notification to the helper over
//!    a per-process UDS at `$XDG_RUNTIME_DIR/shit/shim.sock`. The
//!    notification is fire-and-forget with a 50ms `select(2)` deadline
//!    on the ack; allow-on-timeout. **S24.D ships the notification
//!    plumbing as a passthrough-only no-op** — the UDS client wiring
//!    lands in S24.D.2 once the daemon's shim_listener accept loop
//!    is in place. Kill switch via `SHIT_SHIM_DISABLE=1`.
//! 3. Forwards to the real libc symbol via the resolved function pointer.
//!
//! ## Why we need it on BSD
//!
//! FreeBSD has no fanotify-perm equivalent and no EndpointSecurity
//! equivalent (see `.docs/sprints/S10-bsd-tier.md`). `dtrace` can
//! *observe* syscalls but cannot block them. The LD_PRELOAD shim is
//! the only generic, no-kernel-module way to get pre-mutation events
//! out of dynamic binaries on FreeBSD.
//!
//! ## What this does NOT do (and why)
//!
//! - **Statically-linked binaries:** LD_PRELOAD doesn't apply; the
//!   shim is silently inert. Coverage drops to kqueue-post-hoc for
//!   that process. Documented in `.docs/audits/bsd-coverage.md`.
//! - **Setuid binaries:** the dynamic loader strips LD_PRELOAD before
//!   exec to prevent privilege escalation. Same coverage drop.
//! - **Hold the syscall:** stage 1 (this revision) only notifies and
//!   passes through. The full version awaits a 50ms allow/deny
//!   decision from the helper; on timeout we allow and mark `partial`.

#![allow(clippy::missing_safety_doc)]

pub mod dispatch;
pub mod install_config;
pub mod install_pattern;
pub mod prefix_match;
pub mod runtime;

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
))]
mod next {
    //! `dlsym(RTLD_NEXT, ...)`-based resolver for the real next-in-chain
    //! libc symbols. Each accessor caches its result in a `OnceLock<usize>`
    //! so we pay the dlsym cost exactly once per process lifetime.
    //!
    //! Storing the function pointer as `usize` (rather than the typed
    //! `fn` pointer) avoids `Send`/`Sync` bounds problems on the inner
    //! type and keeps the cache trivially `Sync`. We `transmute` back
    //! at the call site.
    //!
    //! `RTLD_NEXT` is the load-bearing handle here: dlsym with
    //! `RTLD_DEFAULT` would resolve back to our interposer and
    //! infinite-loop on the first call.

    use libc::{c_char, c_int, c_uint, c_void, off_t, size_t, ssize_t};
    use std::sync::OnceLock;

    /// Look up a symbol via `dlsym(RTLD_NEXT, name)`. Returns 0 if the
    /// symbol isn't found — interposers handle that by falling back to
    /// libc's own thin wrapper, accepting that the libc function might
    /// itself recurse if linked statically.
    unsafe fn dlsym_next(name: &[u8]) -> usize {
        // SAFETY: name is a NUL-terminated byte string; RTLD_NEXT is a
        // valid pseudo-handle on every libc we target.
        debug_assert!(name.last() == Some(&0), "dlsym name must be NUL-terminated");
        unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast::<c_char>()) as usize }
    }

    pub fn real_unlink() -> unsafe extern "C" fn(*const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"unlink\0") });
        // SAFETY: dlsym returned the real libc::unlink entry point.
        unsafe { std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char) -> c_int>(addr) }
    }

    pub fn real_open() -> unsafe extern "C" fn(*const c_char, c_int, c_uint) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"open\0") });
        // open(2) is variadic in libc but we treat it as the 3-arg form
        // — POSIX guarantees mode is read only when O_CREAT is in flags,
        // so passing an unused mode for the 2-arg case is well-defined.
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char, c_int, c_uint) -> c_int>(
                addr,
            )
        }
    }

    pub fn real_truncate() -> unsafe extern "C" fn(*const c_char, off_t) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"truncate\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char, off_t) -> c_int>(addr)
        }
    }

    pub fn real_ftruncate() -> unsafe extern "C" fn(c_int, off_t) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"ftruncate\0") });
        unsafe { std::mem::transmute::<usize, unsafe extern "C" fn(c_int, off_t) -> c_int>(addr) }
    }

    pub fn real_pwrite() -> unsafe extern "C" fn(c_int, *const c_void, size_t, off_t) -> ssize_t {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"pwrite\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(c_int, *const c_void, size_t, off_t) -> ssize_t,
            >(addr)
        }
    }

    pub fn real_mmap()
    -> unsafe extern "C" fn(*mut c_void, size_t, c_int, c_int, c_int, off_t) -> *mut c_void {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"mmap\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(
                    *mut c_void,
                    size_t,
                    c_int,
                    c_int,
                    c_int,
                    off_t,
                ) -> *mut c_void,
            >(addr)
        }
    }
    /// Return the magic null fn pointer test, used by `disabled()` to
    /// short-circuit when dlsym failed to resolve any symbol. Cheap.
    pub fn is_zero(p: usize) -> bool {
        p == 0
    }

    /// Convert a typed real-fn pointer back to its usize representation
    /// for `is_zero` checks.
    pub fn as_usize<F>(f: F) -> usize {
        // SAFETY: F is one of the fn pointers above, all of which are
        // the same size as `usize`.
        unsafe { std::mem::transmute_copy(&f) }
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
))]
mod policy {
    //! Pre-mutation notification policy. Stage 1 (this revision):
    //! only the kill-switch lives here. The UDS notification client
    //! lands in S24.D.2.

    use std::sync::OnceLock;

    /// True when the shim is muted via `SHIT_SHIM_DISABLE=1`. Cached
    /// after the first call so the env probe happens once per process.
    pub fn disabled() -> bool {
        static D: OnceLock<bool> = OnceLock::new();
        *D.get_or_init(|| std::env::var_os("SHIT_SHIM_DISABLE").as_deref() == Some("1".as_ref()))
    }

    /// Notification stub. The full version sends a pre-mutation frame
    /// over the per-process UDS at `$XDG_RUNTIME_DIR/shit/shim.sock`
    /// and waits up to 50ms for an ack via `select(2)`. For S24.D.1
    /// we passthrough always.
    /// Resolve the shim socket path. Mirrors `shitd::shim_listener::shim_socket_path`'s
    /// derivation: `${XDG_RUNTIME_DIR:-/tmp}/shit-shim.sock`. Cached for
    /// the process lifetime.
    fn socket_path() -> &'static std::path::Path {
        static P: OnceLock<std::path::PathBuf> = OnceLock::new();
        P.get_or_init(|| {
            let dir = std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
            dir.join("shit-shim.sock")
        })
        .as_path()
    }

    /// Notify the daemon of a pending mutation. Best-effort: failures
    /// (no daemon, socket missing, timeout, encode error) are silently
    /// swallowed and we allow the syscall through. The contract is
    /// **fail-open** — the shim must never block a user's command
    /// because the daemon's shim listener is unavailable.
    ///
    /// 50 ms read deadline mirrors the locked design decision in
    /// the S24 plan. We can't use `select(2)` directly from safe Rust
    /// here, but `set_read_timeout` on a `UnixStream` gives the same
    /// allow-on-timeout property.
    pub fn notify_pre_mutation(syscall: &'static str, arg: &str) {
        if disabled() {
            return;
        }
        let _ = try_notify(syscall, arg);
    }

    fn try_notify(syscall: &'static str, arg: &str) -> std::io::Result<()> {
        use shit_proto::{ShimAck, ShimNotification, decode_frame, encode_frame};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, SystemTime};

        let path = socket_path();
        // Best-effort `connect(2)` — if the socket doesn't exist (no
        // daemon, daemon down, wrong $XDG_RUNTIME_DIR), bail silently.
        let mut stream = UnixStream::connect(path)?;
        stream.set_write_timeout(Some(Duration::from_millis(50)))?;
        stream.set_read_timeout(Some(Duration::from_millis(50)))?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // SAFETY: shim runs in arbitrary user processes; getpid is a
        // syscall, not an interposer target, so this is safe.
        let pid = unsafe { libc::getpid() } as u32;
        let note = ShimNotification {
            pid,
            syscall: syscall.to_string(),
            arg: arg.to_string(),
            ts_unix_nanos: now,
        };
        let frame =
            encode_frame(&note).map_err(|e| std::io::Error::other(format!("encode: {e}")))?;
        stream.write_all(&frame)?;

        // Best-effort ack read. We don't actually act on the ack today
        // (Allow-always), but draining it lets the listener's per-conn
        // task observe a clean close. Errors here are non-fatal.
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap_or(0);
        if n > 0 {
            let _: Result<ShimAck, _> = decode_frame(&buf[..n]);
        }
        Ok(())
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
))]
mod interposers {
    use super::{next, policy};
    use libc::{
        O_RDWR, O_TRUNC, O_WRONLY, c_char, c_int, c_uint, c_void, mode_t, off_t, size_t, ssize_t,
    };

    fn cstr_to_string(path: *const c_char) -> String {
        if path.is_null() {
            return String::new();
        }
        // SAFETY: caller's libc-contract guarantees `path` is a valid
        // NUL-terminated C string when non-null.
        let bytes = unsafe { std::ffi::CStr::from_ptr(path) };
        bytes.to_string_lossy().into_owned()
    }

    /// `unlink(2)` interposer — drops a directory entry.
    ///
    /// # Safety
    /// `path` must be a valid C string per libc's `unlink(2)` contract.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
        policy::notify_pre_mutation("unlink", &cstr_to_string(path));
        let real = next::real_unlink();
        if next::is_zero(next::as_usize(real)) {
            // dlsym failed; fall through to libc's wrapper. The libc
            // crate's `unlink` is itself a forwarder to the dynamic
            // libc; this is the safest fallback for an environment
            // where RTLD_NEXT doesn't resolve (e.g. fully-static
            // binaries we shouldn't have been preloaded into anyway).
            return unsafe { libc::unlink(path) };
        }
        unsafe { real(path) }
    }

    /// `open(2)` interposer. Variadic in libc but we accept the
    /// 3-arg form — POSIX reads `mode` only when `O_CREAT` is set.
    /// Notifies on any write-mode open (`O_WRONLY`/`O_RDWR`) and on
    /// `O_TRUNC` (truncate-on-open is a common destructive pattern).
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
        let writes = (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0;
        if writes {
            policy::notify_pre_mutation("open", &cstr_to_string(path));
        }
        let real = next::real_open();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::open(path, flags, mode as c_uint) };
        }
        unsafe { real(path, flags, mode) }
    }

    /// `truncate(2)` interposer.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn truncate(path: *const c_char, len: off_t) -> c_int {
        policy::notify_pre_mutation("truncate", &cstr_to_string(path));
        let real = next::real_truncate();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::truncate(path, len) };
        }
        unsafe { real(path, len) }
    }

    /// `ftruncate(2)` interposer. fd-based; no path to log.
    ///
    /// # Safety
    /// `fd` must be a valid open file descriptor.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ftruncate(fd: c_int, len: off_t) -> c_int {
        policy::notify_pre_mutation("ftruncate", &format!("fd:{fd}"));
        let real = next::real_ftruncate();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::ftruncate(fd, len) };
        }
        unsafe { real(fd, len) }
    }

    /// `pwrite(2)` interposer — random-access write. Logged as fd-only;
    /// path resolution requires `/proc/self/fd/N` which isn't on
    /// FreeBSD by default. Helper resolves via kvm/procstat instead.
    ///
    /// # Safety
    /// `buf` must point to at least `count` bytes of readable memory.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn pwrite(
        fd: c_int,
        buf: *const c_void,
        count: size_t,
        offset: off_t,
    ) -> ssize_t {
        policy::notify_pre_mutation("pwrite", &format!("fd:{fd}"));
        let real = next::real_pwrite();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::pwrite(fd, buf, count, offset) };
        }
        unsafe { real(fd, buf, count, offset) }
    }

    /// `mmap(2)` interposer — only notifies when `prot & PROT_WRITE`
    /// AND `flags & MAP_SHARED` (the page-cache-mutating combo). Read-only
    /// or anonymous maps don't change file content.
    ///
    /// # Safety
    /// All `mmap(2)` invariants hold for the caller's argv.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mmap(
        addr: *mut c_void,
        length: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void {
        if (prot & libc::PROT_WRITE) != 0 && (flags & libc::MAP_SHARED) != 0 {
            policy::notify_pre_mutation("mmap_shared_w", &format!("fd:{fd}"));
        }
        let real = next::real_mmap();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::mmap(addr, length, prot, flags, fd, offset) };
        }
        unsafe { real(addr, length, prot, flags, fd, offset) }
    }

    /// Stage-1 compatibility export. Older internal tests imported
    /// `shit_preload_unlink`; keep the symbol around so we don't break
    /// anyone vendoring this crate. The real interposition happens via
    /// the un-prefixed `unlink` above.
    ///
    /// # Safety
    /// Same as `unlink`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shit_preload_unlink(path: *const c_char) -> c_int {
        unsafe { libc::unlink(path) }
    }

    /// Stage-1 compatibility export — see `shit_preload_unlink`.
    ///
    /// # Safety
    /// Same as `open`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shit_preload_open(
        path: *const c_char,
        flags: c_int,
        mode: mode_t,
    ) -> c_int {
        unsafe { libc::open(path, flags, mode as c_uint) }
    }
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
)))]
mod interposers {
    // Other targets (e.g. macOS): cdylib still builds but exposes no
    // interposers. The macOS DYLD_INSERT_LIBRARIES path is not v1.
}

#[cfg(all(
    test,
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    )
))]
mod tests {
    use std::ffi::CString;

    /// `unlink` (the real interposed symbol) on a nonexistent path
    /// returns -1 with errno = ENOENT. This proves both that the
    /// interposer is callable and that it forwards to the real libc.
    #[test]
    fn unlink_of_missing_path_fails() {
        let c = CString::new("/tmp/shit-preload-shim-nonexistent-XXX").unwrap();
        let r = unsafe { super::interposers::unlink(c.as_ptr()) };
        assert!(r < 0, "unlink of nonexistent path should fail");
    }

    /// `truncate` on a missing path also fails. Verifies the new
    /// interposer dispatch.
    #[test]
    fn truncate_of_missing_path_fails() {
        let c = CString::new("/tmp/shit-preload-shim-also-nonexistent-XXX").unwrap();
        let r = unsafe { super::interposers::truncate(c.as_ptr(), 0) };
        assert!(r < 0);
    }

    /// `ftruncate` on a bogus fd fails with EBADF.
    #[test]
    fn ftruncate_of_bogus_fd_fails() {
        let r = unsafe { super::interposers::ftruncate(99_999, 0) };
        assert!(r < 0);
    }

    /// `open` of a missing path with `O_RDONLY` (no write) goes
    /// through; the notification stub is a no-op so this just
    /// confirms the forwarder works.
    #[test]
    fn open_of_missing_path_returns_negative() {
        let c = CString::new("/tmp/shit-preload-shim-nope").unwrap();
        let r = unsafe { super::interposers::open(c.as_ptr(), libc::O_RDONLY, 0) };
        assert!(r < 0, "open of nonexistent should fail");
    }

    /// `pwrite` to a bogus fd fails.
    #[test]
    fn pwrite_to_bogus_fd_fails() {
        let buf = b"hello";
        let r = unsafe { super::interposers::pwrite(99_999, buf.as_ptr().cast(), buf.len(), 0) };
        assert!(r < 0);
    }

    /// SHIT_SHIM_DISABLE short-circuits the policy. The notify call
    /// is a no-op either way today, so this just verifies the env
    /// probe doesn't panic and returns a stable answer.
    #[test]
    fn kill_switch_returns_stable_answer() {
        // Don't actually set the env (other tests would see it); just
        // confirm the cached probe returns the same value twice.
        let a = super::policy::disabled();
        let b = super::policy::disabled();
        assert_eq!(a, b);
    }
}
