// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-preload-shim` — userspace libc-interposition library for the
//! POSIX preload capture tier (S10 / S24.D and the macOS shim lane).
//!
//! ## What this is
//!
//! A `cdylib` loaded into user processes via `LD_PRELOAD` (BSD/Linux)
//! or `DYLD_INSERT_LIBRARIES` (macOS). It interposes
//! a small set of libc calls that mutate file-system state. It captures
//! pre-mutation state before calling libc, then emits the prepared notification
//! to `shit-helper` (via the daemon's shim socket) only when libc succeeds.
//!
//! ## Interposed syscalls (S24.D)
//!
//! - `unlink`, `unlinkat`, `rmdir`, `remove` — explicit removal.
//! - `truncate`, `ftruncate` — size mutation.
//! - `open` / `openat` (when `O_TRUNC` or write modes) — truncate-on-open.
//! - `pwrite` — random-access write (covers `dd conv=notrunc` style).
//! - `mmap` (when `PROT_WRITE` and `MAP_SHARED`) — page-table write window.
//!
//! Each interposer:
//! 1. Resolves the real libc symbol via `dlsym(RTLD_NEXT, ...)`
//!    (cached in a `OnceLock`).
//! 2. Captures any required pre-mutation state, forwards to libc, and on
//!    success optionally sends the prepared notification to the helper over
//!    a per-process UDS at `$XDG_RUNTIME_DIR/shit/shim.sock`. The
//!    notification is fail-open with a 50ms acknowledgement deadline;
//!    transport/capture failures never block the user's syscall. Kill switch
//!    via `SHIT_SHIM_DISABLE=1`.
//!    Failed libc calls never produce journal notifications.
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
//! - **Deny the syscall:** capture is observational and fail-open. The shim
//!   does not turn daemon responses into allow/deny policy decisions.

#![allow(clippy::missing_safety_doc)]

// W06.A.2 — FreeBSD versioned-symbol export for the LD_PRELOAD
// interpose surface. FreeBSD base utilities (install, mv, cp, etc.)
// import libc symbols as e.g. `open@FBSD_1.0`. The rtld resolver
// binds the PLT to the specific versioned symbol. Our shim's
// unversioned `open` is not a match, so without this directive
// rtld falls through to libc's own and the shim is silently inert
// on every versioned base binary.
//
// We can't get the version tag via a `--version-script=` linker
// arg because rustc auto-generates its own version script for
// the cdylib output (listing every `#[no_mangle] pub fn` as a
// global and applying `local: *;` to everything else). Two
// version scripts to lld → either it rejects the combination or
// silently drops our tags. The `.symver` directive in inline
// assembly emits the version tag at object-code level, before
// rustc's version script is layered on top, so lld preserves it.
//
// **W06.A.2.5 followup:** version each interposer at every
// version FreeBSD libc actually exposes for it. Surveyed via
// `objdump -T /lib/libc.so.7` on FreeBSD 14.4. The *at variants
// live at FBSD_1.1, and `openat` *also* at FBSD_1.2. Tagging
// only at FBSD_1.0 (the W06.A.2 prototype) left
// `openat@FBSD_1.1` / `unlinkat@FBSD_1.1` / `renameat@FBSD_1.1`
// uncovered — modern callers that link to those bypassed the
// shim. A regression test in `tests/symver.rs` reads the built
// `.so` and asserts the expected version set.
//
// Multiple `.symver` directives per symbol export each version
// as an alias for the same function body — rtld can substitute
// for any of them.
#[cfg(target_os = "freebsd")]
core::arch::global_asm!(
    // FBSD_1.0 — `open`, `unlink`, `rename`, `truncate`,
    // `ftruncate`, `pwrite`, `mmap`. All the pre-`*at` syscalls.
    ".symver open, open@FBSD_1.0",
    ".symver unlink, unlink@FBSD_1.0",
    ".symver rmdir, rmdir@FBSD_1.0",
    ".symver remove, remove@FBSD_1.0",
    ".symver rename, rename@FBSD_1.0",
    ".symver truncate, truncate@FBSD_1.0",
    ".symver ftruncate, ftruncate@FBSD_1.0",
    ".symver pwrite, pwrite@FBSD_1.0",
    ".symver mmap, mmap@FBSD_1.0",
    // W09.10.1 — mkfifo at FBSD_1.0 (the only version libc exposes).
    ".symver mkfifo, mkfifo@FBSD_1.0",
    // BSD link-shim parity (mirrors macOS PR #175 M03.x.LINK): close
    // the hardlink-create capture gap. `link(2)` at FBSD_1.0.
    ".symver link, link@FBSD_1.0",
    // B10 — xattr-mutation shim parity (mirrors macOS PR #174
    // M03.x.XATTR-MUTATE). FreeBSD's extattr_* family lives at
    // FBSD_1.0 (libc base since FreeBSD 5).
    ".symver extattr_set_file, extattr_set_file@FBSD_1.0",
    ".symver extattr_delete_file, extattr_delete_file@FBSD_1.0",
    // B09 — chflags shim parity (mirrors macOS PR #171
    // M03.x.SETATTR-FAMILY). FreeBSD has no portable `fd -> path`
    // (no F_GETPATH); fd-based `fchflags` mutations are covered
    // by kqueue NOTE_ATTRIB on the vnode plus the helper-side
    // baseline. `chflags(2)` at FBSD_1.0.
    //
    // `chflagsat(2)` at FBSD_1.3. Modern callers may bypass the
    // libc chflags wrapper and call it directly. The interposer
    // captures only path shapes the v1 wire can faithfully replay;
    // all others still pass through unchanged.
    ".symver chflags, chflags@FBSD_1.0",
    ".symver chflagsat, chflagsat@FBSD_1.3",
    // FBSD_1.1 — the *at variants. modern coreutils prefer these.
    // openat ALSO lives at FBSD_1.2 (libc's newer flag-aware
    // form), but lld emits "multiple versions for X" if we tag
    // the same source symbol twice — and the conflict appears
    // not in the cdylib output but when the rlib gets linked
    // into the `shit` bin (which pulls in the interposers as
    // dead-code-but-no_mangle). Picking FBSD_1.1 covers the
    // overwhelming majority of base-binary callers. If a future
    // binary surfaces that links to `openat@FBSD_1.2` exclusively,
    // we extend with a runtime-version-aware fallback (see
    // W06.A.2 followups).
    ".symver openat, openat@FBSD_1.1",
    ".symver unlinkat, unlinkat@FBSD_1.1",
    ".symver renameat, renameat@FBSD_1.1",
    // W09.10.1 — mkfifoat (created in FreeBSD 8).
    ".symver mkfifoat, mkfifoat@FBSD_1.1",
    // BSD link-shim parity — `linkat(2)` at FBSD_1.1.
    ".symver linkat, linkat@FBSD_1.1",
);

pub mod dispatch;
pub mod install_config;
pub mod install_pattern;
pub mod prefix_match;
pub mod runtime;

// M07.A: macOS interposition surface, separate module because the
// mechanism is `__DATA,__interpose` (static section table) rather
// than the `dlsym(RTLD_NEXT)` pattern the BSD/Linux `mod next`
// branch uses. See macos.rs for the rationale.
#[cfg(target_os = "macos")]
pub mod macos;

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

    use libc::{c_char, c_int, c_uint, c_void, mode_t, off_t, size_t, ssize_t};
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

    pub fn real_rmdir() -> unsafe extern "C" fn(*const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"rmdir\0") });
        // SAFETY: dlsym returned the real libc::rmdir entry point.
        unsafe { std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char) -> c_int>(addr) }
    }

    pub fn real_remove() -> unsafe extern "C" fn(*const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"remove\0") });
        // SAFETY: dlsym returned the real libc::remove entry point.
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
    /// W06.A.1 — `unlinkat(2)`. Modern coreutils (`rm`, `find`, ...)
    /// prefer the *at variants over the bare `unlink`. Without this,
    /// LD_PRELOAD'ing the shim against current FreeBSD `rm` produces
    /// zero notifications.
    pub fn real_unlinkat() -> unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"unlinkat\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int>(
                addr,
            )
        }
    }

    /// W06.A.1 — `openat(2)`. FreeBSD's `install(1)` uses `openat`,
    /// not `open`, to create the temp file before atomic-rename.
    pub fn real_openat() -> unsafe extern "C" fn(c_int, *const c_char, c_int, c_uint) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"openat\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(c_int, *const c_char, c_int, c_uint) -> c_int,
            >(addr)
        }
    }

    /// W06.A.1 — `rename(2)`. `install`'s atomic move into place; also
    /// the syscall behind `mv` (W08).
    pub fn real_rename() -> unsafe extern "C" fn(*const c_char, *const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"rename\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(
                addr,
            )
        }
    }

    /// W06.A.1 — `renameat(2)`. Same as `rename` but with dirfd-relative
    /// path resolution.
    pub fn real_renameat()
    -> unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"renameat\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int,
            >(addr)
        }
    }

    /// DR-CR-54 — `renameat2(2)`. Linux-only superset of `renameat`
    /// with a `flags` arg. GNU `mv` (coreutils ≥ 8.30) and Python
    /// 3.12+'s `os.rename` glibc-internal fastpath both call this
    /// directly; missing the interposer means we silently drop
    /// rename events from the canonical user-facing rename tools.
    #[cfg(target_os = "linux")]
    pub fn real_renameat2()
    -> unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_uint) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"renameat2\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_uint) -> c_int,
            >(addr)
        }
    }

    /// W09.10.1 — `mkfifo(2)`. The kqueue NOTE_WRITE on the parent
    /// directory does NOT fire for FIFO/special-file creation on
    /// FreeBSD (kernel-side distinction from regular file/dir
    /// creation), so the helper's dir-diff never observes the new
    /// entry. The shim picks up the slack in-process.
    pub fn real_mkfifo() -> unsafe extern "C" fn(*const c_char, mode_t) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"mkfifo\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char, mode_t) -> c_int>(addr)
        }
    }

    /// BSD link-shim parity — `link(2)`. Creates a new hardlink
    /// `new` pointing at the inode of `old`. Mirrors macOS M03.x.LINK
    /// (PR #175): without an interposer, the daemon never sees the
    /// new alias and undo can't unlink it. Daemon handles `arg=new`
    /// as a TreeOp::Create whose inverse is `unlink(new)`.
    pub fn real_link() -> unsafe extern "C" fn(*const c_char, *const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"link\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(
                addr,
            )
        }
    }

    /// BSD link-shim parity — `linkat(2)`. Dirfd-relative variant.
    pub fn real_linkat()
    -> unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_int) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"linkat\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_int) -> c_int,
            >(addr)
        }
    }

    /// B10 — FreeBSD `extattr_set_file(2)`. Sets an extended
    /// attribute on the file at `path`. Namespace passes as
    /// `attrnamespace` (1=USER, 2=SYSTEM). Returns bytes written
    /// on success, -1 on error.
    #[cfg(target_os = "freebsd")]
    pub fn real_extattr_set_file()
    -> unsafe extern "C" fn(*const c_char, c_int, *const c_char, *const c_void, size_t) -> ssize_t
    {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"extattr_set_file\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(
                    *const c_char,
                    c_int,
                    *const c_char,
                    *const c_void,
                    size_t,
                ) -> ssize_t,
            >(addr)
        }
    }

    /// B10 — FreeBSD `extattr_delete_file(2)`. Returns 0 / -1.
    #[cfg(target_os = "freebsd")]
    pub fn real_extattr_delete_file()
    -> unsafe extern "C" fn(*const c_char, c_int, *const c_char) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"extattr_delete_file\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(*const c_char, c_int, *const c_char) -> c_int,
            >(addr)
        }
    }

    /// B10 — FreeBSD `extattr_get_file(2)`. Used pre-syscall to
    /// snapshot the current value before the interposed call
    /// mutates it. Returns byte count read (or required when
    /// `data` is NULL) on success, -1 on error.
    #[cfg(target_os = "freebsd")]
    pub fn real_extattr_get_file()
    -> unsafe extern "C" fn(*const c_char, c_int, *const c_char, *mut c_void, size_t) -> ssize_t
    {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"extattr_get_file\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(
                    *const c_char,
                    c_int,
                    *const c_char,
                    *mut c_void,
                    size_t,
                ) -> ssize_t,
            >(addr)
        }
    }

    /// B09 — FreeBSD `chflags(2)`. Mutates the file's `st_flags`
    /// bitmap (UF_IMMUTABLE, UF_HIDDEN, SF_*, …). FreeBSD widens
    /// the second arg to `c_ulong`; macOS keeps it `c_uint`.
    #[cfg(target_os = "freebsd")]
    pub fn real_chflags() -> unsafe extern "C" fn(*const c_char, libc::c_ulong) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"chflags\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(*const c_char, libc::c_ulong) -> c_int>(
                addr,
            )
        }
    }

    /// B09 — FreeBSD `chflagsat(2)`. Dirfd-relative variant; the
    /// one /bin/chflags(8) actually calls. `atflag` is 0 or
    /// AT_SYMLINK_NOFOLLOW.
    #[cfg(target_os = "freebsd")]
    pub fn real_chflagsat()
    -> unsafe extern "C" fn(c_int, *const c_char, libc::c_ulong, c_int) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"chflagsat\0") });
        unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(c_int, *const c_char, libc::c_ulong, c_int) -> c_int,
            >(addr)
        }
    }

    /// W09.10.1 — `mkfifoat(2)`. Same gap as `mkfifo` but for the
    /// dirfd-relative variant.
    pub fn real_mkfifoat() -> unsafe extern "C" fn(c_int, *const c_char, mode_t) -> c_int {
        static SYM: OnceLock<usize> = OnceLock::new();
        let addr = *SYM.get_or_init(|| unsafe { dlsym_next(b"mkfifoat\0") });
        unsafe {
            std::mem::transmute::<usize, unsafe extern "C" fn(c_int, *const c_char, mode_t) -> c_int>(
                addr,
            )
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
    target_os = "macos",
))]
mod policy {
    //! Pre-state capture and success-gated UDS notification policy.

    use std::sync::OnceLock;

    /// Install wrappers opt into a prefix-bounded capture scope by exporting
    /// `SHIT_INSTALL_PREFIXES`. Direct/manual preload users that omit the
    /// variable retain the existing all-path behavior used by the generic BSD
    /// and macOS capture tier. A present-but-empty or non-UTF-8 value matches
    /// nothing (fail closed).
    #[derive(Debug)]
    enum CaptureScope {
        Unrestricted,
        Prefixes(crate::prefix_match::PrefixSet),
    }

    impl CaptureScope {
        fn from_encoded(encoded: Option<&str>) -> Self {
            match encoded {
                None => Self::Unrestricted,
                Some(encoded) => Self::Prefixes(crate::prefix_match::PrefixSet::new(
                    encoded.split(':').filter(|prefix| !prefix.is_empty()),
                )),
            }
        }

        fn allows(&self, path: &str) -> bool {
            match self {
                Self::Unrestricted => true,
                Self::Prefixes(prefixes) => prefixes.matches_str(path),
            }
        }

        fn allows_any(&self, paths: &[&str]) -> bool {
            paths.iter().any(|path| self.allows(path))
        }

        /// Fd-backed writes are filtered only when the descriptor's path was
        /// resolved authoritatively. An unresolved fd must stay observable:
        /// dropping it would silently miss a target mutation on FreeBSD hosts
        /// without procfs (or during an fd/path race).
        fn allows_fd_path(&self, resolved_path: Option<&str>) -> bool {
            resolved_path.is_none_or(|path| self.allows(path))
        }
    }

    fn capture_scope() -> &'static CaptureScope {
        static SCOPE: OnceLock<CaptureScope> = OnceLock::new();
        SCOPE.get_or_init(|| {
            let encoded = std::env::var_os(crate::dispatch::SHIT_INSTALL_PREFIXES_ENV);
            match encoded.as_deref().and_then(std::ffi::OsStr::to_str) {
                Some(encoded) => CaptureScope::from_encoded(Some(encoded)),
                None if encoded.is_none() => CaptureScope::Unrestricted,
                None => CaptureScope::from_encoded(Some("")),
            }
        })
    }

    fn capture_scope_allows(path: &str) -> bool {
        capture_scope().allows(path)
    }

    fn capture_scope_allows_any(paths: &[&str]) -> bool {
        capture_scope().allows_any(paths)
    }

    fn capture_scope_allows_fd(fd: libc::c_int) -> bool {
        let resolved = dirfd_base_path(fd).and_then(|path| canonical_path(&path).ok());
        capture_scope().allows_fd_path(resolved.as_deref())
    }

    /// True when the shim is muted via `SHIT_SHIM_DISABLE=1`. Cached
    /// after the first call so the env probe happens once per process.
    pub fn disabled() -> bool {
        static D: OnceLock<bool> = OnceLock::new();
        *D.get_or_init(|| std::env::var_os("SHIT_SHIM_DISABLE").as_deref() == Some("1".as_ref()))
    }

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

    /// A fully captured shim notification which has not crossed the daemon
    /// socket yet.  Destructive interposers build this value before invoking
    /// libc, then call [`PreparedNotification::send`] only when libc reports
    /// success.  Keeping capture and delivery separate avoids journaling an
    /// inverse for a syscall that ultimately failed while still preserving
    /// the pre-mutation bytes and metadata needed by a successful syscall.
    pub(super) struct PreparedNotification {
        syscall: &'static str,
        arg: String,
        pre_image: Option<shit_proto::ShimPreImage>,
        extra_pre_images: Vec<shit_proto::ShimPreImage>,
        failure: Option<shit_proto::ShimFailure>,
    }

    impl PreparedNotification {
        pub(super) fn send(self) {
            let Some(_guard) = NotifyGuard::enter() else {
                return;
            };
            let _ = try_notify(
                self.syscall,
                &self.arg,
                self.pre_image,
                self.extra_pre_images,
                self.failure,
            );
        }
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
    // Called by BSD/Linux fd-based truncate / pwrite / mmap interposers.
    #[allow(dead_code)]
    pub fn notify_pre_mutation(syscall: &'static str, arg: &str) {
        if let Some(prepared) = prepare_pre_mutation(syscall, arg) {
            prepared.send();
        }
    }

    #[allow(dead_code)]
    pub(super) fn prepare_pre_mutation(
        syscall: &'static str,
        arg: &str,
    ) -> Option<PreparedNotification> {
        let allowed = arg
            .strip_prefix("fd:")
            .and_then(|fd| fd.parse::<libc::c_int>().ok())
            .map_or_else(|| capture_scope_allows(arg), capture_scope_allows_fd);
        if should_skip_path(arg) || !allowed {
            return None;
        }
        prepare_inner_with_failure(syscall, arg, None, None)
    }

    /// W06.A.4: notify the daemon AND attach a pre-image payload (file
    /// bytes + metadata) for content-mutating syscalls. The shim
    /// reads up to [`shit_proto::SHIM_INLINE_PREIMAGE_CAP`] bytes
    /// from `path` and ships them inline in the notification.
    ///
    /// `path` is what gets captured — for path-based syscalls
    /// (`open`/`openat`/`truncate`) it's the same as the wire arg;
    /// for `rename`/`renameat` it's the **destination** (which is
    /// what gets atomically replaced).
    ///
    /// A genuinely absent path carries no pre-image (fresh-create shape).
    /// Existing paths that exceed the cap or cannot be read become explicit
    /// `PreImageUnavailable` refusals rather than guessed inverses.
    #[allow(dead_code)]
    pub fn notify_pre_mutation_with_content(syscall: &'static str, path: &str) {
        if let Some(prepared) = prepare_pre_mutation_with_content(syscall, path) {
            prepared.send();
        }
    }

    pub(super) fn prepare_pre_mutation_with_content(
        syscall: &'static str,
        path: &str,
    ) -> Option<PreparedNotification> {
        if should_skip_path(path) {
            return None;
        }
        // Resolve while we are still executing in the mutating process. A
        // relative path has meaning only in this cwd; carrying it into the
        // journal would make `shit undo` reinterpret it from a different cwd.
        // Namespace-entry operations preserve the final lexical component so
        // unlinking a symlink records the link itself rather than its target.
        let (resolved, failure) = if matches!(
            syscall,
            "unlink" | "unlinkat" | "rmdir" | "remove" | "lchown"
        ) {
            canonicalize_parent_or_raw(path, "path")
        } else {
            canonicalize_or_raw(path, "path")
        };
        if should_skip_path(&resolved) {
            return None;
        }
        prepare_resolved_pre_mutation(syscall, &resolved, failure)
    }

    /// Resolve and capture a path-taking `*at` syscall without discarding its
    /// dirfd semantics. Relative paths with an unresolvable real dirfd are
    /// reported as capture failures, never guessed against process cwd.
    #[allow(dead_code)]
    pub fn notify_pre_mutation_at_with_content(
        syscall: &'static str,
        dirfd: libc::c_int,
        path: &str,
        preserve_leaf: bool,
    ) {
        if let Some(prepared) =
            prepare_pre_mutation_at_with_content(syscall, dirfd, path, preserve_leaf)
        {
            prepared.send();
        }
    }

    pub(super) fn prepare_pre_mutation_at_with_content(
        syscall: &'static str,
        dirfd: libc::c_int,
        path: &str,
        preserve_leaf: bool,
    ) -> Option<PreparedNotification> {
        if should_skip_path(path) {
            return None;
        }
        let (resolved, failure) = resolve_path_at(dirfd, path, "path", preserve_leaf);
        if should_skip_path(&resolved) {
            return None;
        }
        prepare_resolved_pre_mutation(syscall, &resolved, failure)
    }

    fn prepare_resolved_pre_mutation(
        syscall: &'static str,
        resolved: &str,
        failure: Option<shit_proto::ShimFailure>,
    ) -> Option<PreparedNotification> {
        if failure.is_none() && !capture_scope_allows(resolved) {
            return None;
        }
        // A resolution failure is refusal-only. Capturing the unresolved raw
        // spelling could read a different cwd entry and compound the error.
        if failure.is_some() {
            prepare_inner_with_failure(syscall, resolved, None, failure)
        } else {
            prepare_inner_with_failure(syscall, resolved, Some(resolved), None)
        }
    }

    /// Prepare a refusal-only notification for a mutation whose syscall
    /// semantics or pre-state cannot currently be represented safely.  The
    /// caller still success-gates delivery exactly like an ordinary prepared
    /// notification, so a failed libc call never leaves a phantom refusal in
    /// the journal.
    #[allow(dead_code)]
    pub(super) fn prepare_unsupported_path_mutation(
        syscall: &'static str,
        path: &str,
        preserve_leaf: bool,
        reason: String,
    ) -> Option<PreparedNotification> {
        if should_skip_path(path) {
            return None;
        }
        let (resolved, resolution_failure) = if preserve_leaf {
            canonicalize_parent_or_raw(path, "path")
        } else {
            canonicalize_or_raw(path, "path")
        };
        let resolved_cleanly = resolution_failure.is_none();
        let failure = resolution_failure.or(Some(shit_proto::ShimFailure::UnsupportedOperation {
            attempted_path: resolved.clone(),
            reason,
        }));
        if resolved_cleanly && (should_skip_path(&resolved) || !capture_scope_allows(&resolved)) {
            return None;
        }
        prepare_inner_with_failure(syscall, &resolved, None, failure)
    }

    /// Dirfd-aware counterpart to [`prepare_unsupported_path_mutation`].
    /// Resolution failures take precedence over the semantic refusal so the
    /// journal reports the earliest point at which a safe inverse became
    /// impossible.
    #[allow(dead_code)]
    pub(super) fn prepare_unsupported_at_mutation(
        syscall: &'static str,
        dirfd: libc::c_int,
        path: &str,
        preserve_leaf: bool,
        reason: String,
    ) -> Option<PreparedNotification> {
        if should_skip_path(path) {
            return None;
        }
        let (resolved, resolution_failure) = resolve_path_at(dirfd, path, "path", preserve_leaf);
        let resolved_cleanly = resolution_failure.is_none();
        let failure = resolution_failure.or(Some(shit_proto::ShimFailure::UnsupportedOperation {
            attempted_path: resolved.clone(),
            reason,
        }));
        if resolved_cleanly && (should_skip_path(&resolved) || !capture_scope_allows(&resolved)) {
            return None;
        }
        prepare_inner_with_failure(syscall, &resolved, None, failure)
    }

    /// Capture identity and metadata without reading file contents. Metadata
    /// syscalls do not alter bytes, and requiring a content snapshot would
    /// unnecessarily refuse directories, large files, and unreadable files.
    #[allow(dead_code)]
    pub(super) fn prepare_metadata_mutation(
        syscall: &'static str,
        path: &str,
        preserve_leaf: bool,
    ) -> Option<PreparedNotification> {
        if disabled() || should_skip_path(path) {
            return None;
        }
        let (resolved, resolution_failure) = if preserve_leaf {
            canonicalize_parent_or_raw(path, "path")
        } else {
            canonicalize_or_raw(path, "path")
        };
        prepare_resolved_metadata_mutation(syscall, resolved, resolution_failure)
    }

    /// Dirfd-aware metadata-only capture for ordinary follow-symlink `*at`
    /// operations. Nofollow variants must use
    /// [`prepare_unsupported_at_mutation`] until replay supports them.
    #[allow(dead_code)]
    pub(super) fn prepare_metadata_at_mutation(
        syscall: &'static str,
        dirfd: libc::c_int,
        path: &str,
        preserve_leaf: bool,
    ) -> Option<PreparedNotification> {
        if disabled() || should_skip_path(path) {
            return None;
        }
        let (resolved, resolution_failure) = resolve_path_at(dirfd, path, "path", preserve_leaf);
        prepare_resolved_metadata_mutation(syscall, resolved, resolution_failure)
    }

    fn prepare_resolved_metadata_mutation(
        syscall: &'static str,
        resolved: String,
        resolution_failure: Option<shit_proto::ShimFailure>,
    ) -> Option<PreparedNotification> {
        if resolution_failure.is_none()
            && (should_skip_path(&resolved) || !capture_scope_allows(&resolved))
        {
            return None;
        }
        let _guard = NotifyGuard::enter()?;
        if let Some(failure) = resolution_failure {
            return Some(PreparedNotification {
                syscall,
                arg: resolved,
                pre_image: None,
                extra_pre_images: Vec::new(),
                failure: Some(failure),
            });
        }

        let pre_image = match capture_metadata_pre_image(&resolved) {
            Ok(pre_image) => pre_image,
            Err(reason) => {
                return Some(PreparedNotification {
                    syscall,
                    arg: resolved.clone(),
                    pre_image: None,
                    extra_pre_images: Vec::new(),
                    failure: Some(shit_proto::ShimFailure::PreImageUnavailable {
                        attempted_path: resolved,
                        reason: format!("metadata pre-image capture failed: {reason}"),
                    }),
                });
            }
        };
        Some(PreparedNotification {
            syscall,
            arg: resolved,
            pre_image: Some(pre_image),
            extra_pre_images: Vec::new(),
            failure: None,
        })
    }

    /// B09 — notify a chflags-family mutation with a metadata-only
    /// pre-image. Unlike content capture this accepts directories,
    /// special files, unreadable files, and regular files above the
    /// inline byte cap; chflags needs only the pre-syscall `st_flags`.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[allow(dead_code)]
    pub fn notify_flags_mutation(syscall: &'static str, path: &str) {
        if let Some(prepared) = prepare_flags_mutation(syscall, path) {
            prepared.send();
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(super) fn prepare_flags_mutation(
        syscall: &'static str,
        path: &str,
    ) -> Option<PreparedNotification> {
        if disabled() || should_skip_path(path) {
            return None;
        }
        let _guard = NotifyGuard::enter()?;
        let (resolved, failure) = canonicalize_or_raw(path, "path");
        if failure.is_none() && (should_skip_path(&resolved) || !capture_scope_allows(&resolved)) {
            return None;
        }
        if let Some(failure) = failure {
            return Some(PreparedNotification {
                syscall,
                arg: resolved,
                pre_image: None,
                extra_pre_images: Vec::new(),
                failure: Some(failure),
            });
        }
        let pre_image = match capture_metadata_pre_image(&resolved) {
            Ok(pre_image) => pre_image,
            Err(reason) => {
                return Some(PreparedNotification {
                    syscall,
                    arg: resolved.clone(),
                    pre_image: None,
                    extra_pre_images: Vec::new(),
                    failure: Some(shit_proto::ShimFailure::PreImageUnavailable {
                        attempted_path: resolved,
                        reason: format!("flags pre-image capture failed: {reason}"),
                    }),
                });
            }
        };
        let wire_arg = pre_image.path.clone();
        Some(PreparedNotification {
            syscall,
            arg: wire_arg,
            pre_image: Some(pre_image),
            extra_pre_images: Vec::new(),
            failure: None,
        })
    }

    /// W06.A.4 rename/renameat variant: the wire `arg` is `from\tto`
    /// but the pre-image target is `to` (the destination — rename
    /// atomically overwrites its content). When `to` doesn't exist
    /// (clean-prefix install / mv to new path), `pre_image` ends up
    /// `None` and the planner falls back to ReverseRename. When `to`
    /// pre-exists (install over an existing file), the captured bytes
    /// drive a RestoreContent inverse instead.
    #[allow(dead_code)]
    pub fn notify_rename_with_dst_preimage(syscall: &'static str, from: &str, to: &str) {
        if let Some(prepared) = prepare_rename_with_dst_preimage(syscall, from, to) {
            prepared.send();
        }
    }

    pub(super) fn prepare_rename_with_dst_preimage(
        syscall: &'static str,
        from: &str,
        to: &str,
    ) -> Option<PreparedNotification> {
        // W09.7: canonicalize both `from` and `to` so the daemon's
        // TreeOp::Rename carries absolute paths. Otherwise tools like
        // `rsync` that call rename(2) with paths relative to their own
        // cwd produce journal events with relative paths, and the
        // planner's ReverseRename inverse — applied from `shit undo`'s
        // cwd, which is typically NOT the same — fails with
        // ConflictMissing ("rename source 'X' does not exist").
        //
        // `from` exists pre-rename so canonicalize works. `to` may not
        // (clean rename into a new path); fall back to its parent +
        // basename when canonicalize itself fails.
        //
        // AU10 — when both canonicalize attempts fail (the
        // load-bearing silent-fallback case the brutal audit pinned)
        // the helper records a structured ShimFailure on the
        // outbound notification so the daemon journals a Refuse
        // marker. The syscall itself still flows through with the
        // raw user arg — we never block the user's command on a
        // capture issue.
        // rename operates on directory entries. Resolve each parent but keep
        // the last component lexical; direct canonicalization would turn a
        // symlink rename into an inverse targeting the symlink's referent.
        let (from_abs, from_failure) = canonicalize_parent_or_raw(from, "from");
        let (to_abs, to_failure) = canonicalize_parent_or_raw(to, "to");
        // Prefer the `from`-side failure when both arms tripped:
        // `from`'s pre-image is the load-bearing input for
        // RestoreContent, so its capture incompleteness is the more
        // alarming signal to surface to the user.
        let failure = from_failure.or(to_failure);
        prepare_resolved_rename(syscall, &from_abs, &to_abs, failure)
    }

    /// Dirfd-aware rename capture. On platforms without a trustworthy fd→path
    /// facility, a relative operand with a real dirfd becomes a refusal rather
    /// than a cwd-relative inverse.
    #[allow(dead_code)]
    pub fn notify_rename_at_with_dst_preimage(
        syscall: &'static str,
        fromfd: libc::c_int,
        from: &str,
        tofd: libc::c_int,
        to: &str,
    ) {
        if let Some(prepared) = prepare_rename_at_with_dst_preimage(syscall, fromfd, from, tofd, to)
        {
            prepared.send();
        }
    }

    pub(super) fn prepare_rename_at_with_dst_preimage(
        syscall: &'static str,
        fromfd: libc::c_int,
        from: &str,
        tofd: libc::c_int,
        to: &str,
    ) -> Option<PreparedNotification> {
        let (from_abs, from_failure) = resolve_path_at(fromfd, from, "from", true);
        let (to_abs, to_failure) = resolve_path_at(tofd, to, "to", true);
        prepare_resolved_rename(syscall, &from_abs, &to_abs, from_failure.or(to_failure))
    }

    /// Emit an explicit refusal for a dirfd-aware rename variant whose
    /// semantics are not equivalent to ordinary rename. The paths are still
    /// resolved in the mutating process so diagnostics identify stable
    /// targets, but no inverse is guessed.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub fn notify_unsupported_rename_at(
        syscall: &'static str,
        fromfd: libc::c_int,
        from: &str,
        tofd: libc::c_int,
        to: &str,
        reason: String,
    ) {
        if let Some(prepared) =
            prepare_unsupported_rename_at(syscall, fromfd, from, tofd, to, reason)
        {
            prepared.send();
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn prepare_unsupported_rename_at(
        syscall: &'static str,
        fromfd: libc::c_int,
        from: &str,
        tofd: libc::c_int,
        to: &str,
        reason: String,
    ) -> Option<PreparedNotification> {
        let (from_abs, from_failure) = resolve_path_at(fromfd, from, "from", true);
        let (to_abs, to_failure) = resolve_path_at(tofd, to, "to", true);
        if from_failure.is_none()
            && to_failure.is_none()
            && !capture_scope_allows_any(&[&from_abs, &to_abs])
        {
            return None;
        }
        let arg = format!("{from_abs}\t{to_abs}");
        let failure =
            from_failure
                .or(to_failure)
                .or(Some(shit_proto::ShimFailure::UnsupportedOperation {
                    attempted_path: to_abs,
                    reason,
                }));
        prepare_inner_with_failure(syscall, &arg, None, failure)
    }

    fn prepare_resolved_rename(
        syscall: &'static str,
        from_abs: &str,
        to_abs: &str,
        failure: Option<shit_proto::ShimFailure>,
    ) -> Option<PreparedNotification> {
        if failure.is_none() && (should_skip_path(from_abs) || should_skip_path(to_abs)) {
            return None;
        }
        if failure.is_none() && !capture_scope_allows_any(&[from_abs, to_abs]) {
            return None;
        }
        // W09.8: an exact rename-to-self is a syscall no-op. Do not attempt to
        // infer the same result by separately statting two distinct pathnames:
        // either entry can be replaced between those probes and the eventual
        // syscall. A false "same inode" result is worse than recording a
        // harmless no-op because it can suppress the only undo evidence for a
        // real rename. Distinct hardlink aliases therefore remain observable.
        if from_abs == to_abs {
            return None;
        }
        let arg = format!("{from_abs}\t{to_abs}");
        if failure.is_some() {
            return prepare_inner_with_failure(syscall, &arg, None, failure);
        }
        // DR-CR-54 — when `from` is a directory, snapshot every
        // regular file in the subtree so the planner can restore
        // the original tree content on undo. pip's wheel installer
        // is the canonical motivator: it renames `site-packages →
        // <staging>` before writing fresh content, and without
        // recursive pre-images the original site-packages contents
        // are unreachable by the time undo runs.
        prepare_rename_inner_with_recursive(syscall, &arg, to_abs, from_abs, None)
    }

    /// DR-CR-54 limits. A directory rename of an enormous tree
    /// would saturate memory and the shim→daemon UDS; cap the walk
    /// to bound worst-case overhead. A tripped limit becomes a loud
    /// refusal: a partial tree snapshot is not a trustworthy inverse.
    const RECURSIVE_MAX_FILES: usize = 1000;
    const RECURSIVE_MAX_ENTRIES: usize = 2000;
    // The large shim frame is capped at 64 MiB. Reserve 32 MiB for the
    // destination's primary bytes, 8 MiB for its xattrs, 4 MiB for recursive
    // xattrs, and 8 MiB for postcard/path/metadata overhead. The remaining
    // 12 MiB bounds recursive file contents.
    const RECURSIVE_MAX_BYTES: u64 = 12 * 1024 * 1024;
    const RECURSIVE_MAX_XATTR_BYTES: u64 = 4 * 1024 * 1024;
    const RECURSIVE_MAX_DEPTH: usize = 5;

    /// Variant of `notify_inner` that ships a directory rename's
    /// recursive subtree pre-images alongside the primary
    /// notification. Walks `from_abs` (the **source** of the
    /// rename, which still has the pre-rename contents at this
    /// point — the libc rename hasn't been forwarded yet), but
    /// only when it is actually a directory.
    fn prepare_rename_inner_with_recursive(
        syscall: &'static str,
        arg: &str,
        capture_path: &str,
        from_abs: &str,
        mut failure: Option<shit_proto::ShimFailure>,
    ) -> Option<PreparedNotification> {
        if disabled() {
            return None;
        }
        let _guard = NotifyGuard::enter()?;
        let (mut pre_image, capture_failure) = if failure.is_none() {
            capture_pre_image_or_failure(syscall, capture_path)
        } else {
            (None, None)
        };
        if failure.is_none() {
            failure = capture_failure;
        }
        // A pre-existing destination without a usable pre-image makes an
        // ordinary ReverseRename lossy. Refusal-only notifications must not
        // attach partial source-tree snapshots that the daemon cannot safely
        // apply in isolation.
        let extras = if failure.is_none() {
            match collect_recursive_pre_images(from_abs) {
                Ok(extras) => extras,
                Err(reason) => {
                    failure = Some(shit_proto::ShimFailure::PreImageUnavailable {
                        attempted_path: from_abs.to_string(),
                        reason,
                    });
                    pre_image = None;
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        // Unlike a single-path notification, rename's wire argument is a
        // packed `from<TAB>to` pair. Replacing it with pre.path when the
        // destination has a pre-image destroys the source operand and makes
        // the daemon reject the event as malformed.
        Some(PreparedNotification {
            syscall,
            arg: arg.to_string(),
            pre_image,
            extra_pre_images: extras,
            failure,
        })
    }

    /// Walk `from_abs` if it is a directory and capture per-file
    /// pre-images for every regular file in the subtree. Non-directories need
    /// no recursive payload. Any unreadable/unsupported entry or resource cap
    /// makes the batch incomplete and therefore returns an explicit refusal.
    fn collect_recursive_pre_images(
        from_abs: &str,
    ) -> Result<Vec<shit_proto::ShimPreImage>, String> {
        use std::os::unix::fs::MetadataExt;
        use std::path::{Path, PathBuf};

        let p = Path::new(from_abs);
        let meta = std::fs::symlink_metadata(p)
            .map_err(|e| format!("rename source metadata unavailable: {e}"))?;
        if !meta.is_dir() {
            return Ok(Vec::new());
        }

        let mut out: Vec<shit_proto::ShimPreImage> = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut total_xattr_bytes: u64 = 0;
        let mut entries_seen: usize = 0;
        // Depth-first walk. (Depth bound keeps a path explosion
        // contained; file/byte caps catch fan-out separately.)
        let mut stack: Vec<(PathBuf, usize)> = vec![(p.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > RECURSIVE_MAX_DEPTH {
                return Err(format!(
                    "recursive rename exceeded depth cap {RECURSIVE_MAX_DEPTH} at {}",
                    dir.display()
                ));
            }
            if out.len() >= RECURSIVE_MAX_FILES {
                return Err(format!(
                    "recursive rename exceeded file cap {RECURSIVE_MAX_FILES}"
                ));
            }
            let rd = std::fs::read_dir(&dir).map_err(|e| {
                format!("cannot read rename source directory {}: {e}", dir.display())
            })?;
            for entry_result in rd {
                let entry = entry_result.map_err(|e| {
                    format!(
                        "cannot enumerate rename source directory {}: {e}",
                        dir.display()
                    )
                })?;
                entries_seen = entries_seen.saturating_add(1);
                if entries_seen > RECURSIVE_MAX_ENTRIES {
                    return Err(format!(
                        "recursive rename exceeded entry cap {RECURSIVE_MAX_ENTRIES}"
                    ));
                }
                if out.len() >= RECURSIVE_MAX_FILES {
                    return Err(format!(
                        "recursive rename exceeded file cap {RECURSIVE_MAX_FILES}"
                    ));
                }
                let path = entry.path();
                // `symlink_metadata` to avoid following symlinks
                // into unrelated parts of the filesystem.
                let emeta = std::fs::symlink_metadata(&path).map_err(|e| {
                    format!("cannot inspect rename source entry {}: {e}", path.display())
                })?;
                if emeta.is_dir() {
                    stack.push((path, depth + 1));
                    continue;
                }
                if !emeta.is_file() {
                    return Err(format!(
                        "recursive rename contains unsupported non-regular entry {}",
                        path.display()
                    ));
                }
                let size = emeta.size();
                if total_bytes.saturating_add(size) > RECURSIVE_MAX_BYTES {
                    return Err(format!(
                        "recursive rename exceeded byte cap {RECURSIVE_MAX_BYTES}"
                    ));
                }
                let s = path.to_str().ok_or_else(|| {
                    format!("recursive rename contains a non-UTF-8 path under {from_abs}")
                })?;
                if should_skip_path(s) {
                    return Err(format!(
                        "recursive rename crossed unsupported pseudo-filesystem entry {s}"
                    ));
                }
                let pre = match capture_pre_image(s) {
                    PreImageCapture::Captured(pre) => pre,
                    PreImageCapture::Absent => {
                        return Err(format!(
                            "recursive rename source file disappeared before capture: {s}"
                        ));
                    }
                    PreImageCapture::Unavailable(reason) => {
                        return Err(format!(
                            "cannot capture recursive rename source file {s}: {reason}"
                        ));
                    }
                };
                // The file can grow between `symlink_metadata` and the read in
                // `capture_pre_image`. Enforce the aggregate cap against the
                // bytes actually captured as well as the optimistic stat size.
                let captured_bytes = pre.bytes.len() as u64;
                if total_bytes.saturating_add(captured_bytes) > RECURSIVE_MAX_BYTES {
                    return Err(format!(
                        "recursive rename exceeded byte cap {RECURSIVE_MAX_BYTES} while capturing {s}"
                    ));
                }
                let captured_xattr_bytes = pre
                    .xattrs
                    .as_ref()
                    .map(|xattrs| {
                        xattrs.iter().fold(0u64, |total, (name, value)| {
                            total
                                .saturating_add(name.len() as u64)
                                .saturating_add(value.len() as u64)
                        })
                    })
                    .unwrap_or(0);
                if total_xattr_bytes.saturating_add(captured_xattr_bytes)
                    > RECURSIVE_MAX_XATTR_BYTES
                {
                    return Err(format!(
                        "recursive rename exceeded xattr byte cap {RECURSIVE_MAX_XATTR_BYTES} while capturing {s}"
                    ));
                }
                total_bytes = total_bytes.saturating_add(captured_bytes);
                total_xattr_bytes = total_xattr_bytes.saturating_add(captured_xattr_bytes);
                out.push(pre);
            }
        }
        Ok(out)
    }

    /// W09.10.1 — create-only notification (no pre-image). Used by
    /// `mkfifo` / `mkfifoat`: the path doesn't exist pre-syscall so
    /// there's nothing to capture; the daemon journals a fresh
    /// `TreeOp::Create` whose inverse is `unlink <path>`.
    ///
    /// Path is canonicalized via the parent-canonicalize + basename
    /// trick (same as rename's `to` handling) — the file doesn't
    /// exist yet, so direct canonicalize would fail. This matters
    /// when callers invoke mkfifo with a relative path; the daemon's
    /// undo-side executor runs from a different cwd and needs the
    /// absolute path to find what to unlink.
    /// M07.B.4.1 — xattr-mutating syscall notification with the
    /// pre-syscall xattr value attached. Builds a minimal
    /// [`ShimPreImage`] (path + inode/dev/mode/uid/gid for keying,
    /// empty `bytes` since xattr ops don't change file content)
    /// with the `xattr` field populated. The daemon's planner uses
    /// `xattr_pre.value` to drive an `set/removexattr` inverse on
    /// undo.
    // Called by the macOS interposers in `super::macos`. BSD/Linux
    // xattr interposers don't exist in the shim today (the existing
    // BSD path doesn't interpose xattr at all; the Linux capture
    // tier handles it via fanotify/LSM), so the function looks
    // dead on those targets. `#[allow(dead_code)]` here is the
    // honest signal — when BSD/Linux gains a parallel xattr
    // interposer, this function picks up its second caller.
    #[allow(dead_code)]
    pub fn notify_xattr_mutation(
        syscall: &'static str,
        path: &str,
        xattr_pre: shit_proto::XattrPreImage,
    ) {
        if let Some(prepared) = prepare_xattr_mutation(syscall, path, xattr_pre) {
            prepared.send();
        }
    }

    #[allow(dead_code)]
    pub(super) fn prepare_xattr_mutation(
        syscall: &'static str,
        path: &str,
        mut xattr_pre: shit_proto::XattrPreImage,
    ) -> Option<PreparedNotification> {
        if disabled() || should_skip_path(path) {
            return None;
        }
        let _guard = NotifyGuard::enter()?;
        let (resolved, path_failure) = canonicalize_or_raw(path, "path");
        if path_failure.is_none()
            && (should_skip_path(&resolved) || !capture_scope_allows(&resolved))
        {
            return None;
        }
        let failure = path_failure.or_else(|| {
            xattr_pre
                .name
                .contains('\0')
                .then(|| shit_proto::ShimFailure::UnsupportedOperation {
                    attempted_path: resolved.clone(),
                    reason: "xattr name is not representable as UTF-8".to_string(),
                })
        });
        if failure.is_some() {
            return Some(PreparedNotification {
                syscall,
                arg: resolved,
                pre_image: None,
                extra_pre_images: Vec::new(),
                failure,
            });
        }
        let mut pre = match capture_metadata_pre_image(&resolved) {
            Ok(pre) => pre,
            Err(reason) => {
                return Some(PreparedNotification {
                    syscall,
                    arg: resolved.clone(),
                    pre_image: None,
                    extra_pre_images: Vec::new(),
                    failure: Some(shit_proto::ShimFailure::PreImageUnavailable {
                        attempted_path: resolved,
                        reason: format!("xattr pre-image capture failed: {reason}"),
                    }),
                });
            }
        };
        // The complete snapshot is authoritative. Rebuild the legacy single-
        // xattr compatibility field from it so a concurrent change between an
        // interposer's preliminary probe and this descriptor snapshot cannot
        // create internally inconsistent wire evidence.
        let snapshot_name = snapshot_xattr_name(&xattr_pre.name);
        xattr_pre.value = pre
            .xattrs
            .as_ref()
            .and_then(|xattrs| xattrs.get(snapshot_name).cloned());
        pre.xattr = Some(xattr_pre);
        Some(PreparedNotification {
            syscall,
            arg: resolved,
            pre_image: Some(pre),
            extra_pre_images: Vec::new(),
            failure: None,
        })
    }

    /// Descriptor-preserving xattr capture for `fsetxattr`/`fremovexattr`.
    /// The caller's fd remains owned by libc; the temporary `File` wrapper is
    /// deliberately `ManuallyDrop` so capture cannot close it.
    #[cfg(target_os = "macos")]
    pub(super) fn prepare_xattr_fd_mutation(
        syscall: &'static str,
        path: &str,
        fd: libc::c_int,
        mut xattr_pre: shit_proto::XattrPreImage,
    ) -> Option<PreparedNotification> {
        use std::os::fd::FromRawFd as _;

        if disabled() || should_skip_path(path) || !capture_scope_allows(path) {
            return None;
        }
        let _guard = NotifyGuard::enter()?;
        if xattr_pre.name.contains('\0') {
            return Some(PreparedNotification {
                syscall,
                arg: path.to_string(),
                pre_image: None,
                extra_pre_images: Vec::new(),
                failure: Some(shit_proto::ShimFailure::UnsupportedOperation {
                    attempted_path: path.to_string(),
                    reason: "xattr name is not representable as UTF-8".to_string(),
                }),
            });
        }

        // SAFETY: the interposer received a live fd from its caller. The
        // ManuallyDrop wrapper borrows it for metadata/xattr syscalls only.
        let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        let mut pre = match capture_metadata_pre_image_from_file(path, &file) {
            Ok(pre) => pre,
            Err(reason) => {
                return Some(PreparedNotification {
                    syscall,
                    arg: path.to_string(),
                    pre_image: None,
                    extra_pre_images: Vec::new(),
                    failure: Some(shit_proto::ShimFailure::PreImageUnavailable {
                        attempted_path: path.to_string(),
                        reason: format!("descriptor xattr pre-image capture failed: {reason}"),
                    }),
                });
            }
        };
        let snapshot_name = snapshot_xattr_name(&xattr_pre.name);
        xattr_pre.value = pre
            .xattrs
            .as_ref()
            .and_then(|xattrs| xattrs.get(snapshot_name).cloned());
        pre.xattr = Some(xattr_pre);
        Some(PreparedNotification {
            syscall,
            arg: path.to_string(),
            pre_image: Some(pre),
            extra_pre_images: Vec::new(),
            failure: None,
        })
    }

    /// Create-only interposers resolve the canonical parent + lexical basename
    /// before calling libc, then notify only after libc succeeds.
    /// Trust that already-absolute destination here: canonicalizing the final
    /// name post-syscall could follow a replacement raced in by another thread
    /// and journal an inverse for the wrong path.
    pub(super) fn notify_create_resolved(
        syscall: &'static str,
        path: &str,
        failure: Option<shit_proto::ShimFailure>,
    ) {
        if should_skip_path(path) || (failure.is_none() && !capture_scope_allows(path)) {
            return;
        }
        notify_inner_with_failure(syscall, path, None, failure);
    }

    /// W09.11 — paths whose mutations are NOT user-visible state
    /// and must never appear in the journal. `/dev/null`, `/dev/zero`,
    /// `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/stdin`,
    /// `/dev/stdout`, `/dev/stderr`, etc. — character/block devices.
    /// Tools like ssh-keygen, openssl, ssh routinely `open(O_WRONLY)`
    /// on `/dev/null` for stderr/log suppression; without this guard
    /// the shim fires a Create event whose `unlink` inverse would
    /// fail with EPERM and surface a spurious "1 failed" in the
    /// undo report.
    ///
    /// Also skip `/proc` (Linux) and `/sys` — kernel pseudo-fs; any
    /// "write" there is a runtime config knob, not a file mutation
    /// we can or should undo.
    fn should_skip_path(path: &str) -> bool {
        path.starts_with("/dev/")
            || path == "/dev"
            || path.starts_with("/proc/")
            || path.starts_with("/sys/")
    }

    /// AU10 — structured failure from [`canonical_path`]. Each
    /// variant maps to a previously-silent fallback in the pre-AU10
    /// implementation. Surfacing them as typed errors lets the
    /// shim's notify path attribute the capture incompleteness
    /// over the wire instead of returning the raw user-passed
    /// string and praying the daemon's path matcher gets lucky.
    #[derive(Debug, thiserror::Error)]
    pub(super) enum CanonicalizeError {
        /// The current string protocol cannot represent an arbitrary POSIX
        /// byte path. Interposer adapters encode that condition with an
        /// impossible (NUL-containing) sentinel so it can only become a
        /// structured refusal, never a replayable path.
        #[error("path is not representable as UTF-8")]
        Unrepresentable,
        /// The path has no `file_name()` component — covers `/`
        /// and trailing-slash inputs. Extremely rare for shim
        /// callsites (would mean the user `rename`'d to "/" which
        /// would EISDIR anyway), but we surface it cleanly.
        #[error("path has no file-name component: {0:?}")]
        NoFileName(String),
        /// Path has no parent component. Same vanishingly-rare
        /// shape as `NoFileName`.
        #[error("path has no parent component: {0:?}")]
        NoParent(String),
        /// The load-bearing case: `canonicalize` failed on both the
        /// path itself AND on its parent. This is exactly the silent
        /// fallback the brutal audit pinned — pre-AU10 we returned
        /// the raw user path and the daemon's path matcher
        /// (which keys on canonicalized absolute paths) missed.
        #[error(
            "canonicalize {path:?} failed ({path_err}); parent {parent:?} also failed ({parent_err})"
        )]
        PathAndParentBothFailed {
            path: String,
            path_err: std::io::Error,
            parent: String,
            parent_err: std::io::Error,
        },
        /// Namespace-entry resolution intentionally does not canonicalize the
        /// final component (which could be a symlink). Its parent could not be
        /// resolved, so there is no safe absolute identity to journal.
        #[error("canonicalize parent {parent:?} for {path:?} failed ({parent_err})")]
        ParentFailed {
            path: String,
            parent: String,
            parent_err: std::io::Error,
        },
    }

    pub(super) fn path_to_utf8(path: &std::path::Path) -> Result<String, CanonicalizeError> {
        path.to_str()
            .map(str::to_owned)
            .ok_or(CanonicalizeError::Unrepresentable)
    }

    /// Resolve `path` to an absolute, symlink-resolved canonical
    /// string. AU10 — replaces the pre-AU10 silent-fallback
    /// `String` return with a `Result` so callers must confront
    /// resolution failure rather than letting the daemon's path
    /// matcher miss silently.
    ///
    /// The Ok path keeps both prior successful branches:
    /// (a) direct `canonicalize` for paths that exist, and
    /// (b) `canonicalize(parent).join(name)` for paths that don't
    /// yet exist (rename destinations on a clean prefix). The
    /// Err path corresponds to the previously-silent
    /// `path.to_string()` fallback at the bottom of the original
    /// implementation.
    pub(super) fn canonical_path(path: &str) -> Result<String, CanonicalizeError> {
        use std::path::{Path, PathBuf};

        if path.contains('\0') {
            return Err(CanonicalizeError::Unrepresentable);
        }

        // Direct canonicalize. When this succeeds the path exists
        // on disk and we get the symlink-resolved absolute form.
        let direct_err = match std::fs::canonicalize(path) {
            Ok(p) => {
                return path_to_utf8(&p);
            }
            Err(e) => e,
        };

        // Path may not exist yet (rename destination on a fresh
        // prefix is the canonical case). Canonicalize the parent
        // and join the basename. `Path::new("gamma.txt").parent()`
        // returns `Some("")` — an empty path — not `Some(".")`,
        // so we have to treat empty-as-cwd explicitly.
        let p = Path::new(path);
        let Some(name) = p.file_name() else {
            return Err(CanonicalizeError::NoFileName(path.to_string()));
        };
        let parent_in = match p.parent() {
            Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
            Some(parent) => parent.to_path_buf(),
            None => return Err(CanonicalizeError::NoParent(path.to_string())),
        };
        match std::fs::canonicalize(&parent_in) {
            Ok(parent_abs) => path_to_utf8(&parent_abs.join(name)),
            Err(parent_err) => Err(CanonicalizeError::PathAndParentBothFailed {
                path: path.to_string(),
                path_err: direct_err,
                parent: parent_in.to_string_lossy().into_owned(),
                parent_err,
            }),
        }
    }

    /// AU10 — Convenience for callers that need to keep the syscall
    /// flowing even when canonicalize fails: returns
    /// `(best_effort_path, Option<ShimFailure>)`. The path is the
    /// canonical form on Ok, or the raw user-passed string on Err —
    /// matching the pre-AU10 behavior for the syscall's own argv
    /// while making the failure observable downstream.
    ///
    /// `which_arg` is the human-facing positional label
    /// ("from"/"to"/"path") embedded in the resulting
    /// `ShimFailure::CanonicalizeFailed` for the daemon's journal.
    pub(super) fn canonicalize_or_raw(
        path: &str,
        which_arg: &str,
    ) -> (String, Option<shit_proto::ShimFailure>) {
        match canonical_path(path) {
            Ok(abs) => (abs, None),
            Err(e) => {
                let failure = shit_proto::ShimFailure::CanonicalizeFailed {
                    which_arg: which_arg.to_string(),
                    attempted_path: path.to_string(),
                    error_chain: format!("{e}"),
                };
                (path.to_string(), Some(failure))
            }
        }
    }

    /// Resolve the parent directory to an absolute canonical path while
    /// preserving the final component exactly as a namespace entry.
    ///
    /// This is the correct identity operation for unlink/rename/create. A
    /// direct `canonicalize(path)` follows a final symlink and would attribute
    /// an inverse to its referent rather than to the directory entry that the
    /// syscall actually mutates.
    pub(super) fn canonical_parent_path(path: &str) -> Result<String, CanonicalizeError> {
        use std::path::{Path, PathBuf};

        if path.contains('\0') {
            return Err(CanonicalizeError::Unrepresentable);
        }

        let p = Path::new(path);
        let Some(name) = p.file_name() else {
            return Err(CanonicalizeError::NoFileName(path.to_string()));
        };
        let parent_in = match p.parent() {
            Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
            Some(parent) => parent.to_path_buf(),
            None => return Err(CanonicalizeError::NoParent(path.to_string())),
        };
        match std::fs::canonicalize(&parent_in) {
            Ok(parent_abs) => path_to_utf8(&parent_abs.join(name)),
            Err(parent_err) => Err(CanonicalizeError::ParentFailed {
                path: path.to_string(),
                parent: parent_in.to_string_lossy().into_owned(),
                parent_err,
            }),
        }
    }

    pub(super) fn canonicalize_parent_or_raw(
        path: &str,
        which_arg: &str,
    ) -> (String, Option<shit_proto::ShimFailure>) {
        match canonical_parent_path(path) {
            Ok(abs) => (abs, None),
            Err(e) => {
                let failure = shit_proto::ShimFailure::CanonicalizeFailed {
                    which_arg: which_arg.to_string(),
                    attempted_path: path.to_string(),
                    error_chain: format!("{e}"),
                };
                (path.to_string(), Some(failure))
            }
        }
    }

    /// Resolve a pathname relative to an `*at` dirfd and then canonicalize it
    /// according to the syscall's identity semantics.
    pub(super) fn resolve_path_at(
        dirfd: libc::c_int,
        path: &str,
        which_arg: &str,
        preserve_leaf: bool,
    ) -> (String, Option<shit_proto::ShimFailure>) {
        use std::path::{Path, PathBuf};

        let input = Path::new(path);
        let candidate = if input.is_absolute() || dirfd == libc::AT_FDCWD {
            input.to_path_buf()
        } else if let Some(base) = dirfd_base_path(dirfd) {
            let base = PathBuf::from(base);
            if !base.is_absolute() {
                let failure = shit_proto::ShimFailure::CanonicalizeFailed {
                    which_arg: which_arg.to_string(),
                    attempted_path: path.to_string(),
                    error_chain: format!("dirfd {dirfd} resolved to non-absolute base {:?}", base),
                };
                return (path.to_string(), Some(failure));
            }
            base.join(input)
        } else {
            let failure = shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg: which_arg.to_string(),
                attempted_path: path.to_string(),
                error_chain: format!(
                    "cannot resolve relative path against dirfd {dirfd} on this platform"
                ),
            };
            return (path.to_string(), Some(failure));
        };

        let Ok(candidate) = path_to_utf8(&candidate) else {
            let failure = shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg: which_arg.to_string(),
                attempted_path: path.to_string(),
                error_chain: CanonicalizeError::Unrepresentable.to_string(),
            };
            return (path.to_string(), Some(failure));
        };
        if preserve_leaf {
            canonicalize_parent_or_raw(&candidate, which_arg)
        } else {
            canonicalize_or_raw(&candidate, which_arg)
        }
    }

    #[cfg(target_os = "linux")]
    fn dirfd_base_path(dirfd: libc::c_int) -> Option<String> {
        std::fs::read_link(format!("/proc/self/fd/{dirfd}"))
            .ok()
            .and_then(|path| path.to_str().map(str::to_string))
    }

    #[cfg(target_os = "macos")]
    fn dirfd_base_path(dirfd: libc::c_int) -> Option<String> {
        super::macos::fd_to_path(dirfd)
    }

    #[cfg(target_os = "freebsd")]
    fn dirfd_base_path(dirfd: libc::c_int) -> Option<String> {
        let mut info: libc::kinfo_file = unsafe { std::mem::zeroed() };
        info.kf_structsize = std::mem::size_of::<libc::kinfo_file>() as libc::c_int;
        // SAFETY: `info` is initialized to the ABI-prescribed size and lives
        // for the duration of the variadic fcntl call.
        if unsafe { libc::fcntl(dirfd, libc::F_KINFO, &mut info) } < 0 {
            return None;
        }
        // SAFETY: a successful F_KINFO call returns a NUL-terminated kf_path.
        unsafe { std::ffi::CStr::from_ptr(info.kf_path.as_ptr()) }
            .to_str()
            .ok()
            .map(str::to_owned)
    }

    #[cfg(any(target_os = "netbsd", target_os = "dragonfly"))]
    fn dirfd_base_path(dirfd: libc::c_int) -> Option<String> {
        let mut path = [0 as libc::c_char; libc::PATH_MAX as usize];
        // SAFETY: `path` is writable for PATH_MAX bytes and F_GETPATH fills it
        // with a NUL-terminated pathname on these BSDs.
        if unsafe { libc::fcntl(dirfd, libc::F_GETPATH, path.as_mut_ptr()) } < 0 {
            return None;
        }
        // SAFETY: guaranteed NUL termination on successful F_GETPATH.
        unsafe { std::ffi::CStr::from_ptr(path.as_ptr()) }
            .to_str()
            .ok()
            .map(str::to_owned)
    }

    #[cfg(target_os = "openbsd")]
    fn dirfd_base_path(_dirfd: libc::c_int) -> Option<String> {
        None
    }

    // Recursion guard for the notify path. The pre-image-capture
    // branch reads the target file via libc::open / libc::read,
    // which on first-load lookups *does* go through our `open`
    // interposer (since the shim's `next::real_open` cache may not
    // be primed yet for the first call). Without this guard the
    // reentrant `open` would call try_notify → open the file
    // again → ... and either deadlock the daemon's per-conn task or
    // blow the stack. Thread-local because each thread is its own
    // independent caller; flipping a process-wide AtomicBool would
    // serialize parallel `make -j` callers.
    //
    // (Plain `//` not `///` — rustdoc doesn't generate docs for
    // items produced by macro invocations, and `-D warnings`
    // promotes that to an error.)
    thread_local! {
        static IN_NOTIFY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// RAII ownership of the per-thread notification/capture guard.  Capture
    /// performs ordinary filesystem I/O which can re-enter our own `open`
    /// interposer; delivery also performs socket I/O.  Nested interposers must
    /// pass through without preparing a second notification.
    struct NotifyGuard;

    impl NotifyGuard {
        fn enter() -> Option<Self> {
            (!IN_NOTIFY.with(|flag| flag.replace(true))).then_some(Self)
        }
    }

    impl Drop for NotifyGuard {
        fn drop(&mut self) {
            IN_NOTIFY.with(|flag| flag.set(false));
        }
    }

    /// Immediate-delivery compatibility wrapper for call sites which have
    /// already established that their mutation succeeded. New destructive
    /// interposers use [`prepare_inner_with_failure`] and success-gate
    /// delivery explicitly instead.
    fn notify_inner_with_failure(
        syscall: &'static str,
        arg: &str,
        capture_path: Option<&str>,
        failure: Option<shit_proto::ShimFailure>,
    ) {
        if let Some(prepared) = prepare_inner_with_failure(syscall, arg, capture_path, failure) {
            prepared.send();
        }
    }

    fn prepare_inner_with_failure(
        syscall: &'static str,
        arg: &str,
        capture_path: Option<&str>,
        mut failure: Option<shit_proto::ShimFailure>,
    ) -> Option<PreparedNotification> {
        if disabled() {
            return None;
        }
        let Some(_guard) = NotifyGuard::enter() else {
            // Re-entrant call (we're already inside notify on this
            // thread — almost always the pre-image read's `open(2)`
            // hitting our own interposer). Skip both the notification
            // AND the pre-image capture; the outer notification covers
            // the user-visible mutation.
            return None;
        };
        let (pre_image, capture_failure) = if failure.is_none() {
            capture_path
                .map(|path| capture_pre_image_or_failure(syscall, path))
                .unwrap_or((None, None))
        } else {
            (None, None)
        };
        if failure.is_none() {
            failure = capture_failure;
        }
        // W09.5: when the captured pre-image canonicalized `path` AND
        // the wire arg IS that same path (single-path syscalls like
        // unlink/open/openat/truncate — but NOT rename whose arg is
        // `from\tto`), substitute the wire arg with the resolved
        // absolute path. The daemon's planner matches TreeOp::Unlink
        // and FilePreImage events by path string equality; if the
        // FilePreImage carries `/abs/dst/x.txt` but the TreeOp::Unlink
        // carries `x.txt` (the relative form tar passed), the
        // atomic_replace classifier never fires and undo races into a
        // RecreatePath-vs-existing-file phantom conflict.
        let wire_arg: String = match (&pre_image, capture_path) {
            (Some(pre), Some(cap)) if cap == arg => pre.path.clone(),
            // A fresh create has no pre-image, but its inverse still needs a
            // stable address. Sending the caller's relative spelling makes
            // undo interpret it from *undo's* cwd, which can unlink an
            // unrelated file. Resolve the absent leaf through its canonical
            // parent before it crosses the wire. If that fails, preserve the
            // raw argument only alongside a structured refusal marker; the
            // daemon rejects relative replay targets defensively.
            (None, Some(cap)) if cap == arg => {
                let (resolved, resolution_failure) = if matches!(
                    syscall,
                    "unlink" | "unlinkat" | "rmdir" | "remove" | "lchown"
                ) {
                    canonicalize_parent_or_raw(cap, "path")
                } else {
                    canonicalize_or_raw(cap, "path")
                };
                if failure.is_none() {
                    failure = resolution_failure;
                }
                resolved
            }
            _ => arg.to_string(),
        };
        Some(PreparedNotification {
            syscall,
            arg: wire_arg,
            pre_image,
            extra_pre_images: Vec::new(),
            failure,
        })
    }

    const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;

    #[cfg(target_os = "freebsd")]
    fn try_read_user_xattrs_fd(
        fd: libc::c_int,
    ) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
        use std::ffi::CString;
        let ns = libc::EXTATTR_NAMESPACE_USER;
        let list_size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
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
        if list_size == 0 {
            return Ok(std::collections::BTreeMap::new());
        }
        let mut names = vec![0u8; list_size];
        let got = unsafe { libc::extattr_list_fd(fd, ns, names.as_mut_ptr().cast(), names.len()) };
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

        let mut out = std::collections::BTreeMap::new();
        let mut total = list_size;
        let mut offset = 0usize;
        while offset < names.len() {
            let len = names[offset] as usize;
            offset += 1;
            if offset + len > names.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed FreeBSD xattr name list",
                ));
            }
            let name = std::str::from_utf8(&names[offset..offset + len]).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            offset += len;
            let c_name = CString::new(name)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let value_size =
                unsafe { libc::extattr_get_fd(fd, ns, c_name.as_ptr(), std::ptr::null_mut(), 0) };
            if value_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let value_size = usize::try_from(value_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {name:?} length does not fit usize"),
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
                libc::extattr_get_fd(
                    fd,
                    ns,
                    c_name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if read < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if read as usize != value_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xattr {name:?} changed during capture (expected {value_size}, read {read})"
                    ),
                ));
            }
            out.insert(name.to_string(), value);
        }
        Ok(out)
    }

    #[cfg(target_os = "macos")]
    fn try_read_user_xattrs_fd(
        fd: libc::c_int,
    ) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
        use std::ffi::CString;
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

        let list_size = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
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
        if list_size == 0 {
            return Ok(std::collections::BTreeMap::new());
        }
        let mut names = vec![0u8; list_size];
        let got = unsafe { flistxattr(fd, names.as_mut_ptr().cast(), names.len(), 0) };
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

        let mut out = std::collections::BTreeMap::new();
        let mut total = list_size;
        for raw in names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let name = std::str::from_utf8(raw).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            let c_name = CString::new(name)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let value_size =
                unsafe { fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
            if value_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let value_size = usize::try_from(value_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {name:?} length does not fit usize"),
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
                fgetxattr(
                    fd,
                    c_name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            };
            if read < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if read as usize != value_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xattr {name:?} changed during capture (expected {value_size}, read {read})"
                    ),
                ));
            }
            out.insert(name.to_string(), value);
        }
        Ok(out)
    }

    #[cfg(target_os = "linux")]
    fn try_read_user_xattrs_fd(
        fd: libc::c_int,
    ) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
        use std::ffi::CString;
        let list_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
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
        if list_size == 0 {
            return Ok(std::collections::BTreeMap::new());
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

        let raw_names =
            unsafe { std::slice::from_raw_parts(names.as_ptr().cast::<u8>(), names.len()) };
        let mut out = std::collections::BTreeMap::new();
        let mut total = list_size;
        for raw in raw_names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let full_name = std::str::from_utf8(raw).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            let Some(name) = full_name.strip_prefix("user.") else {
                continue;
            };
            let c_name = CString::new(full_name)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let value_size =
                unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
            if value_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let value_size = usize::try_from(value_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {full_name:?} length does not fit usize"),
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
                        "xattr {full_name:?} changed during capture (expected {value_size}, read {read})"
                    ),
                ));
            }
            out.insert(name.to_string(), value);
        }
        Ok(out)
    }

    #[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
    fn try_read_user_xattrs_fd(
        _fd: libc::c_int,
    ) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "descriptor xattr capture is unsupported on this platform",
        ))
    }

    #[cfg(target_os = "linux")]
    fn snapshot_xattr_name(name: &str) -> &str {
        name.strip_prefix("user.").unwrap_or(name)
    }

    #[cfg(not(target_os = "linux"))]
    fn snapshot_xattr_name(name: &str) -> &str {
        name
    }

    fn metadata_is_stable(
        before: &std::fs::Metadata,
        after: &std::fs::Metadata,
        flags_before: u32,
        flags_after: u32,
    ) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.size() == after.size()
            && before.mode() == after.mode()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && flags_before == flags_after
    }

    fn capture_metadata_pre_image_from_file(
        path: &str,
        file: &std::fs::File,
    ) -> Result<shit_proto::ShimPreImage, String> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;

        let before = file
            .metadata()
            .map_err(|error| format!("descriptor metadata probe failed: {error}"))?;
        let flags_before = read_fd_st_flags(file.as_raw_fd())
            .ok_or_else(|| "descriptor flags probe failed".to_string())?;
        let xattrs = try_read_user_xattrs_fd(file.as_raw_fd())
            .map_err(|error| format!("descriptor xattr snapshot failed: {error}"))?;
        let after = file
            .metadata()
            .map_err(|error| format!("post-xattr descriptor metadata probe failed: {error}"))?;
        let flags_after = read_fd_st_flags(file.as_raw_fd())
            .ok_or_else(|| "post-xattr descriptor flags probe failed".to_string())?;
        if !metadata_is_stable(&before, &after, flags_before, flags_after) {
            return Err("metadata changed while xattrs were being captured".to_string());
        }

        Ok(shit_proto::ShimPreImage {
            path: path.to_string(),
            dev: before.dev(),
            inode: before.ino(),
            mode: before.mode(),
            uid: before.uid(),
            gid: before.gid(),
            size: before.size(),
            mtime_unix_nanos: before.mtime() as i128 * 1_000_000_000 + before.mtime_nsec() as i128,
            bytes: Vec::new(),
            xattr: None,
            flags: flags_before,
            xattrs: Some(xattrs),
        })
    }

    fn capture_metadata_pre_image(path: &str) -> Result<shit_proto::ShimPreImage, String> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(path)
            .map_err(|error| format!("cannot open target without following symlinks: {error}"))?;
        capture_metadata_pre_image_from_file(path, &file)
    }

    enum PreImageCapture {
        Captured(shit_proto::ShimPreImage),
        Absent,
        Unavailable(String),
    }

    /// Capture the lexical target and identity of a symlink without following
    /// it. A symlink has no readable file-content stream, but its `readlink`
    /// bytes are the complete payload needed by `CreateSymlink` during undo.
    ///
    /// This remains a pathname capture because portable POSIX does not offer a
    /// descriptor that can be read with `readlink(2)`. Bracketing two target
    /// reads with metadata probes makes a concurrent replacement fail closed
    /// instead of combining one link's identity with another link's target.
    fn capture_symlink_pre_image(path: &str, before: std::fs::Metadata) -> PreImageCapture {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;

        let target_before = match std::fs::read_link(path) {
            Ok(target) => target,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "symlink target read failed: {error}"
                ));
            }
        };
        let middle = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "symlink metadata recheck failed: {error}"
                ));
            }
        };
        let target_after = match std::fs::read_link(path) {
            Ok(target) => target,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "symlink target recheck failed: {error}"
                ));
            }
        };
        let after = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "post-read symlink metadata probe failed: {error}"
                ));
            }
        };

        if !middle.file_type().is_symlink()
            || !after.file_type().is_symlink()
            || !metadata_is_stable(&before, &middle, 0, 0)
            || !metadata_is_stable(&middle, &after, 0, 0)
            || target_before != target_after
        {
            return PreImageCapture::Unavailable(
                "symlink changed while its lexical target was being captured".to_string(),
            );
        }

        let target = target_before.as_os_str().as_bytes().to_vec();
        PreImageCapture::Captured(shit_proto::ShimPreImage {
            path: path.to_string(),
            dev: before.dev(),
            inode: before.ino(),
            mode: before.mode(),
            uid: before.uid(),
            gid: before.gid(),
            size: target.len() as u64,
            mtime_unix_nanos: before.mtime() as i128 * 1_000_000_000 + before.mtime_nsec() as i128,
            bytes: target,
            xattr: None,
            // Symlink recreation currently restores the lexical target, not
            // inode flags or xattrs. Keep those fields explicitly empty
            // rather than following the referent to fabricate metadata.
            flags: 0,
            xattrs: Some(std::collections::BTreeMap::new()),
        })
    }

    /// Capture `path` from one descriptor opened without following the final
    /// symlink. Metadata and bytes must describe that same open file: path
    /// probes before/after a separate `std::fs::read` can otherwise combine
    /// inode A's metadata with inode B's bytes during a concurrent replace.
    ///
    /// The read is capped at `CAP + 1`, so a growing file cannot force an
    /// unbounded allocation before we notice it crossed the wire limit. Only
    /// a genuine `ENOENT` is classified as [`PreImageCapture::Absent`]; every
    /// other inability to capture an existing target is an explicit refusal.
    fn capture_pre_image(path: &str) -> PreImageCapture {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return PreImageCapture::Absent;
            }
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "cannot open pre-image without following symlinks: {error}"
                ));
            }
        };

        // File::metadata is fstat(2), not a second pathname lookup.
        let before = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "pre-image descriptor metadata probe failed: {error}"
                ));
            }
        };
        if !before.is_file() {
            return PreImageCapture::Unavailable(format!(
                "pre-image target is not a regular file (mode={:#o})",
                before.mode()
            ));
        }

        let size = before.size();
        if size > shit_proto::SHIM_INLINE_PREIMAGE_CAP {
            return PreImageCapture::Unavailable(format!(
                "pre-image size {size} exceeds inline capture cap {}",
                shit_proto::SHIM_INLINE_PREIMAGE_CAP
            ));
        }
        let flags_before = match read_fd_st_flags(file.as_raw_fd()) {
            Some(flags) => flags,
            None => {
                return PreImageCapture::Unavailable(
                    "pre-image descriptor flags probe failed".to_string(),
                );
            }
        };

        let mut bytes = Vec::with_capacity(size as usize);
        let read_result = {
            let mut bounded = (&mut file).take(shit_proto::SHIM_INLINE_PREIMAGE_CAP + 1);
            bounded.read_to_end(&mut bytes)
        };
        if let Err(error) = read_result {
            return PreImageCapture::Unavailable(format!("pre-image read failed: {error}"));
        }
        if bytes.len() as u64 > shit_proto::SHIM_INLINE_PREIMAGE_CAP {
            return PreImageCapture::Unavailable(format!(
                "pre-image grew beyond inline capture cap {} while being read",
                shit_proto::SHIM_INLINE_PREIMAGE_CAP
            ));
        }

        let xattrs = match try_read_user_xattrs_fd(file.as_raw_fd()) {
            Ok(xattrs) => xattrs,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "pre-image descriptor xattr snapshot failed: {error}"
                ));
            }
        };

        let after = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                return PreImageCapture::Unavailable(format!(
                    "post-read descriptor metadata probe failed: {error}"
                ));
            }
        };
        let flags_after = match read_fd_st_flags(file.as_raw_fd()) {
            Some(flags) => flags,
            None => {
                return PreImageCapture::Unavailable(
                    "post-read descriptor flags probe failed".to_string(),
                );
            }
        };

        // Identity cannot normally change beneath an open descriptor, but
        // checking it makes that invariant explicit. Size/content metadata
        // checks reject concurrent writes, truncation, ownership/mode changes,
        // and short reads rather than accepting a torn pre-image.
        let stable = before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.size() == after.size()
            && before.mode() == after.mode()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && flags_before == flags_after
            && bytes.len() as u64 == size;
        if !stable {
            return PreImageCapture::Unavailable(
                "pre-image changed while it was being captured".to_string(),
            );
        }

        PreImageCapture::Captured(shit_proto::ShimPreImage {
            // Callers resolve the path before capture. Do not canonicalize it
            // again after the read: that would be a fresh lookup which could
            // name a replacement inode rather than this descriptor's file.
            path: path.to_string(),
            dev: before.dev(),
            inode: before.ino(),
            mode: before.mode(),
            uid: before.uid(),
            gid: before.gid(),
            size,
            mtime_unix_nanos: before.mtime() as i128 * 1_000_000_000 + before.mtime_nsec() as i128,
            bytes,
            // M07.B.4.1 — content-only pre-image captures don't
            // populate the xattr field; xattr-mutating syscalls
            // build their own ShimPreImage with this set.
            xattr: None,
            flags: flags_before,
            xattrs: Some(xattrs),
        })
    }

    /// Capture an existing regular file or explain why no safe inverse can be
    /// produced. `None, None` is reserved for a genuinely absent path, which
    /// is the only shape callers may classify as a fresh destination/create.
    pub(super) fn capture_pre_image_or_failure(
        syscall: &'static str,
        path: &str,
    ) -> (
        Option<shit_proto::ShimPreImage>,
        Option<shit_proto::ShimFailure>,
    ) {
        // Namespace-deletion syscalls can represent a symlink completely as
        // (identity, lexical target), and the daemon maps that marker to
        // SymlinkRemovedIdentified. Do not enable this for rename destination
        // pre-images: restoring an overwritten symlink is a distinct compound
        // inverse and must remain a refusal until that shape is modeled.
        //
        // For non-symlinks (and a racy initial ENOENT), let the nofollow open
        // below make the authoritative absent/captured decision. A concurrent
        // creator must not be mistaken for a fresh path and later unlinked by
        // undo.
        let capture = if matches!(syscall, "unlink" | "unlinkat" | "remove") {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    capture_symlink_pre_image(path, metadata)
                }
                Ok(metadata) if metadata.file_type().is_file() => capture_pre_image(path),
                Ok(metadata) => {
                    use std::os::unix::fs::MetadataExt as _;
                    PreImageCapture::Unavailable(format!(
                        "deletion target is not a regular file or symlink (mode={:#o})",
                        metadata.mode()
                    ))
                }
                // A failed lstat is not authoritative: the nofollow open can
                // still distinguish a genuine absence from a transient path
                // lookup failure without ever following the final component.
                Err(_) => capture_pre_image(path),
            }
        } else {
            capture_pre_image(path)
        };
        match capture {
            PreImageCapture::Captured(pre_image) => (Some(pre_image), None),
            PreImageCapture::Absent => (None, None),
            PreImageCapture::Unavailable(reason) => (
                None,
                Some(shit_proto::ShimFailure::PreImageUnavailable {
                    attempted_path: path.to_string(),
                    reason,
                }),
            ),
        }
    }

    /// Capture only the stat identity and `st_flags` required to undo a
    /// chflags-family syscall. A failed flags probe returns `None` rather
    /// than fabricating zero as an authoritative pre-state.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[allow(dead_code)]
    pub(super) fn capture_flags_pre_image(path: &str) -> Option<shit_proto::ShimPreImage> {
        capture_metadata_pre_image(path).ok()
    }

    /// Read BSD/macOS inode flags from the already-open capture descriptor.
    /// Linux and the other BSD targets currently have no replayed `st_flags`
    /// field in this shim path, so zero is their authoritative wire value.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fn read_fd_st_flags(fd: libc::c_int) -> Option<u32> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` points to writable storage for one libc::stat and fd
        // is borrowed from a live File for the duration of this call.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: successful fstat initialized the entire structure.
        Some(unsafe { stat.assume_init() }.st_flags)
    }

    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    fn read_fd_st_flags(_fd: libc::c_int) -> Option<u32> {
        Some(0)
    }

    fn try_notify(
        syscall: &'static str,
        arg: &str,
        pre_image: Option<shit_proto::ShimPreImage>,
        extra_pre_images: Vec<shit_proto::ShimPreImage>,
        failure: Option<shit_proto::ShimFailure>,
    ) -> std::io::Result<()> {
        use shit_proto::{
            ShimAck, ShimNotification, decode_frame, encode_shim_notification_frame,
            encode_shim_notification_frame_large,
        };
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, SystemTime};

        let path = socket_path();
        // Best-effort `connect(2)` — if the socket doesn't exist (no
        // daemon, daemon down, wrong $XDG_RUNTIME_DIR), bail silently.
        let mut stream = UnixStream::connect(path)?;
        // W06.A.4.1: the write timeout must scale with payload size.
        // The default 50 ms was sized for sub-MAX_FRAME_SIZE (256 KiB)
        // notifications and would time out partway through a multi-MiB
        // pre-image-carrying frame — write_all returns Err with only
        // the first few hundred KiB delivered, and the daemon's
        // decoder rejects the truncated frame ("frame length mismatch:
        // header says ..., buffer has ..."), so the inline pre-image
        // is silently dropped.
        //
        // 5s is generous: a local UDS sustains ~1 GB/s, so the
        // SHIM_INLINE_PREIMAGE_CAP (32 MiB) ships in ~30 ms in the
        // happy case. The extra slack accommodates a slow daemon
        // drain (the listener handle_one is async-tokio, may not be
        // immediately scheduled). For notifications without
        // pre-image, the original 50 ms stays — those are tiny and a
        // hung daemon shouldn't pause a user's `unlink` for 5s.
        let write_timeout = if pre_image.is_some() || !extra_pre_images.is_empty() {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(50)
        };
        stream.set_write_timeout(Some(write_timeout))?;
        stream.set_read_timeout(Some(Duration::from_millis(50)))?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // SAFETY: shim runs in arbitrary user processes; getpid is a
        // syscall, not an interposer target, so this is safe.
        let pid = unsafe { libc::getpid() } as u32;
        let has_pre = pre_image.is_some();
        let has_extras = !extra_pre_images.is_empty();
        let note = ShimNotification {
            pid,
            syscall: syscall.to_string(),
            arg: arg.to_string(),
            ts_unix_nanos: now,
            pre_image,
            extra_pre_images,
            // AU10 — populated when an upstream resolution step
            // (canonicalize, primarily) tripped the previously-
            // silent fallback. The daemon's shim_listener journals
            // a Refuse marker keyed by this field.
            failure,
        };
        // Pre-image notifications can carry up to ~256 KiB of bytes;
        // small notifications fit MAX_FRAME_SIZE comfortably. Use the
        // large-frame encoder uniformly — the cap is the only
        // difference, and the daemon's reader matches.
        // DR-CR-54: a recursive batch can blow well past the small-
        // frame cap even with `pre_image=None`; pick large-frame
        // whenever extras are present too.
        let frame = if has_pre || has_extras {
            encode_shim_notification_frame_large(&note)
                .map_err(|e| std::io::Error::other(format!("encode: {e}")))?
        } else {
            encode_shim_notification_frame(&note)
                .map_err(|e| std::io::Error::other(format!("encode: {e}")))?
        };
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn install_scope_excludes_build_churn_and_keeps_targets() {
            let scope = CaptureScope::from_encoded(Some(
                "/usr/local:/Users/u/Library/Python:/Users/u/.cargo/bin",
            ));

            assert!(scope.allows("/Users/u/Library/Python/3.14/bin/tool"));
            assert!(scope.allows("/Users/u/Library/Python/3.14/lib/python/site-packages/pkg.py"));
            assert!(!scope.allows("/private/tmp/pip-build/wheel/pkg.py"));
            assert!(!scope.allows("/Users/u/src/pkg/build/lib/pkg.py"));
        }

        #[test]
        fn install_scope_keeps_cross_boundary_rename() {
            let scope = CaptureScope::from_encoded(Some("/Users/u/Library/Python"));

            assert!(scope.allows_any(&[
                "/private/tmp/pip-build/pkg.py",
                "/Users/u/Library/Python/3.14/lib/python/site-packages/pkg.py",
            ]));
            assert!(scope.allows_any(&[
                "/Users/u/Library/Python/3.14/lib/python/site-packages/pkg.py",
                "/private/tmp/pip-old/pkg.py",
            ]));
            assert!(!scope.allows_any(&["/private/tmp/pip-build/a", "/private/tmp/pip-build/b",]));
        }

        #[test]
        fn absent_scope_is_legacy_unrestricted_but_empty_scope_denies_all() {
            let unrestricted = CaptureScope::from_encoded(None);
            assert!(unrestricted.allows("/any/user/path"));

            let empty = CaptureScope::from_encoded(Some(""));
            assert!(!empty.allows("/usr/local/bin/tool"));
        }

        #[test]
        fn install_scope_filters_known_fd_paths_but_retains_unresolved_fds() {
            let scope = CaptureScope::from_encoded(Some("/Users/u/Library/Python"));

            assert!(scope.allows_fd_path(Some(
                "/Users/u/Library/Python/3.14/lib/python/site-packages/pkg.py"
            )));
            assert!(!scope.allows_fd_path(Some("/private/tmp/pip-build/pkg.py")));
            assert!(
                scope.allows_fd_path(None),
                "an unresolved fd cannot be proven out of install scope"
            );
        }

        #[test]
        fn recursive_payload_budget_reserves_large_frame_overhead() {
            let payload_budget = shit_proto::SHIM_INLINE_PREIMAGE_CAP
                + XATTR_CAPTURE_CAP as u64
                + RECURSIVE_MAX_BYTES
                + RECURSIVE_MAX_XATTR_BYTES
                + 8 * 1024 * 1024;
            assert!(payload_budget <= shit_proto::MAX_LARGE_FRAME_SIZE as u64);
        }

        #[test]
        fn descriptor_capture_preserves_regular_file_bytes_and_identity() {
            use std::os::unix::fs::MetadataExt as _;

            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("regular");
            std::fs::write(&path, b"before").expect("write pre-image");
            let expected = std::fs::symlink_metadata(&path).expect("stat pre-image");

            let captured = match capture_pre_image(path.to_str().expect("UTF-8 temp path")) {
                PreImageCapture::Captured(captured) => captured,
                PreImageCapture::Absent => panic!("existing file reported absent"),
                PreImageCapture::Unavailable(reason) => panic!("capture refused: {reason}"),
            };
            assert_eq!(captured.bytes, b"before");
            assert_eq!(captured.size, 6);
            assert_eq!(captured.dev, expected.dev());
            assert_eq!(captured.inode, expected.ino());
            assert_eq!(captured.path, path.to_str().expect("UTF-8 temp path"));
            assert!(
                captured.xattrs.is_some(),
                "successful capture must distinguish proven-empty xattrs from unavailable"
            );
        }

        #[test]
        fn empty_regular_file_is_a_real_pre_image() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("empty");
            std::fs::File::create(&path).expect("create empty file");

            let (pre_image, failure) =
                capture_pre_image_or_failure("truncate", path.to_str().expect("UTF-8 temp path"));
            let pre_image = pre_image.expect("empty file must be captured");
            assert!(pre_image.bytes.is_empty());
            assert_eq!(pre_image.size, 0);
            assert!(failure.is_none());
        }

        #[test]
        fn only_missing_path_is_classified_as_absent() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let missing = tmp.path().join("missing");
            let (pre_image, failure) =
                capture_pre_image_or_failure("open", missing.to_str().expect("UTF-8 temp path"));
            assert!(pre_image.is_none());
            assert!(failure.is_none());
        }

        #[test]
        fn non_regular_targets_are_explicit_refusals() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let directory = tmp.path().join("directory");
            std::fs::create_dir(&directory).expect("create directory");

            let (pre_image, failure) = capture_pre_image_or_failure(
                "unlink",
                directory.to_str().expect("UTF-8 temp path"),
            );
            assert!(pre_image.is_none());
            assert!(matches!(
                failure,
                Some(shit_proto::ShimFailure::PreImageUnavailable { .. })
            ));
        }

        #[test]
        fn symlink_target_is_captured_lexically_without_following() {
            use std::os::unix::fs::{MetadataExt as _, symlink};

            let tmp = tempfile::tempdir().expect("tempdir");
            let target = tmp.path().join("target");
            let link = tmp.path().join("link");
            std::fs::write(&target, b"target").expect("write symlink target");
            symlink("target", &link).expect("create relative symlink");

            let (pre_image, failure) =
                capture_pre_image_or_failure("unlink", link.to_str().expect("UTF-8 temp path"));
            let pre_image = pre_image.expect("symlink deletion marker");
            assert!(failure.is_none());
            assert_eq!(pre_image.bytes, b"target");
            assert_eq!(pre_image.mode & libc::S_IFMT as u32, libc::S_IFLNK as u32);
            assert_ne!(pre_image.inode, std::fs::metadata(&target).unwrap().ino());

            let (rename_pre_image, rename_failure) =
                capture_pre_image_or_failure("rename", link.to_str().expect("UTF-8 temp path"));
            assert!(rename_pre_image.is_none());
            assert!(matches!(
                rename_failure,
                Some(shit_proto::ShimFailure::PreImageUnavailable { .. })
            ));
        }

        #[test]
        fn oversized_regular_file_is_an_explicit_refusal() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("oversized");
            let file = std::fs::File::create(&path).expect("create sparse file");
            file.set_len(shit_proto::SHIM_INLINE_PREIMAGE_CAP + 1)
                .expect("extend sparse file");

            let (pre_image, failure) =
                capture_pre_image_or_failure("truncate", path.to_str().expect("UTF-8 temp path"));
            assert!(pre_image.is_none());
            assert!(matches!(
                failure,
                Some(shit_proto::ShimFailure::PreImageUnavailable { .. })
            ));
        }

        #[test]
        fn metadata_capture_accepts_directory_without_content_bytes() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let prepared = prepare_metadata_mutation(
                "chmod",
                tmp.path().to_str().expect("UTF-8 temp path"),
                false,
            )
            .expect("prepared metadata notification");
            let pre = prepared.pre_image.expect("metadata pre-image");
            assert!(pre.bytes.is_empty());
            assert!(pre.xattrs.is_some());
            assert!(prepared.failure.is_none());
        }

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
        #[test]
        fn descriptor_capture_carries_pre_mutation_xattr_snapshot() {
            use std::ffi::CString;

            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("xattr-snapshot");
            std::fs::write(&path, b"before").expect("write target");
            let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            let value = b"preserve-me";

            #[cfg(target_os = "macos")]
            let rc = unsafe {
                let name = CString::new("user.shit.snapshot").unwrap();
                libc::setxattr(
                    c_path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            };
            #[cfg(target_os = "linux")]
            let rc = unsafe {
                let name = CString::new("user.shit.snapshot").unwrap();
                libc::setxattr(
                    c_path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            #[cfg(target_os = "freebsd")]
            let rc = unsafe {
                let name = CString::new("shit.snapshot").unwrap();
                libc::extattr_set_file(
                    c_path.as_ptr(),
                    libc::EXTATTR_NAMESPACE_USER,
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                ) as libc::c_int
            };
            if rc < 0 {
                eprintln!(
                    "skip: test filesystem rejected xattrs: {}",
                    std::io::Error::last_os_error()
                );
                return;
            }

            let captured = match capture_pre_image(path.to_str().expect("UTF-8 temp path")) {
                PreImageCapture::Captured(captured) => captured,
                PreImageCapture::Absent => panic!("existing file reported absent"),
                PreImageCapture::Unavailable(reason) => panic!("capture refused: {reason}"),
            };
            let key = if cfg!(target_os = "macos") {
                "user.shit.snapshot"
            } else {
                "shit.snapshot"
            };
            assert_eq!(
                captured
                    .xattrs
                    .as_ref()
                    .and_then(|xattrs| xattrs.get(key))
                    .map(Vec::as_slice),
                Some(value.as_slice())
            );
        }

        #[test]
        fn xattr_target_probe_failure_becomes_refusal() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let missing = tmp.path().join("missing");
            let prepared = prepare_xattr_mutation(
                "setxattr",
                missing.to_str().expect("UTF-8 temp path"),
                shit_proto::XattrPreImage {
                    name: "user.test".to_string(),
                    value: None,
                },
            )
            .expect("prepared refusal");
            assert!(prepared.pre_image.is_none());
            assert!(matches!(
                prepared.failure,
                Some(shit_proto::ShimFailure::PreImageUnavailable { .. })
            ));
        }

        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        #[test]
        fn flags_probe_failure_becomes_refusal() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let missing = tmp.path().join("missing");
            let prepared =
                prepare_flags_mutation("chflags", missing.to_str().expect("UTF-8 temp path"))
                    .expect("prepared refusal");
            assert!(prepared.pre_image.is_none());
            assert!(matches!(
                prepared.failure,
                Some(shit_proto::ShimFailure::PreImageUnavailable { .. })
            ));
        }
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

    #[cfg(any(target_os = "linux", target_os = "dragonfly"))]
    unsafe fn errno_ptr() -> *mut c_int {
        // SAFETY: libc exposes the calling thread's errno cell.
        unsafe { libc::__errno_location() }
    }

    #[cfg(target_os = "freebsd")]
    unsafe fn errno_ptr() -> *mut c_int {
        // SAFETY: libc exposes the calling thread's errno cell.
        unsafe { libc::__error() }
    }

    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    unsafe fn errno_ptr() -> *mut c_int {
        // SAFETY: libc exposes the calling thread's errno cell.
        unsafe { libc::__errno() }
    }

    pub(super) fn current_errno() -> c_int {
        // SAFETY: `errno_ptr` returns a valid pointer to this thread's errno.
        unsafe { *errno_ptr() }
    }

    pub(super) fn set_errno(value: c_int) {
        // SAFETY: `errno_ptr` returns a valid pointer to this thread's errno.
        unsafe { *errno_ptr() = value };
    }

    /// Capture before `mutate`, restore the caller's incoming errno before
    /// entering libc, and deliver the prepared notification only after the
    /// result satisfies `succeeded`.  Delivery is best-effort but performs
    /// socket I/O, so preserve the errno left by libc across it as well.
    pub(super) fn call_mutation_and_notify_with<T, P, Prepare, Mutate, Succeeded, Notify>(
        prepare: Prepare,
        mutate: Mutate,
        succeeded: Succeeded,
        notify: Notify,
    ) -> T
    where
        Prepare: FnOnce() -> Option<P>,
        Mutate: FnOnce() -> T,
        Succeeded: FnOnce(&T) -> bool,
        Notify: FnOnce(P),
    {
        let incoming_errno = current_errno();
        let prepared = prepare();
        set_errno(incoming_errno);

        let result = mutate();
        let result_errno = current_errno();
        if succeeded(&result) {
            if let Some(prepared) = prepared {
                notify(prepared);
            }
        } else {
            // Drop captured buffers before the final errno restore. Their
            // deallocation is normally errno-neutral, but keeping *all*
            // post-libc work on the protected side makes the ABI contract
            // explicit and robust to future prepared-state destructors.
            drop(prepared);
        }
        set_errno(result_errno);
        result
    }

    /// Resolve before a create-only syscall, but emit its journal notification
    /// only after the syscall reports success. This prevents EEXIST/EPERM
    /// failures from fabricating an Unlink inverse for a pre-existing path.
    pub(super) fn call_create_and_notify_with<Create, Resolve, Notify>(
        syscall: &'static str,
        create: Create,
        resolve: Resolve,
        notify: Notify,
    ) -> c_int
    where
        Create: FnOnce() -> c_int,
        Resolve: FnOnce() -> (String, Option<shit_proto::ShimFailure>),
        Notify: FnOnce(&'static str, &str, Option<shit_proto::ShimFailure>),
    {
        call_mutation_and_notify_with(
            || Some(resolve()),
            create,
            |result| *result == 0,
            |(resolved, failure)| notify(syscall, &resolved, failure),
        )
    }

    /// `unlink(2)` interposer — drops a directory entry.
    ///
    /// # Safety
    /// `path` must be a valid C string per libc's `unlink(2)` contract.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
        // W09.5: tar/cpio/gzip use unlink-then-open(O_CREAT) to
        // replace a file's content rather than the atomic-rename
        // shape `install` / `mv` use. By the time the shim sees
        // the subsequent open, the file is already gone and the
        // open interposer's pre-image capture returns None.
        // Capture HERE, before the unlink fires — the file still
        // exists at notify time. The planner's
        // `classify_replace_paths` recognizes the resulting
        // Unlink + PreImage shape and emits RestoreContent for the
        // path's old bytes; the Unlink's RecreatePath inverse is
        // suppressed in that case.
        let path_string = cstr_to_string(path);
        let real = next::real_unlink();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation_with_content("unlink", &path_string),
            || {
                if next::is_zero(next::as_usize(real)) {
                    // dlsym failed; fall through to libc's wrapper. The libc
                    // crate's `unlink` is itself a forwarder to the dynamic
                    // libc; this is the safest fallback for an environment
                    // where RTLD_NEXT doesn't resolve (e.g. fully-static
                    // binaries we shouldn't have been preloaded into anyway).
                    unsafe { libc::unlink(path) }
                } else {
                    unsafe { real(path) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// `rmdir(2)` interposer. Directory reconstruction is not yet fully
    /// modeled, so successful removals carry an explicit capture refusal
    /// instead of a lossy mode-only marker.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_rmdir();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation_with_content("rmdir", &path_string),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::rmdir(path) }
                } else {
                    unsafe { real(path) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// `remove(3)` interposer. Regular files receive descriptor-bound content
    /// snapshots; directories and other non-regular entries fail closed with
    /// a capture refusal until their full reconstruction metadata is modeled.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn remove(path: *const c_char) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_remove();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation_with_content("remove", &path_string),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::remove(path) }
                } else {
                    unsafe { real(path) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
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
        let path_string = cstr_to_string(path);
        let real = next::real_open();
        call_mutation_and_notify_with(
            || {
                writes
                    .then(|| policy::prepare_pre_mutation_with_content("open", &path_string))
                    .flatten()
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::open(path, flags, mode as c_uint) }
                } else {
                    unsafe { real(path, flags, mode) }
                }
            },
            |result| *result >= 0,
            policy::PreparedNotification::send,
        )
    }

    /// `unlinkat(2)` interposer. W06.A.1 — modern FreeBSD `rm` /
    /// `find` use `unlinkat` not `unlink`. Without this the shim
    /// produced zero notifications for typical removals.
    ///
    /// # Safety
    /// `path` must be a valid C string when non-NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flag: c_int) -> c_int {
        let path_str = cstr_to_string(path);
        // W09.5: same shape as `unlink` — capture pre-image bytes
        // before the unlink, so unlink-then-open(O_CREAT) tools
        // can be undone.
        let real = next::real_unlinkat();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation_at_with_content("unlinkat", dirfd, &path_str, true),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::unlinkat(dirfd, path, flag) }
                } else {
                    unsafe { real(dirfd, path, flag) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// `openat(2)` interposer. W06.A.1 — FreeBSD `install(1)` uses
    /// `openat(AT_FDCWD, temp_path, O_RDWR|O_CREAT|O_EXCL, mode)`
    /// before the atomic-rename. Notification policy mirrors `open`:
    /// only on write-mode (`O_WRONLY` / `O_RDWR` / `O_TRUNC`).
    ///
    /// # Safety
    /// `path` must be a valid C string when non-NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn openat(
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: c_uint,
    ) -> c_int {
        let writes = (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0;
        let path_string = cstr_to_string(path);
        let real = next::real_openat();
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
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::openat(dirfd, path, flags, mode as c_uint) }
                } else {
                    unsafe { real(dirfd, path, flags, mode) }
                }
            },
            |result| *result >= 0,
            policy::PreparedNotification::send,
        )
    }

    /// `rename(2)` interposer. W06.A.1 — `install`'s atomic move
    /// into place; also the syscall behind `mv` (W08).
    ///
    /// # Safety
    /// `from` and `to` must be valid C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rename(from: *const c_char, to: *const c_char) -> c_int {
        // W06.A.4: install(1) / mv use rename to atomically replace
        // the destination's content. Capture pre-image of `to` (when
        // it exists) so the planner can RestoreContent rather than
        // ReverseRename (which would leave dst empty + content stuck
        // at the source tmpfile path).
        let from_string = cstr_to_string(from);
        let to_string = cstr_to_string(to);
        let real = next::real_rename();
        call_mutation_and_notify_with(
            || policy::prepare_rename_with_dst_preimage("rename", &from_string, &to_string),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::rename(from, to) }
                } else {
                    unsafe { real(from, to) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// `renameat(2)` interposer.
    ///
    /// # Safety
    /// `from` and `to` must be valid C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn renameat(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
    ) -> c_int {
        // W06.A.4: same atomic-replace shape as `rename` — capture
        // pre-image of the destination.
        let from_string = cstr_to_string(from);
        let to_string = cstr_to_string(to);
        let real = next::real_renameat();
        call_mutation_and_notify_with(
            || {
                policy::prepare_rename_at_with_dst_preimage(
                    "renameat",
                    fromfd,
                    &from_string,
                    tofd,
                    &to_string,
                )
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::renameat(fromfd, from, tofd, to) }
                } else {
                    unsafe { real(fromfd, from, tofd, to) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// DR-CR-54 — `renameat2(2)` interposer. Linux-only. A zero flags
    /// value has ordinary rename semantics. Non-zero variants (notably
    /// RENAME_EXCHANGE and RENAME_WHITEOUT) require distinct inverses; emit a
    /// loud refusal until those are modeled instead of mis-journaling them as
    /// an ordinary one-way rename. Pass `flags` through to libc verbatim.
    ///
    /// # Safety
    /// `from` and `to` must be valid C strings.
    #[cfg(target_os = "linux")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn renameat2(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_uint,
    ) -> c_int {
        let from_string = cstr_to_string(from);
        let to_string = cstr_to_string(to);
        let real = next::real_renameat2();
        call_mutation_and_notify_with(
            || {
                if flags == 0 {
                    policy::prepare_rename_at_with_dst_preimage(
                        "renameat2",
                        fromfd,
                        &from_string,
                        tofd,
                        &to_string,
                    )
                } else {
                    policy::prepare_unsupported_rename_at(
                        "renameat2",
                        fromfd,
                        &from_string,
                        tofd,
                        &to_string,
                        format!("renameat2 flags {flags:#x} are not modeled"),
                    )
                }
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    // glibc < 2.28 had no `renameat2` wrapper; fall back
                    // through raw syscall. This branch is unreachable on
                    // any glibc shipped within the project's MSRV-era
                    // distros, but defensive.
                    unsafe {
                        libc::syscall(libc::SYS_renameat2, fromfd, from, tofd, to, flags as c_uint)
                            as c_int
                    }
                } else {
                    unsafe { real(fromfd, from, tofd, to, flags) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// W09.10.1 — `mkfifo(2)` interposer. FreeBSD's kqueue
    /// `NOTE_WRITE` on the parent directory does NOT fire for FIFO
    /// (or special-file) creation — the kernel distinguishes
    /// regular-file/directory adds from FIFO/socket/device adds at
    /// the vnode op level, and only the former bump the parent's
    /// content-change indicator. Without an interposer the daemon
    /// never sees the new entry and undo no-ops. Notify the daemon
    /// here so it can journal a `TreeOp::Create`; the undo executor
    /// reverses with `unlink(2)` (works for FIFOs).
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: mode_t) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_mkfifo();
        call_create_and_notify_with(
            "mkfifo",
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::mkfifo(path, mode) }
                } else {
                    unsafe { real(path, mode) }
                }
            },
            || policy::canonicalize_parent_or_raw(&path_string, "path"),
            policy::notify_create_resolved,
        )
    }

    /// W09.10.1 — `mkfifoat(2)` interposer. Dirfd-relative variant.
    /// Same NOTE_WRITE gap as `mkfifo`.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkfifoat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_mkfifoat();
        call_create_and_notify_with(
            "mkfifoat",
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::mkfifoat(dirfd, path, mode) }
                } else {
                    unsafe { real(dirfd, path, mode) }
                }
            },
            || policy::resolve_path_at(dirfd, &path_string, "path", true),
            policy::notify_create_resolved,
        )
    }

    /// `link(2)` interposer — creates a new hardlink `new` pointing
    /// at the inode of `old`. BSD kqueue `NOTE_WRITE` on the parent
    /// directory DOES fire for hardlink creation, but the helper's
    /// dir-diff treats the new alias as an unknown inode and can't
    /// classify it as a hardlink-create without the syscall name.
    /// Notifying here lets the daemon journal a `TreeOp::Create`
    /// whose inverse is `unlink(new)` (the existing aliased file
    /// stays untouched). Mirrors macOS M03.x.LINK (PR #175).
    ///
    /// # Safety
    /// `old` and `new` must be valid C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn link(old: *const c_char, new: *const c_char) -> c_int {
        // Notify with the NEW path — that's what the daemon's
        // shim_listener TreeOp::Create handler expects (see
        // shim_listener.rs::"link" | "linkat" arm). The old path
        // is unchanged; we don't need to journal it.
        let new_string = cstr_to_string(new);
        let real = next::real_link();
        call_create_and_notify_with(
            "link",
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::link(old, new) }
                } else {
                    unsafe { real(old, new) }
                }
            },
            || policy::canonicalize_parent_or_raw(&new_string, "path"),
            policy::notify_create_resolved,
        )
    }

    /// `linkat(2)` interposer — dirfd-relative variant of `link(2)`.
    /// The `flags` argument carries AT_SYMLINK_FOLLOW (FreeBSD,
    /// macOS); we don't inspect it because the journal/undo flow
    /// is identical regardless of symlink-following semantics on
    /// the source: the destination is still a new directory entry
    /// whose inverse is `unlink(new)`.
    ///
    /// `newpath` may be relative to `newdirfd`. The notifier resolves
    /// that directory handle in the mutating process and preserves the
    /// not-yet-existing lexical leaf. If this platform cannot resolve a
    /// real dirfd safely, it emits a structured refusal instead of a
    /// cwd-relative inverse.
    ///
    /// # Safety
    /// `oldpath` and `newpath` must be valid C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn linkat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
        flags: c_int,
    ) -> c_int {
        let new_string = cstr_to_string(newpath);
        let real = next::real_linkat();
        call_create_and_notify_with(
            "linkat",
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::linkat(olddirfd, oldpath, newdirfd, newpath, flags) }
                } else {
                    unsafe { real(olddirfd, oldpath, newdirfd, newpath, flags) }
                }
            },
            || policy::resolve_path_at(newdirfd, &new_string, "path", true),
            policy::notify_create_resolved,
        )
    }

    // B10 — FreeBSD `extattr_*` xattr-mutation interposers. Mirrors
    // macOS PR #174 (M03.x.XATTR-MUTATE). FreeBSD's xattr API
    // diverges from Linux/macOS: namespace is a separate `int`
    // argument (1=USER, 2=SYSTEM), name has no platform-style
    // prefix. The current executor supports the USER namespace and expects
    // raw FreeBSD names; SYSTEM must refuse until namespace is represented on
    // the wire instead of being folded into a different literal name.

    /// Preserve USER names exactly. Other namespaces get an impossible
    /// sentinel which the policy layer turns into a structured refusal.
    #[cfg(target_os = "freebsd")]
    fn extattr_ns_name(ns: c_int, name: *const c_char) -> String {
        if ns == 1 {
            cstr_to_string(name)
        } else {
            "\0shit:unsupported-extattr-namespace".to_string()
        }
    }

    /// Read the pre-mutation xattr value via `extattr_get_file(2)`.
    /// `Ok(None)` means the attribute is authoritatively absent (ENOATTR);
    /// every other probe/read failure is an explicit capture error. Treating
    /// I/O or permission failures as absence would make undo delete an xattr
    /// whose old value we never captured.
    #[cfg(target_os = "freebsd")]
    unsafe fn read_extattr_value(
        path: *const c_char,
        ns: c_int,
        name: *const c_char,
    ) -> Result<Option<Vec<u8>>, String> {
        if path.is_null() || name.is_null() {
            return Err("null path or xattr name".to_string());
        }
        let real_get = next::real_extattr_get_file();
        if next::is_zero(next::as_usize(real_get)) {
            return Err("extattr_get_file could not be resolved".to_string());
        }
        let sz = unsafe { real_get(path, ns, name, std::ptr::null_mut(), 0) };
        if sz < 0 {
            let errno = current_errno();
            return if errno == libc::ENOATTR {
                Ok(None)
            } else {
                Err(format!("extattr size probe failed with errno {errno}"))
            };
        }
        if sz == 0 {
            return Ok(Some(Vec::new()));
        }
        if sz as u64 > shit_proto::SHIM_INLINE_PREIMAGE_CAP {
            return Err(format!(
                "xattr pre-image size {sz} exceeds inline capture cap {}",
                shit_proto::SHIM_INLINE_PREIMAGE_CAP
            ));
        }
        let mut buf = vec![0u8; sz as usize];
        let got = unsafe {
            real_get(
                path,
                ns,
                name,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as size_t,
            )
        };
        if got < 0 {
            let errno = current_errno();
            return if errno == libc::ENOATTR {
                Ok(None)
            } else {
                Err(format!("extattr value read failed with errno {errno}"))
            };
        }
        buf.truncate(got as usize);
        Ok(Some(buf))
    }

    /// `extattr_set_file(2)` interposer. Captures the pre-mutation
    /// value before the syscall hits the kernel; ships it via
    /// [`shit_proto::XattrPreImage`] so the planner can drive an
    /// undo that either restores the old value (when present) or
    /// removes the xattr (when absent pre-syscall).
    ///
    /// # Safety
    /// `path` and `name` must be valid C strings per
    /// `extattr_set_file(2)`'s contract.
    #[cfg(target_os = "freebsd")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn extattr_set_file(
        path: *const c_char,
        attrnamespace: c_int,
        attrname: *const c_char,
        data: *const c_void,
        nbytes: size_t,
    ) -> ssize_t {
        let path_string = cstr_to_string(path);
        let real = next::real_extattr_set_file();
        call_mutation_and_notify_with(
            || match unsafe { read_extattr_value(path, attrnamespace, attrname) } {
                Ok(pre_value) => {
                    let xattr_pre = shit_proto::XattrPreImage {
                        name: extattr_ns_name(attrnamespace, attrname),
                        value: pre_value,
                    };
                    policy::prepare_xattr_mutation("setxattr", &path_string, xattr_pre)
                }
                Err(reason) => policy::prepare_unsupported_path_mutation(
                    "setxattr",
                    &path_string,
                    false,
                    format!("xattr pre-image unavailable: {reason}"),
                ),
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::extattr_set_file(path, attrnamespace, attrname, data, nbytes) }
                } else {
                    unsafe { real(path, attrnamespace, attrname, data, nbytes) }
                }
            },
            |result| *result >= 0,
            policy::PreparedNotification::send,
        )
    }

    /// `extattr_delete_file(2)` interposer. Captures the
    /// pre-mutation value (the xattr being deleted) so undo can
    /// restore it via setxattr.
    ///
    /// # Safety
    /// `path` and `name` must be valid C strings.
    #[cfg(target_os = "freebsd")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn extattr_delete_file(
        path: *const c_char,
        attrnamespace: c_int,
        attrname: *const c_char,
    ) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_extattr_delete_file();
        call_mutation_and_notify_with(
            || match unsafe { read_extattr_value(path, attrnamespace, attrname) } {
                Ok(pre_value) => {
                    let xattr_pre = shit_proto::XattrPreImage {
                        name: extattr_ns_name(attrnamespace, attrname),
                        value: pre_value,
                    };
                    policy::prepare_xattr_mutation("removexattr", &path_string, xattr_pre)
                }
                Err(reason) => policy::prepare_unsupported_path_mutation(
                    "removexattr",
                    &path_string,
                    false,
                    format!("xattr pre-image unavailable: {reason}"),
                ),
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::extattr_delete_file(path, attrnamespace, attrname) }
                } else {
                    unsafe { real(path, attrnamespace, attrname) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// B09 — `chflags(2)` interposer. Mutates the BSD `st_flags`
    /// bitmap (UF_IMMUTABLE, UF_HIDDEN, SF_NOUNLINK, …). Mirrors
    /// `notify_flags_mutation` snapshots the current st_flags BEFORE
    /// the syscall fires. The daemon tags that metadata-only pre-image
    /// so the planner emits a dedicated RestoreFlags inverse.
    ///
    /// FreeBSD's chflags signature: `int chflags(const char *path,
    /// unsigned long flags)`. macOS keeps `c_uint`; FreeBSD widened
    /// to `c_ulong` — the actual flag bits all fit in u32 but the
    /// ABI demands the wider arg.
    ///
    /// # Safety
    /// `path` must be a valid NUL-terminated C string.
    #[cfg(target_os = "freebsd")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chflags(path: *const c_char, flags: libc::c_ulong) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_chflags();
        call_mutation_and_notify_with(
            || policy::prepare_flags_mutation("chflags", &path_string),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::chflags(path, flags) }
                } else {
                    unsafe { real(path, flags) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// `chflagsat(2)` interposer — the dirfd-relative variant. The
    /// current wire carries only a path, not dirfd or `atflag`, so
    /// capture is limited to shapes the path-based RestoreFlags op can
    /// faithfully replay: follow-symlink calls using AT_FDCWD, plus
    /// absolute paths (whose dirfd is ignored). Other calls still pass
    /// through but rely on the helper's post-hoc NOTE_ATTRIB capture.
    ///
    /// # Safety
    /// `path` must be a valid NUL-terminated C string.
    #[cfg(target_os = "freebsd")]
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chflagsat(
        dirfd: c_int,
        path: *const c_char,
        flags: libc::c_ulong,
        atflag: c_int,
    ) -> c_int {
        let path_string = cstr_to_string(path);
        let real = next::real_chflagsat();
        call_mutation_and_notify_with(
            || {
                if should_capture_chflagsat(dirfd, &path_string, atflag) {
                    policy::prepare_flags_mutation("chflags", &path_string)
                } else {
                    policy::prepare_unsupported_at_mutation(
                        "chflags",
                        dirfd,
                        &path_string,
                        true,
                        format!(
                            "chflagsat dirfd/atflag semantics are not replayable (atflag={atflag:#x})"
                        ),
                    )
                }
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::chflagsat(dirfd, path, flags, atflag) }
                } else {
                    unsafe { real(dirfd, path, flags, atflag) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    #[cfg(target_os = "freebsd")]
    pub(super) fn should_capture_chflagsat(dirfd: c_int, path: &str, atflag: c_int) -> bool {
        atflag == 0 && (dirfd == libc::AT_FDCWD || std::path::Path::new(path).is_absolute())
    }

    /// `truncate(2)` interposer.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn truncate(path: *const c_char, len: off_t) -> c_int {
        // W06.A.4: truncate(path, 0) before re-writing is a common
        // overwrite shape; capture pre-image to enable undo.
        let path_string = cstr_to_string(path);
        let real = next::real_truncate();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation_with_content("truncate", &path_string),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::truncate(path, len) }
                } else {
                    unsafe { real(path, len) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
    }

    /// `ftruncate(2)` interposer. fd-based; no path to log.
    ///
    /// # Safety
    /// `fd` must be a valid open file descriptor.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ftruncate(fd: c_int, len: off_t) -> c_int {
        let arg = format!("fd:{fd}");
        let real = next::real_ftruncate();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation("ftruncate", &arg),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::ftruncate(fd, len) }
                } else {
                    unsafe { real(fd, len) }
                }
            },
            |result| *result == 0,
            policy::PreparedNotification::send,
        )
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
        let arg = format!("fd:{fd}");
        let real = next::real_pwrite();
        call_mutation_and_notify_with(
            || policy::prepare_pre_mutation("pwrite", &arg),
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::pwrite(fd, buf, count, offset) }
                } else {
                    unsafe { real(fd, buf, count, offset) }
                }
            },
            // A zero-byte pwrite is a successful no-op, not a mutation.
            |result| *result > 0,
            policy::PreparedNotification::send,
        )
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
        let writes = (prot & libc::PROT_WRITE) != 0 && (flags & libc::MAP_SHARED) != 0;
        let arg = format!("fd:{fd}");
        let real = next::real_mmap();
        call_mutation_and_notify_with(
            || {
                writes
                    .then(|| policy::prepare_pre_mutation("mmap_shared_w", &arg))
                    .flatten()
            },
            || {
                if next::is_zero(next::as_usize(real)) {
                    unsafe { libc::mmap(addr, length, prot, flags, fd, offset) }
                } else {
                    unsafe { real(addr, length, prot, flags, fd, offset) }
                }
            },
            |result| *result != libc::MAP_FAILED,
            policy::PreparedNotification::send,
        )
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
    use std::cell::Cell;
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

    /// The wrapper-level commit gate is the invariant all destructive POSIX
    /// interposers share: capture may run before libc, but a failed libc result
    /// must not deliver the captured notification.
    #[test]
    fn failed_mutation_does_not_deliver_prepared_notification() {
        let delivered = Cell::new(0);
        let result = super::interposers::call_mutation_and_notify_with(
            || Some("captured-before-libc"),
            || -1,
            |result| *result == 0,
            |_| delivered.set(delivered.get() + 1),
        );
        assert_eq!(result, -1);
        assert_eq!(delivered.get(), 0);
    }

    #[test]
    fn successful_mutation_delivers_exactly_once() {
        let delivered = Cell::new(0);
        let result = super::interposers::call_mutation_and_notify_with(
            || Some("captured-before-libc"),
            || 0,
            |result| *result == 0,
            |_| delivered.set(delivered.get() + 1),
        );
        assert_eq!(result, 0);
        assert_eq!(delivered.get(), 1);
    }

    #[test]
    fn capture_and_delivery_preserve_libc_errno_boundaries() {
        super::interposers::set_errno(libc::EBUSY);
        let result = super::interposers::call_mutation_and_notify_with(
            || {
                // Simulate filesystem probes during pre-image capture.
                super::interposers::set_errno(libc::EACCES);
                Some(())
            },
            || {
                assert_eq!(super::interposers::current_errno(), libc::EBUSY);
                // Simulate the errno state left by libc on return.
                super::interposers::set_errno(libc::EAGAIN);
                0
            },
            |result| *result == 0,
            |_| {
                // Simulate socket I/O performed by delivery.
                super::interposers::set_errno(libc::EPIPE);
            },
        );
        assert_eq!(result, 0);
        assert_eq!(super::interposers::current_errno(), libc::EAGAIN);
    }

    #[test]
    fn rmdir_of_missing_path_fails() {
        let c = CString::new("/tmp/shit-preload-shim-no-such-dir-XXX").unwrap();
        let r = unsafe { super::interposers::rmdir(c.as_ptr()) };
        assert!(r < 0, "rmdir of nonexistent path should fail");
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

/// AU10 — `canonical_path` + `canonicalize_or_raw` unit tests.
/// Gated to the same Unix targets as `mod policy` itself since these
/// resolvers run inside the platform interposers. Windows has no preload shim.
#[cfg(all(
    test,
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
        target_os = "macos",
    )
))]
mod canonical_tests {
    /// Resolving an existing absolute path succeeds and returns the
    /// canonical form. `/tmp` exists on every unix dev host.
    #[test]
    fn canonical_path_resolves_existing_absolute() {
        let r = super::policy::canonical_path("/tmp").expect("canonicalize /tmp");
        assert!(r.starts_with('/'));
    }

    /// Resolving a non-existent path whose parent DOES exist returns
    /// Ok via the parent-canonicalize + basename trick. Critical for
    /// the rename `to` (clean-prefix install) path.
    #[test]
    fn canonical_path_resolves_nonexistent_with_extant_parent() {
        let r = super::policy::canonical_path("/tmp/shit-au10-canon-nonexistent-XYZ")
            .expect("parent-canonicalize fallback");
        assert!(r.ends_with("/shit-au10-canon-nonexistent-XYZ"));
        assert!(r.starts_with("/"));
    }

    /// Fresh relative paths are the common open(O_CREAT) shape. They must be
    /// made absolute while the shim still has the mutating process's cwd;
    /// resolving them later from `shit undo`'s cwd is unsafe.
    #[test]
    fn canonical_path_resolves_relative_nonexistent_leaf_against_cwd() {
        let leaf = format!("shit-relative-canon-does-not-exist-{}", std::process::id());
        let got = super::policy::canonical_path(&leaf).expect("canonicalize relative parent");
        let expected = std::fs::canonicalize(".")
            .expect("canonicalize cwd")
            .join(&leaf)
            .to_string_lossy()
            .into_owned();
        assert_eq!(got, expected);
    }

    /// Namespace-entry resolution must not follow the final symlink. An
    /// unlink/rename inverse addresses the link itself, not its referent.
    #[test]
    fn canonical_parent_path_preserves_final_symlink_component() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");
        std::fs::write(&target, b"target").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let got = super::policy::canonical_parent_path(link.to_str().expect("utf8 path"))
            .expect("canonicalize parent");
        let canonical_link_entry = std::fs::canonicalize(tmp.path())
            .expect("canonicalize temp parent")
            .join("link");
        let canonical_target = std::fs::canonicalize(&target).expect("canonicalize target");
        assert_eq!(std::path::Path::new(&got), canonical_link_entry);
        assert_ne!(std::path::Path::new(&got), canonical_target);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn canonical_path_refuses_non_utf8_canonical_parent() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let non_utf8_parent = tmp.path().join(OsString::from_vec(b"parent-\xff".to_vec()));
        std::fs::create_dir(&non_utf8_parent).expect("create non-UTF-8 directory");
        std::fs::write(non_utf8_parent.join("leaf"), b"data").expect("write leaf");

        // The spelling passed by the caller is valid UTF-8, but canonicalize
        // traverses the symlink to a path the string wire cannot represent.
        let alias = tmp.path().join("utf8-alias");
        symlink(&non_utf8_parent, &alias).expect("create UTF-8 alias");
        let input = alias.join("leaf");
        let err = super::policy::canonical_path(input.to_str().expect("UTF-8 alias path"))
            .expect_err("non-UTF-8 canonical path must be refused");
        assert!(matches!(
            err,
            super::policy::CanonicalizeError::Unrepresentable
        ));
    }

    #[test]
    fn path_to_utf8_rejects_unrepresentable_posix_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"path-\xff".to_vec()));
        let err = super::policy::path_to_utf8(&path).expect_err("invalid UTF-8 must refuse");
        assert!(matches!(
            err,
            super::policy::CanonicalizeError::Unrepresentable
        ));
    }

    #[test]
    fn rename_hardlink_aliases_are_not_suppressed_by_racy_path_probes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = tmp.path().join("first");
        let alias = tmp.path().join("alias");
        std::fs::write(&first, b"same inode").expect("write source");
        std::fs::hard_link(&first, &alias).expect("create hardlink alias");

        assert!(
            super::policy::prepare_rename_with_dst_preimage(
                "rename",
                first.to_str().expect("UTF-8 temp path"),
                alias.to_str().expect("UTF-8 temp path"),
            )
            .is_some()
        );
    }

    #[test]
    fn at_fdcwd_relative_path_resolves_absolute() {
        let leaf = format!("shit-at-fdcwd-does-not-exist-{}", std::process::id());
        let (got, failure) = super::policy::resolve_path_at(libc::AT_FDCWD, &leaf, "path", true);
        assert!(failure.is_none());
        assert!(std::path::Path::new(&got).is_absolute());
        assert!(got.ends_with(&leaf));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn real_dirfd_relative_path_resolves_against_fd() {
        use std::os::fd::AsRawFd;

        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = std::fs::File::open(tmp.path()).expect("open tempdir");
        let (got, failure) = super::policy::resolve_path_at(dir.as_raw_fd(), "child", "path", true);
        assert!(failure.is_none());
        let expected = std::fs::canonicalize(tmp.path())
            .expect("canonicalize tempdir")
            .join("child");
        assert_eq!(std::path::Path::new(&got), expected);
    }

    #[cfg(target_os = "openbsd")]
    #[test]
    fn unresolved_real_dirfd_relative_path_is_refused() {
        let (got, failure) = super::policy::resolve_path_at(42, "child", "path", true);
        assert_eq!(got, "child");
        assert!(failure.is_some());
    }

    /// The audit's load-bearing failure mode: both the path AND its
    /// parent are non-canonicalize-able (path under a non-existent
    /// dir). Pre-AU10 this silently returned the raw input. Post-AU10
    /// it returns Err(PathAndParentBothFailed).
    #[test]
    fn canonical_path_fails_when_both_path_and_parent_inaccessible() {
        let raw = "/this-dir-does-not-exist-shit-au10/subdir/leaf";
        let err = super::policy::canonical_path(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("canonicalize"),
            "error message should describe canonicalize failure: {msg}"
        );
    }

    /// `canonicalize_or_raw` preserves the raw user-passed path on
    /// Err so the syscall stays unblocked, and populates a structured
    /// failure for the outbound notification.
    #[test]
    fn canonicalize_or_raw_returns_raw_on_failure() {
        let raw = "/this-dir-does-not-exist-shit-au10/subdir/leaf";
        let (got, failure) = super::policy::canonicalize_or_raw(raw, "from");
        assert_eq!(got, raw, "raw path passed through on Err");
        let f = failure.expect("failure must be populated on Err");
        match f {
            shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg,
                attempted_path,
                ..
            } => {
                assert_eq!(which_arg, "from");
                assert_eq!(attempted_path, raw);
            }
            other => panic!("expected CanonicalizeFailed, got {other:?}"),
        }
    }

    /// On the Ok path `canonicalize_or_raw` returns no failure and
    /// the canonical form.
    #[test]
    fn canonicalize_or_raw_returns_none_failure_on_success() {
        let (got, failure) = super::policy::canonicalize_or_raw("/tmp", "path");
        assert!(failure.is_none(), "no failure on Ok path");
        assert!(got.starts_with('/'));
    }
}

/// B09 — flags capture is metadata-only and therefore must not inherit
/// the regular-file/readability/32-MiB restrictions of content capture.
#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
mod flags_capture_tests {
    #[test]
    fn flags_pre_image_accepts_directory_without_content_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().to_str().expect("utf8 temp path");
        let pre = super::policy::capture_flags_pre_image(path).expect("flags pre-image");
        assert!(pre.bytes.is_empty());
        assert_ne!(pre.inode, 0);
        assert_eq!(pre.path, path);
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod chflagsat_capture_tests {
    use super::interposers::should_capture_chflagsat;

    #[test]
    fn capture_gate_accepts_replayable_paths_only() {
        assert!(should_capture_chflagsat(libc::AT_FDCWD, "relative", 0));
        assert!(should_capture_chflagsat(42, "/absolute", 0));
        assert!(!should_capture_chflagsat(42, "relative", 0));
        assert!(!should_capture_chflagsat(
            libc::AT_FDCWD,
            "/absolute",
            libc::AT_SYMLINK_NOFOLLOW,
        ));
    }
}
