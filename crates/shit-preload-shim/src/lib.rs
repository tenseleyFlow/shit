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
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
core::arch::global_asm!(
    // FBSD_1.0 — `open`, `unlink`, `rename`, `truncate`,
    // `ftruncate`, `pwrite`, `mmap`. All the pre-`*at` syscalls.
    ".symver open, open@FBSD_1.0",
    ".symver unlink, unlink@FBSD_1.0",
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

// L5 — open64/openat64/fortify/creat and mkdir/mkdirat/rmdir.
#[cfg(target_os = "linux")]
mod linux_extra;

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

    /// L5 — cached `dlsym(RTLD_NEXT, name)` for interposers kept outside
    /// this module; 0 when absent.
    #[cfg(target_os = "linux")]
    pub fn lookup(cache: &'static OnceLock<usize>, name: &'static [u8]) -> usize {
        *cache.get_or_init(|| unsafe { dlsym_next(name) })
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
    // Called by BSD/Linux truncate / ftruncate / pwrite / mmap
    // interposers. macOS adds those interposers in M07.B; until
    // then this function is dead on the macos build.
    #[allow(dead_code)]
    pub fn notify_pre_mutation(syscall: &'static str, arg: &str) {
        if should_skip_path(arg) {
            return;
        }
        notify_inner(syscall, arg, None);
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
    /// Cases where the pre-image will be absent (file doesn't exist,
    /// exceeds cap, read fails) still ship the notification with
    /// `pre_image=None`; the daemon decides how to journal it.
    pub fn notify_pre_mutation_with_content(syscall: &'static str, path: &str) {
        if should_skip_path(path) {
            return;
        }
        notify_inner(syscall, path, Some(path));
    }

    /// Outcome of resolving an `*at` syscall's `(dirfd, path)` pair for
    /// the journal.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    ))]
    #[derive(Debug)]
    pub enum AtResolution {
        /// Absolute, canonical key.
        Resolved(String),
        /// Could not be keyed: the raw path plus the AU10 marker to
        /// journal. Never a cwd-based absolute key.
        Failed(String, shit_proto::ShimFailure),
        /// Neither the target nor its parent exists, so the syscall
        /// cannot mutate anything. Send nothing.
        Nothing,
    }

    /// The one resolver all four `*at` interposers (unlinkat, openat,
    /// renameat, renameat2) share. Joins `(dirfd, path)`; a path that
    /// is still relative under a real dirfd (BSD, or Linux without
    /// /proc) fails closed with the marker and is never canonicalized
    /// against the cwd. Otherwise canonicalizes once; when that fails
    /// because the parent is missing (ENOENT/ENOTDIR) there is nothing
    /// to capture, any other failure ships the marker.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    ))]
    pub fn resolve_at_for_notify(dirfd: libc::c_int, path: &str, which_arg: &str) -> AtResolution {
        let joined = join_at_path(dirfd, path);
        if !joined.starts_with('/') && dirfd != libc::AT_FDCWD {
            return AtResolution::Failed(
                path.to_string(),
                shit_proto::ShimFailure::CanonicalizeFailed {
                    which_arg: which_arg.to_string(),
                    attempted_path: path.to_string(),
                    error_chain: format!("dirfd {dirfd} could not be resolved to a directory"),
                },
            );
        }
        match canonical_path(&joined) {
            Ok(abs) => AtResolution::Resolved(abs),
            Err(CanonicalizeError::PathAndParentBothFailed { parent_err, .. })
                if matches!(
                    parent_err.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::ENOTDIR)
                ) =>
            {
                AtResolution::Nothing
            }
            Err(e) => AtResolution::Failed(
                joined.clone(),
                shit_proto::ShimFailure::CanonicalizeFailed {
                    which_arg: which_arg.to_string(),
                    attempted_path: joined,
                    error_chain: format!("{e}"),
                },
            ),
        }
    }

    /// `*at` variant of [`notify_pre_mutation_with_content`] for
    /// unlinkat/openat: resolves via [`resolve_at_for_notify`].
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    ))]
    pub fn notify_pre_mutation_with_content_at(
        syscall: &'static str,
        dirfd: libc::c_int,
        path: &str,
    ) {
        match resolve_at_for_notify(dirfd, path, "path") {
            AtResolution::Resolved(abs) => {
                if should_skip_path(&abs) {
                    return;
                }
                notify_inner_with_failure(syscall, &abs, Some(&abs), None, true);
            }
            AtResolution::Failed(raw, failure) => {
                if should_skip_path(&raw) {
                    return;
                }
                notify_inner_with_failure(syscall, &raw, None, Some(failure), false);
            }
            AtResolution::Nothing => {}
        }
    }

    /// `*at` variant of [`notify_rename_with_dst_preimage`] for
    /// renameat/renameat2, using the same shared resolver.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    ))]
    pub fn notify_rename_at(
        syscall: &'static str,
        fromfd: libc::c_int,
        from: &str,
        tofd: libc::c_int,
        to: &str,
    ) -> Option<RenamePending> {
        let f = resolve_at_for_notify(fromfd, from, "from");
        let t = resolve_at_for_notify(tofd, to, "to");
        match (f, t) {
            (AtResolution::Nothing, _) | (_, AtResolution::Nothing) => None,
            (AtResolution::Resolved(a), AtResolution::Resolved(b)) => {
                notify_rename_with_dst_preimage(syscall, &a, &b)
            }
            // Prefer the `from` failure, as notify_rename does.
            (AtResolution::Failed(fa, fe), AtResolution::Failed(ta, _))
            | (AtResolution::Failed(fa, fe), AtResolution::Resolved(ta))
            | (AtResolution::Resolved(fa), AtResolution::Failed(ta, fe)) => {
                let arg = format!("{fa}\t{ta}");
                notify_inner_with_failure(syscall, &arg, None, Some(fe), false);
                None
            }
        }
    }

    /// A mutation whose path could not be keyed: send the raw arg (for a
    /// rename, `from\tto`) with the AU10 marker and no capture.
    #[cfg(target_os = "macos")]
    pub fn notify_unresolved(syscall: &'static str, arg: &str, failure: shit_proto::ShimFailure) {
        notify_inner_with_failure(syscall, arg, None, Some(failure), false);
    }

    /// B09 — notify a chflags-family mutation with a metadata-only
    /// pre-image. Unlike content capture this accepts directories,
    /// special files, unreadable files, and regular files above the
    /// inline byte cap; chflags needs only the pre-syscall `st_flags`.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub fn notify_flags_mutation(syscall: &'static str, path: &str, follow: bool) {
        if disabled() || should_skip_path(path) {
            return;
        }
        if IN_NOTIFY.with(|f| f.replace(true)) {
            return;
        }
        let (resolved, failure) = canonicalize_or_raw(path, "path");
        let pre_image = capture_flags_pre_image(&resolved, follow);
        let wire_arg = pre_image
            .as_ref()
            .map(|pre| pre.path.clone())
            .unwrap_or_else(|| resolved.clone());
        let _ = try_notify(syscall, &wire_arg, pre_image, Vec::new(), failure);
        IN_NOTIFY.with(|f| f.set(false));
    }

    /// W06.A.4 rename/renameat variant: the wire `arg` is `from\tto`
    /// but the pre-image target is `to` (the destination — rename
    /// atomically overwrites its content). When `to` doesn't exist
    /// (clean-prefix install / mv to new path), `pre_image` ends up
    /// `None` and the planner falls back to ReverseRename. When `to`
    /// pre-exists (install over an existing file), the captured bytes
    /// drive a RestoreContent inverse instead.
    pub fn notify_rename_with_dst_preimage(
        syscall: &'static str,
        from: &str,
        to: &str,
    ) -> Option<RenamePending> {
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
        let (from_abs, from_failure) = canonicalize_or_raw(from, "from");
        let (to_abs, to_failure) = canonicalize_or_raw(to, "to");
        // Prefer the `from`-side failure when both arms tripped:
        // `from`'s pre-image is the load-bearing input for
        // RestoreContent, so its capture incompleteness is the more
        // alarming signal to surface to the user.
        let failure = from_failure.or(to_failure);
        // W09.8: rename-to-self is a syscall no-op. POSIX
        // `rename(2)` of a file to itself returns success without
        // touching anything; the kernel fires no notification.
        // Synthesizing a Rename+PreImage event pair would drive
        // the planner's atomic_replace classifier to emit a
        // RestoreContent that rewrites the file via tmpfile+rename,
        // churning the inode for zero user-visible benefit. Mirror
        // the kernel: emit nothing for `mv x x`. After
        // canonicalization above this also catches `./foo` vs
        // `foo`, symlink-equal pairs, etc.
        if from_abs == to_abs {
            return None;
        }
        let arg = format!("{from_abs}\t{to_abs}");
        // DR-CR-54 — when `from` is a directory, snapshot every
        // regular file in the subtree so the planner can restore
        // the original tree content on undo. pip's wheel installer
        // is the canonical motivator: it renames `site-packages →
        // <staging>` before writing fresh content, and without
        // recursive pre-images the original site-packages contents
        // are unreachable by the time undo runs.
        notify_rename_inner_with_recursive(syscall, &arg, &to_abs, &from_abs, failure)
    }

    /// DR-CR-54 limits. A directory rename of an enormous tree
    /// would saturate memory and the shim→daemon UDS; cap the walk
    /// to bound worst-case overhead. When a limit trips we ship
    /// what we have, marked incomplete (L5): the planner restores
    /// those files but does not treat the walk as the whole subtree.
    const RECURSIVE_MAX_FILES: usize = 1000;
    const RECURSIVE_MAX_BYTES: u64 = 50 * 1024 * 1024;
    const RECURSIVE_MAX_DEPTH: usize = 5;
    /// L5 (finding 6): directories count too, or a directory-heavy tree
    /// could outgrow the frame with no file cap tripping.
    const RECURSIVE_MAX_DIRS: usize = 1000;
    /// L5 (finding 6): everything the frame carries (bytes, paths,
    /// xattrs, per-record overhead) stays under this, well inside the
    /// wire's 64 MiB `MAX_LARGE_FRAME_SIZE`.
    const RECURSIVE_FRAME_BUDGET: u64 = 60 * 1024 * 1024;
    /// Rough postcard cost of one record beyond its path, bytes and xattrs.
    const RECORD_OVERHEAD: u64 = 128;

    /// L5 — a rename the shim notified, for the post-syscall outcome.
    pub struct RenamePending {
        syscall: &'static str,
        arg: String,
        to_abs: String,
        source: (u64, u64),
        call_id: u64,
    }

    /// L5 — a process-unique id for one rename-family call, carried on its
    /// pre-syscall notification and on its outcome. Never 0.
    fn next_call_id() -> u64 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        // SAFETY: getpid is a plain syscall.
        let pid = unsafe { libc::getpid() } as u64;
        (pid << 32) | u64::from(N.fetch_add(1, Ordering::Relaxed).wrapping_add(1).max(1))
    }

    /// Bytes of walk pre-images per `rename_walk` notification when a
    /// rename's frame had to be split.
    const WALK_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

    /// Variant of `notify_inner` that ships a directory rename's
    /// recursive subtree pre-images alongside the primary
    /// notification. Walks `from_abs` (the **source** of the
    /// rename, which still has the pre-rename contents at this
    /// point — the libc rename hasn't been forwarded yet), but
    /// only when it is actually a directory.
    fn notify_rename_inner_with_recursive(
        syscall: &'static str,
        arg: &str,
        capture_path: &str,
        from_abs: &str,
        failure: Option<shit_proto::ShimFailure>,
    ) -> Option<RenamePending> {
        use std::os::unix::fs::MetadataExt;
        if disabled() {
            return None;
        }
        if IN_NOTIFY.with(|f| f.replace(true)) {
            return None;
        }
        let call_id = next_call_id();
        let source = std::fs::symlink_metadata(from_abs).ok();
        let pre_image = capture_pre_image(capture_path);
        let (extras, walk) = collect_recursive_pre_images(from_abs);
        // #222: the wire arg stays `from\tto` for the whole rename
        // family, overwrite or not. The pre-image carries the
        // destination path on its own; replacing the arg with it left
        // the daemon nothing to journal a TreeOp::Rename from.
        let extra = |walk| Extra {
            walk,
            call_id,
            ..Extra::default()
        };
        if walk.is_none() {
            // A file rename: nothing to fall back to, so no copies.
            let _ = try_notify_full(syscall, arg, pre_image, extras, failure, extra(None));
        } else {
            let sent = try_notify_full(
                syscall,
                arg,
                pre_image.clone(),
                extras.clone(),
                failure.clone(),
                extra(walk),
            );
            // Finding 6, review item 7: a frame too big with the walk must
            // lose neither the Rename nor the files' bytes. Send the
            // pre-images on their own in chunks (`rename_walk`, which
            // journals no Rename), then the Rename without them. Without
            // the walk record the planner treats the walk as incomplete.
            if sent.is_err() {
                send_walk_chunks(arg, extras, call_id);
                let _ = try_notify_full(syscall, arg, pre_image, Vec::new(), failure, extra(None));
            }
        }
        IN_NOTIFY.with(|f| f.set(false));
        Some(RenamePending {
            syscall,
            arg: arg.to_string(),
            to_abs: capture_path.to_string(),
            source: source.as_ref().map_or((0, 0), |m| (m.dev(), m.ino())),
            call_id,
        })
    }

    fn send_walk_chunks(arg: &str, extras: Vec<shit_proto::ShimPreImage>, call_id: u64) {
        let budget = walk_chunk_bytes();
        let mut chunk: Vec<shit_proto::ShimPreImage> = Vec::new();
        let mut bytes = 0u64;
        let flush = |chunk: &mut Vec<shit_proto::ShimPreImage>| {
            if !chunk.is_empty() {
                let _ = try_notify_full(
                    "rename_walk",
                    arg,
                    None,
                    std::mem::take(chunk),
                    None,
                    Extra {
                        call_id,
                        ..Extra::default()
                    },
                );
            }
        };
        for pre in extras {
            let cost = pre.bytes.len() as u64 + pre.path.len() as u64 + RECORD_OVERHEAD;
            if !chunk.is_empty() && bytes + cost > budget {
                flush(&mut chunk);
                bytes = 0;
            }
            bytes += cost;
            chunk.push(pre);
        }
        flush(&mut chunk);
    }

    fn walk_chunk_bytes() -> u64 {
        #[cfg(test)]
        if let Some(limit) = test_capture::frame_limit() {
            return (limit / 2) as u64;
        }
        WALK_CHUNK_BYTES
    }

    /// L5 — after a rename-family call returns: report its result with
    /// the inode now at `to` (the planner's proof a directory rename
    /// happened) or its errno (which retracts the Rename the pre-syscall
    /// notification journaled). Every call reports, so the daemon can tell
    /// each call's own Rename from a second tier's. Nothing waits on the
    /// daemon's ack, and the daemon matches the call by id instead of
    /// resolving the pid again. Leaves errno as the call set it.
    pub fn finish_rename(pending: Option<RenamePending>, rc: libc::c_int) {
        use std::os::unix::fs::MetadataExt;
        let Some(p) = pending else {
            return;
        };
        let saved = std::io::Error::last_os_error();
        let errno = if rc == 0 {
            0
        } else {
            saved.raw_os_error().unwrap_or(libc::EIO)
        };
        if disabled() || IN_NOTIFY.with(|f| f.replace(true)) {
            return;
        }
        let dest = if errno == 0 {
            std::fs::symlink_metadata(&p.to_abs)
                .ok()
                .map_or((0, 0), |m| (m.dev(), m.ino()))
        } else {
            (0, 0)
        };
        let outcome = shit_proto::ShimRenameOutcome {
            errno,
            source_dev: p.source.0,
            source_inode: p.source.1,
            dest_dev: dest.0,
            dest_inode: dest.1,
        };
        let _ = try_notify_full(
            p.syscall,
            &p.arg,
            None,
            Vec::new(),
            None,
            Extra {
                outcome: Some(outcome),
                call_id: p.call_id,
                no_ack: true,
                ..Extra::default()
            },
        );
        IN_NOTIFY.with(|f| f.set(false));
        if let Some(e) = saved.raw_os_error() {
            // SAFETY: errno is a valid thread-local lvalue.
            unsafe { set_errno(e) };
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn set_errno(e: libc::c_int) {
        unsafe { *libc::__errno_location() = e };
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly"))]
    pub(crate) unsafe fn set_errno(e: libc::c_int) {
        unsafe { *libc::__error() = e };
    }

    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    pub(crate) unsafe fn set_errno(e: libc::c_int) {
        unsafe { *libc::__errno() = e };
    }

    /// One walked entry's record.
    fn walk_entry(path: &str, meta: &std::fs::Metadata) -> shit_proto::ShimWalkEntry {
        use std::os::unix::fs::MetadataExt;
        shit_proto::ShimWalkEntry {
            path: path.to_string(),
            dev: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime_unix_nanos: meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128,
            flags: read_st_flags(path, false).unwrap_or(0),
            xattrs: read_xattrs(path),
        }
    }

    fn entry_cost(e: &shit_proto::ShimWalkEntry) -> u64 {
        let x: u64 = e
            .xattrs
            .iter()
            .flatten()
            .map(|(k, v)| (k.len() + v.len()) as u64 + 16)
            .sum();
        e.path.len() as u64 + x + RECORD_OVERHEAD
    }

    /// Walk `from_abs` if it is a directory and capture per-file
    /// pre-images for every regular file in the subtree, plus (L5) a
    /// record of every entry. Returns nothing for non-directories.
    /// Symlinks, devices, fifos, and other non-regular entries are
    /// skipped (their pre-images aren't a `RestoreContent`-shaped fix),
    /// which makes the walk incomplete.
    ///
    /// Directory records are sent only when the walk saw every entry,
    /// captured every file and stayed within its caps. The source
    /// directory's record comes first.
    pub(super) fn collect_recursive_pre_images(
        from_abs: &str,
    ) -> (Vec<shit_proto::ShimPreImage>, Option<shit_proto::ShimWalk>) {
        use std::os::unix::fs::MetadataExt;
        use std::path::{Path, PathBuf};

        let p = Path::new(from_abs);
        let Ok(meta) = std::fs::symlink_metadata(p) else {
            return (Vec::new(), None);
        };
        if !meta.is_dir() {
            return (Vec::new(), None);
        }

        let mut out: Vec<shit_proto::ShimPreImage> = Vec::new();
        let mut file_entries: Vec<shit_proto::ShimWalkEntry> = Vec::new();
        let mut dirs: Vec<shit_proto::ShimWalkEntry> = vec![walk_entry(from_abs, &meta)];
        let mut complete = true;
        let mut total_bytes: u64 = 0;
        let mut frame: u64 = entry_cost(&dirs[0]);
        // Depth-first walk. (Depth bound keeps a path explosion
        // contained; file/byte caps catch fan-out separately.)
        let mut stack: Vec<(PathBuf, usize)> = vec![(p.to_path_buf(), 0)];
        'walk: while let Some((dir, depth)) = stack.pop() {
            if depth > RECURSIVE_MAX_DEPTH {
                complete = false;
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&dir) else {
                complete = false;
                continue;
            };
            for entry in rd {
                let Ok(entry) = entry else {
                    complete = false;
                    continue;
                };
                if out.len() >= RECURSIVE_MAX_FILES {
                    complete = false;
                    break 'walk;
                }
                let path = entry.path();
                // `symlink_metadata` to avoid following symlinks
                // into unrelated parts of the filesystem.
                let Ok(emeta) = std::fs::symlink_metadata(&path) else {
                    complete = false;
                    continue;
                };
                let Some(s) = path.to_str() else {
                    complete = false;
                    continue;
                };
                if emeta.is_dir() {
                    if dirs.len() >= RECURSIVE_MAX_DIRS {
                        complete = false;
                        break 'walk;
                    }
                    let rec = walk_entry(s, &emeta);
                    frame = frame.saturating_add(entry_cost(&rec));
                    dirs.push(rec);
                    stack.push((path, depth + 1));
                    continue;
                }
                if !emeta.is_file() || should_skip_path(s) {
                    // Symlink, fifo, socket, device — skip; their
                    // restore semantics aren't covered by a plain
                    // RestoreContent + bytes payload.
                    complete = false;
                    continue;
                }
                let size = emeta.size();
                if total_bytes.saturating_add(size) > RECURSIVE_MAX_BYTES
                    || frame.saturating_add(size) > RECURSIVE_FRAME_BUDGET
                {
                    complete = false;
                    break 'walk;
                }
                match capture_pre_image(s) {
                    Some(pre) => {
                        let rec = walk_entry(&pre.path, &emeta);
                        total_bytes = total_bytes.saturating_add(pre.bytes.len() as u64);
                        frame = frame
                            .saturating_add(pre.bytes.len() as u64)
                            .saturating_add(pre.path.len() as u64 + RECORD_OVERHEAD)
                            .saturating_add(entry_cost(&rec));
                        out.push(pre);
                        file_entries.push(rec);
                    }
                    None => complete = false,
                }
            }
        }
        if frame > RECURSIVE_FRAME_BUDGET {
            complete = false;
        }
        let mut entries = if complete { dirs } else { Vec::new() };
        entries.append(&mut file_entries);
        let walk = shit_proto::ShimWalk {
            complete,
            files: out.len() as u32,
            entries,
        };
        (out, Some(walk))
    }

    /// L5 (finding 3): an entry's xattrs, read before the syscall.
    /// Linux: the `user.` namespace, which is what restore writes back.
    #[cfg(target_os = "linux")]
    fn read_xattrs(path: &str) -> Option<Vec<(String, Vec<u8>)>> {
        xattrs_with(path, |name| name.starts_with("user."))
    }

    /// macOS: everything but `com.apple.*`, as the daemon reads them.
    #[cfg(target_os = "macos")]
    fn read_xattrs(path: &str) -> Option<Vec<(String, Vec<u8>)>> {
        xattrs_with(path, |name| !name.starts_with("com.apple."))
    }

    /// BSD: not read here; the daemon reads them after the ack.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn read_xattrs(_path: &str) -> Option<Vec<(String, Vec<u8>)>> {
        None
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn xattrs_with(path: &str, keep: impl Fn(&str) -> bool) -> Option<Vec<(String, Vec<u8>)>> {
        let c = std::ffi::CString::new(path).ok()?;
        let size = unsafe { list_xattrs(&c, &mut []) };
        if size < 0 {
            return None;
        }
        let mut names = vec![0u8; size as usize];
        let n = unsafe { list_xattrs(&c, &mut names) };
        if n < 0 {
            return None;
        }
        let mut out = Vec::new();
        for raw in names[..n as usize].split(|b| *b == 0) {
            let Ok(name) = std::str::from_utf8(raw) else {
                continue;
            };
            if name.is_empty() || !keep(name) {
                continue;
            }
            let cn = std::ffi::CString::new(name).ok()?;
            let vsize = unsafe { get_xattr(&c, &cn, &mut []) };
            if vsize < 0 {
                return None;
            }
            let mut val = vec![0u8; vsize as usize];
            let got = unsafe { get_xattr(&c, &cn, &mut val) };
            if got < 0 {
                return None;
            }
            val.truncate(got as usize);
            out.push((name.to_string(), val));
        }
        Some(out)
    }

    #[cfg(target_os = "linux")]
    unsafe fn list_xattrs(path: &std::ffi::CStr, buf: &mut [u8]) -> isize {
        unsafe { libc::llistxattr(path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) }
    }

    #[cfg(target_os = "linux")]
    unsafe fn get_xattr(path: &std::ffi::CStr, name: &std::ffi::CStr, buf: &mut [u8]) -> isize {
        unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        }
    }

    #[cfg(target_os = "macos")]
    unsafe fn list_xattrs(path: &std::ffi::CStr, buf: &mut [u8]) -> isize {
        unsafe {
            libc::listxattr(
                path.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::XATTR_NOFOLLOW,
            )
        }
    }

    #[cfg(target_os = "macos")]
    unsafe fn get_xattr(path: &std::ffi::CStr, name: &std::ffi::CStr, buf: &mut [u8]) -> isize {
        unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        }
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
        use std::os::unix::fs::MetadataExt;
        if disabled() || should_skip_path(path) {
            return;
        }
        if IN_NOTIFY.with(|f| f.replace(true)) {
            return;
        }
        let resolved = std::fs::canonicalize(path)
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_else(|| path.to_string());
        // Stat for inode/dev keying. Falls through with zeroed
        // identity on stat failure — the daemon can still match
        // by path string.
        let (dev, inode, mode, uid, gid, size, mtime_nanos) =
            match std::fs::symlink_metadata(&resolved) {
                Ok(m) => (
                    m.dev(),
                    m.ino(),
                    m.mode(),
                    m.uid(),
                    m.gid(),
                    m.size(),
                    m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
                ),
                Err(_) => (0, 0, 0, 0, 0, 0, 0),
            };
        let pre = shit_proto::ShimPreImage {
            path: resolved.clone(),
            dev,
            inode,
            mode,
            uid,
            gid,
            size,
            mtime_unix_nanos: mtime_nanos,
            // Empty file bytes — xattr ops don't change file content.
            bytes: Vec::new(),
            xattr: Some(xattr_pre),
            // M03.x.SETATTR — xattr-mutation notifications don't
            // probe st_flags (the syscall doesn't change them).
            // Default to 0; the chflags-side path populates flags
            // when relevant.
            flags: 0,
        };
        let _ = try_notify(syscall, &resolved, Some(pre), Vec::new(), None);
        IN_NOTIFY.with(|f| f.set(false));
    }

    // macOS create-only wrappers use `notify_create_resolved` so they can
    // preserve the dirfd-resolved path and its structured AU10 failure.
    // Linux/BSD still call this canonicalizing form.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn notify_create(syscall: &'static str, path: &str) {
        if should_skip_path(path) {
            return;
        }
        // AU10 — canonicalize_or_raw returns the raw user-passed
        // path on Err so the syscall keeps flowing; the failure is
        // surfaced over the wire so the daemon can journal the
        // capture incompleteness instead of silently mis-attributing
        // the future unlink-inverse to a relative path.
        let (abs, failure) = canonicalize_or_raw(path, "path");
        if should_skip_path(&abs) {
            return;
        }
        notify_inner_with_failure(syscall, &abs, None, failure, false);
    }

    /// macOS create-only interposers resolve the canonical parent + lexical
    /// basename before calling libc, then notify only after libc succeeds.
    /// Trust that already-absolute destination here: canonicalizing the final
    /// name post-syscall could follow a replacement raced in by another thread
    /// and journal an inverse for the wrong path.
    /// The Linux `mkdir`/`mkdirat` interposers (L5) use it the same way.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn notify_create_resolved(
        syscall: &'static str,
        path: &str,
        failure: Option<shit_proto::ShimFailure>,
    ) {
        if should_skip_path(path) {
            return;
        }
        notify_inner_with_failure(syscall, path, None, failure, false);
    }

    /// L5 — an `rmdir(2)` resolved and stat'ed before the call.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub struct PendingRemoval {
        syscall: &'static str,
        path: String,
        failure: Option<shit_proto::ShimFailure>,
        stat: Option<shit_proto::ShimStat>,
    }

    /// L5 — before `rmdir(2)`: resolve the path (the directory still
    /// exists) and keep its lstat for the notification.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn removal_begin(syscall: &'static str, path: &str) -> Option<PendingRemoval> {
        use std::os::unix::fs::MetadataExt;
        if disabled() || should_skip_path(path) {
            return None;
        }
        let (abs, failure) = canonicalize_or_raw(path, "path");
        if should_skip_path(&abs) {
            return None;
        }
        let stat = std::fs::symlink_metadata(&abs)
            .ok()
            .map(|m| shit_proto::ShimStat {
                dev: m.dev(),
                inode: m.ino(),
                mode: m.mode(),
            });
        Some(PendingRemoval {
            syscall,
            path: abs,
            failure,
            stat,
        })
    }

    /// L5 (review item 3) — after `rmdir(2)`: notify only when it
    /// removed the directory. A refused rmdir (ENOTEMPTY from
    /// `--ignore-fail-on-non-empty` or `os.removedirs`) removed nothing.
    /// Leaves errno as the call set it.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn removal_end(pending: Option<PendingRemoval>, rc: libc::c_int) {
        let Some(p) = pending else {
            return;
        };
        if rc != 0 || IN_NOTIFY.with(|f| f.replace(true)) {
            return;
        }
        let saved = std::io::Error::last_os_error();
        let _ = try_notify_full(
            p.syscall,
            &p.path,
            None,
            Vec::new(),
            p.failure,
            Extra {
                pre_stat: p.stat,
                ..Extra::default()
            },
        );
        IN_NOTIFY.with(|f| f.set(false));
        if let Some(e) = saved.raw_os_error() {
            // SAFETY: errno is a valid thread-local lvalue.
            unsafe { set_errno(e) };
        }
    }

    /// L5 — the target of a write-capable open, before resolution.
    pub enum OpenTarget<'a> {
        /// `open`, `open64`, `creat*`, `truncate`: a path as given.
        Path(&'a str),
        /// `openat`, `openat64`: a name relative to a dirfd.
        #[cfg(any(
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
            target_os = "linux",
        ))]
        At(libc::c_int, &'a str),
    }

    /// L5 — an open that may create its target, to settle after the call.
    pub struct PendingCreate {
        path: String,
        /// Set when the shim could not show the path was absent before
        /// the call: then a successful open is a capture gap, not a
        /// Create.
        gap: Option<shit_proto::ShimFailure>,
    }

    /// True for opens that can change a file's bytes or create it.
    /// `O_TMPFILE` creates no name (a later `linkat` is its own event).
    pub fn is_write_open(flags: libc::c_int) -> bool {
        #[cfg(target_os = "linux")]
        if flags & libc::O_TMPFILE == libc::O_TMPFILE {
            return false;
        }
        flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC) != 0
    }

    fn uncaptured(path: &str, reason: &str) -> shit_proto::ShimFailure {
        shit_proto::ShimFailure::PreImageUncaptured {
            path: path.to_string(),
            reason: reason.to_string(),
        }
    }

    fn resolve_open_target(
        target: OpenTarget<'_>,
    ) -> Option<(String, Option<shit_proto::ShimFailure>)> {
        match target {
            OpenTarget::Path(p) => Some(canonicalize_or_raw(p, "path")),
            #[cfg(any(
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "dragonfly",
                target_os = "linux",
            ))]
            OpenTarget::At(dirfd, p) => match resolve_at_for_notify(dirfd, p, "path") {
                AtResolution::Resolved(abs) => Some((abs, None)),
                AtResolution::Failed(raw, f) => Some((raw, Some(f))),
                AtResolution::Nothing => None,
            },
        }
    }

    /// L5 — the one policy for write-capable opens (`open`, `openat`,
    /// `open64`, `openat64`, the fortify entries, `creat*`, macOS `open`
    /// and `openat`), run before the call.
    ///
    /// An existing regular file is captured and sent with its bytes. One
    /// the shim cannot capture (over the inline cap, unreadable) is sent
    /// with a capture-gap marker and no bytes, so undo refuses it instead
    /// of unlinking the user's file. A path that is absent before an
    /// `O_CREAT` open comes back as a [`PendingCreate`]: the Create is
    /// journaled by [`write_open_end`] only if the call succeeded.
    pub fn write_open_begin(
        syscall: &'static str,
        target: OpenTarget<'_>,
        flags: libc::c_int,
    ) -> Option<PendingCreate> {
        if disabled() || !is_write_open(flags) || IN_NOTIFY.with(|f| f.get()) {
            return None;
        }
        let (abs, failure) = resolve_open_target(target)?;
        if should_skip_path(&abs) {
            return None;
        }
        let creates = flags & libc::O_CREAT != 0;
        match (std::fs::symlink_metadata(&abs), std::fs::metadata(&abs)) {
            // Exists (or is a symlink to something that does).
            (Ok(_), Ok(m)) => {
                if !m.is_file() {
                    // Fifos, sockets, devices outside /dev: no bytes to
                    // restore and nothing created.
                    return None;
                }
                notify_existing_file(syscall, &abs, &m, failure);
                None
            }
            (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => {
                creates.then_some(PendingCreate {
                    path: abs,
                    gap: failure,
                })
            }
            // A dangling symlink (the open would create its target
            // elsewhere) or a stat that failed: the prior state is not
            // known, so a success is a gap.
            _ => creates.then(|| PendingCreate {
                gap: Some(failure.unwrap_or_else(|| uncaptured(&abs, "prior state unknown"))),
                path: abs,
            }),
        }
    }

    /// L5 — after a write-capable open: a Create for a target that was
    /// absent before and now exists because the call succeeded. Leaves
    /// errno as the call set it.
    pub fn write_open_end(pending: Option<PendingCreate>, rc: libc::c_int) {
        let Some(p) = pending else {
            return;
        };
        if rc < 0 {
            return;
        }
        let saved = std::io::Error::last_os_error();
        match p.gap {
            None => notify_inner_with_failure("open_create", &p.path, None, None, false),
            Some(f) => notify_inner_with_failure("open", &p.path, None, Some(f), false),
        }
        if let Some(e) = saved.raw_os_error() {
            // SAFETY: errno is a valid thread-local lvalue.
            unsafe { set_errno(e) };
        }
    }

    /// L5 — `truncate(2)` on a path: capture the existing file, or send
    /// the gap marker. Nothing is created.
    #[cfg(not(target_os = "macos"))]
    pub fn notify_existing_content(syscall: &'static str, path: &str) {
        if disabled() || IN_NOTIFY.with(|f| f.get()) {
            return;
        }
        let (abs, failure) = canonicalize_or_raw(path, "path");
        if should_skip_path(&abs) {
            return;
        }
        if let Ok(m) = std::fs::metadata(&abs)
            && m.is_file()
        {
            notify_existing_file(syscall, &abs, &m, failure);
        }
    }

    fn notify_existing_file(
        syscall: &'static str,
        abs: &str,
        meta: &std::fs::Metadata,
        failure: Option<shit_proto::ShimFailure>,
    ) {
        if failure.is_some() {
            notify_inner_with_failure(syscall, abs, None, failure, false);
            return;
        }
        if IN_NOTIFY.with(|f| f.replace(true)) {
            return;
        }
        match capture_pre_image_resolved(abs, true) {
            Some(pre) => {
                let arg = pre.path.clone();
                let _ = try_notify(syscall, &arg, Some(pre), Vec::new(), None);
            }
            None => {
                let reason = if meta.len() > shit_proto::SHIM_INLINE_PREIMAGE_CAP {
                    "over the shim's inline pre-image cap"
                } else {
                    "could not be read"
                };
                let _ = try_notify(
                    syscall,
                    abs,
                    None,
                    Vec::new(),
                    Some(uncaptured(abs, reason)),
                );
            }
        }
        IN_NOTIFY.with(|f| f.set(false));
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

    /// Resolve a directory fd to its path with `fcntl(F_KINFO)`.
    #[cfg(target_os = "freebsd")]
    pub(super) fn dirfd_path(dirfd: libc::c_int) -> Option<String> {
        // SAFETY: kinfo_file is plain data; F_KINFO fills it for `dirfd`.
        let mut kif: libc::kinfo_file = unsafe { std::mem::zeroed() };
        kif.kf_structsize = std::mem::size_of::<libc::kinfo_file>() as libc::c_int;
        let rc = unsafe { libc::fcntl(dirfd, libc::F_KINFO, &mut kif as *mut libc::kinfo_file) };
        if rc != 0 {
            return None;
        }
        let bytes: Vec<u8> = kif
            .kf_path
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        let path = String::from_utf8(bytes).ok()?;
        path.starts_with('/').then_some(path)
    }

    /// DR-CR-54.B — join an `*at` syscall's `(dirfd, path)` pair into
    /// the path the kernel will act on, without canonicalizing.
    ///
    /// Absolute paths and `AT_FDCWD` are returned as given (both are
    /// already relative to the right base: nothing or the cwd). For a
    /// real dirfd on Linux, `/proc/self/fd/<dirfd>` names the
    /// directory and on FreeBSD `fcntl(F_KINFO)` does; the result is
    /// `dir/path`. Anywhere else (NetBSD, OpenBSD, DragonFly) the raw path is returned unchanged: a
    /// relative key that cannot be matched fails closed, where
    /// canonicalizing it against the cwd would invent a wrong
    /// absolute key.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    ))]
    pub fn join_at_path(dirfd: libc::c_int, path: &str) -> String {
        if path.starts_with('/') || dirfd == libc::AT_FDCWD {
            return path.to_string();
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(dir) = std::fs::read_link(format!("/proc/self/fd/{dirfd}"))
                && let Some(s) = dir.join(path).to_str()
            {
                return s.to_string();
            }
        }
        #[cfg(target_os = "freebsd")]
        {
            return join_with_dir(dirfd_path(dirfd), path);
        }
        #[allow(unreachable_code)]
        path.to_string()
    }

    /// Join a resolved directory path with `path`; an unresolved
    /// directory leaves `path` raw (the caller then fails closed).
    #[cfg(target_os = "freebsd")]
    pub(super) fn join_with_dir(dir: Option<String>, path: &str) -> String {
        match dir {
            Some(d) => std::path::Path::new(&d)
                .join(path)
                .to_str()
                .map_or_else(|| path.to_string(), str::to_string),
            None => path.to_string(),
        }
    }

    /// AU10 — structured failure from [`canonical_path`]. Each
    /// variant maps to a previously-silent fallback in the pre-AU10
    /// implementation. Surfacing them as typed errors lets the
    /// shim's notify path attribute the capture incompleteness
    /// over the wire instead of returning the raw user-passed
    /// string and praying the daemon's path matcher gets lucky.
    #[derive(Debug, thiserror::Error)]
    pub(super) enum CanonicalizeError {
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

        // Direct canonicalize. When this succeeds the path exists
        // on disk and we get the symlink-resolved absolute form.
        let direct_err = match std::fs::canonicalize(path) {
            Ok(p) => {
                return Ok(p.to_string_lossy().into_owned());
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
            Ok(parent_abs) => Ok(parent_abs.join(name).to_string_lossy().into_owned()),
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

    fn notify_inner(syscall: &'static str, arg: &str, capture_path: Option<&str>) {
        notify_inner_with_failure(syscall, arg, capture_path, None, false);
    }

    /// AU10 — variant of `notify_inner` that lets the caller attach
    /// a structured `ShimFailure` to the outbound notification. The
    /// pre-AU10 [`notify_inner`] is preserved as a thin wrapper so
    /// the dozen-plus syscall-interposer callsites that have no
    /// failure to report stay untouched.
    fn notify_inner_with_failure(
        syscall: &'static str,
        arg: &str,
        capture_path: Option<&str>,
        failure: Option<shit_proto::ShimFailure>,
        path_resolved: bool,
    ) {
        if disabled() {
            return;
        }
        if IN_NOTIFY.with(|f| f.replace(true)) {
            // Re-entrant call (we're already inside notify on this
            // thread — almost always the pre-image read's `open(2)`
            // hitting our own interposer). Skip both the notification
            // AND the pre-image capture; the outer notification covers
            // the user-visible mutation.
            return;
        }
        let pre_image = capture_path.and_then(|c| capture_pre_image_resolved(c, path_resolved));
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
            _ => arg.to_string(),
        };
        let _ = try_notify(syscall, &wire_arg, pre_image, Vec::new(), failure);
        IN_NOTIFY.with(|f| f.set(false));
    }

    /// Read `path` into a [`ShimPreImage`] payload, capped at
    /// [`shit_proto::SHIM_INLINE_PREIMAGE_CAP`]. Returns `None` if the
    /// path doesn't exist (e.g. `open(O_CREAT|O_EXCL)` against a new
    /// file), is not a regular file (device nodes, fifos), exceeds
    /// the inline cap, or the read fails.
    fn capture_pre_image(path: &str) -> Option<shit_proto::ShimPreImage> {
        capture_pre_image_resolved(path, false)
    }

    /// [`capture_pre_image`]; `path_resolved` skips the second
    /// canonicalize when the caller already produced a canonical key.
    fn capture_pre_image_resolved(
        path: &str,
        path_resolved: bool,
    ) -> Option<shit_proto::ShimPreImage> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let size = meta.size();
        if size > shit_proto::SHIM_INLINE_PREIMAGE_CAP {
            return None;
        }
        let bytes = std::fs::read(path).ok()?;
        // Resolve to an absolute path so the daemon sees the same
        // identity regardless of the caller's cwd. `canonicalize`
        // follows symlinks; we'd rather emit the path the user saw,
        // so fall back to the original string on failure.
        let resolved = if path_resolved {
            path.to_string()
        } else {
            std::fs::canonicalize(path)
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
                .unwrap_or_else(|| path.to_string())
        };
        // M03.x.SETATTR — read BSD/macOS st_flags via raw libc::lstat.
        // std::fs::Metadata doesn't expose st_flags cross-platform;
        // 0 on Linux (no chflags). Best-effort: on stat failure use 0
        // (caller's RestoreMetadata diff then has a known floor).
        let flags = read_st_flags(path, false).unwrap_or(0);
        Some(shit_proto::ShimPreImage {
            path: resolved,
            dev: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            size,
            mtime_unix_nanos: meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128,
            bytes,
            // M07.B.4.1 — content-only pre-image captures don't
            // populate the xattr field; xattr-mutating syscalls
            // build their own ShimPreImage with this set.
            xattr: None,
            flags,
        })
    }

    /// Capture only the stat identity and `st_flags` required to undo a
    /// chflags-family syscall. A failed flags probe returns `None` rather
    /// than fabricating zero as an authoritative pre-state.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    ///
    /// `follow` selects stat (chflags(2), chflagsat(..., 0), which follow
    /// symlinks) versus lstat (AT_SYMLINK_NOFOLLOW, lchflags).
    pub(super) fn capture_flags_pre_image(
        path: &str,
        follow: bool,
    ) -> Option<shit_proto::ShimPreImage> {
        use std::os::unix::fs::MetadataExt;
        let meta = if follow {
            std::fs::metadata(path).ok()?
        } else {
            std::fs::symlink_metadata(path).ok()?
        };
        let flags = read_st_flags(path, follow)?;
        Some(shit_proto::ShimPreImage {
            path: path.to_string(),
            dev: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            size: meta.size(),
            mtime_unix_nanos: meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128,
            bytes: Vec::new(),
            xattr: None,
            flags,
        })
    }

    /// M03.x.SETATTR — read `st_flags` for the path. BSD/macOS only;
    /// other targets have no chflags concept. libc exposes the field
    /// as u32 on both Apple and FreeBSD.
    #[cfg(target_os = "macos")]
    fn read_st_flags(path: &str, follow: bool) -> Option<u32> {
        use std::ffi::CString;
        let Ok(c) = CString::new(path) else {
            return None;
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: c is a valid NUL-terminated CString; st is owned.
        let rc = unsafe {
            if follow {
                libc::stat(c.as_ptr(), &mut st)
            } else {
                libc::lstat(c.as_ptr(), &mut st)
            }
        };
        if rc != 0 {
            return None;
        }
        Some(st.st_flags)
    }
    #[cfg(target_os = "freebsd")]
    fn read_st_flags(path: &str, follow: bool) -> Option<u32> {
        use std::ffi::CString;
        let Ok(c) = CString::new(path) else {
            return None;
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: c is a valid NUL-terminated CString; st is owned.
        let rc = unsafe {
            if follow {
                libc::stat(c.as_ptr(), &mut st)
            } else {
                libc::lstat(c.as_ptr(), &mut st)
            }
        };
        if rc != 0 {
            return None;
        }
        Some(st.st_flags)
    }
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    fn read_st_flags(_path: &str, _follow: bool) -> Option<u32> {
        None
    }

    fn try_notify(
        syscall: &'static str,
        arg: &str,
        pre_image: Option<shit_proto::ShimPreImage>,
        extra_pre_images: Vec<shit_proto::ShimPreImage>,
        failure: Option<shit_proto::ShimFailure>,
    ) -> std::io::Result<()> {
        try_notify_full(
            syscall,
            arg,
            pre_image,
            extra_pre_images,
            failure,
            Extra::default(),
        )
    }

    /// The L5 fields of a notification.
    #[derive(Default)]
    struct Extra {
        walk: Option<shit_proto::ShimWalk>,
        outcome: Option<shit_proto::ShimRenameOutcome>,
        pre_stat: Option<shit_proto::ShimStat>,
        call_id: u64,
        /// The outcome is not waited on: nothing acts on its ack.
        no_ack: bool,
    }

    /// [`try_notify`] with the L5 rename fields.
    fn try_notify_full(
        syscall: &'static str,
        arg: &str,
        pre_image: Option<shit_proto::ShimPreImage>,
        extra_pre_images: Vec<shit_proto::ShimPreImage>,
        failure: Option<shit_proto::ShimFailure>,
        extra: Extra,
    ) -> std::io::Result<()> {
        let Extra {
            walk,
            outcome,
            pre_stat,
            call_id,
            no_ack,
        } = extra;
        use shit_proto::{
            ShimAck, ShimNotification, decode_frame, encode_frame, encode_frame_large,
        };
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, SystemTime};

        #[cfg(test)]
        if test_capture::active() {
            let note = ShimNotification {
                pid: 0,
                syscall: syscall.to_string(),
                arg: arg.to_string(),
                ts_unix_nanos: 0,
                pre_image,
                extra_pre_images,
                failure,
                walk,
                outcome,
                pre_stat,
                call_id,
            };
            if let Some(limit) = test_capture::frame_limit()
                && encode_frame_large(&note).map_or(true, |f| f.len() > limit)
            {
                return Err(std::io::Error::other("frame over the test limit"));
            }
            test_capture::push(note);
            return Ok(());
        }
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
        let write_timeout = if pre_image.is_some() || !extra_pre_images.is_empty() || walk.is_some()
        {
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
        let has_extras = !extra_pre_images.is_empty() || walk.is_some();
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
            walk,
            outcome,
            pre_stat,
            call_id,
        };
        // Pre-image notifications can carry up to ~256 KiB of bytes;
        // small notifications fit MAX_FRAME_SIZE comfortably. Use the
        // large-frame encoder uniformly — the cap is the only
        // difference, and the daemon's reader matches.
        // DR-CR-54: a recursive batch can blow well past the small-
        // frame cap even with `pre_image=None`; pick large-frame
        // whenever extras are present too.
        let frame = if has_pre || has_extras {
            encode_frame_large(&note).map_err(|e| std::io::Error::other(format!("encode: {e}")))?
        } else {
            encode_frame(&note).map_err(|e| std::io::Error::other(format!("encode: {e}")))?
        };
        stream.write_all(&frame)?;

        // Best-effort ack read. We don't actually act on the ack today
        // (Allow-always), but draining it lets the listener's per-conn
        // task observe a clean close. Errors here are non-fatal.
        // L5 (review item 9): a rename outcome is sent after the syscall
        // and nothing waits on it, so do not hold the caller up for it.
        if no_ack {
            return Ok(());
        }
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap_or(0);
        if n > 0 {
            let _: Result<ShimAck, _> = decode_frame(&buf[..n]);
        }
        Ok(())
    }

    /// Unit-test hook: while a capture is active on this thread,
    /// `try_notify` records the notification instead of sending it.
    #[cfg(test)]
    pub mod test_capture {
        use std::cell::RefCell;
        thread_local! {
            static NOTES: RefCell<Option<Vec<shit_proto::ShimNotification>>> =
                const { RefCell::new(None) };
            static LIMIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
        }
        /// Frames larger than this fail to send, as an oversized frame
        /// would.
        pub fn frame_limit() -> Option<usize> {
            LIMIT.with(|l| l.get())
        }
        #[cfg_attr(target_os = "macos", allow(dead_code))]
        pub fn set_frame_limit(limit: Option<usize>) {
            LIMIT.with(|l| l.set(limit));
        }
        pub fn active() -> bool {
            NOTES.with(|n| n.borrow().is_some())
        }
        pub fn push(note: shit_proto::ShimNotification) {
            NOTES.with(|n| {
                if let Some(v) = n.borrow_mut().as_mut() {
                    v.push(note);
                }
            });
        }
        /// Run `f` with capture on and return what it would have sent.
        pub fn capture(f: impl FnOnce()) -> Vec<shit_proto::ShimNotification> {
            NOTES.with(|n| *n.borrow_mut() = Some(Vec::new()));
            f();
            NOTES.with(|n| n.borrow_mut().take().unwrap_or_default())
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
    use libc::{c_char, c_int, c_uint, c_void, mode_t, off_t, size_t, ssize_t};

    pub(crate) fn cstr_to_string(path: *const c_char) -> String {
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
        policy::notify_pre_mutation_with_content("unlink", &cstr_to_string(path));
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
        // W06.A.4: open(..., O_TRUNC|O_WRONLY|O_RDWR) on an existing
        // file is the canonical content-overwrite shape (e.g.
        // `install -m … src dst` where dst already exists). L5: one
        // policy for every write-capable open; see
        // `policy::write_open_begin`.
        let pending = policy::write_open_begin(
            "open",
            policy::OpenTarget::Path(&cstr_to_string(path)),
            flags,
        );
        let real = next::real_open();
        let rc = if next::is_zero(next::as_usize(real)) {
            unsafe { libc::open(path, flags, mode as c_uint) }
        } else {
            unsafe { real(path, flags, mode) }
        };
        policy::write_open_end(pending, rc);
        rc
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
        // DR-CR-54.B — a bare relative "x" under `unlinkat(dirfd, "x")`
        // cannot be matched against absolute-pathed FilePreImage
        // events. The `_at` notifier joins dirfd + path, canonicalizes
        // once, fails closed on an unjoinable dirfd, and attaches the
        // AU10 marker. W09.5: pre-image bytes are captured before the
        // unlink so unlink-then-open(O_CREAT) tools can be undone.
        policy::notify_pre_mutation_with_content_at("unlinkat", dirfd, &path_str);
        let real = next::real_unlinkat();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::unlinkat(dirfd, path, flag) };
        }
        unsafe { real(dirfd, path, flag) }
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
        // W06.A.4 / DR-CR-54.B / L5: same policy as `open`, with the
        // dirfd resolved to an absolute key up front.
        let pending = policy::write_open_begin(
            "openat",
            policy::OpenTarget::At(dirfd, &cstr_to_string(path)),
            flags,
        );
        let real = next::real_openat();
        let rc = if next::is_zero(next::as_usize(real)) {
            unsafe { libc::openat(dirfd, path, flags, mode as c_uint) }
        } else {
            unsafe { real(dirfd, path, flags, mode) }
        };
        policy::write_open_end(pending, rc);
        rc
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
        let pending = policy::notify_rename_with_dst_preimage(
            "rename",
            &cstr_to_string(from),
            &cstr_to_string(to),
        );
        let real = next::real_rename();
        let rc = if next::is_zero(next::as_usize(real)) {
            unsafe { libc::rename(from, to) }
        } else {
            unsafe { real(from, to) }
        };
        // L5: report a directory rename's result and any failure.
        policy::finish_rename(pending, rc);
        rc
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
        // DR-CR-54.B: resolve the *at-style (fd, path) pairs to
        // absolute paths up-front. Without this, daemon-side path
        // equality against shim-recursive-walk FilePreImages fails
        // and the classifier can't reach atomic-replace.
        let from_str = cstr_to_string(from);
        let to_str = cstr_to_string(to);
        let pending = policy::notify_rename_at("renameat", fromfd, &from_str, tofd, &to_str);
        let real = next::real_renameat();
        let rc = if next::is_zero(next::as_usize(real)) {
            unsafe { libc::renameat(fromfd, from, tofd, to) }
        } else {
            unsafe { real(fromfd, from, tofd, to) }
        };
        policy::finish_rename(pending, rc);
        rc
    }

    /// DR-CR-54 — `renameat2(2)` interposer. Linux-only. The
    /// extra `flags` arg (RENAME_NOREPLACE / RENAME_EXCHANGE /
    /// RENAME_WHITEOUT) shapes the kernel-level semantics but
    /// doesn't change what we journal: the destination is still
    /// the address that gets clobbered, and the source is still
    /// what we want to recursively pre-image when it's a
    /// directory. Pass `flags` through to libc verbatim.
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
        // DR-CR-54.B: same dirfd→absolute resolution as renameat.
        let from_str = cstr_to_string(from);
        let to_str = cstr_to_string(to);
        let pending = policy::notify_rename_at("renameat2", fromfd, &from_str, tofd, &to_str);
        let real = next::real_renameat2();
        let rc = if next::is_zero(next::as_usize(real)) {
            // glibc < 2.28 had no `renameat2` wrapper; fall back
            // through raw syscall. This branch is unreachable on
            // any glibc shipped within the project's MSRV-era
            // distros, but defensive.
            unsafe {
                libc::syscall(libc::SYS_renameat2, fromfd, from, tofd, to, flags as c_uint) as c_int
            }
        } else {
            unsafe { real(fromfd, from, tofd, to, flags) }
        };
        policy::finish_rename(pending, rc);
        rc
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
        policy::notify_create("mkfifo", &cstr_to_string(path));
        let real = next::real_mkfifo();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::mkfifo(path, mode) };
        }
        unsafe { real(path, mode) }
    }

    /// W09.10.1 — `mkfifoat(2)` interposer. Dirfd-relative variant.
    /// Same NOTE_WRITE gap as `mkfifo`.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkfifoat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
        policy::notify_create("mkfifoat", &cstr_to_string(path));
        let real = next::real_mkfifoat();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::mkfifoat(dirfd, path, mode) };
        }
        unsafe { real(dirfd, path, mode) }
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
        policy::notify_create("link", &cstr_to_string(new));
        let real = next::real_link();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::link(old, new) };
        }
        unsafe { real(old, new) }
    }

    /// `linkat(2)` interposer — dirfd-relative variant of `link(2)`.
    /// The `flags` argument carries AT_SYMLINK_FOLLOW (FreeBSD,
    /// macOS); we don't inspect it because the journal/undo flow
    /// is identical regardless of symlink-following semantics on
    /// the source: the destination is still a new directory entry
    /// whose inverse is `unlink(new)`.
    ///
    /// `newpath` may be relative to `newdirfd`. We pass it through
    /// to `notify_create`, which canonicalizes via `realpath(3)`;
    /// `realpath` fails on a not-yet-existing path so it falls
    /// back to the raw string. For the common `newdirfd=AT_FDCWD`
    /// case this yields a CWD-relative path that the daemon resolves
    /// the same way; for the rare per-dirfd case the daemon's
    /// `inode_of` falls through to the sentinel and the executor's
    /// `unlink` reverse handles the missing-inode case fine.
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
        policy::notify_create("linkat", &cstr_to_string(newpath));
        let real = next::real_linkat();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::linkat(olddirfd, oldpath, newdirfd, newpath, flags) };
        }
        unsafe { real(olddirfd, oldpath, newdirfd, newpath, flags) }
    }

    // B10 — FreeBSD `extattr_*` xattr-mutation interposers. Mirrors
    // macOS PR #174 (M03.x.XATTR-MUTATE). FreeBSD's xattr API
    // diverges from Linux/macOS: namespace is a separate `int`
    // argument (1=USER, 2=SYSTEM), name has no platform-style
    // prefix. We normalize on the wire by pre-encoding the
    // namespace into the name ("user.foo" / "system.foo") so the
    // daemon's existing setxattr/removexattr handlers (PR #174)
    // route them without a per-platform branch.

    /// Pre-encode FreeBSD's separate namespace argument into a
    /// macOS-style namespace.name string.
    #[cfg(target_os = "freebsd")]
    fn extattr_ns_name(ns: c_int, name: *const c_char) -> String {
        let prefix = match ns {
            1 => "user.",
            2 => "system.",
            _ => "",
        };
        format!("{}{}", prefix, cstr_to_string(name))
    }

    /// Read the pre-mutation xattr value via `extattr_get_file(2)`.
    /// Returns `None` when the xattr doesn't exist (ENOATTR) or
    /// the read fails — the daemon overlay treats `None` as
    /// "absent pre-syscall", so set→delete and delete→noop undo
    /// paths come out right.
    #[cfg(target_os = "freebsd")]
    unsafe fn read_extattr_value(
        path: *const c_char,
        ns: c_int,
        name: *const c_char,
    ) -> Option<Vec<u8>> {
        if path.is_null() || name.is_null() {
            return None;
        }
        let real_get = next::real_extattr_get_file();
        if next::is_zero(next::as_usize(real_get)) {
            return None;
        }
        let sz = unsafe { real_get(path, ns, name, std::ptr::null_mut(), 0) };
        if sz < 0 {
            return None;
        }
        if sz == 0 {
            return Some(Vec::new());
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
            return None;
        }
        buf.truncate(got as usize);
        Some(buf)
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
        let pre_value = unsafe { read_extattr_value(path, attrnamespace, attrname) };
        let xattr_pre = shit_proto::XattrPreImage {
            name: extattr_ns_name(attrnamespace, attrname),
            value: pre_value,
        };
        policy::notify_xattr_mutation("setxattr", &cstr_to_string(path), xattr_pre);
        let real = next::real_extattr_set_file();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::extattr_set_file(path, attrnamespace, attrname, data, nbytes) };
        }
        unsafe { real(path, attrnamespace, attrname, data, nbytes) }
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
        let pre_value = unsafe { read_extattr_value(path, attrnamespace, attrname) };
        let xattr_pre = shit_proto::XattrPreImage {
            name: extattr_ns_name(attrnamespace, attrname),
            value: pre_value,
        };
        policy::notify_xattr_mutation("removexattr", &cstr_to_string(path), xattr_pre);
        let real = next::real_extattr_delete_file();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::extattr_delete_file(path, attrnamespace, attrname) };
        }
        unsafe { real(path, attrnamespace, attrname) }
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
        policy::notify_flags_mutation("chflags", &cstr_to_string(path), true);
        let real = next::real_chflags();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::chflags(path, flags) };
        }
        unsafe { real(path, flags) }
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
        if let Some((target, follow)) = chflagsat_target(dirfd, &path_string, atflag) {
            // Keep the wire name aligned with chflags so the daemon routes
            // both replayable entry points through the same source tag.
            policy::notify_flags_mutation("chflags", &target, follow);
        }
        let real = next::real_chflagsat();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::chflagsat(dirfd, path, flags, atflag) };
        }
        unsafe { real(dirfd, path, flags, atflag) }
    }

    /// Decide whether a `chflagsat` call is replayable as a path-based
    /// RestoreFlags and, if so, return the path to snapshot plus whether
    /// the syscall follows a final symlink.
    ///
    /// - Absolute path: dirfd is ignored.
    /// - `AT_FDCWD` with a relative path: the daemon-side canonicalizer
    ///   resolves against the process cwd.
    /// - Real dirfd with a relative path (what `/bin/chflags` issues via
    ///   fts): join onto the dirfd's path.
    /// - `AT_SYMLINK_NOFOLLOW`: replayable only when the target is not a
    ///   symlink (then follow and no-follow agree).
    #[cfg(target_os = "freebsd")]
    pub(super) fn chflagsat_target(
        dirfd: c_int,
        path: &str,
        atflag: c_int,
    ) -> Option<(String, bool)> {
        chflagsat_target_with(dirfd, path, atflag, policy::dirfd_path)
    }

    #[cfg(target_os = "freebsd")]
    pub(super) fn chflagsat_target_with(
        dirfd: c_int,
        path: &str,
        atflag: c_int,
        resolve_dirfd: impl FnOnce(c_int) -> Option<String>,
    ) -> Option<(String, bool)> {
        let nofollow = match atflag {
            0 => false,
            f if f == libc::AT_SYMLINK_NOFOLLOW => true,
            _ => return None,
        };
        let full = if std::path::Path::new(path).is_absolute() || dirfd == libc::AT_FDCWD {
            path.to_string()
        } else {
            let base = resolve_dirfd(dirfd)?;
            std::path::Path::new(&base)
                .join(path)
                .to_string_lossy()
                .into_owned()
        };
        if nofollow {
            let is_symlink = std::fs::symlink_metadata(&full)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true);
            if is_symlink {
                return None;
            }
        }
        Some((full, !nofollow))
    }

    /// `truncate(2)` interposer.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn truncate(path: *const c_char, len: off_t) -> c_int {
        // W06.A.4: truncate(path, 0) before re-writing is a common
        // overwrite shape; capture pre-image to enable undo.
        // L5: an uncapturable file gets the gap marker, never a Create.
        policy::notify_existing_content("truncate", &cstr_to_string(path));
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

/// AU10 — `canonical_path` + `canonicalize_or_raw` unit tests.
/// Gated to the same unix targets as `mod policy` itself since
/// canonical_path lives inside policy and only runs from
/// interposers on unix; running these tests on Windows or macOS
/// would not exercise any production code path the interposer
/// uses.
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
mod canonical_tests {
    /// `AT_FDCWD` and absolute paths join to themselves; canonicalizing
    /// the join absolutizes a relative path.
    #[test]
    fn join_at_path_passthrough_and_relative_canonicalize() {
        assert_eq!(
            super::policy::join_at_path(libc::AT_FDCWD, "Cargo.toml"),
            "Cargo.toml"
        );
        assert_eq!(super::policy::join_at_path(99, "/abs/x"), "/abs/x");
        let (r, f) = super::policy::canonicalize_or_raw("Cargo.toml", "path");
        assert!(
            r.starts_with('/') && r.ends_with("/Cargo.toml"),
            "got {r:?}"
        );
        assert!(f.is_none());
    }

    /// A real dirfd joins against /proc/self/fd; an unresolvable
    /// directory yields a canonicalize failure that names the joined
    /// path, which is what the `*at` notifiers journal as the AU10
    /// marker.
    #[cfg(target_os = "linux")]
    #[test]
    fn join_at_path_with_dirfd_feeds_canonicalize_failure_marker() {
        use std::os::fd::AsRawFd;
        let dir = std::fs::File::open("/proc/self").expect("open dir");
        let joined = super::policy::join_at_path(dir.as_raw_fd(), "no-such-dir-au10/leaf");
        assert!(joined.starts_with('/'), "got {joined:?}");
        let (got, failure) = super::policy::canonicalize_or_raw(&joined, "path");
        assert_eq!(got, joined);
        match failure.expect("canonicalize must fail under a missing dir") {
            shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg,
                attempted_path,
                ..
            } => {
                assert_eq!(which_arg, "path");
                assert_eq!(attempted_path, joined);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Unjoinable relative path under a real dirfd fails closed: raw
    /// path, marker, never a cwd-based absolute key.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_at_unjoinable_dirfd_fails_closed() {
        match super::policy::resolve_at_for_notify(9_999_999, "leaf", "path") {
            super::policy::AtResolution::Failed(raw, _) => assert_eq!(raw, "leaf"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Missing parent: syscall cannot mutate, send nothing. Missing
    /// leaf under an existing parent: resolves (create/overwrite case).
    #[test]
    fn resolve_at_missing_parent_sends_nothing_missing_leaf_resolves() {
        use super::policy::{AtResolution, resolve_at_for_notify};
        let r = resolve_at_for_notify(libc::AT_FDCWD, "/no-such-dir-au10-xyz/stale/file", "path");
        assert!(matches!(r, AtResolution::Nothing), "got {r:?}");
        let r = resolve_at_for_notify(libc::AT_FDCWD, "/tmp/au10-new-leaf-xyz", "path");
        match r {
            AtResolution::Resolved(p) => assert!(p.ends_with("/au10-new-leaf-xyz")),
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    /// FreeBSD: a resolvable dirfd joins to dir/path; an unresolved
    /// one leaves the raw path (fail closed). The F_KINFO call itself
    /// runs in the FreeBSD VM smokes.
    #[cfg(target_os = "freebsd")]
    #[test]
    fn freebsd_join_with_dir_joins_or_stays_raw() {
        assert_eq!(
            super::policy::join_with_dir(Some("/a/b".into()), "x"),
            "/a/b/x"
        );
        assert_eq!(super::policy::join_with_dir(None, "x"), "x");
    }

    /// FreeBSD: a real directory fd resolves through F_KINFO.
    #[cfg(target_os = "freebsd")]
    #[test]
    fn freebsd_join_at_path_resolves_real_dirfd() {
        use std::os::fd::AsRawFd;
        let dir = std::fs::File::open("/tmp").expect("open /tmp");
        let joined = super::policy::join_at_path(dir.as_raw_fd(), "leaf");
        assert!(
            joined.starts_with('/') && joined.ends_with("/leaf"),
            "got {joined:?}"
        );
    }

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
            other => panic!("{other:?}"),
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
        let pre = super::policy::capture_flags_pre_image(path, true).expect("flags pre-image");
        assert!(pre.bytes.is_empty());
        assert_ne!(pre.inode, 0);
        assert_eq!(pre.path, path);
    }

    #[test]
    fn flags_pre_image_follows_symlink_unless_nofollow() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_s = link.to_str().unwrap();
        let followed = super::policy::capture_flags_pre_image(link_s, true).unwrap();
        let direct = super::policy::capture_flags_pre_image(link_s, false).unwrap();
        let target_ino = std::fs::metadata(&target).unwrap().ino();
        assert_eq!(followed.inode, target_ino);
        assert_ne!(direct.inode, target_ino);
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod chflagsat_capture_tests {
    use super::interposers::chflagsat_target_with;

    #[test]
    fn capture_gate_resolves_relative_name_against_real_dirfd() {
        let got = chflagsat_target_with(42, "name", 0, |fd| {
            assert_eq!(fd, 42);
            Some("/base/dir".to_string())
        });
        assert_eq!(got, Some(("/base/dir/name".to_string(), true)));
    }

    #[test]
    fn capture_gate_accepts_absolute_and_cwd_shapes() {
        assert_eq!(
            chflagsat_target_with(libc::AT_FDCWD, "relative", 0, |_| None),
            Some(("relative".to_string(), true))
        );
        assert_eq!(
            chflagsat_target_with(42, "/absolute", 0, |_| None),
            Some(("/absolute".to_string(), true))
        );
    }

    #[test]
    fn capture_gate_skips_when_dirfd_unresolvable() {
        assert_eq!(chflagsat_target_with(42, "name", 0, |_| None), None);
    }

    #[test]
    fn nofollow_is_replayable_only_for_non_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let link = tmp.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let f = file.to_str().unwrap();
        let l = link.to_str().unwrap();
        assert_eq!(
            chflagsat_target_with(libc::AT_FDCWD, f, libc::AT_SYMLINK_NOFOLLOW, |_| None),
            Some((f.to_string(), false))
        );
        assert_eq!(
            chflagsat_target_with(libc::AT_FDCWD, l, libc::AT_SYMLINK_NOFOLLOW, |_| None),
            None
        );
    }
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
mod rename_wire_tests;
