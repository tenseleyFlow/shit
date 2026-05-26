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
);

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
        notify_inner(syscall, path, Some(path));
    }

    /// W06.A.4 rename/renameat variant: the wire `arg` is `from\tto`
    /// but the pre-image target is `to` (the destination — rename
    /// atomically overwrites its content). When `to` doesn't exist
    /// (clean-prefix install / mv to new path), `pre_image` ends up
    /// `None` and the planner falls back to ReverseRename. When `to`
    /// pre-exists (install over an existing file), the captured bytes
    /// drive a RestoreContent inverse instead.
    pub fn notify_rename_with_dst_preimage(syscall: &'static str, from: &str, to: &str) {
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
        // basename when canonicalize itself fails. Last resort: the raw
        // string as the user passed it — undo gets the same conflict
        // we'd get without this fix, but at least we tried.
        let from_abs = canonical_path(from);
        let to_abs = canonical_path(to);
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
            return;
        }
        let arg = format!("{from_abs}\t{to_abs}");
        notify_inner(syscall, &arg, Some(to));
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
    pub fn notify_create(syscall: &'static str, path: &str) {
        let abs = canonical_path(path);
        notify_inner(syscall, &abs, None);
    }

    /// Best-effort absolute path resolution. Prefer `canonicalize`
    /// (resolves symlinks + relative components); fall back to a
    /// parent-canonicalize + basename join when the path itself
    /// doesn't yet exist; final fallback is the original string.
    fn canonical_path(path: &str) -> String {
        use std::path::{Path, PathBuf};
        if let Ok(p) = std::fs::canonicalize(path)
            && let Some(s) = p.to_str()
        {
            return s.to_string();
        }
        // Path may not exist (rename destination on a fresh path).
        // Canonicalize the parent and join the basename. Note that
        // `Path::new("gamma.txt").parent()` returns Some("") — an
        // empty path — not `Some(".")`. Treat empty as cwd.
        let p = Path::new(path);
        let Some(name) = p.file_name() else {
            return path.to_string();
        };
        let parent_in = match p.parent() {
            Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
            Some(parent) => parent.to_path_buf(),
            None => return path.to_string(),
        };
        if let Ok(parent_abs) = std::fs::canonicalize(&parent_in) {
            return parent_abs.join(name).to_string_lossy().into_owned();
        }
        path.to_string()
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
        let pre_image = capture_path.and_then(capture_pre_image);
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
        let _ = try_notify(syscall, &wire_arg, pre_image);
        IN_NOTIFY.with(|f| f.set(false));
    }

    /// Read `path` into a [`ShimPreImage`] payload, capped at
    /// [`shit_proto::SHIM_INLINE_PREIMAGE_CAP`]. Returns `None` if the
    /// path doesn't exist (e.g. `open(O_CREAT|O_EXCL)` against a new
    /// file), is not a regular file (device nodes, fifos), exceeds
    /// the inline cap, or the read fails.
    fn capture_pre_image(path: &str) -> Option<shit_proto::ShimPreImage> {
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
        let resolved = std::fs::canonicalize(path)
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_else(|| path.to_string());
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
        })
    }

    fn try_notify(
        syscall: &'static str,
        arg: &str,
        pre_image: Option<shit_proto::ShimPreImage>,
    ) -> std::io::Result<()> {
        use shit_proto::{
            ShimAck, ShimNotification, decode_frame, encode_frame, encode_frame_large,
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
        let write_timeout = if pre_image.is_some() {
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
        let note = ShimNotification {
            pid,
            syscall: syscall.to_string(),
            arg: arg.to_string(),
            ts_unix_nanos: now,
            pre_image,
        };
        // Pre-image notifications can carry up to ~256 KiB of bytes;
        // small notifications fit MAX_FRAME_SIZE comfortably. Use the
        // large-frame encoder uniformly — the cap is the only
        // difference, and the daemon's reader matches.
        let frame = if has_pre {
            encode_frame_large(&note).map_err(|e| std::io::Error::other(format!("encode: {e}")))?
        } else {
            encode_frame(&note).map_err(|e| std::io::Error::other(format!("encode: {e}")))?
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
        let writes = (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0;
        if writes {
            // W06.A.4: open(..., O_TRUNC|O_WRONLY|O_RDWR) on an existing
            // file is the canonical content-overwrite shape (e.g.
            // `install -m … src dst` where dst already exists). Capture
            // the pre-image so undo can restore.
            policy::notify_pre_mutation_with_content("open", &cstr_to_string(path));
        }
        let real = next::real_open();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::open(path, flags, mode as c_uint) };
        }
        unsafe { real(path, flags, mode) }
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
        policy::notify_pre_mutation_with_content("unlinkat", &path_str);
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
        let writes = (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0 || (flags & O_TRUNC) != 0;
        if writes {
            // W06.A.4: same content-overwrite shape as `open` —
            // capture pre-image bytes when the target exists.
            policy::notify_pre_mutation_with_content("openat", &cstr_to_string(path));
        }
        let real = next::real_openat();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::openat(dirfd, path, flags, mode as c_uint) };
        }
        unsafe { real(dirfd, path, flags, mode) }
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
        policy::notify_rename_with_dst_preimage(
            "rename",
            &cstr_to_string(from),
            &cstr_to_string(to),
        );
        let real = next::real_rename();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::rename(from, to) };
        }
        unsafe { real(from, to) }
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
        policy::notify_rename_with_dst_preimage(
            "renameat",
            &cstr_to_string(from),
            &cstr_to_string(to),
        );
        let real = next::real_renameat();
        if next::is_zero(next::as_usize(real)) {
            return unsafe { libc::renameat(fromfd, from, tofd, to) };
        }
        unsafe { real(fromfd, from, tofd, to) }
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

    /// `truncate(2)` interposer.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn truncate(path: *const c_char, len: off_t) -> c_int {
        // W06.A.4: truncate(path, 0) before re-writing is a common
        // overwrite shape; capture pre-image to enable undo.
        policy::notify_pre_mutation_with_content("truncate", &cstr_to_string(path));
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
