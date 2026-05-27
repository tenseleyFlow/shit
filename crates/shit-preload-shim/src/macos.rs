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

use libc::{c_char, c_int, c_void};

// M07.A.1: first interposer. Proves the DYLD_INTERPOSE Rust pattern
// works on this codebase end-to-end (compiles, links into a cdylib,
// the `__DATA,__interpose` section is emitted with the expected
// pair). Subsequent slices (M07.A.2..) extend to open / openat /
// rename / renameat / unlinkat / mkdir / mkdirat with the same
// pattern.
//
// Stage 1 of the interposer is passthrough-only: we delegate
// straight to libc::unlink. M07.A.N wires the daemon notification
// (mirroring the BSD/Linux dispatch path) once the shim's macOS
// runtime hooks are in place. Keeping stage 1 passthrough means
// the interposer can land + be validated in CI without depending
// on the daemon being reachable.

/// Replacement for `unlink(2)`. Currently a passthrough; the
/// notification dispatch lands in a subsequent M07.A slice.
///
/// # Safety
/// Same contract as `libc::unlink` — `pathname` must point to a
/// valid NUL-terminated C string for the duration of the call.
unsafe extern "C" fn my_unlink(pathname: *const c_char) -> c_int {
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
    unsafe { libc::renameat(fromfd, from, tofd, to) }
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
}
