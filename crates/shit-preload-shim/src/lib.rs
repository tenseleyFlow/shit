// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-preload-shim` — userspace libc-interposition library for the
//! BSD capture tier (S10).
//!
//! ## What this is
//!
//! A `cdylib` loaded into user processes via `LD_PRELOAD` (BSD/Linux)
//! or `DYLD_INSERT_LIBRARIES` (macOS, not used in v1). It interposes
//! a small set of libc calls that mutate file-system state and emits
//! a pre-mutation notification to `shit-helper` over a per-process
//! UDS before calling through to the real libc symbol.
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
//! - **Hold the syscall:** stage 1 calls through to libc immediately.
//!   The full version awaits a 50ms allow/deny decision from the
//!   helper; on timeout we allow and mark `partial`.
//!
//! ## Stage 1 contract
//!
//! Compile cleanly as a cdylib on BSD targets, expose the
//! interposable symbols as `extern "C"`, and pass through to libc
//! unmodified. No IPC, no helper coupling. This validates the
//! build/link/install story before we wire actual interposition.

#![allow(clippy::missing_safety_doc)]

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "linux",
))]
mod interposers {
    use libc::{c_char, c_int, mode_t};

    /// Stage-1 `unlink` interposer. Calls through to libc immediately.
    /// Stage 2 will notify the helper first and await a verdict.
    ///
    /// # Safety
    /// `path` must be a valid C string per libc's `unlink(2)` contract.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shit_preload_unlink(path: *const c_char) -> c_int {
        // SAFETY: forwarded contract — caller guarantees `path` is a
        // valid NUL-terminated C string.
        unsafe { libc::unlink(path) }
    }

    /// Stage-1 `open` interposer. Variadic in real libc; we accept
    /// the three-arg form here and let the linker route accordingly.
    ///
    /// # Safety
    /// `path` must be a valid C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shit_preload_open(
        path: *const c_char,
        flags: c_int,
        mode: mode_t,
    ) -> c_int {
        // SAFETY: forwarded contract.
        unsafe { libc::open(path, flags, mode) }
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

// The `#[unsafe(no_mangle)]` attribute on each interposer forces the
// symbol into the cdylib's export table directly — no `pub use` shim
// is required and adding one would only produce an unused-import lint.

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

    #[test]
    fn unlink_passthrough_returns_negative_on_missing_path() {
        let c = CString::new("/tmp/shit-preload-shim-nonexistent-XXX").unwrap();
        let r = unsafe { super::shit_preload_unlink(c.as_ptr()) };
        assert!(r < 0, "unlink of nonexistent path should fail");
    }
}
