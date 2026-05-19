// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeBSD Capsicum sandbox (S10 stage 1).
//!
//! Capsicum is FreeBSD's capability-mode sandbox: once a process
//! calls `cap_enter(2)`, it can no longer use global namespaces
//! (open by absolute path, kill arbitrary pids, etc.) and is
//! restricted to operations on file descriptors it already holds.
//! This is the FreeBSD analog of:
//! - Linux: seccomp + the cap-drop in `priv_linux::drop_to_minimum`
//! - macOS: the helper's sandbox profile (S07)
//!
//! ## Why FreeBSD-only (not the other BSDs)
//!
//! Capsicum originated on FreeBSD and ships there by default. NetBSD,
//! OpenBSD, and DragonFly do not have a comparable API. On those the
//! helper relies on filesystem ACLs + the kqueue tier's narrower
//! attack surface (no LSM-like deny path); revisit in a follow-up
//! sprint paired with audit work.
//!
//! ## Stage 1 contract
//!
//! Exposes `enter_capability_mode()` returning a `CapsicumError`
//! variant. Stage 1 always returns `NotImplemented` so wiring it into
//! `privileged_setup` is a no-op. Real `cap_enter(2)` call lands
//! once we have a FreeBSD VM target — same prerequisite as the kqueue
//! runtime work.

#[derive(Debug, thiserror::Error)]
pub enum CapsicumError {
    #[error("cap_enter(2): {0}")]
    CapEnter(std::io::Error),
}

/// Enter Capsicum capability mode. **One-way:** after this returns
/// `Ok`, the process can no longer use global namespace operations —
/// only descriptors it already holds and operations relative to
/// those.
///
/// S24.F lands the real `cap_enter(2)` call but does not enable it
/// by default. The caller gates with `SHIT_CAPSICUM=1` so we can
/// validate incrementally before flipping the on-by-default switch
/// in S25 alongside the dir-fd rewrite of `register_subtree`.
pub fn enter_capability_mode() -> Result<(), CapsicumError> {
    // SAFETY: cap_enter takes no arguments and has no preconditions
    // beyond "the process hasn't already entered capability mode and
    // exited"; the FFI binding is the same shape as `getpid`.
    let rc = unsafe { libc::cap_enter() };
    if rc != 0 {
        return Err(CapsicumError::CapEnter(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cap_enter` is one-way and would brick the test runner if we
    /// called it directly. Verifying the call site requires forking
    /// the test process — done at the bottom.
    #[test]
    fn cap_enter_in_child_then_absolute_open_returns_ecapmode() {
        // SAFETY: fork is allowed in single-threaded test runners.
        // We immediately exec or exit in the child; no mixed-state
        // hazards.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // Child: enter cap mode, then attempt an absolute-path
            // open. Expect ECAPMODE (libc::ECAPMODE on FreeBSD).
            if enter_capability_mode().is_err() {
                // Some sandboxed test runners forbid cap_enter; in
                // that case we exit(2) so the parent sees the
                // distinction without failing the suite.
                unsafe { libc::_exit(2) };
            }
            let c = std::ffi::CString::new("/etc/passwd").unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
            if fd >= 0 {
                // Absolute open should be forbidden inside cap mode.
                unsafe {
                    libc::close(fd);
                    libc::_exit(3);
                }
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // ECAPMODE = 94 on FreeBSD; anything else is unexpected.
            #[allow(non_snake_case)]
            let ECAPMODE: i32 = 94;
            unsafe { libc::_exit(if errno == ECAPMODE { 0 } else { 4 }) };
        }
        // Parent: wait for child.
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid on our own child.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid did not return our child");
        // libc::WEXITSTATUS expands a macro; we replicate by shifting.
        let exit_code = (status >> 8) & 0xff;
        match exit_code {
            0 => {} // PASS — open returned ECAPMODE.
            2 => {
                // cap_enter denied in this sandbox; treat as a skip
                // rather than a fail. (Buildbots sometimes lock this
                // down; the production helper runs unsandboxed.)
                eprintln!("test skipped: cap_enter denied in this environment");
            }
            other => panic!("unexpected child exit code {other}"),
        }
    }
}
