// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resolve a pid's current working directory to a host-side path
//! (S24.B). The capture runtime uses this to figure out which subtree
//! to register with kqueue when the daemon issues `WatchTree { root_pid, .. }`.
//!
//! **FreeBSD (B05):** raw `sysctl(KERN_PROC_CWD)` returning a
//! `struct kinfo_file`. The previous `procstat(1)` shell-out worked
//! pre-B05 but is blocked under Capsicum capability mode because
//! `execve(2)` is forbidden. `KERN_PROC_CWD` is on capsicum's
//! whitelist and works for any pid the caller can otherwise see.
//!
//! On NetBSD/OpenBSD/DragonFly we currently return `None`; per the S10
//! tier doc those BSDs are best-effort and the producer falls back to
//! refusing the watch with a logged warning.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::path::PathBuf;

/// Resolve `pid`'s cwd. Returns `None` when the pid is gone, the
/// resolver isn't supported on this BSD, or the platform syscall
/// failed in a way that's not actionable.
pub fn resolve_pid_cwd(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "freebsd")]
    {
        resolve_via_sysctl_kern_proc_cwd(pid)
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = pid;
        None
    }
}

/// FreeBSD `sysctl(kern.proc.cwd.<pid>)` returns one or more
/// `struct kinfo_file` records. The first record is the cwd; its
/// `kf_path` field is a NUL-terminated absolute path.
///
/// Capsicum-compatible: sysctl on KERN_PROC_CWD is whitelisted in
/// capability mode. No `execve` required.
#[cfg(target_os = "freebsd")]
fn resolve_via_sysctl_kern_proc_cwd(pid: u32) -> Option<PathBuf> {
    // MIB: [CTL_KERN, KERN_PROC, KERN_PROC_CWD, pid]
    let mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_CWD,
        pid as libc::c_int,
    ];
    // First call: probe the required buffer size with a NULL output
    // pointer. The kernel writes the byte count into len.
    let mut len: libc::size_t = 0;
    // SAFETY: mib is a stack-allocated slice we hand a pointer to;
    // sysctl reads it, writes only into `len`. NULL output pointer is
    // documented FreeBSD behavior for size queries.
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return None;
    }
    let mut buf: Vec<u8> = vec![0; len];
    // SAFETY: buf has capacity == len; sysctl writes up to len bytes
    // and updates len to actual written size on success.
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    parse_kinfo_file_cwd(&buf)
}

/// Extract the `kf_path` string from the first `struct kinfo_file`
/// in `buf`. Kept separate so we can unit-test the parsing logic
/// without invoking the syscall.
///
/// Layout safety: `kinfo_file` has `kf_structsize` as its first
/// `int` field, telling us the actual record size at runtime. We
/// use libc's `kinfo_file` struct definition for field access; the
/// `kf_path` field is a `[c_char; PATH_MAX]` near the end.
#[cfg(target_os = "freebsd")]
fn parse_kinfo_file_cwd(buf: &[u8]) -> Option<PathBuf> {
    if buf.len() < std::mem::size_of::<libc::kinfo_file>() {
        return None;
    }
    // SAFETY: buf is at least kinfo_file-sized; sysctl returned a
    // well-formed record. Reading kf_path as a NUL-terminated CStr
    // is sound because the kernel always writes a terminator.
    let kif: &libc::kinfo_file = unsafe { &*(buf.as_ptr() as *const libc::kinfo_file) };
    let cstr = unsafe { std::ffi::CStr::from_ptr(kif.kf_path.as_ptr()) };
    let path_str = cstr.to_str().ok()?;
    if path_str.is_empty() {
        return None;
    }
    Some(PathBuf::from(path_str))
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::*;

    #[test]
    fn resolves_own_cwd() {
        // The test process is alive; sysctl should resolve its cwd.
        // We don't assert the specific path (cargo's working dir
        // varies); we just assert *some* path resolves.
        let cwd = resolve_pid_cwd(std::process::id());
        assert!(cwd.is_some(), "expected to resolve own cwd via sysctl");
        let p = cwd.unwrap();
        assert!(p.is_absolute(), "cwd must be absolute, got {}", p.display());
    }

    #[test]
    fn returns_none_for_nonexistent_pid() {
        // PID 0 (kernel) and very-high PIDs are unlikely to exist as
        // userspace processes; sysctl returns 0 records.
        let cwd = resolve_pid_cwd(u32::MAX);
        assert!(cwd.is_none(), "expected None for nonexistent pid");
    }
}
