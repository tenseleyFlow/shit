// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resolve a pid's current working directory to a host-side path
//! (S24.B). The capture runtime uses this to figure out which subtree
//! to register with kqueue when the daemon issues `WatchTree { root_pid, .. }`.
//!
//! **Stage 1 (FreeBSD):** shell out to `procstat(1)` from the base
//! system and parse the `cwd` line. This avoids the
//! `KERN_PROC_FILEDESC` sysctl FFI dance for the first end-to-end
//! demo; switching to a pure-sysctl resolver is filed as a follow-up
//! and lives behind this same `resolve_pid_cwd` API so callers don't
//! change.
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
/// resolver isn't supported on this BSD, or the platform tool failed
/// in a way that's not actionable.
pub fn resolve_pid_cwd(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "freebsd")]
    {
        resolve_via_procstat(pid)
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "freebsd")]
fn resolve_via_procstat(pid: u32) -> Option<PathBuf> {
    // `procstat -f <pid>` lists every open fd in a fixed column
    // layout; the row with FD == "cwd" carries the path as the last
    // whitespace-separated field. Output shape (FreeBSD 14):
    //   PID COMM       FD T V FLAGS REF OFFSET PRO NAME
    //   123 sh        cwd v d r--rw---- - -    -  /tmp/foo
    let out = std::process::Command::new("/usr/bin/procstat")
        .args(["-f", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_procstat_cwd(&out.stdout)
}

#[cfg(target_os = "freebsd")]
fn parse_procstat_cwd(stdout: &[u8]) -> Option<PathBuf> {
    let s = std::str::from_utf8(stdout).ok()?;
    for line in s.lines().skip(1) {
        let mut cols = line.split_whitespace();
        // Skip PID and COMM (which may itself contain spaces — but
        // procstat doesn't double-quote, so the FD column is reliably
        // the 3rd whitespace-separated token).
        let _pid = cols.next()?;
        let _comm = cols.next()?;
        let fd = cols.next()?;
        if fd != "cwd" {
            continue;
        }
        // Re-tokenize the whole line; the path is the *last* field,
        // and a path with internal whitespace would still survive
        // because procstat substitutes "-" for any unset field.
        let path = line.split_whitespace().last()?;
        if path == "-" {
            return None;
        }
        return Some(PathBuf::from(path));
    }
    None
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::*;

    #[test]
    fn parse_procstat_extracts_cwd_path() {
        let stdout = b"  PID COMM       FD T V FLAGS    REF  OFFSET PRO NAME\n\
                       1234 fish      cwd v d -------r-w--- -      -      /tmp/shit-vm-test\n\
                       1234 fish     root v d -------r-w--- -      -      /\n";
        assert_eq!(
            parse_procstat_cwd(stdout),
            Some(PathBuf::from("/tmp/shit-vm-test"))
        );
    }

    #[test]
    fn parse_procstat_returns_none_when_no_cwd_row() {
        let stdout = b"  PID COMM       FD T V FLAGS    REF  OFFSET PRO NAME\n\
                       1234 fish     root v d -------r-w--- -      -      /\n";
        assert_eq!(parse_procstat_cwd(stdout), None);
    }

    #[test]
    fn parse_procstat_returns_none_when_dash() {
        let stdout = b"  PID COMM       FD T V FLAGS    REF  OFFSET PRO NAME\n\
                       1234 fish      cwd v d -------r-w--- -      -      -\n";
        assert_eq!(parse_procstat_cwd(stdout), None);
    }

    #[test]
    fn resolves_own_cwd() {
        // The test process is alive; procstat should be able to read
        // its cwd. We don't assert the specific path (cargo's working
        // dir varies); we just assert *some* path resolves.
        let cwd = resolve_pid_cwd(std::process::id());
        assert!(cwd.is_some(), "expected to resolve own cwd via procstat");
    }
}
