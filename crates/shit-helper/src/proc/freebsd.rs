// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeBSD process enumeration (B02, DR-50).
//!
//! Closes the gap the original S18 sprint left open:
//! `proc/enumerate.rs:11` notes "BSD: `sysctl(KERN_PROC_PID)`
//! (DR-50 — not implemented Stage 1)". This module is that
//! implementation.
//!
//! ## Approach
//!
//! Use raw `sysctl(2)` via the libc-exposed [`libc::kinfo_proc`]
//! struct. The two-step probe pattern is canonical on FreeBSD:
//! call sysctl once with a NULL output buffer to discover the
//! required size, then call again with a buffer of that size.
//! Argv comes from a separate per-pid `KERN_PROC_ARGS` sysctl (the
//! `ki_args` field on `kinfo_proc` is a pointer into kernel memory,
//! unusable from userspace). CWD comes from `KERN_PROC_CWD` (which
//! is whitelisted by capsicum and doesn't require procfs).
//!
//! ## Privilege
//!
//! `KERN_PROC_*` is readable by any user for processes the user
//! owns OR for processes whose `kinfo_proc` is in the unrestricted
//! set (most process metadata except environ). Argv via
//! `KERN_PROC_ARGS` is generally readable. CWD via `KERN_PROC_CWD`
//! requires either root OR being the process owner. Same pattern
//! as Linux — the helper auto-escalates when it sees EPERM is the
//! plan but that's deferred; for v1 we accept that other-user pids
//! get a truncated snapshot.

#![allow(dead_code)] // exposed via cfg-gated dispatch in enumerate.rs / kill_targets.rs

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;
use std::mem;

use shit_proto::ProcSnapshot;

/// One-shot full-table snapshot via `sysctl(KERN_PROC_PROC, 0)`.
///
/// `KERN_PROC_PROC` (8) returns userland processes (excluding
/// kernel threads). `KERN_PROC_ALL` (0) would include kernel
/// threads — fine for some use cases but noisier for pattern
/// matching. We use PROC by default.
fn kinfo_procs_all() -> io::Result<Vec<libc::kinfo_proc>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PROC];
    sysctl_array(&mut mib)
}

/// Per-pid snapshot via `sysctl(KERN_PROC_PID, pid)`. Returns at
/// most one `kinfo_proc`; ESRCH means the pid is gone.
fn kinfo_proc_for_pid(pid: u32) -> io::Result<Option<libc::kinfo_proc>> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as libc::c_int,
    ];
    match sysctl_array(&mut mib) {
        Ok(mut v) if !v.is_empty() => Ok(Some(v.remove(0))),
        Ok(_) => Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Generic two-step sysctl that returns an array of `T` (typically
/// `kinfo_proc`). The kernel reports the required size in the first
/// call, then writes the array in the second.
fn sysctl_array<T: Copy>(mib: &mut [libc::c_int]) -> io::Result<Vec<T>> {
    let name_len = mib.len() as libc::c_uint;
    let mut size: libc::size_t = 0;
    // Probe required size.
    // SAFETY: mib is a valid array of c_int with name_len entries;
    // passing null output is documented as "compute required size".
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            name_len,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let n = size / mem::size_of::<T>();
    let mut buf: Vec<T> = Vec::with_capacity(n);
    // SAFETY: cap is `n`, len is set to `n` after the sysctl writes
    // exactly `n * sizeof(T)` bytes. The kernel may write fewer (if
    // procs exit between the two calls), in which case we truncate
    // below using the kernel-updated `size`.
    unsafe { buf.set_len(n) };
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            name_len,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = size / mem::size_of::<T>();
    buf.truncate(actual);
    Ok(buf)
}

/// Per-pid argv via `sysctl(KERN_PROC_ARGS, pid)`. Returns the
/// raw zero-separated bytes the kernel reports.
fn proc_args_bytes(pid: u32) -> io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_ARGS,
        pid as libc::c_int,
    ];
    let mut size: libc::size_t = 0;
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size];
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(size);
    Ok(buf)
}

/// Per-pid CWD via `sysctl(KERN_PROC_CWD, pid)`. Returns the
/// path as a Rust String, or empty on permission/lookup failure.
fn proc_cwd(pid: u32) -> String {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_CWD,
        pid as libc::c_int,
    ];
    let mut size: libc::size_t = 0;
    // Probe.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 || size == 0 {
        return String::new();
    }
    // FreeBSD packs cwd into a struct kinfo_file; size will be that
    // struct's reported size. For our purpose we want the path; the
    // simpler shape is to call `procstat -fbn <pid>` for the cwd
    // line, but that requires execve which we're avoiding for
    // capsicum-readiness (B05).
    //
    // Empirically, KERN_PROC_CWD returns a `struct kinfo_file` whose
    // last field is `kf_path` (a fixed-size char array). To keep
    // this module portable across FreeBSD 13/14/15 ABI bumps without
    // mirroring `struct kinfo_file`, scan the buffer for the longest
    // NUL-terminated path-looking substring near its end.
    let mut buf = vec![0u8; size];
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 {
        return String::new();
    }
    buf.truncate(size);
    extract_path_from_kinfo_file(&buf)
}

/// Pull the embedded path out of a `kinfo_file` byte blob. The
/// last contiguous run of printable ASCII + path characters ending
/// at a NUL is the path. Resilient to struct layout drift.
fn extract_path_from_kinfo_file(buf: &[u8]) -> String {
    // Find a candidate run: contiguous bytes that look like a path,
    // terminated by NUL. Walk from the end backward to find the
    // last NUL; then walk further back to find the start (first
    // non-path-ish byte).
    let nul = match buf.iter().rposition(|&b| b == 0) {
        Some(i) if i > 0 => i,
        _ => return String::new(),
    };
    // Find the start of the run.
    let mut start = nul;
    while start > 0 {
        let b = buf[start - 1];
        let ok = b == b'/'
            || b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'_' | b'-' | b'+' | b'=' | b':' | b'@' | b' ');
        if !ok {
            break;
        }
        start -= 1;
    }
    // Must start with '/' to be a plausible cwd.
    while start < nul && buf[start] != b'/' {
        start += 1;
    }
    if start >= nul {
        return String::new();
    }
    String::from_utf8_lossy(&buf[start..nul]).into_owned()
}

/// Snapshot one process by pid into the wire-format struct. Mirror
/// of `linux::snapshot` in `enumerate.rs`. Returns Err if the pid
/// doesn't exist; populates whatever it can otherwise.
pub fn snapshot(pid: u32) -> anyhow::Result<ProcSnapshot> {
    let kp =
        kinfo_proc_for_pid(pid)?.ok_or_else(|| anyhow::anyhow!("pid {pid} not found (ESRCH)"))?;

    let comm = unsafe { CStr::from_ptr(kp.ki_comm.as_ptr()) }
        .to_string_lossy()
        .into_owned();

    let args_bytes = proc_args_bytes(pid).unwrap_or_default();
    let argv: Vec<String> = args_bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();

    // FreeBSD has no /proc/<pid>/environ analog without procfs.
    // KERN_PROC_ENV exists but is restricted (root or owner). For
    // v1 we omit env_summary on FreeBSD and document the gap.
    let env_summary: BTreeMap<String, String> = BTreeMap::new();

    Ok(ProcSnapshot {
        pid,
        comm,
        argv,
        cwd: proc_cwd(pid),
        env_summary,
        parent_pid: kp.ki_ppid as u32,
        start_time_secs: kp.ki_start.tv_sec as u64,
        tty: None, // ki_tdev encoded; deferred to a richer mapping
    })
}

/// pid → effective uid via the cached kinfo_proc.
pub fn uid_of(pid: u32) -> Option<u32> {
    kinfo_proc_for_pid(pid).ok().flatten().map(|kp| kp.ki_uid)
}

/// Walk the process table and return pids whose pgrp matches `pgid`.
pub fn pids_in_pgroup(pgid: u32) -> Option<Vec<u32>> {
    let procs = kinfo_procs_all().ok()?;
    let mut out = Vec::new();
    for kp in procs {
        if kp.ki_pgid as u32 == pgid {
            out.push(kp.ki_pid as u32);
        }
    }
    Some(out)
}

/// Walk the process table and return pids matching `pattern` against
/// `comm` (the short name kernel-stored, up to COMMLEN) or against
/// the full argv (joined with spaces). Filters honored:
/// - `user` (uid number OR username — resolved via /etc/passwd)
/// - `group` (pgid as number; same semantics as Linux)
pub fn pids_matching(pattern: &str, filters: &BTreeMap<String, String>) -> Vec<u32> {
    let procs = match kinfo_procs_all() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let user_filter = filters.get("user").and_then(|u| resolve_uid(u));
    let group_filter = filters.get("group").and_then(|g| g.parse::<u32>().ok());

    let mut out = Vec::new();
    for kp in procs {
        let pid = kp.ki_pid as u32;
        // ki_comm filter: short name only.
        let comm = unsafe { CStr::from_ptr(kp.ki_comm.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        // argv via per-pid sysctl (silently empty on EPERM/ESRCH).
        let args = proc_args_bytes(pid).unwrap_or_default();
        let args_str: String = args
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if !comm.contains(pattern) && !args_str.contains(pattern) {
            continue;
        }
        if let Some(uid) = user_filter
            && kp.ki_uid != uid
        {
            continue;
        }
        if let Some(g) = group_filter
            && kp.ki_pgid as u32 != g
        {
            continue;
        }
        out.push(pid);
    }
    out
}

/// Resolve a uid number OR a username to a uid. Mirror of
/// `kill_targets.rs::linux::resolve_uid`.
fn resolve_uid(name_or_num: &str) -> Option<u32> {
    if let Ok(n) = name_or_num.parse::<u32>() {
        return Some(n);
    }
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let n = fields.next()?;
        let _pw = fields.next();
        let uid = fields.next()?;
        if n == name_or_num {
            return uid.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_self_returns_argv_and_comm() {
        let s = snapshot(std::process::id()).expect("self-snapshot");
        assert!(!s.argv.is_empty(), "argv empty");
        assert!(!s.comm.is_empty(), "comm empty");
        assert!(s.parent_pid > 0, "ppid 0");
    }

    #[test]
    fn enumerate_by_pattern_finds_self() {
        // The test binary is itself in the process table; pattern
        // match by a substring of argv[0] should return at least
        // our own pid.
        let argv0 = std::env::args().next().unwrap_or_default();
        let leaf = std::path::Path::new(&argv0)
            .file_name()
            .and_then(|s| s.to_str())
            .map(String::from)
            .unwrap_or_default();
        if leaf.is_empty() {
            return; // can't form a stable pattern
        }
        let pids = pids_matching(&leaf, &BTreeMap::new());
        assert!(pids.contains(&std::process::id()), "self pid missing");
    }

    #[test]
    fn pids_in_pgroup_self() {
        // Our own pgrp should contain at least our own pid. The pgid
        // is typically the shell or test runner's pid; pid itself
        // shows up either way as a member of *some* group, so we
        // verify via getpgid(0).
        let our_pgid = unsafe { libc::getpgid(0) } as u32;
        let members = pids_in_pgroup(our_pgid).expect("pids_in_pgroup");
        assert!(
            members.contains(&std::process::id()),
            "self not in own pgrp"
        );
    }

    #[test]
    fn extract_path_handles_typical_buf() {
        // Synthesize a kinfo_file-ish buffer ending with a path.
        let mut buf = vec![0u8; 64];
        let suffix = b"/home/freebsd/scratch";
        buf.extend_from_slice(suffix);
        buf.push(0);
        let p = extract_path_from_kinfo_file(&buf);
        assert_eq!(p, "/home/freebsd/scratch");
    }

    #[test]
    fn extract_path_no_path_returns_empty() {
        // Buffer with no '/' at all → empty.
        let buf = vec![0u8; 64];
        assert_eq!(extract_path_from_kinfo_file(&buf), "");
    }
}
