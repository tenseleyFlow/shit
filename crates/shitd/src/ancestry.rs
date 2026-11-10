// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-ancestor lookup (DR-24). Walks the parent chain from a
//! given pid up toward init, so the tier-event handlers
//! ([`crate::pkg`], [`crate::env_track`], [`crate::svc_track`],
//! [`crate::net_track`], [`crate::proc_track`], [`crate::db_track`])
//! can find which shell pid — and therefore which active command
//! window `(session_id, command_seq)` — owns a given event-emitter.
//!
//! ## Why the daemon owns this
//!
//! The helper has its own `/proc` enumeration for stage-1 snapshotting
//! (capturing argv/cwd/env for `kill` targets). Ancestry walking
//! belongs in the daemon because:
//!
//! 1. The session→shell-pid map is *in the daemon* (registered on
//!    `SessionOpen` from each shell hook).
//! 2. Tier events arrive on the daemon's UDS socket and need
//!    ancestry resolution *before* they can be journaled under the
//!    right command-window.
//!
//! ## Platform support
//!
//! - **Linux**: reads `/proc/<pid>/status::PPid`. Fast (~10µs).
//! - **FreeBSD**: `sysctl(KERN_PROC_PID)` and `kinfo_proc::ki_ppid`.
//!   This used to fork `ps -o ppid=` per hop on the daemon's single
//!   runtime thread. Measured in the FreeBSD VM, a 10-hop walk took
//!   8.5 ms idle and 150 ms (median) with the CPUs oversubscribed,
//!   past the preload shim's 50 ms ack timeout. The shim then let the
//!   syscall run, rsync exited, the walk hit a dead pid and the shim
//!   listener dropped the notification (#202).
//! - **macOS**: `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)` and `pbsi_ppid`,
//!   which reads processes of any uid (`PROC_PIDTBSDINFO` refuses other
//!   users, so a walk through `sudo` stopped there). `ps -o ppid=` (~5 ms
//!   per hop) is the fallback when libproc refuses (#210, #251).
//!
//! ## Loop guard
//!
//! pid-recycling races could in theory let the walker visit the same
//! pid twice or chase a pid that's been reused. Walk is capped at
//! [`MAX_WALK_DEPTH`]; if we hit the cap the chain is returned as
//! collected (the caller treats "no tracked shell in this chain" as
//! "event not attributable to a command window" and drops it — the
//! daemon already handles that branch for orphan events).

// Consumed by DR-25/DR-32/DR-36/DR-41/DR-53/DR-58 in the binding
// chunks. Until those land, the functions look dead to the compiler.
#![allow(dead_code)]

use std::collections::HashSet;

/// Hard cap on how far up the chain we'll walk. Realistic chains:
/// init (1) → systemd/launchd → login shell → wrapper-shell →
/// command. That's 5-6 hops. 256 is generous and bounds the worst
/// case if a future pid-recycling race makes the chain loop.
pub const MAX_WALK_DEPTH: usize = 256;

/// Walk the parent chain from `start_pid` upward. Returns `[start_pid,
/// ppid, gppid, ...]` up to the first pid whose parent is 0 or 1
/// (init/launchd), or until the walk hits [`MAX_WALK_DEPTH`].
///
/// An unresolvable pid (race: it exited between the event arrival
/// and the walk) terminates the chain at the last successfully
/// resolved step. Returns at least `[start_pid]` even if no parent
/// resolves — the caller checks for "did the chain include a known
/// shell pid?"; returning an empty vec would force an extra branch
/// at every callsite for the same outcome.
pub fn ancestor_chain(start_pid: u32) -> Vec<u32> {
    let mut chain = Vec::with_capacity(8);
    let mut seen: HashSet<u32> = HashSet::with_capacity(8);
    let mut cur = start_pid;
    for _ in 0..MAX_WALK_DEPTH {
        if !seen.insert(cur) {
            // Loop — pid recycling race. Stop here.
            break;
        }
        chain.push(cur);
        match parent_pid(cur) {
            Some(0) | Some(1) | None => break,
            Some(p) if p == cur => break, // defensive: pid==ppid would also loop
            Some(p) => cur = p,
        }
    }
    chain
}

/// Look up the parent pid of `pid`. Returns `None` if the pid no
/// longer exists or the platform query failed.
#[cfg(target_os = "linux")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&path).ok()?;
    parse_ppid_linux(&content)
}

#[cfg(target_os = "linux")]
fn parse_ppid_linux(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(target_os = "freebsd")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        libc::c_int::try_from(pid).ok()?,
    ];
    // SAFETY: kinfo_proc is plain old data; the kernel fills it.
    let mut kp: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut size: libc::size_t = std::mem::size_of::<libc::kinfo_proc>();
    // SAFETY: mib has 4 valid entries, kp is writable for `size`
    // bytes, and no new value is passed.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            (&mut kp as *mut libc::kinfo_proc).cast(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    // A pid that has exited returns rc 0 with size 0, or ESRCH.
    if rc != 0 || size < std::mem::size_of::<libc::kinfo_proc>() {
        return None;
    }
    u32::try_from(kp.ki_ppid).ok()
}

#[cfg(target_os = "macos")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    parent_pid_libproc(pid).or_else(|| parent_pid_ps(pid))
}

/// `struct proc_bsdshortinfo` from `<sys/proc_info.h>`; the libc crate
/// does not declare it.
#[cfg(target_os = "macos")]
#[repr(C)]
#[allow(dead_code)] // Layout only; the walk reads pbsi_ppid.
struct ProcBsdShortInfo {
    pbsi_pid: u32,
    pbsi_ppid: u32,
    pbsi_pgid: u32,
    pbsi_status: u32,
    pbsi_comm: [libc::c_char; 16],
    pbsi_flags: u32,
    pbsi_uid: libc::uid_t,
    pbsi_gid: libc::gid_t,
    pbsi_ruid: libc::uid_t,
    pbsi_rgid: libc::gid_t,
    pbsi_svuid: libc::uid_t,
    pbsi_svgid: libc::gid_t,
    pbsi_rfu: u32,
}

#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<ProcBsdShortInfo>() == 64);

/// `PROC_PIDT_SHORTBSDINFO` from `<sys/proc_info.h>`.
#[cfg(target_os = "macos")]
const PROC_PIDT_SHORTBSDINFO: libc::c_int = 13;

/// R8 (#210, #251): libproc in process. The short flavor has no
/// same-user check, so the walk passes `sudo` and setuid ancestors.
#[cfg(target_os = "macos")]
fn parent_pid_libproc(pid: u32) -> Option<u32> {
    // SAFETY: ProcBsdShortInfo is plain old data; zeroed is a valid value.
    let mut info: ProcBsdShortInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdShortInfo>() as libc::c_int;
    // SAFETY: `info` is writable for `size` bytes, and this flavor fills
    // exactly a proc_bsdshortinfo.
    let rc = unsafe {
        libc::proc_pidinfo(
            libc::c_int::try_from(pid).ok()?,
            PROC_PIDT_SHORTBSDINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    (rc >= size).then_some(info.pbsi_ppid)
}

/// The fallback when libproc refuses: one `ps` fork per hop.
#[cfg(target_os = "macos")]
fn parent_pid_ps(pid: u32) -> Option<u32> {
    use std::process::{Command, Stdio};
    let out = Command::new("ps")
        .arg("-o")
        .arg("ppid=")
        .arg("-p")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    std::str::from_utf8(&out.stdout).ok()?.trim().parse().ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn parent_pid(_pid: u32) -> Option<u32> {
    None
}

/// Walk `start_pid`'s ancestry and return the first pid in the chain
/// that appears in `tracked_shells`. Returns `None` if no tracked
/// shell is found in the chain (event isn't attributable to a
/// command window — the caller drops it).
///
/// Hot-path-shape: the chain is short (≤6 typical), `tracked_shells`
/// is a HashSet, so this is O(chain_len) lookups.
pub fn find_tracked_shell(start_pid: u32, tracked_shells: &HashSet<u32>) -> Option<u32> {
    ancestor_chain(start_pid)
        .into_iter()
        .find(|pid| tracked_shells.contains(pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R8 review, item 3: the libproc flavor agrees with the kernel for
    /// our own parent, and reads a process of another uid (launchd, pid 1,
    /// is root's) where `PROC_PIDTBSDINFO` refuses. Hosted macOS runs
    /// this as a non-root user.
    #[cfg(target_os = "macos")]
    #[test]
    fn libproc_short_info_reads_parents_of_any_uid() {
        // SAFETY: getppid and geteuid have no preconditions.
        let (ppid, euid) = unsafe { (libc::getppid(), libc::geteuid()) };
        assert_eq!(parent_pid_libproc(std::process::id()), Some(ppid as u32));
        assert_eq!(parent_pid_ps(std::process::id()), Some(ppid as u32));
        assert_eq!(
            parent_pid_libproc(1),
            Some(0),
            "launchd's parent through libproc (euid {euid})"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ppid_linux_finds_field() {
        let s = "Name:\tbash\nState:\tS\nPid:\t100\nPPid:\t99\n";
        assert_eq!(parse_ppid_linux(s), Some(99));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ppid_linux_returns_none_on_missing_field() {
        let s = "Name:\tbash\nState:\tS\nPid:\t100\n";
        assert_eq!(parse_ppid_linux(s), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ppid_linux_handles_leading_whitespace() {
        // The kernel pads the value with a tab; some kernels with
        // spaces. Trim handles both.
        let s = "PPid:   42\n";
        assert_eq!(parse_ppid_linux(s), Some(42));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ppid_linux_ignores_unrelated_lines_containing_ppid_substr() {
        // Defensive: a future status field whose name happens to
        // contain "PPid" as a substring shouldn't match. We use
        // strip_prefix("PPid:") so only a line starting with that
        // matches.
        let s = "VmPPidLike:\t99\nPPid:\t42\n";
        assert_eq!(parse_ppid_linux(s), Some(42));
    }

    #[test]
    fn ancestor_chain_for_self_terminates() {
        // /proc/<pid>/status on Linux, sysctl on FreeBSD and libproc
        // on macOS: the test platform either way produces a chain.
        // We only assert it terminates within the depth limit and
        // includes our own pid as the first element.
        let pid = std::process::id();
        let chain = ancestor_chain(pid);
        assert!(!chain.is_empty());
        assert_eq!(chain[0], pid);
        assert!(chain.len() <= MAX_WALK_DEPTH);
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn parent_pid_matches_getppid() {
        // SAFETY: getppid has no preconditions.
        let ppid = unsafe { libc::getppid() } as u32;
        let me = std::process::id();
        assert_eq!(parent_pid(me), Some(ppid));
        // A test runner directly under init has no second chain entry.
        if ppid > 1 {
            assert_eq!(ancestor_chain(me).get(1).copied(), Some(ppid));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn exited_pid_has_no_parent() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        child.wait().expect("reap true");
        assert_eq!(parent_pid(pid), None);
        assert_eq!(ancestor_chain(pid), vec![pid]);
    }

    #[test]
    fn ancestor_chain_terminates_at_init() {
        // Walk from self; the last pid must be 1's child or earlier
        // (we stop *at* the pid whose parent is 0/1). Conservative:
        // the chain length is < MAX_WALK_DEPTH and finite.
        let chain = ancestor_chain(std::process::id());
        assert!(chain.len() < MAX_WALK_DEPTH);
    }

    #[test]
    fn ancestor_chain_for_nonexistent_pid_returns_just_that_pid() {
        // A pid that almost certainly doesn't exist. The walker can't
        // resolve the parent, so the chain contains only the start.
        let chain = ancestor_chain(u32::MAX);
        assert_eq!(chain, vec![u32::MAX]);
    }

    #[test]
    fn ancestor_chain_for_pid_1_yields_short_chain() {
        // pid 1 is init/launchd; its parent is 0. Chain should be
        // just [1] (we stop *at* the entry whose parent is 0).
        let chain = ancestor_chain(1);
        assert!(!chain.is_empty());
        assert_eq!(chain[0], 1);
        assert!(chain.len() <= 2);
    }

    #[test]
    fn find_tracked_shell_finds_direct_parent() {
        let pid = std::process::id();
        // self's parent is in the chain at index 1.
        let chain = ancestor_chain(pid);
        if chain.len() >= 2 {
            let parent = chain[1];
            let tracked: HashSet<u32> = [parent].into_iter().collect();
            assert_eq!(find_tracked_shell(pid, &tracked), Some(parent));
        }
    }

    #[test]
    fn find_tracked_shell_returns_none_when_no_match() {
        let tracked: HashSet<u32> = HashSet::new();
        assert_eq!(find_tracked_shell(std::process::id(), &tracked), None);
    }

    #[test]
    fn find_tracked_shell_returns_start_pid_when_self_is_tracked() {
        // Edge case: the emitting process IS the tracked shell.
        // Common when a hook command runs in the shell itself
        // (e.g. an `apt install` inside the active interactive shell).
        let pid = std::process::id();
        let tracked: HashSet<u32> = [pid].into_iter().collect();
        assert_eq!(find_tracked_shell(pid, &tracked), Some(pid));
    }
}
