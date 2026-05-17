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
//! - **macOS / BSD**: shells out to `ps -o ppid= -p <pid>`. Slower
//!   (~5ms for the fork+exec) but rock-solid across versions and
//!   doesn't require a `libc::kinfo_proc` binding that varies by
//!   target. Tier events are rare enough (a few per second on a
//!   typical interactive workload) that the cost is invisible.
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

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn parent_pid(pid: u32) -> Option<u32> {
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
    let s = std::str::from_utf8(&out.stdout).ok()?.trim();
    s.parse().ok()
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
        // /proc/<pid>/status is real on Linux and ps -o ppid= works
        // on macOS — the test platform either way produces a chain.
        // We only assert it terminates within the depth limit and
        // includes our own pid as the first element.
        let pid = std::process::id();
        let chain = ancestor_chain(pid);
        assert!(!chain.is_empty());
        assert_eq!(chain[0], pid);
        assert!(chain.len() <= MAX_WALK_DEPTH);
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
