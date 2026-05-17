// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tracked process tree. For each in-flight command we track the
//! `root_pid` plus its descendants — events from PIDs outside any
//! tracked tree are allowed through without capture.
//!
//! Descendant discovery is via `/proc/<pid>/stat` parent-PID lookup,
//! cached. When we see a new PID in a fanotify event, we walk up via
//! `ppid` until we hit either a tracked root (→ track this pid too)
//! or PID 0/1 (→ untracked). This is racey vs. process exit; we
//! tolerate ESRCH by treating the pid as "not tracked, don't capture."
//!
//! S09 (eBPF tracepoints) replaces this with a kernel-level
//! `sched_process_fork` hook for race-free descendant discovery; this
//! module is the S08-tier polled fallback.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use uuid::Uuid;

/// One tracked subtree, keyed by `(session, command_seq)`.
#[derive(Debug, Clone)]
pub struct TrackedTree {
    pub session: Uuid,
    pub command_seq: u64,
    pub root_pid: i32,
    /// PIDs known to be in this subtree. Includes `root_pid`. Grows as
    /// `is_in_tree` walks discover new descendants.
    pub members: std::collections::HashSet<i32>,
}

/// Map of all currently tracked subtrees plus a per-PID lookup cache.
#[derive(Debug, Default)]
pub struct TreeMap {
    /// Key is `(session, command_seq)`.
    trees: HashMap<(Uuid, u64), TrackedTree>,
    /// Cache: pid → which tree it belongs to, if any. Avoids walking
    /// `/proc/<pid>/stat` every event.
    pid_cache: HashMap<i32, Option<(Uuid, u64)>>,
}

impl TreeMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start watching a new subtree. Drops any prior cached results
    /// (descendants of the new root may be cached as "untracked").
    pub fn watch(&mut self, session: Uuid, command_seq: u64, root_pid: i32) {
        let mut members = std::collections::HashSet::new();
        members.insert(root_pid);
        let tree = TrackedTree {
            session,
            command_seq,
            root_pid,
            members,
        };
        self.trees.insert((session, command_seq), tree);
        self.pid_cache.clear();
    }

    /// Stop watching a subtree. Cache is cleared because previously
    /// cached pids may now belong to no tracked tree.
    pub fn unwatch(&mut self, session: Uuid, command_seq: u64) {
        self.trees.remove(&(session, command_seq));
        self.pid_cache.clear();
    }

    /// Is `pid` a descendant of any currently tracked root? Result is
    /// cached. Tolerates ESRCH (process exited mid-lookup) by treating
    /// it as "not tracked."
    pub fn is_tracked(&mut self, pid: i32) -> Option<(Uuid, u64)> {
        if let Some(cached) = self.pid_cache.get(&pid) {
            return *cached;
        }
        let resolved = self.resolve(pid);
        self.pid_cache.insert(pid, resolved);
        if let Some((s, seq)) = resolved
            && let Some(tree) = self.trees.get_mut(&(s, seq))
        {
            tree.members.insert(pid);
        }
        resolved
    }

    /// Walk `/proc/<pid>/stat` up the parent chain looking for a
    /// tracked root. Bounded depth so a malicious/cycling proc tree
    /// can't loop us forever (real Linux pid 1 is init; we stop there
    /// regardless).
    fn resolve(&self, pid: i32) -> Option<(Uuid, u64)> {
        const MAX_DEPTH: usize = 64;
        let mut current = pid;
        for _ in 0..MAX_DEPTH {
            // Direct hit on any tracked root.
            for ((s, seq), tree) in &self.trees {
                if current == tree.root_pid {
                    return Some((*s, *seq));
                }
            }
            // Walk up.
            match parent_pid(current) {
                Some(0) | Some(1) | None => return None,
                Some(ppid) => current = ppid,
            }
        }
        None
    }
}

/// Read the parent PID from `/proc/<pid>/stat`. The field layout is
/// `pid (comm) state ppid ...` where `comm` may contain spaces +
/// closing-paren characters — we scan from the end backwards to find
/// the *last* `)`, then take the next field after it as `state` and
/// the one after as `ppid`. This is the standard idiom for parsing
/// `/proc/<pid>/stat` safely.
fn parent_pid(pid: i32) -> Option<i32> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let raw = fs::read_to_string(&path).ok()?;
    // Find the last ')' — comm field ends there. Everything after is
    // space-delimited fixed-width.
    let close = raw.rfind(')')?;
    let after = &raw[close + 1..];
    let mut fields = after.split_whitespace();
    let _state = fields.next()?;
    let ppid: i32 = fields.next()?.parse().ok()?;
    Some(ppid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_adds_root_to_members() {
        let mut tm = TreeMap::new();
        let s = Uuid::nil();
        tm.watch(s, 1, 4242);
        let tree = tm.trees.get(&(s, 1)).unwrap();
        assert!(tree.members.contains(&4242));
        assert_eq!(tree.root_pid, 4242);
    }

    #[test]
    fn unwatch_removes_tree_and_clears_cache() {
        let mut tm = TreeMap::new();
        let s = Uuid::nil();
        tm.watch(s, 1, 4242);
        tm.pid_cache.insert(9999, Some((s, 1)));
        tm.unwatch(s, 1);
        assert!(!tm.trees.contains_key(&(s, 1)));
        assert!(tm.pid_cache.is_empty());
    }

    #[test]
    fn is_tracked_returns_some_for_root_pid_in_real_proc() {
        // Use the current process as a synthetic "root" — the helper's
        // own PID is always resolvable via /proc.
        let pid = std::process::id() as i32;
        let mut tm = TreeMap::new();
        let s = Uuid::nil();
        tm.watch(s, 1, pid);
        assert_eq!(tm.is_tracked(pid), Some((s, 1)));
    }

    #[test]
    fn is_tracked_returns_none_for_unwatched_pid() {
        let mut tm = TreeMap::new();
        // PID 1 (init) is always present but we haven't watched it.
        assert_eq!(tm.is_tracked(1), None);
    }

    #[test]
    fn esrch_on_stale_pid_treated_as_untracked() {
        let mut tm = TreeMap::new();
        // PID guaranteed not to exist (i32::MAX). resolve() must not
        // panic; cache must store None.
        let res = tm.is_tracked(i32::MAX);
        assert_eq!(res, None);
        assert_eq!(tm.pid_cache.get(&i32::MAX), Some(&None));
    }

    #[test]
    fn cache_hit_avoids_resolve() {
        let mut tm = TreeMap::new();
        let s = Uuid::nil();
        // Pre-seed cache with a value that resolve() wouldn't produce.
        tm.pid_cache.insert(54321, Some((s, 99)));
        assert_eq!(tm.is_tracked(54321), Some((s, 99)));
    }
}
