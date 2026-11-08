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

    /// Like `is_tracked`, but matches against the ancestry the BPF
    /// program recorded at hook-fire time (`task->real_parent->tgid`,
    /// then each tgid above it, nearest first; 0 past the top) instead
    /// of walking `/proc/<pid>/stat` at event-consume time.
    ///
    /// The ringbuf reader runs async to the syscall. A short-lived tool
    /// (rm, chmod, mkdir) has usually exited by the time its event is
    /// consumed, and its `/proc` entry is gone. AR00.5 recorded only
    /// the parent, which covers a direct child of the tracked shell.
    /// A shell that forks for the last command of `sh -c '...'` (dash
    /// on Ubuntu 24.04) puts the tool two levels down, and the `/proc`
    /// walk then loses the race to the tool's exit (#209). Matching
    /// every recorded ancestor closes it for trees up to the recorded
    /// depth.
    ///
    /// Deeper trees still fall back to the `/proc` walk, first from the
    /// pid, then from the topmost recorded ancestor, which is the one
    /// most likely to still be alive.
    pub fn is_tracked_with_ancestry(&mut self, pid: i32, ancestry: &[i32]) -> Option<(Uuid, u64)> {
        if let Some(cached) = self.pid_cache.get(&pid) {
            return *cached;
        }
        // A 0 slot means the kernel walk ran past the top of the tree.
        let recorded = ancestry
            .iter()
            .position(|&a| a <= 0)
            .map_or(ancestry, |end| &ancestry[..end]);
        let resolved = self
            .root_in(std::iter::once(pid).chain(recorded.iter().copied()))
            .or_else(|| self.resolve(pid))
            .or_else(|| match recorded.last() {
                Some(&top) if top > 1 => self.resolve(top),
                _ => None,
            });
        self.pid_cache.insert(pid, resolved);
        if let Some((s, seq)) = resolved
            && let Some(tree) = self.trees.get_mut(&(s, seq))
        {
            tree.members.insert(pid);
        }
        resolved
    }

    /// The first tracked tree whose root is one of `pids`.
    fn root_in(&self, pids: impl Iterator<Item = i32>) -> Option<(Uuid, u64)> {
        for p in pids {
            for ((s, seq), tree) in &self.trees {
                if p == tree.root_pid {
                    return Some((*s, *seq));
                }
            }
        }
        None
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

    /// Pids no live process has, so the `/proc` fallback finds nothing
    /// and only the recorded ancestry can attribute the event.
    const GONE_CHILD: i32 = i32::MAX - 1;
    const GONE_SH: i32 = i32::MAX - 2;
    const ROOT: i32 = i32::MAX - 3;

    #[test]
    fn exited_grandchild_is_tracked_through_recorded_ancestry() {
        // #209: `sh -c 'chmod 600 big'` under a shell that forks for the
        // last command. Both chmod and sh are gone when the event is read.
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(209);
        tm.watch(s, 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &[GONE_SH, ROOT, 0, 0]),
            Some((s, 1))
        );
        assert!(tm.trees[&(s, 1)].members.contains(&GONE_CHILD));
    }

    #[test]
    fn parent_alone_does_not_reach_a_grandparent_root() {
        // The AR00.5 behavior this replaces: with only the parent
        // recorded, an exited grandchild is dropped.
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(209);
        tm.watch(s, 1, ROOT);
        assert_eq!(tm.is_tracked_with_ancestry(GONE_CHILD, &[GONE_SH]), None);
    }

    #[test]
    fn direct_child_and_root_are_tracked() {
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(1);
        tm.watch(s, 3, ROOT);
        assert_eq!(tm.is_tracked_with_ancestry(ROOT, &[0]), Some((s, 3)));
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &[ROOT, 1, 0]),
            Some((s, 3))
        );
    }

    #[test]
    fn ancestry_stops_at_the_first_zero() {
        // A 0 slot means the walk ran past the top. Anything after it is
        // not ancestry and must not match.
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(2);
        tm.watch(s, 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &[GONE_SH, 0, ROOT]),
            None
        );
    }

    #[test]
    fn unrelated_ancestry_is_untracked() {
        let mut tm = TreeMap::new();
        tm.watch(Uuid::from_u128(3), 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &[GONE_SH, 1, 0, 0]),
            None
        );
    }

    #[test]
    fn live_process_deeper_than_the_recorded_ancestry_uses_proc() {
        // This test process is alive and its parent chain reaches the
        // test runner's parent, so the /proc fallback finds that root
        // even though no recorded ancestor matches.
        let me = std::process::id() as i32;
        let parent = parent_pid(me).expect("own ppid");
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(4);
        tm.watch(s, 1, parent);
        assert_eq!(tm.is_tracked_with_ancestry(me, &[GONE_SH, 0]), Some((s, 1)));
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
