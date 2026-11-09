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
    /// Processes whose events, and whose descendants' events, are never
    /// attributed (the helper and the daemon).
    excluded: Vec<i32>,
}

impl TreeMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Never attribute `pids` or anything below them.
    pub fn set_excluded(&mut self, pids: Vec<i32>) {
        self.excluded = pids;
        self.pid_cache.clear();
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
    /// program recorded at hook-fire time instead of walking
    /// `/proc/<pid>/stat` at event-consume time.
    ///
    /// `tgid` is the event's process. A thread of the tracked root has
    /// tid != tgid == root, and its `real_parent` is the root's parent,
    /// so the lookup, the cache and `members` are keyed by tgid.
    /// `ancestry` is `task->real_parent->tgid` then each tgid above it,
    /// nearest first, with 0 past the top.
    ///
    /// The ringbuf reader runs async to the syscall. A short-lived tool
    /// (rm, chmod, mkdir) has usually exited by the time its event is
    /// consumed, and its `/proc` entry is gone. AR00.5 recorded only
    /// the parent, which covers a direct child of the tracked shell.
    /// A shell that forks for the last command of `sh -c '...'` (dash
    /// on Ubuntu 24.04) puts the tool two levels down, and the `/proc`
    /// walk then loses the race to the tool's exit (#209).
    ///
    /// A 0 slot means the kernel recorded the whole chain, so the answer
    /// is final and `/proc` is not read: no walk for every untracked
    /// shallow process, and no misattribution through a reused pid.
    /// Only when every slot is filled is the tree deeper than the
    /// record, and then one `/proc` walk continues above the topmost
    /// recorded ancestor.
    ///
    /// The excluded processes (helper, daemon) and their descendants are
    /// never attributed, whether they show up in the record or the walk.
    pub fn is_tracked_with_ancestry(&mut self, tgid: i32, ancestry: &[i32]) -> Option<(Uuid, u64)> {
        if let Some(cached) = self.pid_cache.get(&tgid) {
            return *cached;
        }
        let end = ancestry.iter().position(|&a| a <= 0);
        let recorded = &ancestry[..end.unwrap_or(ancestry.len())];
        let chain = || std::iter::once(tgid).chain(recorded.iter().copied());
        let resolved = if chain().any(|p| self.excluded.contains(&p)) {
            None
        } else if let Some(hit) = self.root_in(chain()) {
            Some(hit)
        } else if end.is_none() {
            match recorded.last() {
                Some(&top) if top > 1 => parent_pid(top).and_then(|above| self.resolve(above)),
                _ => None,
            }
        } else {
            None
        };
        self.pid_cache.insert(tgid, resolved);
        if let Some((s, seq)) = resolved
            && let Some(tree) = self.trees.get_mut(&(s, seq))
        {
            tree.members.insert(tgid);
        }
        resolved
    }

    /// The first tracked tree whose root is one of `pids`.
    fn root_in(&self, pids: impl IntoIterator<Item = i32>) -> Option<(Uuid, u64)> {
        for p in pids {
            for ((s, seq), tree) in &self.trees {
                if p == tree.root_pid {
                    return Some((*s, *seq));
                }
            }
        }
        None
    }

    /// Who owns a ring-buffer drop recorded for `tgid` with the ancestry
    /// BPF read at the time (#229). Unlike event attribution, a drop
    /// that cannot be placed must not be called someone else's: strict
    /// mode charges an [`LossOwner::Unknown`] drop to every active
    /// command. A chain the kernel recorded in full, with no tracked
    /// root in it, belongs to no command. A truncated chain is Unknown:
    /// following it up `/proc` could reach a reused pid and charge the
    /// wrong command. This reads no `/proc`, so it is cheap to call with
    /// the tree locked.
    pub fn classify_loss(&self, tgid: i32, ancestry: &[i32]) -> LossOwner {
        let end = ancestry.iter().position(|&a| a <= 0);
        let recorded = &ancestry[..end.unwrap_or(ancestry.len())];
        let chain = || std::iter::once(tgid).chain(recorded.iter().copied());
        if chain().any(|p| self.excluded.contains(&p)) {
            return LossOwner::Other;
        }
        if let Some((s, seq)) = self.root_in(chain()) {
            return LossOwner::Command(s, seq);
        }
        if end.is_some() {
            LossOwner::Other
        } else {
            LossOwner::Unknown
        }
    }

    /// Walk `/proc/<pid>/stat` up the parent chain from `pid` looking
    /// for a tracked root. An excluded process on the way ends the walk
    /// untracked. Bounded depth so a malicious/cycling proc tree can't
    /// loop us forever (real Linux pid 1 is init; we stop there
    /// regardless).
    fn resolve(&self, pid: i32) -> Option<(Uuid, u64)> {
        const MAX_DEPTH: usize = 64;
        let mut current = pid;
        for _ in 0..MAX_DEPTH {
            if self.excluded.contains(&current) {
                return None;
            }
            if let Some(hit) = self.root_in([current]) {
                return Some(hit);
            }
            match parent_pid(current) {
                Some(0) | Some(1) | None => return None,
                Some(ppid) => current = ppid,
            }
        }
        None
    }
}

/// The owner of a ring-buffer drop, from [`TreeMap::classify_loss`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossOwner {
    /// The tracked command `(session, seq)`.
    Command(Uuid, u64),
    /// A process outside every tracked tree.
    Other,
    /// Could not be placed.
    Unknown,
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

    /// Pids no live process has, so a `/proc` read finds nothing and
    /// only the recorded ancestry can attribute the event.
    const GONE_CHILD: i32 = i32::MAX - 1;
    const GONE_SH: i32 = i32::MAX - 2;
    const ROOT: i32 = i32::MAX - 3;
    const HELPER: i32 = i32::MAX - 4;

    /// A recorded ancestry as the reader builds it: parent first, 9
    /// slots, 0 past the top.
    fn chain(pids: &[i32]) -> [i32; 9] {
        let mut out = [0; 9];
        out[..pids.len()].copy_from_slice(pids);
        out
    }

    /// This test process and its parent, read from /proc. The parent
    /// may be pid 1 (a container); every test below works either way,
    /// because `resolve` checks for a root before it stops at pid 1.
    fn me_and_parent() -> (i32, i32) {
        let me = std::process::id() as i32;
        (me, parent_pid(me).expect("own ppid"))
    }

    #[test]
    fn exited_grandchild_is_tracked_through_recorded_ancestry() {
        // #209: `sh -c 'chmod 600 big'` under a shell that forks for the
        // last command. Both chmod and sh are gone when the event is read.
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(209);
        tm.watch(s, 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &chain(&[GONE_SH, ROOT])),
            Some((s, 1))
        );
        assert!(tm.trees[&(s, 1)].members.contains(&GONE_CHILD));
    }

    #[test]
    fn parent_alone_does_not_reach_a_grandparent_root() {
        // The AR00.5 behavior this replaces: with only the parent
        // recorded, an exited grandchild is dropped.
        let mut tm = TreeMap::new();
        tm.watch(Uuid::from_u128(209), 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &chain(&[GONE_SH])),
            None
        );
    }

    #[test]
    fn direct_child_and_root_are_tracked() {
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(1);
        tm.watch(s, 3, ROOT);
        assert_eq!(tm.is_tracked_with_ancestry(ROOT, &chain(&[])), Some((s, 3)));
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &chain(&[ROOT, 1])),
            Some((s, 3))
        );
    }

    #[test]
    fn thread_of_the_root_is_tracked_by_its_tgid() {
        // A non-leader thread of the tracked shell: its tid is not the
        // root, and its real_parent is the root's parent. The tgid is
        // the root.
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(5);
        tm.watch(s, 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(ROOT, &chain(&[GONE_SH, 1])),
            Some((s, 1))
        );
    }

    #[test]
    fn ancestry_stops_at_the_first_zero() {
        // A 0 slot means the walk ran past the top. Anything after it is
        // not ancestry and must not match.
        let mut tm = TreeMap::new();
        tm.watch(Uuid::from_u128(2), 1, ROOT);
        let mut ancestry = chain(&[GONE_SH]);
        ancestry[2] = ROOT;
        assert_eq!(tm.is_tracked_with_ancestry(GONE_CHILD, &ancestry), None);
    }

    #[test]
    fn unrelated_ancestry_is_untracked() {
        let mut tm = TreeMap::new();
        tm.watch(Uuid::from_u128(3), 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &chain(&[GONE_SH, 1])),
            None
        );
    }

    #[test]
    fn helper_children_are_not_attributed_to_the_command() {
        // dpkg-query run by the helper, which runs under the tracked
        // shell (as in every smoke). The root is in the record, but the
        // helper is below it.
        let mut tm = TreeMap::new();
        tm.set_excluded(vec![HELPER]);
        tm.watch(Uuid::from_u128(6), 1, ROOT);
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &chain(&[HELPER, GONE_SH, ROOT])),
            None
        );
        assert_eq!(tm.is_tracked_with_ancestry(HELPER, &chain(&[ROOT])), None);
    }

    #[test]
    fn complete_ancestry_does_not_read_proc() {
        // This process is alive and its /proc parent is the root. The
        // recorded chain (a 0 slot after GONE_SH) says the kernel saw
        // the whole tree, so /proc is not consulted.
        let (me, parent) = me_and_parent();
        let mut tm = TreeMap::new();
        tm.watch(Uuid::from_u128(7), 1, parent);
        assert_eq!(tm.is_tracked_with_ancestry(me, &chain(&[GONE_SH])), None);
    }

    #[test]
    fn truncated_ancestry_walks_proc_above_the_top() {
        // Every slot filled: the tree is deeper than the record. The
        // walk starts at the parent of the topmost recorded ancestor
        // (this process) and finds the root there.
        let (me, parent) = me_and_parent();
        let s = Uuid::from_u128(8);
        let mut tm = TreeMap::new();
        tm.watch(s, 1, parent);
        let mut ancestry = [GONE_SH; 9];
        ancestry[8] = me;
        assert_eq!(
            tm.is_tracked_with_ancestry(GONE_CHILD, &ancestry),
            Some((s, 1))
        );
    }

    #[test]
    fn proc_walk_stops_at_an_excluded_process() {
        // Same walk, with the process it reaches excluded. Exclusion is
        // checked before the root match, as it is for the record.
        let (me, parent) = me_and_parent();
        let mut tm = TreeMap::new();
        tm.set_excluded(vec![parent]);
        tm.watch(Uuid::from_u128(9), 1, parent);
        let mut ancestry = [GONE_SH; 9];
        ancestry[8] = me;
        assert_eq!(tm.is_tracked_with_ancestry(GONE_CHILD, &ancestry), None);
    }

    #[test]
    fn cache_hit_avoids_resolve() {
        let mut tm = TreeMap::new();
        let s = Uuid::nil();
        // Pre-seed cache with a value that resolve() wouldn't produce.
        tm.pid_cache.insert(54321, Some((s, 99)));
        assert_eq!(tm.is_tracked(54321), Some((s, 99)));
    }

    #[test]
    fn loss_owner_follows_the_recorded_ancestry() {
        // #229: a drop by a gone grandchild of the root is the root's
        // command; a drop by a process whose full chain holds no root is
        // nobody's; a drop under the helper is nobody's.
        let mut tm = TreeMap::new();
        let s = Uuid::from_u128(229);
        tm.watch(s, 4, ROOT);
        tm.set_excluded(vec![HELPER]);
        assert_eq!(
            tm.classify_loss(GONE_CHILD, &chain(&[GONE_SH, ROOT, 1])),
            LossOwner::Command(s, 4)
        );
        assert_eq!(
            tm.classify_loss(GONE_CHILD, &chain(&[GONE_SH, 1])),
            LossOwner::Other
        );
        assert_eq!(
            tm.classify_loss(GONE_CHILD, &chain(&[HELPER, ROOT])),
            LossOwner::Other
        );
    }

    #[test]
    fn truncated_loss_chain_is_unknown() {
        // Every slot filled: nothing recorded says whether a tracked root
        // is above it, and /proc may hold a reused pid there. The chain
        // is this live process, so a /proc walk would find one.
        let mut tm = TreeMap::new();
        let (me, parent) = me_and_parent();
        tm.watch(Uuid::from_u128(229), 5, parent_pid(parent).unwrap_or(1));
        let full = [me; 9];
        assert_eq!(tm.classify_loss(me, &full), LossOwner::Unknown);
    }
}
