// SPDX-License-Identifier: AGPL-3.0-or-later

//! Active-command map (DR-25 prerequisite).
//!
//! Maps `shell_pid → (session_id, seq)` for every command currently
//! between [`HookMessage::PreExec`] and [`HookMessage::PostExec`].
//! Tier-event handlers (pkg/env/svc/net/proc/db) call
//! [`ActiveCommands::resolve_by_descendant`] with the emitter's pid;
//! it walks the ancestor chain (DR-24's
//! [`crate::ancestry::ancestor_chain`]) and returns the
//! `(session, seq)` of the first ancestor that's a tracked shell.
//!
//! ## Why in-memory and not the sqlite index
//!
//! The index has the durable record, but tier-event binding is a
//! hot-path lookup that happens *while a command is running* — the
//! sqlite group-commit batching means the `PreExec` insert may not
//! yet be visible by the time a tier event arrives milliseconds
//! later. The in-memory map closes that gap with a `Mutex<HashMap>`
//! that's updated synchronously inside the `server::handle` body.
//!
//! ## Concurrency model
//!
//! - PreExec inserts (atomic on the daemon's main task).
//! - PostExec removes.
//! - Tier-event handlers read.
//! - Single Mutex is fine — these handlers are not on a critical
//!   per-syscall path.
//!
//! ## Background commands
//!
//! A shell can have multiple commands in-flight (`cmd &`). The map
//! stores **a stack per shell pid** so the most recent PreExec
//! "wins" for ancestry resolution. PostExec removes the matching
//! entry by `(session, seq)` — not just the latest — so two
//! out-of-order backgrounded commands resolve cleanly.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use shit_planner::CommandId;

use crate::ancestry::ancestor_chain;

/// A cap on remembered emitters per command. A command that spawns more
/// shim-notifying processes than this loses the exit fallback for the
/// extras; the walk still attributes them while they are alive.
const MAX_EMITTERS_PER_COMMAND: usize = 4096;

/// In-memory map of shell pid → command stack. Cleared as PostExec
/// arrives for each command.
#[derive(Debug, Default)]
pub struct ActiveCommands {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Per-shell-pid stack of active (session, seq). The stack lets
    /// background jobs (`cmd &`) coexist with foreground commands —
    /// most recent PreExec is at the back; resolution prefers the
    /// most recent (foreground) command.
    stacks: HashMap<u32, Vec<CommandId>>,
    /// Per active command, the shim emitters a walk has attributed to
    /// it, as `(pid, process epoch)`. An emitter that sends several
    /// notifications (rsync renaming one temp file per destination) may
    /// exit, or lose an ancestor, before a later walk finishes; this
    /// keeps its later notifications bound to the same command (#202).
    /// The epoch comes from the shim, so a reused pid cannot match, even
    /// after the emitter is gone and could no longer be stat'd.
    emitters: HashMap<CommandId, HashSet<(u32, u64)>>,
}

impl ActiveCommands {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a new command has started on `shell_pid`.
    pub fn insert(&self, shell_pid: u32, command: CommandId) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        g.stacks.entry(shell_pid).or_default().push(command);
    }

    /// Remove a command on PostExec. Matches by `(session, seq)` so
    /// out-of-order completion of backgrounded commands works.
    /// Returns `true` if the command was removed; `false` if it was
    /// already gone (orphan PostExec — already logged as a warning
    /// elsewhere).
    pub fn remove(&self, shell_pid: u32, command: CommandId) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(stack) = g.stacks.get_mut(&shell_pid) else {
            return false;
        };
        let Some(idx) = stack.iter().position(|c| *c == command) else {
            return false;
        };
        stack.remove(idx);
        if stack.is_empty() {
            g.stacks.remove(&shell_pid);
        }
        g.emitters.remove(&command);
        true
    }

    /// Resolve the active command for an emitter pid. Walks the
    /// emitter's ancestor chain; the first ancestor with active
    /// commands is the owning shell. Returns the *most recent* of
    /// that shell's stack (the foreground command — backgrounded
    /// commands are intentionally lower-priority).
    ///
    /// Returns `None` if no ancestor is in the active map (the
    /// caller drops the event as "orphan / not attributable").
    pub fn resolve_by_descendant(&self, emitter_pid: u32) -> Option<CommandId> {
        let chain = ancestor_chain(emitter_pid);
        let g = self.inner.lock().ok()?;
        g.tracked_in(&chain)
    }

    /// [`Self::resolve_by_descendant`] for a shim notification, which
    /// carries the emitter's process epoch. If the walk finds no tracked
    /// shell, the notification still binds to the command an earlier
    /// walk found for this same process. An epoch of 0 is no identity
    /// and never binds.
    pub fn resolve_shim_emitter(&self, emitter_pid: u32, epoch: u64) -> Option<CommandId> {
        self.resolve_chain(emitter_pid, epoch, &ancestor_chain(emitter_pid))
    }

    fn resolve_chain(&self, emitter_pid: u32, epoch: u64, chain: &[u32]) -> Option<CommandId> {
        let mut g = self.inner.lock().ok()?;
        let key = (emitter_pid, epoch);
        if let Some(cmd) = g.tracked_in(chain) {
            if epoch != 0 {
                let seen = g.emitters.entry(cmd).or_default();
                if seen.len() < MAX_EMITTERS_PER_COMMAND {
                    seen.insert(key);
                }
            }
            return Some(cmd);
        }
        if epoch == 0 {
            return None;
        }
        // Entries exist only for active commands: remove() drops them
        // under this same lock. Newest command wins if a long-lived
        // emitter was seen in more than one.
        g.emitters
            .iter()
            .filter(|(_, seen)| seen.contains(&key))
            .map(|(cmd, _)| *cmd)
            .max_by_key(|cmd| cmd.seq)
    }

    /// Number of shell pids currently with an active command. For
    /// metrics / debug only. Wired to `shit metrics` in a later DR.
    #[allow(dead_code)]
    pub fn tracked_shell_count(&self) -> usize {
        self.inner.lock().map(|g| g.stacks.len()).unwrap_or(0)
    }

    /// Number of commands in flight across all shells.
    #[allow(dead_code)]
    pub fn active_command_count(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.stacks.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }
}

impl Inner {
    fn tracked_in(&self, chain: &[u32]) -> Option<CommandId> {
        chain
            .iter()
            .find_map(|pid| self.stacks.get(pid).and_then(|stack| stack.last()).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    #[test]
    fn insert_and_remove_round_trip() {
        let a = ActiveCommands::new();
        a.insert(1234, cmd(1));
        assert_eq!(a.tracked_shell_count(), 1);
        assert_eq!(a.active_command_count(), 1);
        assert!(a.remove(1234, cmd(1)));
        assert_eq!(a.tracked_shell_count(), 0);
        assert_eq!(a.active_command_count(), 0);
    }

    #[test]
    fn remove_unknown_returns_false() {
        let a = ActiveCommands::new();
        assert!(!a.remove(1234, cmd(1)));
        a.insert(1234, cmd(1));
        // Wrong seq.
        assert!(!a.remove(1234, cmd(2)));
        // Wrong pid.
        assert!(!a.remove(9999, cmd(1)));
    }

    #[test]
    fn stack_preserves_background_command_after_foreground_finishes() {
        let a = ActiveCommands::new();
        // Backgrounded command first.
        a.insert(1234, cmd(1));
        // Foreground command second.
        a.insert(1234, cmd(2));
        // Foreground completes.
        assert!(a.remove(1234, cmd(2)));
        // Background is still in flight; resolve_by_descendant on a
        // child of 1234 should pick it up.
        assert_eq!(a.active_command_count(), 1);
    }

    #[test]
    fn resolve_by_descendant_finds_self_when_self_is_tracked() {
        let a = ActiveCommands::new();
        let pid = std::process::id();
        a.insert(pid, cmd(7));
        assert_eq!(a.resolve_by_descendant(pid), Some(cmd(7)));
    }

    #[test]
    fn resolve_by_descendant_returns_none_when_no_ancestor_tracked() {
        let a = ActiveCommands::new();
        // Insert something for an unrelated pid that's definitely
        // not in our ancestry.
        a.insert(u32::MAX - 1, cmd(1));
        assert_eq!(a.resolve_by_descendant(std::process::id()), None);
    }

    const EPOCH: u64 = 1_000;

    fn bound() -> ActiveCommands {
        let a = ActiveCommands::new();
        a.insert(100, cmd(1));
        assert_eq!(a.resolve_chain(300, EPOCH, &[300, 200, 100]), Some(cmd(1)));
        a
    }

    #[test]
    fn exited_emitter_keeps_its_earlier_binding() {
        // #202: rsync renames three temp files and exits right after the
        // last one; the later walk stops at the dead pid.
        assert_eq!(bound().resolve_chain(300, EPOCH, &[300]), Some(cmd(1)));
    }

    #[test]
    fn ancestor_death_mid_walk_keeps_the_binding() {
        // The walk stops at a dead intermediate; the start pid resolved.
        assert_eq!(bound().resolve_chain(300, EPOCH, &[300, 200]), Some(cmd(1)));
    }

    #[test]
    fn reparented_emitter_keeps_the_binding() {
        // The parent exited and the emitter now sits directly under init.
        assert_eq!(bound().resolve_chain(300, EPOCH, &[300]), Some(cmd(1)));
    }

    #[test]
    fn reused_pid_does_not_match_a_binding() {
        // Same pid, later process, both alive and already exited: dropped.
        let a = bound();
        assert_eq!(a.resolve_chain(300, EPOCH + 1, &[300, 50]), None);
        assert_eq!(a.resolve_chain(300, EPOCH + 1, &[300]), None);
    }

    #[test]
    fn emitter_without_earlier_binding_is_dropped() {
        let a = ActiveCommands::new();
        a.insert(100, cmd(1));
        assert_eq!(a.resolve_chain(300, EPOCH, &[300]), None);
    }

    #[test]
    fn zero_epoch_never_binds() {
        let a = ActiveCommands::new();
        a.insert(100, cmd(1));
        assert_eq!(a.resolve_chain(300, 0, &[300, 100]), Some(cmd(1)));
        assert_eq!(a.resolve_chain(300, 0, &[300]), None);
    }

    #[test]
    fn binding_ends_with_its_command() {
        let a = bound();
        assert!(a.remove(100, cmd(1)));
        a.insert(100, cmd(2));
        assert_eq!(a.resolve_chain(300, EPOCH, &[300]), None);
        assert!(a.inner.lock().unwrap().emitters.is_empty());
    }

    #[test]
    fn long_lived_emitter_binds_to_its_newest_command() {
        let a = bound();
        a.insert(100, cmd(2));
        assert_eq!(a.resolve_chain(300, EPOCH, &[300, 100]), Some(cmd(2)));
        assert_eq!(a.resolve_chain(300, EPOCH, &[300]), Some(cmd(2)));
    }

    #[test]
    fn emitters_per_command_are_bounded() {
        let a = ActiveCommands::new();
        a.insert(100, cmd(1));
        let extra = MAX_EMITTERS_PER_COMMAND as u32 + 10;
        for pid in 1000..1000 + extra {
            assert_eq!(a.resolve_chain(pid, EPOCH, &[pid, 100]), Some(cmd(1)));
        }
        let g = a.inner.lock().unwrap();
        assert_eq!(g.emitters[&cmd(1)].len(), MAX_EMITTERS_PER_COMMAND);
    }

    #[test]
    fn walk_still_attributes_past_the_cap() {
        let a = ActiveCommands::new();
        a.insert(100, cmd(1));
        for pid in 1000..1000 + MAX_EMITTERS_PER_COMMAND as u32 {
            a.resolve_chain(pid, EPOCH, &[pid, 100]);
        }
        assert_eq!(a.resolve_chain(9, EPOCH, &[9, 100]), Some(cmd(1)));
        assert_eq!(a.resolve_chain(9, EPOCH, &[9]), None);
    }

    #[test]
    fn resolve_by_descendant_prefers_most_recent_in_stack() {
        let a = ActiveCommands::new();
        let pid = std::process::id();
        a.insert(pid, cmd(1));
        a.insert(pid, cmd(2));
        a.insert(pid, cmd(3));
        assert_eq!(a.resolve_by_descendant(pid), Some(cmd(3)));
    }

    #[test]
    fn remove_in_arbitrary_order_resolves_remaining_correctly() {
        let a = ActiveCommands::new();
        let pid = std::process::id();
        a.insert(pid, cmd(1));
        a.insert(pid, cmd(2));
        a.insert(pid, cmd(3));
        // Remove the middle one.
        assert!(a.remove(pid, cmd(2)));
        // Top of stack is still cmd(3).
        assert_eq!(a.resolve_by_descendant(pid), Some(cmd(3)));
    }

    #[test]
    fn empty_shell_entry_is_cleaned_up_on_last_remove() {
        let a = ActiveCommands::new();
        a.insert(1234, cmd(1));
        a.insert(1234, cmd(2));
        assert_eq!(a.tracked_shell_count(), 1);
        a.remove(1234, cmd(1));
        assert_eq!(a.tracked_shell_count(), 1);
        a.remove(1234, cmd(2));
        assert_eq!(a.tracked_shell_count(), 0);
    }

    #[test]
    fn concurrent_insert_remove_does_not_lose_data() {
        let a = std::sync::Arc::new(ActiveCommands::new());
        let a2 = std::sync::Arc::clone(&a);
        let pid = std::process::id();
        let h = std::thread::spawn(move || {
            for i in 0..500 {
                let c = CommandId {
                    session: Uuid::nil(),
                    seq: i,
                };
                a2.insert(pid + 1, c);
                a2.remove(pid + 1, c);
            }
        });
        for i in 500..1000 {
            let c = CommandId {
                session: Uuid::nil(),
                seq: i,
            };
            a.insert(pid + 2, c);
            a.remove(pid + 2, c);
        }
        h.join().unwrap();
        assert_eq!(a.active_command_count(), 0);
    }
}
