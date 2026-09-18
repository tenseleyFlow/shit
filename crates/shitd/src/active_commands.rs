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

use std::collections::HashMap;
use std::sync::Mutex;

use shit_planner::CommandId;

use crate::ancestry::ancestor_chain;

/// In-memory map of shell pid → command stack. Cleared as PostExec
/// arrives for each command.
#[derive(Debug, Default)]
pub struct ActiveCommands {
    /// Per-shell-pid stack of active (session, seq). The stack lets
    /// background jobs (`cmd &`) coexist with foreground commands —
    /// most recent PreExec is at the back; resolution prefers the
    /// most recent (foreground) command.
    inner: Mutex<HashMap<u32, Vec<CommandId>>>,
}

impl ActiveCommands {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a new command has started on `shell_pid`.
    ///
    /// Returns `false` when the exact command identity is already active under
    /// any shell. Duplicate PreExec delivery must not create a second stack
    /// entry that survives the matching PostExec.
    pub fn insert(&self, shell_pid: u32, command: CommandId) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        if g.values().any(|stack| stack.contains(&command)) {
            return false;
        }
        g.entry(shell_pid).or_default().push(command);
        true
    }

    /// Remove a command on PostExec. Matches by `(session, seq)` so
    /// out-of-order completion of backgrounded commands works.
    /// Returns `true` if the command was removed; `false` if it was
    /// already gone (orphan PostExec — already logged as a warning
    /// elsewhere).
    #[allow(dead_code)]
    pub fn remove(&self, shell_pid: u32, command: CommandId) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(stack) = g.get_mut(&shell_pid) else {
            return false;
        };
        let Some(idx) = stack.iter().position(|c| *c == command) else {
            return false;
        };
        stack.remove(idx);
        if stack.is_empty() {
            g.remove(&shell_pid);
        }
        true
    }

    /// Find the shell pid that owns an exact command. This is a recovery path
    /// for PostExec when the durable command row could not be read; normal
    /// finalization already has the pid from `CommandRecord`.
    pub fn shell_pid_for(&self, command: CommandId) -> Option<u32> {
        let g = self.inner.lock().ok()?;
        g.iter()
            .find_map(|(pid, stack)| stack.contains(&command).then_some(*pid))
    }

    /// Remove an exact command without requiring its shell pid. Used only on
    /// close/error paths so a missing durable command row cannot leave stale
    /// attribution state behind.
    pub fn remove_command(&self, command: CommandId) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let owner = g.iter().find_map(|(pid, stack)| {
            stack
                .iter()
                .position(|candidate| *candidate == command)
                .map(|index| (*pid, index))
        });
        let Some((pid, index)) = owner else {
            return false;
        };
        let stack = g
            .get_mut(&pid)
            .expect("owner was discovered while holding the same map lock");
        stack.remove(index);
        if stack.is_empty() {
            g.remove(&pid);
        }
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
        for pid in chain {
            if let Some(stack) = g.get(&pid)
                && let Some(cmd) = stack.last()
            {
                return Some(*cmd);
            }
        }
        None
    }

    /// Verify that `emitter_pid` descends from the shell that owns one exact
    /// command identity. Unlike [`Self::resolve_by_descendant`], this does not
    /// select the top of a shell's active stack: an exported command identity
    /// carried by a background wrapper must continue to bind to that command
    /// even after a newer foreground `PreExec` is pushed.
    pub fn resolve_exact_by_descendant(
        &self,
        emitter_pid: u32,
        expected: CommandId,
    ) -> Option<CommandId> {
        let chain = ancestor_chain(emitter_pid);
        let g = self.inner.lock().ok()?;
        chain.into_iter().find_map(|pid| {
            g.get(&pid)
                .is_some_and(|stack| stack.contains(&expected))
                .then_some(expected)
        })
    }

    /// Number of shell pids currently with an active command. For
    /// metrics / debug only. Wired to `shit metrics` in a later DR.
    #[allow(dead_code)]
    pub fn tracked_shell_count(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Number of commands in flight across all shells.
    #[allow(dead_code)]
    pub fn active_command_count(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }

    /// Deterministic, de-duplicated snapshot of every command currently in
    /// flight. Used by process-wide capture health failures (for example, a
    /// helper disconnect) that must refuse all affected commands at once.
    pub fn snapshot(&self) -> Vec<CommandId> {
        self.inner
            .lock()
            .map(|g| {
                g.values()
                    .flat_map(|stack| stack.iter().copied())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
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
        assert!(a.insert(1234, cmd(1)));
        assert_eq!(a.tracked_shell_count(), 1);
        assert_eq!(a.active_command_count(), 1);
        assert!(a.remove(1234, cmd(1)));
        assert_eq!(a.tracked_shell_count(), 0);
        assert_eq!(a.active_command_count(), 0);
    }

    #[test]
    fn duplicate_command_identity_is_not_pushed_twice() {
        let a = ActiveCommands::new();
        assert!(a.insert(1234, cmd(1)));
        assert!(!a.insert(1234, cmd(1)));
        assert!(!a.insert(5678, cmd(1)));
        assert_eq!(a.active_command_count(), 1);
        assert!(a.remove_command(cmd(1)));
        assert_eq!(a.active_command_count(), 0);
        assert!(!a.remove_command(cmd(1)));
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
    fn command_keyed_lookup_and_removal_do_not_need_durable_pid() {
        let a = ActiveCommands::new();
        a.insert(1234, cmd(1));
        a.insert(1234, cmd(2));
        assert_eq!(a.shell_pid_for(cmd(1)), Some(1234));
        assert!(a.remove_command(cmd(1)));
        assert_eq!(a.shell_pid_for(cmd(1)), None);
        assert_eq!(a.shell_pid_for(cmd(2)), Some(1234));
        assert!(a.remove_command(cmd(2)));
        assert_eq!(a.tracked_shell_count(), 0);
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
    fn exact_resolution_binds_background_identity_not_stack_top() {
        let a = ActiveCommands::new();
        let shell_pid = std::process::id();
        let background = cmd(1);
        let foreground = cmd(2);
        a.insert(shell_pid, background);
        a.insert(shell_pid, foreground);

        assert_eq!(a.resolve_by_descendant(shell_pid), Some(foreground));
        assert_eq!(
            a.resolve_exact_by_descendant(shell_pid, background),
            Some(background)
        );
        assert_eq!(
            a.resolve_exact_by_descendant(shell_pid, foreground),
            Some(foreground)
        );
        assert_eq!(a.resolve_exact_by_descendant(shell_pid, cmd(3)), None);
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

    #[test]
    fn snapshot_is_deduplicated_and_deterministic() {
        let a = ActiveCommands::new();
        a.insert(2000, cmd(3));
        a.insert(1000, cmd(2));
        a.insert(1000, cmd(1));
        a.insert(3000, cmd(2));

        assert_eq!(a.snapshot(), vec![cmd(1), cmd(2), cmd(3)]);
    }
}
