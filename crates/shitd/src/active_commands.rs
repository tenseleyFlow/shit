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
    pub fn insert(&self, shell_pid: u32, command: CommandId) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        g.entry(shell_pid).or_default().push(command);
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
