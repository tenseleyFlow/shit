// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-command accounting of eBPF ring-buffer drops (#229).
//!
//! Every LSM object counts its failed ring-buffer reserves twice: once
//! in a host-wide total, and once per tgid in an LRU map that also
//! holds the process's ancestry at the time of the drop. The readers
//! poll both and queue the per-tgid increases here. At WatchTree and
//! UnwatchTree the request loop attributes the queued increases to
//! commands through the pid trees, the same way it attributes events.
//!
//! A command's loss value is the drops attributed to it plus every drop
//! no tgid entry explains. The second part covers LRU eviction and drops
//! whose process cannot be placed: those are charged to every active
//! command, which is what the host-wide counter did for all drops. So
//! strict mode still refuses whenever a drop could have been the
//! command's, and no longer refuses for a drop that provably was not.

use std::collections::HashMap;
use std::sync::Mutex;

use shit_planner::events::CommandId;

use super::ANCESTRY_DEPTH;
use crate::fanotify::tree::{LossOwner, TreeMap};

/// Drops recorded for one tgid since the previous poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TgidLoss {
    pub tgid: u32,
    /// Parent first, then the tgids above it; 0 past the top.
    pub ancestry: [i32; ANCESTRY_DEPTH + 1],
    pub count: u64,
}

/// The attribution state. Pure: the caller supplies the host-wide total
/// and a classifier.
#[derive(Debug, Default)]
pub struct LossLedger {
    charged: HashMap<CommandId, u64>,
    /// Sum of the per-tgid increases absorbed so far, whoever owned them.
    explained: u64,
    /// Largest shortfall of `explained` against the total seen. The
    /// per-tgid entry is updated before the total, so `explained` can run
    /// ahead of a total read a moment earlier; taking the maximum keeps
    /// that from looking like a loss once the total catches up.
    unexplained: u64,
}

impl LossLedger {
    /// Attribute `pending` and bring the shortfall up to date against
    /// `total`, the host-wide drop count.
    pub fn absorb(
        &mut self,
        total: u64,
        pending: impl IntoIterator<Item = TgidLoss>,
        mut classify: impl FnMut(&TgidLoss) -> LossOwner,
    ) {
        for loss in pending {
            match classify(&loss) {
                LossOwner::Command(session, seq) => {
                    *self.charged.entry(CommandId { session, seq }).or_default() += loss.count;
                    self.explained += loss.count;
                }
                LossOwner::Other => self.explained += loss.count,
                LossOwner::Unknown => {}
            }
        }
        self.unexplained = self.unexplained.max(total.saturating_sub(self.explained));
    }

    /// The monotonic loss value for `command`: compare two readings.
    pub fn value(&self, command: CommandId) -> u64 {
        self.unexplained + self.charged.get(&command).copied().unwrap_or(0)
    }

    pub fn forget(&mut self, command: CommandId) {
        self.charged.remove(&command);
    }
}

static PENDING: Mutex<Vec<TgidLoss>> = Mutex::new(Vec::new());

static LEDGER: Mutex<Option<LossLedger>> = Mutex::new(None);

/// Queue per-tgid increases a reader observed.
pub(crate) fn queue(losses: impl IntoIterator<Item = TgidLoss>) {
    if let Ok(mut q) = PENDING.lock() {
        q.extend(losses);
    }
}

/// Attribute every queued drop through `tree`, then return `command`'s
/// loss value. Call with the tree still watching `command`. Classifying
/// reads no `/proc` (see [`TreeMap::classify_loss`]), so holding the tree
/// lock across this call costs only an in-memory scan.
pub fn ringbuf_loss_value(tree: &TreeMap, command: CommandId) -> u64 {
    let pending = PENDING
        .lock()
        .map(|mut q| std::mem::take(&mut *q))
        .unwrap_or_default();
    let total = super::ringbuf_losses_observed();
    let mut guard = LEDGER.lock().unwrap_or_else(|p| p.into_inner());
    let ledger = guard.get_or_insert_with(LossLedger::default);
    ledger.absorb(total, pending, |l| {
        tree.classify_loss(l.tgid as i32, &l.ancestry)
    });
    ledger.value(command)
}

/// Drop `command`'s attribution once its watch has closed.
pub fn forget_ringbuf_losses(command: CommandId) {
    let mut guard = LEDGER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(l) = guard.as_mut() {
        l.forget(command);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::from_u128(229),
            seq,
        }
    }

    fn loss(tgid: u32, count: u64) -> TgidLoss {
        TgidLoss {
            tgid,
            ancestry: [0; ANCESTRY_DEPTH + 1],
            count,
        }
    }

    /// Owner by tgid: 10 is command 1's, 20 nobody's, 30 unknown.
    fn owner(l: &TgidLoss) -> LossOwner {
        match l.tgid {
            10 => LossOwner::Command(cmd(1).session, 1),
            20 => LossOwner::Other,
            _ => LossOwner::Unknown,
        }
    }

    #[test]
    fn an_unrelated_processs_drops_do_not_charge_the_command() {
        let mut l = LossLedger::default();
        l.absorb(0, [], owner);
        let (a0, b0) = (l.value(cmd(1)), l.value(cmd(2)));
        l.absorb(5, [loss(20, 5)], owner);
        assert_eq!(l.value(cmd(1)) - a0, 0);
        assert_eq!(l.value(cmd(2)) - b0, 0);
    }

    #[test]
    fn a_commands_own_drops_charge_only_it() {
        let mut l = LossLedger::default();
        let (a0, b0) = (l.value(cmd(1)), l.value(cmd(2)));
        l.absorb(3, [loss(10, 3)], owner);
        assert_eq!(l.value(cmd(1)) - a0, 3);
        assert_eq!(l.value(cmd(2)) - b0, 0);
    }

    #[test]
    fn unplaceable_and_evicted_drops_charge_everyone() {
        let mut l = LossLedger::default();
        let (a0, b0) = (l.value(cmd(1)), l.value(cmd(2)));
        // One unknown owner, and two drops no tgid entry reports (LRU
        // eviction).
        l.absorb(4, [loss(30, 1), loss(20, 1)], owner);
        assert_eq!(l.value(cmd(1)) - a0, 3);
        assert_eq!(l.value(cmd(2)) - b0, 3);
    }

    #[test]
    fn per_tgid_counts_running_ahead_of_the_total_are_not_loss() {
        let mut l = LossLedger::default();
        let a0 = l.value(cmd(2));
        // The tgid entry was read after a drop the total had not shown.
        l.absorb(1, [loss(20, 2)], owner);
        assert_eq!(l.value(cmd(2)), a0);
        l.absorb(2, [], owner);
        assert_eq!(l.value(cmd(2)), a0);
    }
}
