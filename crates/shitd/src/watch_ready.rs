// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR00.5 / task #105 — per-CommandId watch-readiness rendezvous.
//!
//! `shit hook-send pre-exec` (the shell hook) sends a `PreExec` over
//! the hook datagram socket and then -- before returning to the
//! shell -- calls `CtlRequest::WaitWatchReady` to block until the
//! helper has actually finished setting up capture for the new
//! command. The helper signals readiness via
//! `HelperResponse::WatchTreeReady { session, command_seq }`.
//!
//! Both events are asynchronous wrt each other. Three orderings to
//! support:
//!
//!   1. **Wait first, ready later (normal cold path).** The shell
//!      hook's wait arrives before the helper finishes its
//!      `pre_open_tree`. We park a `oneshot::Sender` in the map under
//!      `Pending`; when readiness arrives, we drain it and the
//!      receiver task wakes.
//!   2. **Ready first, wait later (warm path or fast helper).** The
//!      helper finishes before the shell hook's ctl round-trip lands
//!      its WaitWatchReady. We mark `Ready` immediately; the wait
//!      hits the map, sees `Ready`, and returns without sleeping.
//!   3. **Multiple waiters for the same command (defensive).** Two
//!      shell hooks racing on the same (session, seq) -- shouldn't
//!      happen in practice but cheap to support: `Pending` holds a
//!      `Vec<Sender>`, all get drained on readiness.
//!
//! A durable capture refusal also marks the rendezvous failed. This wakes the
//! shell-side wait immediately while preserving the fail-open shell contract;
//! the refusal in the journal is what makes a later undo fail closed.
//! Entries are removed by `UnwatchTree` to keep the map bounded.

use shit_planner::events::CommandId;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::oneshot;

/// State of one (session, command_seq) entry.
enum State {
    /// Helper hasn't signaled WatchTreeReady yet. The Vec is the list
    /// of oneshot senders we'll drain when readiness lands.
    Pending(Vec<oneshot::Sender<Result<(), String>>>),
    /// Helper has signaled. Subsequent waiters complete immediately.
    Ready,
    /// Capture failed before readiness (or became known-incomplete later).
    /// Preserve the first reason so a stray/late Ready cannot erase it.
    Failed(String),
}

/// Per-CommandId readiness map. Cheap to clone (Arc).
pub struct WatchReadyMap {
    inner: Mutex<HashMap<CommandId, State>>,
}

impl WatchReadyMap {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Helper signaled readiness. Drain any pending waiters and flip
    /// the entry to `Ready` so late waiters also complete fast.
    /// Returns `true` when the command is ready, or `false` when a prior
    /// failure was preserved instead.
    pub fn mark_ready(&self, cmd: CommandId) -> bool {
        let mut map = self.inner.lock().unwrap();
        match map.remove(&cmd) {
            Some(State::Failed(reason)) => {
                // A refusal is irreversible for this command. In particular,
                // a helper must not be able to send Ready after an attach or
                // baseline failure and turn incomplete evidence authoritative.
                map.insert(cmd, State::Failed(reason));
                false
            }
            Some(State::Pending(senders)) => {
                map.insert(cmd, State::Ready);
                for sender in senders {
                    // Receiver may have dropped (caller timed out). That's
                    // fine; ignore.
                    let _ = sender.send(Ok(()));
                }
                true
            }
            Some(State::Ready) | None => {
                map.insert(cmd, State::Ready);
                true
            }
        }
    }

    /// Mark capture setup/evidence incomplete and wake pending waiters with a
    /// concrete reason. The first failure wins and cannot be overwritten by a
    /// late readiness notification.
    pub fn mark_failed(&self, cmd: CommandId, reason: impl Into<String>) {
        let mut map = self.inner.lock().unwrap();
        let reason = reason.into();
        match map.remove(&cmd) {
            Some(State::Failed(first_reason)) => {
                map.insert(cmd, State::Failed(first_reason));
            }
            Some(State::Pending(senders)) => {
                map.insert(cmd, State::Failed(reason.clone()));
                for sender in senders {
                    let _ = sender.send(Err(reason.clone()));
                }
            }
            Some(State::Ready) | None => {
                map.insert(cmd, State::Failed(reason));
            }
        }
    }

    /// Shell hook is asking to block until readiness. The receiver resolves to
    /// `Ok(())` on readiness and `Err(reason)` on an explicit refusal. Dropping
    /// the entry (for example, when teardown races a stale waiter) drops the
    /// oneshot sender, which the caller also treats as not-ready.
    pub fn await_ready(&self, cmd: CommandId) -> oneshot::Receiver<Result<(), String>> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(&cmd) {
            Some(State::Ready) => {
                // Already ready; fire the receiver synchronously.
                let _ = tx.send(Ok(()));
            }
            Some(State::Failed(reason)) => {
                let _ = tx.send(Err(reason.clone()));
            }
            Some(State::Pending(senders)) => {
                senders.push(tx);
            }
            None => {
                map.insert(cmd, State::Pending(vec![tx]));
            }
        }
        rx
    }

    /// Drop the entry for a finished command. Called from the
    /// helper's UnwatchTree dispatch in the daemon so the map stays
    /// bounded over a long-running daemon. Any pending senders are
    /// dropped, which fires the receiver with Err -- the caller
    /// (a stale shell hook?) will see "not ready".
    pub fn forget(&self, cmd: CommandId) {
        let _ = self.inner.lock().unwrap().remove(&cmd);
    }
}

impl Default for WatchReadyMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use uuid::Uuid;

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    #[tokio::test]
    async fn ready_after_wait_drains_pending() {
        let map = Arc::new(WatchReadyMap::new());
        let rx = map.await_ready(cmd(1));
        let m2 = Arc::clone(&map);
        tokio::spawn(async move {
            m2.mark_ready(cmd(1));
        });
        rx.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ready_before_wait_completes_immediately() {
        let map = WatchReadyMap::new();
        map.mark_ready(cmd(2));
        let rx = map.await_ready(cmd(2));
        rx.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn multiple_waiters_all_complete() {
        let map = Arc::new(WatchReadyMap::new());
        let rx1 = map.await_ready(cmd(3));
        let rx2 = map.await_ready(cmd(3));
        let m2 = Arc::clone(&map);
        tokio::spawn(async move {
            m2.mark_ready(cmd(3));
        });
        rx1.await.unwrap().unwrap();
        rx2.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forget_after_wait_yields_err() {
        let map = WatchReadyMap::new();
        let rx = map.await_ready(cmd(4));
        map.forget(cmd(4));
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn failure_wakes_waiters_and_is_sticky_against_late_ready() {
        let map = WatchReadyMap::new();
        let rx = map.await_ready(cmd(5));
        map.mark_failed(cmd(5), "baseline incomplete");
        assert_eq!(rx.await.unwrap().unwrap_err(), "baseline incomplete");

        assert!(!map.mark_ready(cmd(5)));
        let late = map.await_ready(cmd(5));
        assert_eq!(late.await.unwrap().unwrap_err(), "baseline incomplete");
    }

    #[tokio::test]
    async fn failure_before_wait_completes_immediately() {
        let map = WatchReadyMap::new();
        map.mark_failed(cmd(6), "attach failed");
        assert_eq!(
            map.await_ready(cmd(6)).await.unwrap().unwrap_err(),
            "attach failed"
        );
    }
}
