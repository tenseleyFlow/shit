// SPDX-License-Identifier: AGPL-3.0-or-later

//! Env-tracking ingestion on the daemon side (S15.4).
//!
//! `shit hook-send pre-exec-env` and `... post-exec-env` produce
//! [`HookMessage::PreExecEnv`] and [`HookMessage::PostExecEnv`]. The
//! handlers below pair them by `(session, seq)`:
//!
//! - `PreExecEnv` arrives carrying only the 32-byte hash plus the
//!   `(session, seq)` key. We stash the hash; the daemon does not
//!   ask the shell to re-send the block on the common no-change
//!   path.
//! - `PostExecEnv` arrives with the full block. We hash it; if the
//!   hash matches the stashed pre, the env didn't change and the
//!   event is dropped. Otherwise we diff against… well, against
//!   nothing yet — the pre-block isn't retained. Stage 1 records
//!   the *post* state plus the pre-hash; the planner's eventual
//!   diff phase needs the pre block too.
//!
//! That last bullet is the gap S15 deliberately doesn't try to
//! close in this sprint: the pre-block-retention scheme (either
//! always-send-on-pre or daemon-asks-on-mismatch) lands together
//! with the capture-runtime pipeline (DR-32). Stage 1 logs what it
//! sees and provides a hook for tests.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::CommandId;

/// TTL for stashed Pre events. Same logic as the pkg-event stash:
/// orphan entries (no matching Post within this window) get evicted
/// by the janitor task.
pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPre {
    pub env_hash: [u8; 32],
    pub ts: Instant,
}

/// In-memory pre-stash keyed by `(session, seq)`. The shell-hook
/// sends one PreExecEnv per command (when env tracking is enabled);
/// the matching PostExecEnv arrives milliseconds-to-seconds later.
pub struct EnvPreStash {
    inner: Mutex<HashMap<CommandId, EnvPre>>,
}

impl EnvPreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key: CommandId, env_hash: [u8; 32]) {
        let mut g = self.inner.lock().unwrap();
        g.insert(
            key,
            EnvPre {
                env_hash,
                ts: Instant::now(),
            },
        );
    }

    pub fn take(&self, key: CommandId) -> Option<EnvPre> {
        let mut g = self.inner.lock().unwrap();
        g.remove(&key)
    }

    /// Drop entries older than `PRE_STASH_TTL`. Returns the number
    /// evicted.
    pub fn sweep_expired(&self) -> usize {
        let mut g = self.inner.lock().unwrap();
        let cutoff = Instant::now()
            .checked_sub(PRE_STASH_TTL)
            .unwrap_or_else(Instant::now);
        let before = g.len();
        g.retain(|_, e| e.ts >= cutoff);
        before - g.len()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

impl Default for EnvPreStash {
    fn default() -> Self {
        Self::new()
    }
}

/// What the post-handler decided about an incoming PostExecEnv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    /// No Pre stashed for this (session, seq) — orphan; logged and
    /// dropped.
    Orphan,
    /// Pre + Post hashes match — env didn't change; dropped.
    Unchanged,
    /// Hashes differ — Stage 1 will record this for the planner.
    /// Carries the parsed post-block as a map so the renderer can
    /// inspect it.
    Changed {
        pre_hash: [u8; 32],
        post_hash: [u8; 32],
    },
}

/// Handle a PreExecEnv message: stash the hash.
pub fn handle_pre(stash: &EnvPreStash, key: CommandId, env_hash: [u8; 32]) {
    stash.insert(key, env_hash);
    tracing::debug!(
        session = %key.session,
        seq = key.seq,
        "env-pre stashed"
    );
}

/// Handle a PostExecEnv message. Returns a [`PostOutcome`] describing
/// what we decided. The actual journal write happens in a follow-up
/// (DR-32) when the (session, seq) → CaptureEvent::EnvDiff binding
/// is in place.
pub fn handle_post(stash: &EnvPreStash, key: CommandId, env_block: &[u8]) -> PostOutcome {
    let pre = match stash.take(key) {
        Some(p) => p,
        None => {
            tracing::warn!(
                session = %key.session,
                seq = key.seq,
                "env-post with no matching pre; dropping (orphan)"
            );
            return PostOutcome::Orphan;
        }
    };
    let post_hash = shit_planner::hash_env_block(env_block);
    if post_hash == pre.env_hash {
        tracing::debug!(
            session = %key.session,
            seq = key.seq,
            "env-post unchanged; dropping"
        );
        return PostOutcome::Unchanged;
    }
    tracing::info!(
        session = %key.session,
        seq = key.seq,
        "env-post changed (DR-32 will journal the diff)"
    );
    PostOutcome::Changed {
        pre_hash: pre.env_hash,
        post_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn cid() -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq: 1,
        }
    }

    #[test]
    fn pre_post_pair_unchanged_when_hashes_match() {
        let stash = EnvPreStash::new();
        let block = b"FOO=bar\0BAZ=qux".as_slice();
        let h = shit_planner::hash_env_block(block);
        handle_pre(&stash, cid(), h);
        let outcome = handle_post(&stash, cid(), block);
        assert_eq!(outcome, PostOutcome::Unchanged);
        assert_eq!(stash.len(), 0, "Post drains the stash");
    }

    #[test]
    fn pre_post_pair_changed_when_hashes_differ() {
        let stash = EnvPreStash::new();
        let pre_h = shit_planner::hash_env_block(b"FOO=bar");
        handle_pre(&stash, cid(), pre_h);
        let outcome = handle_post(&stash, cid(), b"FOO=NEW");
        match outcome {
            PostOutcome::Changed {
                pre_hash,
                post_hash,
            } => {
                assert_eq!(pre_hash, pre_h);
                assert_ne!(post_hash, pre_h);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn orphan_post_is_dropped() {
        let stash = EnvPreStash::new();
        let outcome = handle_post(&stash, cid(), b"FOO=bar");
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn sweep_evicts_old_entries() {
        let stash = EnvPreStash::new();
        // Manually insert with a backdated timestamp.
        {
            let mut g = stash.inner.lock().unwrap();
            g.insert(
                cid(),
                EnvPre {
                    env_hash: [0; 32],
                    ts: Instant::now()
                        .checked_sub(PRE_STASH_TTL + Duration::from_secs(1))
                        .expect("system clock supports subtraction"),
                },
            );
        }
        assert_eq!(stash.sweep_expired(), 1);
        assert_eq!(stash.len(), 0);
    }
}
