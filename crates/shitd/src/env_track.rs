// SPDX-License-Identifier: AGPL-3.0-or-later

//! Env-tracking ingestion on the daemon side (S15.4, DR-32).
//!
//! `shit hook-send pre-exec-env` and `... post-exec-env` produce
//! [`HookMessage::PreExecEnv`] and [`HookMessage::PostExecEnv`]. The
//! handlers below pair them by `(session, seq)`:
//!
//! - `PreExecEnv` arrives with the full pre-command env block. We
//!   stash both the hash (for cheap unchanged-check) and the block
//!   bytes (for diff computation).
//! - `PostExecEnv` arrives with the post-command block. We hash it;
//!   if the hash matches the stashed pre, env is unchanged and the
//!   event is dropped. Otherwise we compute the diff via
//!   [`shit_planner::diff_env_blocks`] and write a
//!   [`CaptureEventKind::EnvDiff`] under the matching `(session, seq)`.
//!
//! Env events arrive with `(session, seq)` already known (from the
//! shell-hook side), so unlike pkg/svc/net/proc/db this tier doesn't
//! need an ancestry lookup.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::{CommandId, EnvFilter};
use shit_store::Index;

/// TTL for stashed Pre events. Same logic as the pkg-event stash:
/// orphan entries (no matching Post within this window) get evicted
/// by the janitor task.
pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPre {
    pub env_hash: [u8; 32],
    /// Pre-command env block bytes (DR-32). Retained so the
    /// post-handler can compute a real `EnvDiff` rather than just
    /// flagging "changed."
    pub env_block: Vec<u8>,
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

    pub fn insert(&self, key: CommandId, env_block: Vec<u8>) {
        let env_hash = shit_planner::hash_env_block(&env_block);
        let mut g = self.inner.lock().unwrap();
        g.insert(
            key,
            EnvPre {
                env_hash,
                env_block,
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
    /// Hashes differ AND the diff has at least one non-filtered key —
    /// DR-32 journals a `CaptureEvent::EnvDiff` under `(session, seq)`.
    Changed {
        pre_hash: [u8; 32],
        post_hash: [u8; 32],
        added: usize,
        removed: usize,
        modified: usize,
    },
}

/// Handle a PreExecEnv message: stash the pre-block.
pub fn handle_pre(stash: &EnvPreStash, key: CommandId, env_block: Vec<u8>) {
    stash.insert(key, env_block);
    tracing::debug!(
        session = %key.session,
        seq = key.seq,
        "env-pre stashed"
    );
}

/// Handle a PostExecEnv message. Returns a [`PostOutcome`].
///
/// On `Changed`: writes a [`CaptureEventKind::EnvDiff`] to `index`
/// under `(session, seq)`. The diff respects the filter's ignore and
/// redaction rules — ignored vars are dropped, redact-marked vars
/// have their values replaced with the redaction token. The renderer
/// applies the filter again at display time for defence-in-depth.
pub fn handle_post(
    stash: &EnvPreStash,
    key: CommandId,
    env_block: &[u8],
    filter: &EnvFilter,
    index: &Index,
) -> PostOutcome {
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
    // DR-32: compute the diff and journal it. `diff_env_blocks`
    // applies the filter (ignore + redact) inline.
    let diff = shit_planner::diff_env_blocks(&pre.env_block, env_block, filter);
    if diff.is_empty() {
        // Hash differed but the user-visible diff is empty — every
        // changed var is filter-ignored (e.g. a tool only touched
        // OLDPWD). Drop.
        tracing::debug!(
            session = %key.session,
            seq = key.seq,
            "env-post hash changed but filtered diff is empty; dropping"
        );
        return PostOutcome::Unchanged;
    }
    let kind = CaptureEventKind::EnvDiff {
        added: diff.added.clone(),
        removed: diff.removed.clone(),
        modified: diff.modified.clone(),
    };
    let ev = CaptureEvent {
        id: EventId(0), // sqlite assigns
        command: key,
        ts: crate::server::next_ts(),
        partial: false,
        kind,
    };
    match index.put_event(&ev) {
        Ok(eid) => tracing::info!(
            session = %key.session,
            seq = key.seq,
            %eid,
            added = diff.added.len(),
            removed = diff.removed.len(),
            modified = diff.modified.len(),
            "env-post journaled (DR-32)"
        ),
        Err(e) => tracing::warn!(
            err = %e,
            session = %key.session,
            seq = key.seq,
            "env-post journal write failed"
        ),
    }
    PostOutcome::Changed {
        pre_hash: pre.env_hash,
        post_hash,
        added: diff.added.len(),
        removed: diff.removed.len(),
        modified: diff.modified.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{CommandRecord, PlannerStore, TimePoint};
    use uuid::Uuid;

    fn cid() -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq: 1,
        }
    }

    /// Build a temp-dir Index pre-populated with the test session
    /// and command so put_event() doesn't FK-fail.
    fn fixture() -> (tempfile::TempDir, Index) {
        let tmp = tempfile::tempdir().unwrap();
        let idx = Index::open(tmp.path().join("index.sqlite")).unwrap();
        idx.put_session(Uuid::nil(), "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&CommandRecord {
            command: cid(),
            cmd_string: None,
            cwd: std::path::PathBuf::from("/"),
            pid: 0,
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(0, 0),
            ended_at: None,
            exit_code: None,
            event_ids: vec![],
        })
        .unwrap();
        (tmp, idx)
    }

    #[test]
    fn pre_post_pair_unchanged_when_hashes_match() {
        let (_tmp, idx) = fixture();
        let stash = EnvPreStash::new();
        let block = b"FOO=bar\0BAZ=qux".to_vec();
        handle_pre(&stash, cid(), block.clone());
        let outcome = handle_post(&stash, cid(), &block, &EnvFilter::default(), &idx);
        assert_eq!(outcome, PostOutcome::Unchanged);
        assert_eq!(stash.len(), 0, "Post drains the stash");
        // No event journaled.
        assert_eq!(idx.events_for_command(cid()).len(), 0);
    }

    #[test]
    fn pre_post_pair_changed_writes_env_diff_event() {
        let (_tmp, idx) = fixture();
        let stash = EnvPreStash::new();
        let pre_block = b"FOO=bar".to_vec();
        let pre_h = shit_planner::hash_env_block(&pre_block);
        handle_pre(&stash, cid(), pre_block);
        let outcome = handle_post(&stash, cid(), b"FOO=NEW", &EnvFilter::default(), &idx);
        match outcome {
            PostOutcome::Changed {
                pre_hash,
                post_hash,
                added,
                removed,
                modified,
            } => {
                assert_eq!(pre_hash, pre_h);
                assert_ne!(post_hash, pre_h);
                assert_eq!(added, 0);
                assert_eq!(removed, 0);
                assert_eq!(modified, 1);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
        let events = idx.events_for_command(cid());
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            CaptureEventKind::EnvDiff {
                added,
                removed,
                modified,
            } => {
                assert!(added.is_empty());
                assert!(removed.is_empty());
                assert_eq!(modified.get("FOO").unwrap().0, "bar");
                assert_eq!(modified.get("FOO").unwrap().1, "NEW");
            }
            other => panic!("expected EnvDiff, got {other:?}"),
        }
    }

    #[test]
    fn orphan_post_is_dropped() {
        let (_tmp, idx) = fixture();
        let stash = EnvPreStash::new();
        let outcome = handle_post(&stash, cid(), b"FOO=bar", &EnvFilter::default(), &idx);
        assert_eq!(outcome, PostOutcome::Orphan);
        assert_eq!(idx.events_for_command(cid()).len(), 0);
    }

    #[test]
    fn filtered_only_diff_is_treated_as_unchanged() {
        let (_tmp, idx) = fixture();
        let stash = EnvPreStash::new();
        // Pre is empty; Post adds only OLDPWD, which the default
        // filter ignores. User shouldn't see "changed" and no event
        // should be journaled.
        handle_pre(&stash, cid(), b"".to_vec());
        let outcome = handle_post(&stash, cid(), b"OLDPWD=/tmp", &EnvFilter::default(), &idx);
        assert_eq!(outcome, PostOutcome::Unchanged);
        assert_eq!(idx.events_for_command(cid()).len(), 0);
    }

    #[test]
    fn redacted_var_value_does_not_leak_into_journal() {
        let (_tmp, idx) = fixture();
        let stash = EnvPreStash::new();
        handle_pre(&stash, cid(), b"".to_vec());
        // GITHUB_TOKEN is in the default redact list.
        handle_post(
            &stash,
            cid(),
            b"GITHUB_TOKEN=ghp_supersecret",
            &EnvFilter::default(),
            &idx,
        );
        let events = idx.events_for_command(cid());
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            CaptureEventKind::EnvDiff { added, .. } => {
                let v = added.get("GITHUB_TOKEN").expect("token var present");
                assert_ne!(v, "ghp_supersecret", "value MUST be redacted in journal");
            }
            other => panic!("expected EnvDiff, got {other:?}"),
        }
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
                    env_block: Vec::new(),
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
