// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR06.1 — shell-state ingestion (pwd diff for cd-undo).
//!
//! Mirrors `env_track` exactly: `PreExecShellState` stashes the
//! pre-command pwd by `(session, seq)`, `PostExecShellState` looks
//! it up + diffs against the post pwd + emits a
//! `CaptureEventKind::ShellStateDiff` if non-empty. The planner
//! then maps that to `InverseOp::ShellStateRestore` with a pre-
//! rendered `cd '<pwd_before>'` snippet.
//!
//! v1 ships pwd only. Aliases / set-opts / function defs come
//! later (additive on the `Snapshot` shape in `shit_shell::state`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::CommandId;
use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::time::TimePoint;
use shit_store::Index;

/// Same TTL as the env pre-stash. An orphan Pre (no Post within
/// the window) gets evicted by the daemon's janitor task.
pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct ShellStatePre {
    pub pwd: PathBuf,
    pub ts: Instant,
}

pub struct ShellStatePreStash {
    inner: Mutex<HashMap<CommandId, ShellStatePre>>,
}

impl ShellStatePreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key: CommandId, pwd: PathBuf) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        g.insert(
            key,
            ShellStatePre {
                pwd,
                ts: Instant::now(),
            },
        );
    }

    pub fn take(&self, key: CommandId) -> Option<ShellStatePre> {
        self.inner.lock().ok()?.remove(&key)
    }

    /// Drop entries older than `PRE_STASH_TTL`. Called by the
    /// daemon's janitor; returns the eviction count.
    #[allow(dead_code)]
    pub fn sweep_expired(&self) -> usize {
        let Ok(mut g) = self.inner.lock() else {
            return 0;
        };
        let now = Instant::now();
        let before = g.len();
        g.retain(|_, v| now.saturating_duration_since(v.ts) < PRE_STASH_TTL);
        before - g.len()
    }
}

impl Default for ShellStatePreStash {
    fn default() -> Self {
        Self::new()
    }
}

/// Stash the pre-command pwd. Called from the daemon's
/// HookMessage::PreExecShellState handler.
pub fn handle_pre(stash: &ShellStatePreStash, command: CommandId, pwd: PathBuf) {
    stash.insert(command, pwd);
}

/// Take the matching pre-pwd, diff against post-pwd, journal a
/// ShellStateDiff event when they differ. No-op when the pre is
/// missing (orphan post — TTL expired or hook misordering).
pub fn handle_post(
    stash: &ShellStatePreStash,
    command: CommandId,
    pwd_after: PathBuf,
    index: &Index,
    ts: TimePoint,
) {
    let Some(pre) = stash.take(command) else {
        tracing::debug!(
            session = %command.session,
            seq = command.seq,
            "post-exec-shell-state with no matching pre; dropping"
        );
        return;
    };
    if pre.pwd == pwd_after {
        // No change → no event.
        return;
    }
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::ShellStateDiff {
            pwd_before: pre.pwd,
            pwd_after,
        },
    };
    if let Err(e) = index.put_event(&event) {
        tracing::warn!(err = %e, "shell-state-diff put_event failed");
    }
}
