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
    /// AR06.2 — `set -o` snapshot: name → value (typically
    /// "on"/"off", sometimes stringly).
    pub opts: std::collections::BTreeMap<String, String>,
    /// AR06.3 — alias snapshot: name → expansion.
    pub aliases: std::collections::BTreeMap<String, String>,
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

    pub fn insert(
        &self,
        key: CommandId,
        pwd: PathBuf,
        opts: std::collections::BTreeMap<String, String>,
        aliases: std::collections::BTreeMap<String, String>,
    ) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        g.insert(
            key,
            ShellStatePre {
                pwd,
                opts,
                aliases,
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

/// Convert the wire-form Vec<(name, value)> pairs to a BTreeMap
/// for canonical ordering + cheap diff.
fn pairs_to_map(pairs: Vec<(String, String)>) -> std::collections::BTreeMap<String, String> {
    pairs.into_iter().collect()
}

/// Stash the pre-command shell state. Called from the daemon's
/// HookMessage::PreExecShellState handler.
pub fn handle_pre(
    stash: &ShellStatePreStash,
    command: CommandId,
    pwd: PathBuf,
    opts: Vec<(String, String)>,
    aliases: Vec<(String, String)>,
) {
    stash.insert(command, pwd, pairs_to_map(opts), pairs_to_map(aliases));
}

/// Take the matching pre-state, diff against post values, journal
/// a ShellStateDiff event when ANY dimension changed (pwd / opts /
/// aliases). No-op when pre is missing (orphan post — TTL expired
/// or hook misordering).
pub fn handle_post(
    stash: &ShellStatePreStash,
    command: CommandId,
    pwd_after: PathBuf,
    opts_after_pairs: Vec<(String, String)>,
    aliases_after_pairs: Vec<(String, String)>,
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
    let opts_after = pairs_to_map(opts_after_pairs);
    let aliases_after = pairs_to_map(aliases_after_pairs);

    let pwd_changed = pre.pwd != pwd_after;
    let opts_diff = diff_string_map(&pre.opts, &opts_after);
    let aliases_diff = diff_optional_map(&pre.aliases, &aliases_after);

    if !pwd_changed && opts_diff.is_empty() && aliases_diff.is_empty() {
        // Nothing to do.
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
            opts: opts_diff,
            aliases: aliases_diff,
            funcs: Vec::new(), // AR06.4 — follow-up
        },
    };
    if let Err(e) = index.put_event(&event) {
        tracing::warn!(err = %e, "shell-state-diff put_event failed");
    }
}

/// Diff two name→value maps. Both sides always have a value
/// (set-opts are always-present). Returns `(name, pre, post)` for
/// names whose values differ.
fn diff_string_map(
    pre: &std::collections::BTreeMap<String, String>,
    post: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let all: std::collections::BTreeSet<&String> = pre.keys().chain(post.keys()).collect();
    for name in all {
        let p = pre.get(name).cloned().unwrap_or_default();
        let q = post.get(name).cloned().unwrap_or_default();
        if p != q {
            out.push((name.clone(), p, q));
        }
    }
    out
}

/// Diff two name→value maps where either side may be missing.
/// Returns `(name, pre, post)` triples for any name present on at
/// least one side with a different value.
fn diff_optional_map(
    pre: &std::collections::BTreeMap<String, String>,
    post: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, Option<String>, Option<String>)> {
    let mut out = Vec::new();
    let all: std::collections::BTreeSet<&String> = pre.keys().chain(post.keys()).collect();
    for name in all {
        let p = pre.get(name).cloned();
        let q = post.get(name).cloned();
        if p != q {
            out.push((name.clone(), p, q));
        }
    }
    out
}
