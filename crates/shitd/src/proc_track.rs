// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-lifecycle hook ingestion on the daemon side (S18.6).
//!
//! Same shape as `pkg` / `env_track` / `svc_track` / `net_track`:
//! Pre stash by `(tool, pid)` (the helper pid that wrapped the
//! kill), Post correlates by the same key. The Pre snapshot
//! captures one [`ProcSnapshot`] per target; the Post diff is
//! "which targets are still in the new snapshot list?" — survived
//! pids stay, missing pids are presumed killed.
//!
//! Journal-write under `(session, seq)` is DR-53.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_proto::{ProcEventReq, ProcSnapshot, ProcToolWire};

pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcKey {
    pub tool: ProcToolWire,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct ProcPre {
    pub targets: Vec<ProcSnapshot>,
    pub argv: Vec<String>,
    pub ts: Instant,
}

pub struct ProcPreStash {
    inner: Mutex<HashMap<ProcKey, ProcPre>>,
}

impl ProcPreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, key: ProcKey, pre: ProcPre) {
        self.inner.lock().unwrap().insert(key, pre);
    }
    pub fn take(&self, key: &ProcKey) -> Option<ProcPre> {
        self.inner.lock().unwrap().remove(key)
    }
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

impl Default for ProcPreStash {
    fn default() -> Self {
        Self::new()
    }
}

/// Post outcome per target. The planner consumes a `Killed`
/// snapshot to render the restart suggestion; `Survived` is logged
/// for transparency but doesn't produce an inverse op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOutcome {
    Killed(ProcSnapshot),
    Survived(ProcSnapshot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    Orphan,
    Resolved {
        argv: Vec<String>,
        targets: Vec<TargetOutcome>,
    },
}

pub fn handle(stash: &ProcPreStash, req: ProcEventReq) -> PostOutcome {
    let key = ProcKey {
        tool: req.tool,
        pid: req.pid,
    };
    match req.phase {
        shit_proto::PkgPhase::Pre => {
            tracing::debug!(
                tool = req.tool.as_str(),
                pid = req.pid,
                target_count = req.targets.len(),
                "proc-pre stashed"
            );
            stash.insert(
                key,
                ProcPre {
                    targets: req.targets,
                    argv: req.target_argv,
                    ts: Instant::now(),
                },
            );
            PostOutcome::Orphan
        }
        shit_proto::PkgPhase::Post => {
            let Some(pre) = stash.take(&key) else {
                tracing::warn!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    "proc-post with no matching pre; dropping (orphan)"
                );
                return PostOutcome::Orphan;
            };
            // Post.targets is the *current* snapshot — the same
            // pids re-enumerated. A pid that's still in Post.targets
            // and whose start_time_secs matches the pre is alive
            // (Survived); anything else is presumed Killed.
            let mut outcomes = Vec::with_capacity(pre.targets.len());
            for pre_snap in pre.targets {
                let survived = req.targets.iter().any(|post_snap| {
                    post_snap.pid == pre_snap.pid
                        && post_snap.start_time_secs == pre_snap.start_time_secs
                });
                if survived {
                    outcomes.push(TargetOutcome::Survived(pre_snap));
                } else {
                    outcomes.push(TargetOutcome::Killed(pre_snap));
                }
            }
            let killed_count = outcomes
                .iter()
                .filter(|o| matches!(o, TargetOutcome::Killed(_)))
                .count();
            tracing::info!(
                tool = req.tool.as_str(),
                pid = req.pid,
                killed = killed_count,
                survived = outcomes.len() - killed_count,
                "proc-post resolved (DR-53 will journal the diff)"
            );
            PostOutcome::Resolved {
                argv: pre.argv,
                targets: outcomes,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_proto::PkgPhase;

    fn snap(pid: u32, start: u64, comm: &str) -> ProcSnapshot {
        ProcSnapshot {
            pid,
            comm: comm.into(),
            argv: vec![comm.into()],
            cwd: String::new(),
            env_summary: std::collections::BTreeMap::new(),
            parent_pid: 1,
            start_time_secs: start,
            tty: None,
        }
    }

    fn req(phase: PkgPhase, pid: u32, targets: Vec<ProcSnapshot>) -> ProcEventReq {
        ProcEventReq {
            tool: ProcToolWire::Kill,
            phase,
            target_argv: vec!["-9".into(), "1234".into()],
            targets,
            pid,
            uid: 1000,
        }
    }

    #[test]
    fn killed_when_post_missing_pid() {
        let stash = ProcPreStash::new();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, 42, vec![snap(1234, 100, "sleep")]),
        );
        let outcome = handle(&stash, req(PkgPhase::Post, 42, vec![]));
        match outcome {
            PostOutcome::Resolved { targets, .. } => {
                assert!(matches!(targets[0], TargetOutcome::Killed(_)));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn survived_when_post_has_same_start_time() {
        let stash = ProcPreStash::new();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, 42, vec![snap(1234, 100, "sleep")]),
        );
        let outcome = handle(
            &stash,
            req(PkgPhase::Post, 42, vec![snap(1234, 100, "sleep")]),
        );
        match outcome {
            PostOutcome::Resolved { targets, .. } => {
                assert!(matches!(targets[0], TargetOutcome::Survived(_)));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn killed_when_post_pid_reused_with_different_start_time() {
        // PID-reuse defense: if the post snapshot has the same
        // pid but a different start_time_secs, the original
        // process is gone (its slot is now occupied by a new
        // process born after the kill).
        let stash = ProcPreStash::new();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, 42, vec![snap(1234, 100, "sleep")]),
        );
        let outcome = handle(
            &stash,
            req(PkgPhase::Post, 42, vec![snap(1234, 999, "whoever")]),
        );
        match outcome {
            PostOutcome::Resolved { targets, .. } => {
                assert!(matches!(targets[0], TargetOutcome::Killed(_)));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn orphan_post_is_dropped() {
        let stash = ProcPreStash::new();
        let outcome = handle(&stash, req(PkgPhase::Post, 99, vec![]));
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn sweep_evicts_old_entries() {
        let stash = ProcPreStash::new();
        let key = ProcKey {
            tool: ProcToolWire::Kill,
            pid: 42,
        };
        {
            let mut g = stash.inner.lock().unwrap();
            g.insert(
                key,
                ProcPre {
                    targets: vec![],
                    argv: vec![],
                    ts: Instant::now()
                        .checked_sub(PRE_STASH_TTL + Duration::from_secs(1))
                        .expect("clock subtraction"),
                },
            );
        }
        assert_eq!(stash.sweep_expired(), 1);
        assert_eq!(stash.len(), 0);
    }
}
