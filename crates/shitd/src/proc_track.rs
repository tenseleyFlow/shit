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

use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId, ProcessOpKind};
use shit_proto::{ProcEventReq, ProcSnapshot, ProcToolWire};
use shit_store::Index;

use crate::active_commands::ActiveCommands;

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

pub fn handle(
    stash: &ProcPreStash,
    req: ProcEventReq,
    active: &ActiveCommands,
    index: &Index,
) -> PostOutcome {
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
            // DR-53: resolve once per Post and journal one
            // ProcessOp per killed target. Survived targets aren't
            // journaled — the user's command didn't actually mutate
            // their state.
            if killed_count > 0
                && let Some(command) = active.resolve_by_descendant(req.pid)
            {
                let signal = parse_signal_from_argv(&pre.argv);
                for outcome in &outcomes {
                    if let TargetOutcome::Killed(snap) = outcome {
                        let kind = CaptureEventKind::ProcessOp {
                            kind: ProcessOpKind::Killed,
                            pid: snap.pid,
                            argv: snap.argv.clone(),
                            cwd: std::path::PathBuf::from(&snap.cwd),
                            env_summary: snap.env_summary.clone(),
                            parent_pid: snap.parent_pid,
                            signal,
                        };
                        let ev = CaptureEvent {
                            id: EventId(0),
                            command,
                            ts: crate::server::next_ts(),
                            partial: false,
                            kind,
                        };
                        if let Err(e) = index.put_event(&ev) {
                            tracing::warn!(
                                err = %e,
                                tool = req.tool.as_str(),
                                killed_pid = snap.pid,
                                "proc-post journal write failed"
                            );
                        }
                    }
                }
                tracing::info!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    session = %command.session,
                    seq = command.seq,
                    killed = killed_count,
                    survived = outcomes.len() - killed_count,
                    "proc-post journaled (DR-53)"
                );
            } else if killed_count > 0 {
                tracing::warn!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    killed = killed_count,
                    "proc-post not attributable to active command window; dropping"
                );
            } else {
                tracing::debug!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    survived = outcomes.len(),
                    "proc-post resolved (all targets survived; no journal write)"
                );
            }
            PostOutcome::Resolved {
                argv: pre.argv,
                targets: outcomes,
            }
        }
    }
}

/// Best-effort signal parser for `kill`-family argv. Recognises
/// `-9`, `-SIGTERM`, `-s SIGKILL`, and the bare-name shorthands
/// (`SIGKILL` and `KILL`). Returns `None` when no signal is
/// specified or the form is unfamiliar; the default kill(2)
/// behaviour is SIGTERM (15), but we leave that interpretation to
/// the renderer rather than baking it in here.
fn parse_signal_from_argv(argv: &[String]) -> Option<i32> {
    // Walk argv looking for either `-N`, `-NAME`, or `-s NAME`.
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-s" || a == "--signal" {
            if let Some(next) = argv.get(i + 1) {
                return name_or_number_to_signum(next);
            }
            return None;
        }
        if let Some(rest) = a.strip_prefix('-') {
            if rest.is_empty() {
                i += 1;
                continue;
            }
            if let Some(n) = name_or_number_to_signum(rest) {
                return Some(n);
            }
        }
        i += 1;
    }
    None
}

fn name_or_number_to_signum(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse::<i32>()
        && (1..=64).contains(&n)
    {
        return Some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    match name {
        "HUP" => Some(1),
        "INT" => Some(2),
        "QUIT" => Some(3),
        "KILL" => Some(9),
        "USR1" => Some(10),
        "USR2" => Some(12),
        "PIPE" => Some(13),
        "ALRM" => Some(14),
        "TERM" => Some(15),
        "STOP" => Some(19),
        "CONT" => Some(18),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{CommandId, CommandRecord, PlannerStore, TimePoint};
    use shit_proto::PkgPhase;
    use uuid::Uuid;

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

    fn fixture() -> (tempfile::TempDir, Index, ActiveCommands, CommandId) {
        let tmp = tempfile::tempdir().unwrap();
        let idx = Index::open(tmp.path().join("index.sqlite")).unwrap();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        let command = CommandId { session, seq: 1 };
        idx.put_command(&CommandRecord {
            command,
            cmd_string: None,
            cwd: std::path::PathBuf::from("/"),
            pid: std::process::id(),
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(0, 0),
            ended_at: None,
            exit_code: None,
            event_ids: vec![],
        })
        .unwrap();
        let active = ActiveCommands::new();
        active.insert(std::process::id(), command);
        (tmp, idx, active, command)
    }

    #[test]
    fn killed_when_post_missing_pid_writes_process_op() {
        let (_tmp, idx, active, command) = fixture();
        let stash = ProcPreStash::new();
        let pid = std::process::id();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, pid, vec![snap(1234, 100, "sleep")]),
            &active,
            &idx,
        );
        let outcome = handle(&stash, req(PkgPhase::Post, pid, vec![]), &active, &idx);
        match outcome {
            PostOutcome::Resolved { targets, .. } => {
                assert!(matches!(targets[0], TargetOutcome::Killed(_)));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
        let events = idx.events_for_command(command);
        assert_eq!(events.len(), 1, "exactly one ProcessOp event for the killed target");
        match &events[0].kind {
            CaptureEventKind::ProcessOp {
                kind,
                pid: target_pid,
                signal,
                ..
            } => {
                assert_eq!(*kind, ProcessOpKind::Killed);
                assert_eq!(*target_pid, 1234);
                assert_eq!(*signal, Some(9), "kill -9 1234 parses as SIGKILL");
            }
            other => panic!("expected ProcessOp, got {other:?}"),
        }
    }

    #[test]
    fn survived_when_post_has_same_start_time() {
        let (_tmp, idx, active, command) = fixture();
        let stash = ProcPreStash::new();
        let pid = std::process::id();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, pid, vec![snap(1234, 100, "sleep")]),
            &active,
            &idx,
        );
        let outcome = handle(
            &stash,
            req(PkgPhase::Post, pid, vec![snap(1234, 100, "sleep")]),
            &active,
            &idx,
        );
        match outcome {
            PostOutcome::Resolved { targets, .. } => {
                assert!(matches!(targets[0], TargetOutcome::Survived(_)));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
        // No journal write for surviving targets.
        assert_eq!(idx.events_for_command(command).len(), 0);
    }

    #[test]
    fn killed_when_post_pid_reused_with_different_start_time() {
        // PID-reuse defense: if the post snapshot has the same
        // pid but a different start_time_secs, the original
        // process is gone (its slot is now occupied by a new
        // process born after the kill).
        let (_tmp, idx, active, _) = fixture();
        let stash = ProcPreStash::new();
        let pid = std::process::id();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, pid, vec![snap(1234, 100, "sleep")]),
            &active,
            &idx,
        );
        let outcome = handle(
            &stash,
            req(PkgPhase::Post, pid, vec![snap(1234, 999, "whoever")]),
            &active,
            &idx,
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
        let (_tmp, idx, active, _) = fixture();
        let stash = ProcPreStash::new();
        let outcome = handle(&stash, req(PkgPhase::Post, 99, vec![]), &active, &idx);
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn parse_signal_from_argv_handles_numeric_and_named() {
        assert_eq!(parse_signal_from_argv(&["-9".into()]), Some(9));
        assert_eq!(parse_signal_from_argv(&["-TERM".into()]), Some(15));
        assert_eq!(parse_signal_from_argv(&["-SIGKILL".into()]), Some(9));
        assert_eq!(
            parse_signal_from_argv(&["-s".into(), "SIGUSR1".into()]),
            Some(10)
        );
        assert_eq!(parse_signal_from_argv(&["1234".into()]), None);
        assert_eq!(parse_signal_from_argv(&[]), None);
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
