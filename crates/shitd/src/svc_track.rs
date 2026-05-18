// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-manager hook ingestion on the daemon side (S16.6, DR-36).
//!
//! Mirrors [`crate::pkg`]: an in-memory Pre stash keyed by
//! `(pid, unit)`, Post pairs and computes the before/after diff,
//! resolves the active command via [`ActiveCommands`] and writes a
//! [`CaptureEventKind::SystemdOp`] under `(session, seq)`.
//!
//! The pid+unit key is the right granularity: a single shell may
//! run `systemctl start a.service && systemctl start b.service`,
//! and each invocation gets its own helper subprocess (so distinct
//! pid), but a complex command like
//! `systemctl daemon-reload && systemctl restart foo` shares a pid
//! across two unit ops — the unit half disambiguates.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId, SystemdScope};
use shit_planner::{ServiceState, parse_launchctl_print, parse_systemctl_show};
use shit_proto::{SvcEventReq, SvcScopeWire, SvcToolWire};
use shit_store::Index;

use crate::active_commands::ActiveCommands;

/// Pre-stash TTL. Same value as pkg/env.
pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

/// Stash key. We include the tool because the same pid could
/// theoretically invoke both systemctl and launchctl (unusual but
/// legal in a script).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SvcKey {
    pub tool: SvcToolWire,
    pub pid: u32,
    pub unit: String,
}

#[derive(Debug, Clone)]
pub struct SvcPre {
    pub state: ServiceState,
    pub verb: String,
    pub ts: Instant,
}

pub struct SvcPreStash {
    inner: Mutex<HashMap<SvcKey, SvcPre>>,
}

impl SvcPreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key: SvcKey, pre: SvcPre) {
        let mut g = self.inner.lock().unwrap();
        g.insert(key, pre);
    }

    pub fn take(&self, key: &SvcKey) -> Option<SvcPre> {
        let mut g = self.inner.lock().unwrap();
        g.remove(key)
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

impl Default for SvcPreStash {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    /// No Pre stashed for this (pid, unit) — orphan.
    Orphan,
    /// Pre and Post states are identical — nothing changed.
    Unchanged,
    /// State differs — the planner gets a diff.
    Changed {
        before: ServiceState,
        after: ServiceState,
        verb: String,
    },
}

/// Parse the raw state string per the tool kind.
fn parse_state(tool: SvcToolWire, raw: &str) -> ServiceState {
    match tool {
        SvcToolWire::Systemctl => parse_systemctl_show(raw),
        SvcToolWire::Launchctl => parse_launchctl_print(raw),
    }
}

pub fn handle(
    stash: &SvcPreStash,
    req: SvcEventReq,
    active: &ActiveCommands,
    index: &Index,
) -> PostOutcome {
    let key = SvcKey {
        tool: req.tool,
        pid: req.pid,
        unit: req.unit.clone(),
    };
    let state = parse_state(req.tool, &req.state_raw);
    match req.phase {
        shit_proto::PkgPhase::Pre => {
            tracing::debug!(
                tool = req.tool.as_str(),
                pid = req.pid,
                unit = %req.unit,
                verb = %req.verb,
                "svc-pre stashed"
            );
            stash.insert(
                key,
                SvcPre {
                    state,
                    verb: req.verb,
                    ts: Instant::now(),
                },
            );
            // Pre never returns a diff; the caller logs and acks.
            PostOutcome::Orphan
        }
        shit_proto::PkgPhase::Post => {
            let Some(pre) = stash.take(&key) else {
                tracing::warn!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    unit = %req.unit,
                    "svc-post with no matching pre; dropping (orphan)"
                );
                return PostOutcome::Orphan;
            };
            if pre.state == state {
                tracing::debug!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    unit = %req.unit,
                    "svc-post unchanged; dropping"
                );
                return PostOutcome::Unchanged;
            }
            // DR-36: resolve the active command via ancestor walk.
            let Some(command) = active.resolve_by_descendant(req.pid) else {
                tracing::warn!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    unit = %req.unit,
                    "svc-post not attributable to active command window; dropping"
                );
                return PostOutcome::Changed {
                    before: pre.state,
                    after: state,
                    verb: pre.verb,
                };
            };
            let kind = CaptureEventKind::SystemdOp {
                scope: wire_to_planner_scope(req.scope),
                unit: req.unit.clone(),
                before: pre.state.clone(),
                after: state.clone(),
            };
            let ev = CaptureEvent {
                id: EventId(0),
                command,
                ts: crate::server::next_ts(),
                partial: false,
                kind,
            };
            match index.put_event(&ev) {
                Ok(eid) => tracing::info!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    unit = %req.unit,
                    verb = %pre.verb,
                    session = %command.session,
                    seq = command.seq,
                    %eid,
                    "svc-post journaled (DR-36)"
                ),
                Err(e) => tracing::warn!(
                    err = %e,
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    unit = %req.unit,
                    "svc-post journal write failed"
                ),
            }
            PostOutcome::Changed {
                before: pre.state,
                after: state,
                verb: pre.verb,
            }
        }
    }
}

fn wire_to_planner_scope(w: SvcScopeWire) -> SystemdScope {
    match w {
        SvcScopeWire::User => SystemdScope::User,
        SvcScopeWire::System => SystemdScope::System,
        SvcScopeWire::LaunchdGui => SystemdScope::LaunchdGui,
        SvcScopeWire::LaunchdSystem => SystemdScope::LaunchdSystem,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_proto::{PkgPhase, SvcScopeWire};

    use shit_planner::{CommandId, CommandRecord, PlannerStore, TimePoint};
    use uuid::Uuid;

    fn req(phase: PkgPhase, pid: u32, verb: &str, raw: &str) -> SvcEventReq {
        SvcEventReq {
            tool: SvcToolWire::Systemctl,
            phase,
            scope: SvcScopeWire::User,
            unit: "nginx.service".into(),
            verb: verb.into(),
            pid,
            uid: 1000,
            state_raw: raw.into(),
        }
    }

    /// Build an Index + ActiveCommands so resolve_by_descendant for
    /// `req.pid = std::process::id()` finds the test command.
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
    fn pre_then_post_unchanged_when_state_identical() {
        let (_tmp, idx, active, _) = fixture();
        let stash = SvcPreStash::new();
        let raw = "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n";
        let pid = std::process::id();
        let _ = handle(&stash, req(PkgPhase::Pre, pid, "start", raw), &active, &idx);
        let outcome = handle(&stash, req(PkgPhase::Post, pid, "start", raw), &active, &idx);
        assert_eq!(outcome, PostOutcome::Unchanged);
        assert_eq!(stash.len(), 0, "Post drains stash");
    }

    #[test]
    fn pre_then_post_changed_writes_systemd_op_event() {
        let (_tmp, idx, active, command) = fixture();
        let stash = SvcPreStash::new();
        let pre_raw = "ActiveState=inactive\nUnitFileState=disabled\nLoadState=loaded\n";
        let post_raw = "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n";
        let pid = std::process::id();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, pid, "enable --now", pre_raw),
            &active,
            &idx,
        );
        let outcome = handle(
            &stash,
            req(PkgPhase::Post, pid, "enable --now", post_raw),
            &active,
            &idx,
        );
        match outcome {
            PostOutcome::Changed {
                before,
                after,
                verb,
            } => {
                assert!(!before.active);
                assert!(!before.enabled);
                assert!(after.active);
                assert!(after.enabled);
                assert_eq!(verb, "enable --now");
            }
            other => panic!("expected Changed, got {other:?}"),
        }
        let events = idx.events_for_command(command);
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            CaptureEventKind::SystemdOp {
                scope,
                unit,
                before,
                after,
            } => {
                assert_eq!(*scope, SystemdScope::User);
                assert_eq!(unit, "nginx.service");
                assert!(!before.active);
                assert!(after.active);
            }
            other => panic!("expected SystemdOp, got {other:?}"),
        }
    }

    #[test]
    fn orphan_post_is_dropped() {
        let (_tmp, idx, active, _) = fixture();
        let stash = SvcPreStash::new();
        let outcome = handle(
            &stash,
            req(
                PkgPhase::Post,
                99,
                "start",
                "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n",
            ),
            &active,
            &idx,
        );
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn post_change_with_no_active_command_does_not_journal() {
        let (_tmp, idx, active, command) = fixture();
        let stash = SvcPreStash::new();
        let stranger_pid = u32::MAX - 1;
        let pre_raw = "ActiveState=inactive\nUnitFileState=disabled\nLoadState=loaded\n";
        let post_raw = "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n";
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, stranger_pid, "start", pre_raw),
            &active,
            &idx,
        );
        let _ = handle(
            &stash,
            req(PkgPhase::Post, stranger_pid, "start", post_raw),
            &active,
            &idx,
        );
        assert_eq!(idx.events_for_command(command).len(), 0);
    }

    #[test]
    fn sweep_evicts_old_entries() {
        let stash = SvcPreStash::new();
        let key = SvcKey {
            tool: SvcToolWire::Systemctl,
            pid: 42,
            unit: "x.service".into(),
        };
        {
            let mut g = stash.inner.lock().unwrap();
            g.insert(
                key,
                SvcPre {
                    state: ServiceState {
                        active: false,
                        enabled: false,
                        masked: false,
                        raw: String::new(),
                    },
                    verb: "start".into(),
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
