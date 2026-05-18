// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-tool hook ingestion on the daemon side (S17.9, DR-41).
//!
//! Mirrors [`crate::pkg`] and [`crate::svc_track`]. On Post-Changed
//! resolves the active command via [`ActiveCommands`] and writes a
//! [`CaptureEventKind::NetworkOp`] with `before_state` /
//! `after_state` raw bytes. `inverse_invocations` is left empty;
//! DR-46 synthesises the actual inverse argv from before/after for
//! tools that need DiffApply (ip-route / ip-addr / ip-link / etc.).
//! FullReload tools (iptables/nft/pfctl) reconstruct their inverse
//! at apply time directly from the before_state bytes.
//!
//! Unlike the service tracker, **we don't parse the state_raw on
//! the daemon side**. The dump is opaque bytes; the executor pipes
//! it back through the tool's own restore command. Equality comes
//! from byte comparison.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId, NetworkTool};
use shit_proto::{NetEventReq, NetToolWire};
use shit_store::Index;

use crate::active_commands::ActiveCommands;

pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetKey {
    pub tool: NetToolWire,
    pub pid: u32,
    pub scope_hint: String,
}

#[derive(Debug, Clone)]
pub struct NetPre {
    pub state_raw: Vec<u8>,
    pub verb: String,
    pub ts: Instant,
}

pub struct NetPreStash {
    inner: Mutex<HashMap<NetKey, NetPre>>,
}

impl NetPreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, key: NetKey, pre: NetPre) {
        self.inner.lock().unwrap().insert(key, pre);
    }
    pub fn take(&self, key: &NetKey) -> Option<NetPre> {
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

impl Default for NetPreStash {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    /// No Pre stashed for this (tool, pid, scope_hint) — orphan.
    Orphan,
    /// Pre and Post bytes are identical.
    Unchanged,
    /// Pre and Post bytes differ.
    Changed {
        before_len: usize,
        after_len: usize,
        verb: String,
    },
}

pub fn handle(
    stash: &NetPreStash,
    req: NetEventReq,
    active: &ActiveCommands,
    index: &Index,
) -> PostOutcome {
    let key = NetKey {
        tool: req.tool,
        pid: req.pid,
        scope_hint: req.scope_hint.clone(),
    };
    match req.phase {
        shit_proto::PkgPhase::Pre => {
            tracing::debug!(
                tool = req.tool.as_str(),
                pid = req.pid,
                scope = %req.scope_hint,
                verb = %req.verb,
                bytes = req.state_raw.len(),
                "net-pre stashed"
            );
            stash.insert(
                key,
                NetPre {
                    state_raw: req.state_raw,
                    verb: req.verb,
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
                    "net-post with no matching pre; dropping (orphan)"
                );
                return PostOutcome::Orphan;
            };
            if pre.state_raw == req.state_raw {
                tracing::debug!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    "net-post unchanged; dropping"
                );
                return PostOutcome::Unchanged;
            }
            let before_len = pre.state_raw.len();
            let after_len = req.state_raw.len();
            let Some(command) = active.resolve_by_descendant(req.pid) else {
                tracing::warn!(
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    "net-post not attributable to active command window; dropping"
                );
                return PostOutcome::Changed {
                    before_len,
                    after_len,
                    verb: pre.verb,
                };
            };
            let kind = CaptureEventKind::NetworkOp {
                tool: wire_to_planner_tool(req.tool),
                before_state: pre.state_raw.clone(),
                after_state: req.state_raw.clone(),
                // DR-46 fills this for DiffApply tools. FullReload
                // tools regenerate it at apply time from
                // `before_state`, so leaving it empty here is fine
                // for both paths today.
                inverse_invocations: Vec::new(),
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
                    verb = %pre.verb,
                    session = %command.session,
                    seq = command.seq,
                    %eid,
                    before_len,
                    after_len,
                    "net-post journaled (DR-41)"
                ),
                Err(e) => tracing::warn!(
                    err = %e,
                    tool = req.tool.as_str(),
                    pid = req.pid,
                    "net-post journal write failed"
                ),
            }
            PostOutcome::Changed {
                before_len,
                after_len,
                verb: pre.verb,
            }
        }
    }
}

fn wire_to_planner_tool(w: NetToolWire) -> NetworkTool {
    match w {
        NetToolWire::Iptables => NetworkTool::Iptables,
        NetToolWire::Ip6tables => NetworkTool::Ip6tables,
        NetToolWire::Nft => NetworkTool::Nft,
        NetToolWire::Ufw => NetworkTool::Ufw,
        NetToolWire::Pfctl => NetworkTool::Pfctl,
        NetToolWire::IpRoute => NetworkTool::IpRoute,
        NetToolWire::IpAddr => NetworkTool::IpAddr,
        NetToolWire::IpLink => NetworkTool::IpLink,
        NetToolWire::Route => NetworkTool::Route,
        NetToolWire::Ifconfig => NetworkTool::Ifconfig,
        NetToolWire::Networksetup => NetworkTool::Networksetup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{CommandId, CommandRecord, PlannerStore, TimePoint};
    use shit_proto::PkgPhase;
    use uuid::Uuid;

    fn req(phase: PkgPhase, pid: u32, verb: &str, raw: &[u8]) -> NetEventReq {
        NetEventReq {
            tool: NetToolWire::Iptables,
            phase,
            verb: verb.into(),
            scope_hint: "filter".into(),
            pid,
            uid: 1000,
            state_raw: raw.to_vec(),
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
    fn pre_post_unchanged_when_bytes_match() {
        let (_tmp, idx, active, _) = fixture();
        let stash = NetPreStash::new();
        let raw = b"# generated by iptables-save\n*filter\n";
        let pid = std::process::id();
        let _ = handle(&stash, req(PkgPhase::Pre, pid, "-A", raw), &active, &idx);
        let outcome = handle(&stash, req(PkgPhase::Post, pid, "-A", raw), &active, &idx);
        assert_eq!(outcome, PostOutcome::Unchanged);
        assert_eq!(stash.len(), 0);
    }

    #[test]
    fn pre_post_changed_writes_network_op_event() {
        let (_tmp, idx, active, command) = fixture();
        let stash = NetPreStash::new();
        let pid = std::process::id();
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, pid, "-A", b"before"),
            &active,
            &idx,
        );
        let outcome = handle(
            &stash,
            req(PkgPhase::Post, pid, "-A", b"after-bytes"),
            &active,
            &idx,
        );
        match outcome {
            PostOutcome::Changed {
                before_len,
                after_len,
                verb,
            } => {
                assert_eq!(before_len, 6);
                assert_eq!(after_len, 11);
                assert_eq!(verb, "-A");
            }
            other => panic!("expected Changed, got {other:?}"),
        }
        let events = idx.events_for_command(command);
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            CaptureEventKind::NetworkOp {
                tool,
                before_state,
                after_state,
                inverse_invocations,
            } => {
                assert_eq!(*tool, NetworkTool::Iptables);
                assert_eq!(before_state, b"before");
                assert_eq!(after_state, b"after-bytes");
                assert!(
                    inverse_invocations.is_empty(),
                    "DR-46 owns the synthesised inverse; DR-41 leaves it empty"
                );
            }
            other => panic!("expected NetworkOp, got {other:?}"),
        }
    }

    #[test]
    fn orphan_post_is_dropped() {
        let (_tmp, idx, active, _) = fixture();
        let stash = NetPreStash::new();
        let outcome = handle(&stash, req(PkgPhase::Post, 99, "-A", b"x"), &active, &idx);
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn post_change_with_no_active_command_does_not_journal() {
        let (_tmp, idx, active, command) = fixture();
        let stash = NetPreStash::new();
        let stranger_pid = u32::MAX - 1;
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, stranger_pid, "-A", b"before"),
            &active,
            &idx,
        );
        let _ = handle(
            &stash,
            req(PkgPhase::Post, stranger_pid, "-A", b"after"),
            &active,
            &idx,
        );
        assert_eq!(idx.events_for_command(command).len(), 0);
    }

    #[test]
    fn sweep_evicts_old_entries() {
        let stash = NetPreStash::new();
        let key = NetKey {
            tool: NetToolWire::Iptables,
            pid: 42,
            scope_hint: "filter".into(),
        };
        {
            let mut g = stash.inner.lock().unwrap();
            g.insert(
                key,
                NetPre {
                    state_raw: vec![],
                    verb: "-A".into(),
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
