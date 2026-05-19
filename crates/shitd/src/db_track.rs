// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database CLI shim ingestion on the daemon side (S19.5).
//!
//! Same shape as `pkg`/`env_track`/`svc_track`/`net_track`/`proc_track`:
//! Pre stashes the parsed connection + statements by
//! `(engine, pid, target)`; Post correlates by the same key and
//! (when the engine probe is wired — DR-56/57) folds in the
//! transaction_state delta.
//!
//! Journal-write under `(session, seq)` is DR-58.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::events::{
    CaptureEvent, CaptureEventKind, CommandId, DbEngine, DbTxState, EventId,
};
use shit_proto::{DbConnInfo, DbEngineWire, DbEventReq, DbTxStateWire};
use shit_store::Index;

use crate::active_commands::ActiveCommands;

pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

/// Pid-based stash key — fallback for orphans / self-spawned tests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DbKey {
    pub engine: DbEngineWire,
    pub pid: u32,
    pub target: String,
}

/// Command-based stash key — used when ancestry resolves to an
/// active command. The psql/mysql/sqlite3 wrappers fire the
/// `db-event` helper twice (pre + post) in distinct processes; the
/// resolved command is the only stable pairing key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DbCommandKey {
    pub command: CommandId,
    pub engine: DbEngineWire,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct DbPre {
    pub conn: DbConnInfo,
    pub statements: Vec<String>,
    pub ts: Instant,
}

pub struct DbPreStash {
    by_command: Mutex<HashMap<DbCommandKey, DbPre>>,
    by_pid: Mutex<HashMap<DbKey, DbPre>>,
}

impl DbPreStash {
    pub fn new() -> Self {
        Self {
            by_command: Mutex::new(HashMap::new()),
            by_pid: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert_by_command(&self, key: DbCommandKey, pre: DbPre) {
        self.by_command.lock().unwrap().insert(key, pre);
    }
    pub fn take_by_command(&self, key: &DbCommandKey) -> Option<DbPre> {
        self.by_command.lock().unwrap().remove(key)
    }
    pub fn insert_by_pid(&self, key: DbKey, pre: DbPre) {
        self.by_pid.lock().unwrap().insert(key, pre);
    }
    pub fn take_by_pid(&self, key: &DbKey) -> Option<DbPre> {
        self.by_pid.lock().unwrap().remove(key)
    }
    pub fn sweep_expired(&self) -> usize {
        let cutoff = Instant::now()
            .checked_sub(PRE_STASH_TTL)
            .unwrap_or_else(Instant::now);
        let mut evicted = 0;
        let mut g = self.by_command.lock().unwrap();
        let before = g.len();
        g.retain(|_, e| e.ts >= cutoff);
        evicted += before - g.len();
        drop(g);
        let mut g = self.by_pid.lock().unwrap();
        let before = g.len();
        g.retain(|_, e| e.ts >= cutoff);
        evicted += before - g.len();
        evicted
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_command.lock().unwrap().len() + self.by_pid.lock().unwrap().len()
    }
}

impl Default for DbPreStash {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome shipped to the planner journal. `Orphan` is the
/// "Post arrived with no matching Pre" case (typically a wrapper
/// that crashed between phases, or a `psql -c BEGIN` left dangling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    Orphan,
    Resolved {
        conn: DbConnInfo,
        statements: Vec<String>,
        transaction_state: DbTxStateWire,
    },
}

pub fn handle(
    stash: &DbPreStash,
    req: DbEventReq,
    active: &ActiveCommands,
    index: &Index,
) -> PostOutcome {
    let pid_key = DbKey {
        engine: req.engine,
        pid: req.pid,
        target: req.conn.target.clone(),
    };
    let cmd_key = active.resolve_by_descendant(req.pid).map(|c| DbCommandKey {
        command: c,
        engine: req.engine,
        target: req.conn.target.clone(),
    });
    match req.phase {
        shit_proto::PkgPhase::Pre => {
            tracing::debug!(
                engine = req.engine.as_str(),
                pid = req.pid,
                target = %req.conn.target,
                stmt_count = req.statements.len(),
                command = ?cmd_key.as_ref().map(|k| k.command),
                "db-pre stashed"
            );
            let pre = DbPre {
                conn: req.conn,
                statements: req.statements,
                ts: Instant::now(),
            };
            if let Some(k) = cmd_key {
                stash.insert_by_command(k, pre);
            } else {
                stash.insert_by_pid(pid_key, pre);
            }
            PostOutcome::Orphan
        }
        shit_proto::PkgPhase::Post => {
            let pre = match cmd_key.as_ref() {
                Some(k) => stash
                    .take_by_command(k)
                    .or_else(|| stash.take_by_pid(&pid_key)),
                None => stash.take_by_pid(&pid_key),
            };
            let Some(pre) = pre else {
                tracing::warn!(
                    engine = req.engine.as_str(),
                    pid = req.pid,
                    target = %req.conn.target,
                    "db-post with no matching pre; dropping (orphan)"
                );
                return PostOutcome::Orphan;
            };
            // DR-58: attribute the event to the active command we
            // already resolved at stash-lookup time. If no active
            // command, fall through with the diagnostic outcome but
            // skip the journal write.
            if let Some(command) = cmd_key.as_ref().map(|k| k.command) {
                let kind = CaptureEventKind::DbOp {
                    engine: wire_to_planner_engine(req.engine),
                    target: pre.conn.target.clone(),
                    statements: pre.statements.clone(),
                    transaction_state: wire_to_planner_tx_state(req.transaction_state),
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
                        engine = req.engine.as_str(),
                        pid = req.pid,
                        target = %pre.conn.target,
                        session = %command.session,
                        seq = command.seq,
                        %eid,
                        stmts = pre.statements.len(),
                        state = ?req.transaction_state,
                        "db-post journaled (DR-58)"
                    ),
                    Err(e) => tracing::warn!(
                        err = %e,
                        engine = req.engine.as_str(),
                        pid = req.pid,
                        "db-post journal write failed"
                    ),
                }
            } else {
                tracing::warn!(
                    engine = req.engine.as_str(),
                    pid = req.pid,
                    target = %pre.conn.target,
                    stmts = pre.statements.len(),
                    "db-post not attributable to active command window; dropping"
                );
            }
            PostOutcome::Resolved {
                conn: pre.conn,
                statements: pre.statements,
                transaction_state: req.transaction_state,
            }
        }
    }
}

fn wire_to_planner_engine(w: DbEngineWire) -> DbEngine {
    match w {
        DbEngineWire::Postgres => DbEngine::Postgres,
        DbEngineWire::Mysql => DbEngine::Mysql,
        DbEngineWire::Sqlite3 => DbEngine::Sqlite3,
    }
}

fn wire_to_planner_tx_state(w: DbTxStateWire) -> DbTxState {
    match w {
        DbTxStateWire::AutoCommit => DbTxState::AutoCommit,
        DbTxStateWire::Committed => DbTxState::Committed,
        DbTxStateWire::RolledBack => DbTxState::RolledBack,
        DbTxStateWire::Unfinished => DbTxState::Unfinished,
        DbTxStateWire::Unknown => DbTxState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{CommandId, CommandRecord, PlannerStore, TimePoint};
    use shit_proto::PkgPhase;
    use uuid::Uuid;

    fn req(
        engine: DbEngineWire,
        phase: PkgPhase,
        pid: u32,
        target: &str,
        statements: Vec<&str>,
        state: DbTxStateWire,
    ) -> DbEventReq {
        DbEventReq {
            engine,
            phase,
            conn: DbConnInfo {
                host: "host".into(),
                port: Some(5432),
                user: "alice".into(),
                target: target.into(),
            },
            statements: statements.into_iter().map(String::from).collect(),
            transaction_state: state,
            pid,
            uid: 1000,
            extras: Default::default(),
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
    fn pre_stashes_and_post_resolves_writes_db_op() {
        let (_tmp, idx, active, command) = fixture();
        let stash = DbPreStash::new();
        let pid = std::process::id();
        let _ = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Pre,
                pid,
                "prod",
                vec!["INSERT INTO t VALUES (1)"],
                DbTxStateWire::Unknown,
            ),
            &active,
            &idx,
        );
        assert_eq!(stash.len(), 1);
        let outcome = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Post,
                pid,
                "prod",
                vec![],
                DbTxStateWire::Committed,
            ),
            &active,
            &idx,
        );
        match outcome {
            PostOutcome::Resolved {
                statements,
                transaction_state,
                ..
            } => {
                assert_eq!(statements.len(), 1);
                assert_eq!(transaction_state, DbTxStateWire::Committed);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
        assert_eq!(stash.len(), 0);
        let events = idx.events_for_command(command);
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            CaptureEventKind::DbOp {
                engine,
                target,
                statements,
                transaction_state,
            } => {
                assert_eq!(*engine, DbEngine::Postgres);
                assert_eq!(target, "prod");
                assert_eq!(statements.len(), 1);
                assert_eq!(*transaction_state, DbTxState::Committed);
            }
            other => panic!("expected DbOp, got {other:?}"),
        }
    }

    #[test]
    fn orphan_post_without_pre() {
        let (_tmp, idx, active, _) = fixture();
        let stash = DbPreStash::new();
        let outcome = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Post,
                42,
                "prod",
                vec![],
                DbTxStateWire::Unknown,
            ),
            &active,
            &idx,
        );
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn key_disambiguates_engine_pid_and_target() {
        let (_tmp, idx, active, _) = fixture();
        let stash = DbPreStash::new();
        let _ = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Pre,
                42,
                "prod",
                vec!["INSERT"],
                DbTxStateWire::Unknown,
            ),
            &active,
            &idx,
        );
        let _ = handle(
            &stash,
            req(
                DbEngineWire::Mysql,
                PkgPhase::Pre,
                42,
                "prod",
                vec!["UPDATE"],
                DbTxStateWire::Unknown,
            ),
            &active,
            &idx,
        );
        // Different engine, same pid/target → different key.
        assert_eq!(stash.len(), 2);

        // Same engine, different pid → different key.
        let _ = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Pre,
                99,
                "prod",
                vec!["DELETE"],
                DbTxStateWire::Unknown,
            ),
            &active,
            &idx,
        );
        assert_eq!(stash.len(), 3);
    }

    #[test]
    fn sweep_evicts_old_entries() {
        let stash = DbPreStash::new();
        let key = DbKey {
            engine: DbEngineWire::Sqlite3,
            pid: 42,
            target: "/tmp/test.db".into(),
        };
        stash.insert_by_pid(
            key,
            DbPre {
                conn: DbConnInfo {
                    host: String::new(),
                    port: None,
                    user: String::new(),
                    target: "/tmp/test.db".into(),
                },
                statements: vec![],
                ts: Instant::now()
                    .checked_sub(PRE_STASH_TTL + Duration::from_secs(1))
                    .expect("clock subtraction"),
            },
        );
        assert_eq!(stash.sweep_expired(), 1);
        assert_eq!(stash.len(), 0);
    }
}
