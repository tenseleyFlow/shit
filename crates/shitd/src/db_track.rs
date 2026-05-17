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

use shit_proto::{DbConnInfo, DbEngineWire, DbEventReq, DbTxStateWire};

pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DbKey {
    pub engine: DbEngineWire,
    pub pid: u32,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct DbPre {
    pub conn: DbConnInfo,
    pub statements: Vec<String>,
    pub ts: Instant,
}

pub struct DbPreStash {
    inner: Mutex<HashMap<DbKey, DbPre>>,
}

impl DbPreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, key: DbKey, pre: DbPre) {
        self.inner.lock().unwrap().insert(key, pre);
    }
    pub fn take(&self, key: &DbKey) -> Option<DbPre> {
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

pub fn handle(stash: &DbPreStash, req: DbEventReq) -> PostOutcome {
    let key = DbKey {
        engine: req.engine,
        pid: req.pid,
        target: req.conn.target.clone(),
    };
    match req.phase {
        shit_proto::PkgPhase::Pre => {
            tracing::debug!(
                engine = req.engine.as_str(),
                pid = req.pid,
                target = %req.conn.target,
                stmt_count = req.statements.len(),
                "db-pre stashed"
            );
            stash.insert(
                key,
                DbPre {
                    conn: req.conn,
                    statements: req.statements,
                    ts: Instant::now(),
                },
            );
            PostOutcome::Orphan
        }
        shit_proto::PkgPhase::Post => {
            let Some(pre) = stash.take(&key) else {
                tracing::warn!(
                    engine = req.engine.as_str(),
                    pid = req.pid,
                    target = %req.conn.target,
                    "db-post with no matching pre; dropping (orphan)"
                );
                return PostOutcome::Orphan;
            };
            tracing::info!(
                engine = req.engine.as_str(),
                pid = req.pid,
                target = %pre.conn.target,
                stmts = pre.statements.len(),
                state = ?req.transaction_state,
                "db-post resolved (DR-58 will journal the diff)"
            );
            PostOutcome::Resolved {
                conn: pre.conn,
                statements: pre.statements,
                transaction_state: req.transaction_state,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_proto::PkgPhase;

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

    #[test]
    fn pre_stashes_and_post_resolves() {
        let stash = DbPreStash::new();
        let _ = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Pre,
                42,
                "prod",
                vec!["INSERT INTO t VALUES (1)"],
                DbTxStateWire::Unknown,
            ),
        );
        assert_eq!(stash.len(), 1);
        let outcome = handle(
            &stash,
            req(
                DbEngineWire::Postgres,
                PkgPhase::Post,
                42,
                "prod",
                vec![],
                DbTxStateWire::Committed,
            ),
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
    }

    #[test]
    fn orphan_post_without_pre() {
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
        );
        assert_eq!(outcome, PostOutcome::Orphan);
    }

    #[test]
    fn key_disambiguates_engine_pid_and_target() {
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
        {
            let mut g = stash.inner.lock().unwrap();
            g.insert(
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
        }
        assert_eq!(stash.sweep_expired(), 1);
        assert_eq!(stash.len(), 0);
    }
}
