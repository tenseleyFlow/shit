// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database-tier executor (S19.7).
//!
//! Handles [`InverseOp::DbNote`]. Asymmetric by engine:
//!
//! - **sqlite3**: a captured DB file is just a regular file. When the
//!   note carries a [`RollbackHint::Sqlite { file_blob: Some(_) }`],
//!   we delegate to the file-tier path: emit a synthetic
//!   [`InverseOp::RestoreContent`] that the file executor will pick
//!   up. When the blob is absent (capture failed) we fall back to
//!   the informational path.
//! - **postgres / mysql**: never executed. We push a
//!   [`DbSuggestion`] onto the sink for `shit show` to render and
//!   return `Applied` (or `WouldApply` on dry-run). Same shape as
//!   the process executor in S18.

use std::cell::RefCell;
use std::path::PathBuf;

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inode::BlobHash;
use crate::inverse::{DbEngine, InverseOp, RollbackHint};

/// One renderable rollback suggestion. The CLI's `render::db`
/// formats this; the executor itself never invokes anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbSuggestion {
    pub engine: DbEngine,
    pub target: String,
    pub statements: Vec<String>,
    pub hint: RollbackHint,
}

/// Sink for the suggestions the executor produces. Mirrors the
/// pattern from `process::SuggestionSink`.
pub trait DbSuggestionSink {
    fn push(&self, s: DbSuggestion);
}

#[derive(Default, Debug)]
pub struct VecDbSuggestionSink {
    buf: RefCell<Vec<DbSuggestion>>,
}

impl VecDbSuggestionSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn take(&self) -> Vec<DbSuggestion> {
        std::mem::take(&mut *self.buf.borrow_mut())
    }
    pub fn len(&self) -> usize {
        self.buf.borrow().len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.borrow().is_empty()
    }
}

impl DbSuggestionSink for VecDbSuggestionSink {
    fn push(&self, s: DbSuggestion) {
        self.buf.borrow_mut().push(s);
    }
}

/// What the executor decided for one [`InverseOp::DbNote`]:
///
/// - `Suggestion` was pushed onto the sink (postgres/mysql, or
///   sqlite without a file blob).
/// - `DelegateFileRestore` is a synthetic
///   [`InverseOp::RestoreContent`] the caller should now run via the
///   file executor — sqlite with a captured blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbExecOutcome {
    Suggestion(DbSuggestion),
    DelegateFileRestore { path: PathBuf, blob: BlobHash },
}

pub struct DbExecutor<S: DbSuggestionSink> {
    sink: S,
}

impl<S: DbSuggestionSink> DbExecutor<S> {
    pub fn new(sink: S) -> Self {
        Self { sink }
    }
    pub fn sink(&self) -> &S {
        &self.sink
    }
}

impl DbExecutor<VecDbSuggestionSink> {
    pub fn with_vec_sink() -> Self {
        Self::new(VecDbSuggestionSink::new())
    }
}

impl<S: DbSuggestionSink> InverseOpExecutor for DbExecutor<S> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::DbNote { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::DbNote {
            engine,
            target,
            statements,
            rollback_hint,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "db executor reached non-db op".into(),
            };
        };

        match decide(*engine, target, statements, rollback_hint) {
            DbExecOutcome::Suggestion(s) => {
                if dry_run {
                    return ExecutionOutcome::WouldApply;
                }
                self.sink.push(s);
                ExecutionOutcome::Applied
            }
            DbExecOutcome::DelegateFileRestore { path, .. } => {
                // The orchestrator should have synthesized the matching
                // RestoreContent op upstream. If we see this at execute
                // time it means the planner emitted a DbNote without
                // also emitting the file op — surface as Skipped with
                // the delegation hint in the reason so the operator can
                // diagnose. The actual delegation lives in the planner;
                // we just refuse to do file-tier work from inside the
                // db-tier executor.
                ExecutionOutcome::Skipped {
                    reason: format!(
                        "sqlite hint carried a blob but no corresponding RestoreContent was \
                         emitted by the planner; expected for {} (DR-58)",
                        path.display()
                    ),
                }
            }
        }
    }
}

/// Pure decision: given a captured DbNote, what should the executor do?
/// Exposed for testing.
pub fn decide(
    engine: DbEngine,
    target: &str,
    statements: &[String],
    hint: &RollbackHint,
) -> DbExecOutcome {
    if let (
        DbEngine::Sqlite3,
        RollbackHint::Sqlite {
            path,
            file_blob: Some(blob),
        },
    ) = (engine, hint)
    {
        return DbExecOutcome::DelegateFileRestore {
            path: path.clone(),
            blob: *blob,
        };
    }
    DbExecOutcome::Suggestion(DbSuggestion {
        engine,
        target: target.to_string(),
        statements: statements.to_vec(),
        hint: hint.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(engine: DbEngine, target: &str, hint: RollbackHint) -> InverseOp {
        InverseOp::DbNote {
            engine,
            target: target.into(),
            statements: vec!["INSERT INTO t VALUES (1)".into()],
            rollback_hint: hint,
        }
    }

    #[test]
    fn postgres_always_pushes_suggestion() {
        let exec = DbExecutor::with_vec_sink();
        let op = note(
            DbEngine::Postgres,
            "prod",
            RollbackHint::Postgres {
                pitr_recommended: true,
                wal_position: Some("0/1A2B3C".into()),
                statements_for_review: vec!["INSERT INTO t VALUES (1)".into()],
            },
        );
        let out = exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(out, ExecutionOutcome::Applied);
        assert_eq!(exec.sink().len(), 1);
    }

    #[test]
    fn mysql_always_pushes_suggestion() {
        let exec = DbExecutor::with_vec_sink();
        let op = note(
            DbEngine::Mysql,
            "prod",
            RollbackHint::Mysql {
                binlog_position: Some("mysql-bin.000001:12345".into()),
                statements_for_review: vec!["UPDATE t SET x = 2".into()],
            },
        );
        let out = exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(out, ExecutionOutcome::Applied);
        assert_eq!(exec.sink().len(), 1);
    }

    #[test]
    fn sqlite_with_blob_delegates_to_file_tier() {
        let outcome = decide(
            DbEngine::Sqlite3,
            "/tmp/test.db",
            &["CREATE TABLE t (id INT)".into()],
            &RollbackHint::Sqlite {
                path: PathBuf::from("/tmp/test.db"),
                file_blob: Some(BlobHash::from_bytes([7; 32])),
            },
        );
        assert!(matches!(outcome, DbExecOutcome::DelegateFileRestore { .. }));
    }

    #[test]
    fn sqlite_without_blob_falls_back_to_suggestion() {
        let outcome = decide(
            DbEngine::Sqlite3,
            "/tmp/test.db",
            &["CREATE TABLE t (id INT)".into()],
            &RollbackHint::Sqlite {
                path: PathBuf::from("/tmp/test.db"),
                file_blob: None,
            },
        );
        assert!(matches!(outcome, DbExecOutcome::Suggestion(_)));
    }

    #[test]
    fn dry_run_does_not_push_suggestion() {
        let exec = DbExecutor::with_vec_sink();
        let op = note(DbEngine::Postgres, "prod", RollbackHint::None);
        let out = exec.execute(&op, true, ConflictPolicy::Abort);
        assert_eq!(out, ExecutionOutcome::WouldApply);
        assert!(exec.sink().is_empty());
    }

    #[test]
    fn rollback_hint_none_renders_as_suggestion() {
        let exec = DbExecutor::with_vec_sink();
        let op = note(DbEngine::Postgres, "prod", RollbackHint::None);
        let out = exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(out, ExecutionOutcome::Applied);
        let s = &exec.sink().take()[0];
        assert!(matches!(s.hint, RollbackHint::None));
    }

    #[test]
    fn sqlite_delegate_from_executor_returns_skipped_with_diagnostic() {
        let exec = DbExecutor::with_vec_sink();
        let op = note(
            DbEngine::Sqlite3,
            "/tmp/test.db",
            RollbackHint::Sqlite {
                path: PathBuf::from("/tmp/test.db"),
                file_blob: Some(BlobHash::from_bytes([1; 32])),
            },
        );
        let out = exec.execute(&op, false, ConflictPolicy::Abort);
        match out {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("RestoreContent"));
                assert!(reason.contains("/tmp/test.db"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn supports_only_db_note() {
        let exec = DbExecutor::with_vec_sink();
        assert!(!exec.supports(&InverseOp::UnsetEnv { name: "X".into() }));
        assert!(exec.supports(&note(DbEngine::Postgres, "x", RollbackHint::None)));
    }

    #[test]
    fn suggestion_carries_engine_target_and_statements() {
        let exec = DbExecutor::with_vec_sink();
        let op = InverseOp::DbNote {
            engine: DbEngine::Mysql,
            target: "prod".into(),
            statements: vec!["UPDATE t SET x = 1".into(), "DELETE FROM t".into()],
            rollback_hint: RollbackHint::None,
        };
        exec.execute(&op, false, ConflictPolicy::Abort);
        let s = &exec.sink().take()[0];
        assert_eq!(s.engine, DbEngine::Mysql);
        assert_eq!(s.target, "prod");
        assert_eq!(s.statements.len(), 2);
    }

    #[test]
    fn multiple_dbnotes_accumulate() {
        let exec = DbExecutor::with_vec_sink();
        for engine in [DbEngine::Postgres, DbEngine::Mysql] {
            let op = note(engine, "prod", RollbackHint::None);
            exec.execute(&op, false, ConflictPolicy::Abort);
        }
        assert_eq!(exec.sink().len(), 2);
    }
}
