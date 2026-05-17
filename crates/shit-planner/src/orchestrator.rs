// SPDX-License-Identifier: AGPL-3.0-or-later

//! Plan execution orchestrator (S11 stage 1 — sequential).
//!
//! Takes an [`UndoPlan`] and a per-tier executor; walks the plan's
//! topologically-ordered nodes; emits an [`ExecutionReport`].
//!
//! ## Stage 1 scope
//!
//! - **Sequential traversal.** Cohorts exist in `PlanNode.cohort` but
//!   stage 1 doesn't run cohort siblings concurrently. Parallel-within-
//!   cohort lands in stage 2 (see DR-14 in `DEFERRED-RUNTIME.md`).
//! - **Conflict re-detection at execute time.** Before each op, probe
//!   the live state and check the op's preconditions. Existence-based
//!   detection only in stage 1 (Missing / Phantom); content-hash-based
//!   Hard conflicts need post-content-hash plumbing through `InverseOp`
//!   — deferred along with the runtime capture pipeline.
//! - **Single tier (Files).** A real tier-router lands once the
//!   package / env / network executors exist (S14+).

use crate::executor::{
    ConflictPolicy, ExecutionOutcome, ExecutionRecord, ExecutionReport, InverseOpExecutor,
    OutcomeKind, PlanSummary,
};
use crate::inverse::{Conflict, InverseOp, UndoPlan};
use crate::probe::StateProbe;

/// The thing that walks an [`UndoPlan`] and applies it.
///
/// Borrows the executor + probe; the orchestrator holds no state of
/// its own across calls. Re-entrant by design.
pub struct Orchestrator<'a, E: InverseOpExecutor, P: StateProbe> {
    executor: &'a E,
    probe: &'a P,
}

impl<'a, E: InverseOpExecutor, P: StateProbe> Orchestrator<'a, E, P> {
    pub fn new(executor: &'a E, probe: &'a P) -> Self {
        Self { executor, probe }
    }

    /// Walk the plan, applying each op. The returned report mirrors
    /// the plan's node order one-for-one.
    pub fn run(&self, plan: &UndoPlan, dry_run: bool, policy: ConflictPolicy) -> ExecutionReport {
        let plan_summary = PlanSummary::from_plan(plan);
        let mut records: Vec<ExecutionRecord> = Vec::with_capacity(plan.nodes.len());

        for (op_index, node) in plan.nodes.iter().enumerate() {
            let op = &node.op;

            // Live-state precondition check. Returns Some(Conflict) when
            // the FS is in a state we can't reconcile with the op's
            // assumptions.
            let conflict = self.precondition_conflict(op);

            let outcome = match (conflict, policy) {
                // No conflict — execute.
                (None, _) => self.executor.execute(op, dry_run, policy),
                // Force ignores any conflict and attempts the op.
                (Some(_), ConflictPolicy::Force) => self.executor.execute(op, dry_run, policy),
                // Skip policy: every conflict short-circuits to Skipped.
                (Some(c), ConflictPolicy::Skip) => ExecutionOutcome::Skipped {
                    reason: format!("conflict: {c:?}"),
                },
                // Abort + any conflict: record it. The post-loop check
                // halts the remainder only if the conflict is blocking
                // (Hard / Phantom). Missing under Abort is recorded but
                // not halting — it's typically informational ("path
                // already gone, op is a no-op").
                (Some(c), ConflictPolicy::Abort) => ExecutionOutcome::Conflict { kind: c.clone() },
            };

            let outcome_kind = OutcomeKind::from_outcome(&outcome);
            let detail = match &outcome {
                ExecutionOutcome::Skipped { reason } => Some(reason.clone()),
                ExecutionOutcome::Conflict { kind } => Some(format!("{kind:?}")),
                ExecutionOutcome::Failed { err } => Some(err.clone()),
                _ => None,
            };
            records.push(ExecutionRecord {
                op_index,
                op: op.clone(),
                tier: op.tier(),
                outcome_kind,
                detail,
            });

            // Abort policy: stop after a blocking conflict OR a hard failure.
            if matches!(policy, ConflictPolicy::Abort)
                && matches!(
                    outcome_kind,
                    OutcomeKind::Failed | OutcomeKind::ConflictHard | OutcomeKind::ConflictPhantom
                )
            {
                tracing::warn!(
                    ?op_index,
                    ?outcome_kind,
                    "orchestrator: abort policy reached; halting remainder of plan"
                );
                break;
            }
        }

        ExecutionReport {
            plan_summary,
            records,
            dry_run,
            policy,
        }
    }

    /// Stage-1 precondition checker. Existence-based only.
    ///
    /// **Deferred (stage 2):** content-hash-based Hard conflicts. The
    /// planner currently captures `post_content_hash` for files but
    /// doesn't plumb it through `InverseOp::RestoreContent` — adding
    /// that hash to the inverse-op variant is the natural shape for
    /// stage 2. Until then we trust the planner's plan-time conflict
    /// annotations on `PlanNode.conflict`.
    fn precondition_conflict(&self, op: &InverseOp) -> Option<Conflict> {
        match op {
            InverseOp::RestoreContent { path, .. }
            | InverseOp::RestoreMetadata { path, .. }
            | InverseOp::Unlink { path } => {
                if self.probe.exists(path) {
                    None
                } else {
                    Some(Conflict::Missing {
                        detail: format!("{path:?} no longer exists"),
                    })
                }
            }
            InverseOp::RecreatePath { path, .. } | InverseOp::CreateSymlink { path, .. } => {
                if self.probe.exists(path) {
                    Some(Conflict::Phantom {
                        detail: format!("{path:?} already exists; cannot recreate"),
                    })
                } else {
                    None
                }
            }
            InverseOp::Rename { from, to } => {
                if !self.probe.exists(from) {
                    Some(Conflict::Missing {
                        detail: format!("rename source {from:?} does not exist"),
                    })
                } else if self.probe.exists(to) {
                    Some(Conflict::Phantom {
                        detail: format!("rename target {to:?} already exists"),
                    })
                } else {
                    None
                }
            }
            // Non-file-tier ops: no FS preconditions; defer to the
            // tier-specific executor's own checks.
            InverseOp::SetEnv { .. }
            | InverseOp::UnsetEnv { .. }
            | InverseOp::PackageRollback { .. }
            | InverseOp::NetworkRollback { .. }
            | InverseOp::SystemdRollback { .. }
            | InverseOp::ProcessNote { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CommandId, CommandRecord};
    use crate::executor::InMemoryBlobReader;
    use crate::executors::FileExecutor;
    use crate::inode::{BlobHash, InodeRef};
    use crate::inverse::PlanNode;
    use crate::metadata::FileMetadata;
    use crate::probe::ProbeStat;
    use crate::probe::mock::InMemoryProbe;
    use crate::time::TimePoint;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn empty_plan() -> UndoPlan {
        UndoPlan {
            command: CommandRecord {
                command: CommandId {
                    session: Uuid::nil(),
                    seq: 0,
                },
                cmd_string: None,
                cwd: PathBuf::from("/tmp"),
                pid: 1,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::min(),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            },
            nodes: vec![],
            warnings: vec![],
        }
    }

    fn sample_meta() -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
        }
    }

    #[test]
    fn empty_plan_yields_empty_report() {
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let probe = InMemoryProbe::new();
        let orc = Orchestrator::new(&exec, &probe);
        let r = orc.run(&empty_plan(), false, ConflictPolicy::default());
        assert_eq!(r.records.len(), 0);
        assert!(r.fully_applied());
    }

    #[test]
    fn missing_target_for_unlink_records_missing_conflict() {
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let probe = InMemoryProbe::new(); // empty — path is absent
        let orc = Orchestrator::new(&exec, &probe);
        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::Unlink {
                path: PathBuf::from("/tmp/gone"),
            },
            cohort: 0,
            conflict: None,
        });
        let r = orc.run(&plan, false, ConflictPolicy::Abort);
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].outcome_kind, OutcomeKind::ConflictMissing);
    }

    #[test]
    fn skip_policy_records_skipped_for_conflict() {
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let probe = InMemoryProbe::new();
        let orc = Orchestrator::new(&exec, &probe);
        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::RestoreMetadata {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/gone"),
                target: sample_meta(),
            },
            cohort: 0,
            conflict: None,
        });
        let r = orc.run(&plan, false, ConflictPolicy::Skip);
        assert_eq!(r.records[0].outcome_kind, OutcomeKind::Skipped);
    }

    #[test]
    fn abort_policy_halts_after_blocking_conflict() {
        let tmpdir = tempfile::tempdir().unwrap();
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let mut probe = InMemoryProbe::new();
        // First op's path exists -> phantom (RecreatePath onto existing).
        let target = tmpdir.path().join("a");
        probe.insert(
            target.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 1),
                meta: sample_meta(),
            },
            None,
        );

        let orc = Orchestrator::new(&exec, &probe);
        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::RecreatePath {
                path: target,
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            },
            cohort: 0,
            conflict: None,
        });
        plan.nodes.push(PlanNode {
            // This second op would normally apply; abort should stop us before it.
            op: InverseOp::Unlink {
                path: PathBuf::from("/tmp/nope"),
            },
            cohort: 1,
            conflict: None,
        });
        let r = orc.run(&plan, false, ConflictPolicy::Abort);
        assert_eq!(r.records.len(), 1, "second op should not be attempted");
        assert_eq!(r.records[0].outcome_kind, OutcomeKind::ConflictPhantom);
    }

    #[test]
    fn dry_run_no_mutation_records_would_apply() {
        let tmpdir = tempfile::tempdir().unwrap();
        let target = tmpdir.path().join("f");
        std::fs::write(&target, b"current").unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);

        let mut probe = InMemoryProbe::new();
        probe.insert(
            target.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 1),
                meta: sample_meta(),
            },
            None,
        );
        let orc = Orchestrator::new(&exec, &probe);

        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::Unlink {
                path: target.clone(),
            },
            cohort: 0,
            conflict: None,
        });
        let r = orc.run(&plan, true, ConflictPolicy::default());
        assert_eq!(r.records[0].outcome_kind, OutcomeKind::WouldApply);
        // The file is still there — dry-run didn't mutate.
        assert!(target.exists());
    }

    #[test]
    fn full_round_trip_restore_then_unlink() {
        let tmpdir = tempfile::tempdir().unwrap();
        let target = tmpdir.path().join("a");
        std::fs::write(&target, b"before").unwrap();

        let mut reader = InMemoryBlobReader::new();
        let blob = BlobHash::from_bytes([5; 32]);
        reader.insert(blob, b"captured".to_vec());

        let exec = FileExecutor::new(&reader);

        // Probe sees the target. (Mock probe; the orchestrator doesn't
        // care about LiveStateProbe here — that's an integration-test
        // concern.)
        let mut probe = InMemoryProbe::new();
        probe.insert(
            target.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 1),
                meta: sample_meta(),
            },
            None,
        );
        let orc = Orchestrator::new(&exec, &probe);

        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::RestoreContent {
                inode: InodeRef::new(1, 1),
                path: target.clone(),
                blob,
            },
            cohort: 0,
            conflict: None,
        });
        let r = orc.run(&plan, false, ConflictPolicy::Abort);
        assert_eq!(r.records[0].outcome_kind, OutcomeKind::Applied);
        assert_eq!(std::fs::read(&target).unwrap(), b"captured");
        assert!(r.fully_applied());
    }
}
