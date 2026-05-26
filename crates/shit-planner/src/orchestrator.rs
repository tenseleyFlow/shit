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

use std::sync::Mutex;

use crate::executor::{
    ConflictPolicy, ExecutionOutcome, ExecutionRecord, ExecutionReport, InverseOpExecutor,
    OutcomeKind, PlanSummary,
};
use crate::inverse::{Conflict, InverseOp, PlanNode, UndoPlan};
use crate::probe::StateProbe;

/// Default cap on cohort-parallel concurrency per the S11/S12 sprint
/// plans. Operators tune via the orchestrator constructor (S12 CLI:
/// `--parallel N` once we wire it through; for now this is the only
/// knob).
pub const DEFAULT_COHORT_PARALLELISM: usize = 4;

/// DR-17 helper: compile a list of glob patterns (`shit undo --paths
/// '/etc/**' --paths '/var/log/**'`) into the
/// [`globset::GlobSet`] the orchestrator's `with_paths_filter`
/// expects.
///
/// Returns:
/// - `Ok(None)` when `patterns` is empty — caller passes that to
///   `with_paths_filter` to clear the filter.
/// - `Ok(Some(set))` when at least one pattern compiled.
/// - `Err` when a pattern is malformed; the error names the bad
///   pattern so the CLI can render it back to the user.
pub fn compile_paths_filter(
    patterns: &[String],
) -> Result<Option<globset::GlobSet>, PathsFilterError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = globset::GlobSetBuilder::new();
    for pat in patterns {
        let glob = globset::Glob::new(pat).map_err(|e| PathsFilterError {
            pattern: pat.clone(),
            source: e,
        })?;
        builder.add(glob);
    }
    let set = builder.build().map_err(|e| PathsFilterError {
        pattern: patterns.join(", "),
        source: e,
    })?;
    Ok(Some(set))
}

/// Compilation failure for a `--paths` pattern.
#[derive(Debug, thiserror::Error)]
#[error("invalid --paths pattern `{pattern}`: {source}")]
pub struct PathsFilterError {
    pub pattern: String,
    #[source]
    pub source: globset::Error,
}

/// Group plan-node indices by cohort, preserving cohort order. The
/// planner emits cohorts in non-decreasing order, so the result here
/// is the natural traversal sequence for `run_parallel`.
fn group_by_cohort(nodes: &[PlanNode]) -> Vec<(u32, Vec<usize>)> {
    let mut groups: Vec<(u32, Vec<usize>)> = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        match groups.last_mut() {
            Some((c, idx)) if *c == node.cohort => idx.push(i),
            _ => groups.push((node.cohort, vec![i])),
        }
    }
    groups
}

/// The thing that walks an [`UndoPlan`] and applies it.
///
/// Borrows the executor + probe; the orchestrator holds no state of
/// its own across calls. Re-entrant by design.
///
/// **Path filter (DR-17 — partial undo):** when set, ops whose
/// `primary_path()` doesn't match any of the patterns are recorded
/// as `Skipped { reason: "filtered out" }`. Ops without a path
/// (env, network, etc.) are not affected — they pass the filter
/// unconditionally so a `--paths '/etc/**'` doesn't accidentally
/// silence environment changes.
pub struct Orchestrator<'a, E: InverseOpExecutor, P: StateProbe> {
    executor: &'a E,
    probe: &'a P,
    paths_filter: Option<globset::GlobSet>,
}

impl<'a, E: InverseOpExecutor, P: StateProbe> Orchestrator<'a, E, P> {
    pub fn new(executor: &'a E, probe: &'a P) -> Self {
        Self {
            executor,
            probe,
            paths_filter: None,
        }
    }

    /// Restrict execution to ops whose path matches at least one
    /// pattern. Pass `None` to clear.
    pub fn with_paths_filter(mut self, set: Option<globset::GlobSet>) -> Self {
        self.paths_filter = set;
        self
    }

    /// True when this op should be skipped because its path doesn't
    /// match the filter. Ops without a path bypass the filter.
    fn filtered_out(&self, op: &InverseOp) -> bool {
        let Some(set) = &self.paths_filter else {
            return false;
        };
        match op.primary_path() {
            Some(p) => !set.is_match(p),
            None => false,
        }
    }

    /// Run the plan with cohort-level parallelism (DR-14 / S12.12).
    ///
    /// Within each `cohort` (as labeled on `PlanNode.cohort`) the
    /// orchestrator spawns up to `max_parallel` threads, executes
    /// sibling ops concurrently, and joins all before advancing to
    /// the next cohort. The planner's invariant is that sibling ops
    /// commute (different inodes, no path conflict), so concurrent
    /// execution is safe without re-checking.
    ///
    /// **Concurrency model:** `std::thread::scope` so we don't pull
    /// in tokio at the planner-crate level. The CLI binary chooses
    /// the runtime; we just need workers. The blocking nature of
    /// the per-op syscalls makes spawn_blocking-style async an
    /// over-engineering for this case.
    ///
    /// Requires `Sync` bounds on the executor and probe since both
    /// are shared across worker threads via `&`.
    pub fn run_parallel(
        &self,
        plan: &UndoPlan,
        dry_run: bool,
        policy: ConflictPolicy,
        max_parallel: usize,
    ) -> ExecutionReport
    where
        E: Sync,
        P: Sync,
    {
        let plan_summary = PlanSummary::from_plan(plan);
        let mut records: Vec<Option<ExecutionRecord>> = vec![None; plan.nodes.len()];
        let mut aborted = false;

        // Group node indices by cohort. We rely on the planner's
        // topological order: cohorts appear in non-decreasing order
        // and never interleave.
        let cohorts = group_by_cohort(&plan.nodes);
        for (_cohort_id, cohort_indices) in cohorts {
            // DR-64 fault-injection: crash at the cohort boundary.
            // Cohorts are disjoint by construction, so a crash here
            // leaves every prior cohort fully applied. Recovery
            // resumes at this cohort.
            shit_proto::fault_inject::maybe_inject("orchestrator.run_parallel.between_cohorts");
            // Collect parallel results in a thread-safe slot.
            let records_slot: Mutex<&mut Vec<Option<ExecutionRecord>>> = Mutex::new(&mut records);
            let abort_flag = Mutex::new(false);
            std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(cohort_indices.len());
                let semaphore = std::sync::Arc::new(Mutex::new(0usize));
                let cap = max_parallel.max(1);

                for op_index in cohort_indices.iter().copied() {
                    let node = &plan.nodes[op_index];
                    let op = &node.op;
                    let sem = std::sync::Arc::clone(&semaphore);
                    let records_slot = &records_slot;
                    let abort_flag = &abort_flag;
                    let handle = s.spawn(move || {
                        // Crude semaphore: spin until the in-flight
                        // count is below cap. Cohorts are small enough
                        // (~tens of nodes) that this is fine; a real
                        // semaphore would only matter at thousands.
                        loop {
                            let mut g = sem.lock().unwrap();
                            if *g < cap {
                                *g += 1;
                                break;
                            }
                            drop(g);
                            std::thread::yield_now();
                        }
                        let record = self.execute_one(op_index, op, dry_run, policy);
                        // Track whether this record triggers abort.
                        if matches!(policy, ConflictPolicy::Abort)
                            && matches!(
                                record.outcome_kind,
                                OutcomeKind::Failed
                                    | OutcomeKind::ConflictHard
                                    | OutcomeKind::ConflictPhantom
                            )
                        {
                            *abort_flag.lock().unwrap() = true;
                        }
                        records_slot.lock().unwrap()[op_index] = Some(record);
                        *sem.lock().unwrap() -= 1;
                    });
                    handles.push(handle);
                }
                for h in handles {
                    let _ = h.join();
                }
            });

            if *abort_flag.lock().unwrap() {
                aborted = true;
                break;
            }
        }

        // Drop trailing `None`s (the post-abort tail) so the report
        // length reflects what was actually attempted.
        let records: Vec<ExecutionRecord> = records.into_iter().flatten().collect();
        if aborted {
            tracing::warn!("orchestrator (parallel): abort policy halted plan");
        }

        ExecutionReport {
            plan_summary,
            records,
            dry_run,
            policy,
        }
    }

    /// Per-op evaluator extracted so it's shareable between the
    /// sequential `run` and the parallel `run_parallel`.
    fn execute_one(
        &self,
        op_index: usize,
        op: &InverseOp,
        dry_run: bool,
        policy: ConflictPolicy,
    ) -> ExecutionRecord {
        if self.filtered_out(op) {
            return ExecutionRecord {
                op_index,
                op: op.clone(),
                tier: op.tier(),
                outcome_kind: OutcomeKind::Skipped,
                detail: Some(format!(
                    "filtered out: {} not matched by --paths",
                    op.primary_path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<no-path>".into())
                )),
            };
        }
        // AR07.1: Refuse nodes are informational only. The orchestrator
        // never dispatches them to an executor (no executor declares
        // InverseTier::Refuse support). Surface as Skipped so the CLI
        // reports them with the catalog reason + remediation rendered
        // from the op itself.
        if let InverseOp::Refuse {
            class,
            reason,
            remediation,
        } = op
        {
            let detail = match remediation {
                Some(rem) => format!("refused ({class}): {reason}. Remediation: {rem}"),
                None => format!("refused ({class}): {reason}"),
            };
            return ExecutionRecord {
                op_index,
                op: op.clone(),
                tier: op.tier(),
                outcome_kind: OutcomeKind::Skipped,
                detail: Some(detail),
            };
        }
        let conflict = self.precondition_conflict(op);
        let outcome = match (conflict, policy) {
            (None, _) => self.executor.execute(op, dry_run, policy),
            (Some(_), ConflictPolicy::Force) => self.executor.execute(op, dry_run, policy),
            (Some(c), ConflictPolicy::Skip) => ExecutionOutcome::Skipped {
                reason: format!("conflict: {c:?}"),
            },
            (Some(c), ConflictPolicy::Abort) => ExecutionOutcome::Conflict { kind: c.clone() },
        };
        let outcome_kind = OutcomeKind::from_outcome(&outcome);
        let detail = match &outcome {
            ExecutionOutcome::Skipped { reason } => Some(reason.clone()),
            ExecutionOutcome::Conflict { kind } => Some(format!("{kind:?}")),
            ExecutionOutcome::Failed { err } => Some(err.clone()),
            _ => None,
        };
        ExecutionRecord {
            op_index,
            op: op.clone(),
            tier: op.tier(),
            outcome_kind,
            detail,
        }
    }

    /// Walk the plan, applying each op. The returned report mirrors
    /// the plan's node order one-for-one.
    pub fn run(&self, plan: &UndoPlan, dry_run: bool, policy: ConflictPolicy) -> ExecutionReport {
        let plan_summary = PlanSummary::from_plan(plan);
        let mut records: Vec<ExecutionRecord> = Vec::with_capacity(plan.nodes.len());

        for (op_index, node) in plan.nodes.iter().enumerate() {
            let op = &node.op;
            // DR-64 fault-injection: crash between serial ops. On
            // restart, the exec log is the source of truth for what
            // was already applied; the recovery path re-runs the
            // plan starting after the last recorded record.
            shit_proto::fault_inject::maybe_inject("orchestrator.run.before_op");
            let record = self.execute_one(op_index, op, dry_run, policy);
            shit_proto::fault_inject::maybe_inject("orchestrator.run.after_op");
            let outcome_kind = record.outcome_kind;
            records.push(record);
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
            // G01.3: RestoreContent does not require the target to
            // exist — its executor writes a tmpfile in the parent
            // dir and renames it into place, creating the target
            // if it isn't there. Stripping the existence check
            // unblocks the `git stash drop` shape where git
            // deletes `.git/refs/stash` + `.git/logs/refs/stash`
            // entirely after rewriting them. As long as the
            // PARENT exists, the executor can succeed; if the
            // parent is gone the executor returns its own
            // ENOENT-with-context as Failed (which is the right
            // signal — a true precondition violation, not a
            // recoverable gap).
            InverseOp::RestoreContent { .. } => None,
            InverseOp::RestoreMetadata { path, .. }
            | InverseOp::Unlink { path }
            | InverseOp::FileExtend { path, .. } => {
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
            // W09.20 — CreateHardlink needs source LIVE (we read its
            // inode) and target ABSENT (we create it). Missing source
            // is a hard failure; existing target is Phantom.
            InverseOp::CreateHardlink { source, target } => {
                if !self.probe.exists(source) {
                    Some(Conflict::Missing {
                        detail: format!(
                            "hardlink source {source:?} no longer exists; cannot link {target:?}"
                        ),
                    })
                } else if self.probe.exists(target) {
                    Some(Conflict::Phantom {
                        detail: format!("{target:?} already exists; cannot link"),
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
            | InverseOp::ProcessNote { .. }
            | InverseOp::DescriptorReverse { .. }
            | InverseOp::KubectlReverse { .. }
            | InverseOp::GhReverse { .. }
            | InverseOp::AwsReverse { .. }
            | InverseOp::TerraformReverse { .. }
            | InverseOp::ContainerRestore { .. }
            | InverseOp::ShellStateRestore { .. }
            | InverseOp::DbNote { .. }
            | InverseOp::Refuse { .. } => None,
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
    fn paths_filter_skips_non_matching_paths() {
        let tmpdir = tempfile::tempdir().unwrap();
        let inside = tmpdir.path().join("inside.txt");
        let outside = tmpdir.path().join("outside.txt");
        std::fs::write(&inside, b"a").unwrap();
        std::fs::write(&outside, b"b").unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);

        let mut probe = InMemoryProbe::new();
        probe.insert(
            inside.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 1),
                meta: sample_meta(),
            },
            None,
        );
        probe.insert(
            outside.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 2),
                meta: sample_meta(),
            },
            None,
        );

        // Filter: only `inside.txt` (literal match).
        let mut builder = globset::GlobSetBuilder::new();
        builder.add(globset::Glob::new(inside.to_str().unwrap()).unwrap());
        let set = builder.build().unwrap();

        let orc = Orchestrator::new(&exec, &probe).with_paths_filter(Some(set));

        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::Unlink {
                path: inside.clone(),
            },
            cohort: 0,
            conflict: None,
        });
        plan.nodes.push(PlanNode {
            op: InverseOp::Unlink {
                path: outside.clone(),
            },
            cohort: 0,
            conflict: None,
        });

        let r = orc.run(&plan, false, ConflictPolicy::default());
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.records[0].outcome_kind, OutcomeKind::Applied);
        assert_eq!(r.records[1].outcome_kind, OutcomeKind::Skipped);
        assert!(
            r.records[1]
                .detail
                .as_ref()
                .unwrap()
                .contains("filtered out"),
            "{:?}",
            r.records[1].detail
        );
        // Inside was applied; outside still exists.
        assert!(!inside.exists());
        assert!(outside.exists());
    }

    #[test]
    fn run_parallel_applies_independent_cohort_siblings() {
        // Three files in cohort 0 (independent inodes). All three
        // should land Applied; the orchestrator must not serialize
        // them artificially under run_parallel.
        let tmpdir = tempfile::tempdir().unwrap();
        let paths: Vec<std::path::PathBuf> = (0..3)
            .map(|i| tmpdir.path().join(format!("f{i}")))
            .collect();
        for p in &paths {
            std::fs::write(p, b"x").unwrap();
        }

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);

        let mut probe = InMemoryProbe::new();
        for (i, p) in paths.iter().enumerate() {
            probe.insert(
                p.clone(),
                ProbeStat {
                    inode: InodeRef::new(1, (i + 1) as u64),
                    meta: sample_meta(),
                },
                None,
            );
        }
        let orc = Orchestrator::new(&exec, &probe);

        let mut plan = empty_plan();
        for p in &paths {
            plan.nodes.push(PlanNode {
                op: InverseOp::Unlink { path: p.clone() },
                cohort: 0,
                conflict: None,
            });
        }
        let r = orc.run_parallel(&plan, false, ConflictPolicy::Skip, 4);
        assert_eq!(r.records.len(), 3);
        for rec in &r.records {
            assert_eq!(rec.outcome_kind, OutcomeKind::Applied, "{rec:?}");
        }
        for p in &paths {
            assert!(!p.exists());
        }
    }

    #[test]
    fn run_parallel_preserves_per_op_order_in_records() {
        // Even when ops run concurrently, the returned `records` are
        // indexed by op_index — they appear in the original plan order.
        let tmpdir = tempfile::tempdir().unwrap();
        let p0 = tmpdir.path().join("a");
        let p1 = tmpdir.path().join("b");
        std::fs::write(&p0, b"x").unwrap();
        std::fs::write(&p1, b"y").unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let mut probe = InMemoryProbe::new();
        probe.insert(
            p0.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 1),
                meta: sample_meta(),
            },
            None,
        );
        probe.insert(
            p1.clone(),
            ProbeStat {
                inode: InodeRef::new(1, 2),
                meta: sample_meta(),
            },
            None,
        );
        let orc = Orchestrator::new(&exec, &probe);

        let mut plan = empty_plan();
        plan.nodes.push(PlanNode {
            op: InverseOp::Unlink { path: p0.clone() },
            cohort: 0,
            conflict: None,
        });
        plan.nodes.push(PlanNode {
            op: InverseOp::Unlink { path: p1.clone() },
            cohort: 0,
            conflict: None,
        });
        let r = orc.run_parallel(&plan, false, ConflictPolicy::Skip, 2);
        assert_eq!(r.records[0].op_index, 0);
        assert_eq!(r.records[1].op_index, 1);
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

    // -----------------------------------------------------------------
    // DR-17: compile_paths_filter helper
    // -----------------------------------------------------------------

    #[test]
    fn compile_paths_filter_empty_returns_none() {
        let r = compile_paths_filter(&[]).unwrap();
        assert!(r.is_none(), "empty patterns clear the filter");
    }

    #[test]
    fn compile_paths_filter_single_pattern_matches_expected_paths() {
        let r = compile_paths_filter(&["/etc/**".to_string()])
            .unwrap()
            .unwrap();
        assert!(r.is_match("/etc/nginx/nginx.conf"));
        assert!(r.is_match("/etc/passwd"));
        assert!(!r.is_match("/var/log/syslog"));
    }

    #[test]
    fn compile_paths_filter_multiple_patterns_are_unioned() {
        let r = compile_paths_filter(&["/etc/**".to_string(), "/var/log/**".to_string()])
            .unwrap()
            .unwrap();
        assert!(r.is_match("/etc/passwd"));
        assert!(r.is_match("/var/log/syslog"));
        assert!(!r.is_match("/tmp/foo"));
    }

    #[test]
    fn compile_paths_filter_rejects_malformed_pattern() {
        // Unclosed character class.
        let err = compile_paths_filter(&["/[unclosed".to_string()]).unwrap_err();
        assert_eq!(err.pattern, "/[unclosed");
    }

    #[test]
    fn compile_paths_filter_then_orchestrator_skips_filtered_op() {
        // End-to-end: compile a filter that EXCLUDES /tmp/excluded
        // and confirm a RestoreContent op for it lands as Skipped
        // in the report.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let included = tmpdir.path().join("kept");
        let excluded = tmpdir.path().join("dropped");
        std::fs::write(&included, b"current").unwrap();
        std::fs::write(&excluded, b"current").unwrap();
        let mut reader = InMemoryBlobReader::new();
        let blob = BlobHash::from_bytes([0x11; 32]);
        reader.insert(blob, b"restored".to_vec());
        let exec = FileExecutor::new(&reader);
        // Probe must report both paths exist so the orchestrator's
        // precondition check doesn't fire `Conflict::Missing`.
        let mut probe = InMemoryProbe::new();
        for (path, ino) in [(&included, 1), (&excluded, 2)] {
            probe.by_path.insert(
                path.clone(),
                (
                    ProbeStat {
                        inode: InodeRef::new(1, ino),
                        meta: FileMetadata {
                            mode: 0o100644,
                            uid: 1000,
                            gid: 1000,
                            size: 7,
                            mtime_unix_nanos: 0,
                            xattrs: Default::default(),
                            acl: None,
                        },
                    },
                    None,
                ),
            );
        }
        // Filter that matches only `included`'s basename via `**`.
        let pat = format!("**/{}", included.file_name().unwrap().display());
        let filter = compile_paths_filter(&[pat]).unwrap();
        let orc = Orchestrator::new(&exec, &probe).with_paths_filter(filter);
        let plan = UndoPlan {
            command: CommandRecord {
                command: CommandId {
                    session: Uuid::nil(),
                    seq: 1,
                },
                cmd_string: None,
                cwd: PathBuf::from("/"),
                pid: 0,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: Some(TimePoint::new(1, 1000)),
                exit_code: Some(0),
                event_ids: vec![],
            },
            nodes: vec![
                PlanNode {
                    op: InverseOp::RestoreContent {
                        inode: InodeRef::new(1, 1),
                        path: included.clone(),
                        blob,
                    },
                    cohort: 0,
                    conflict: None,
                },
                PlanNode {
                    op: InverseOp::RestoreContent {
                        inode: InodeRef::new(1, 2),
                        path: excluded.clone(),
                        blob,
                    },
                    cohort: 0,
                    conflict: None,
                },
            ],
            warnings: vec![],
        };
        let r = orc.run(&plan, false, ConflictPolicy::Skip);
        assert_eq!(r.records.len(), 2);
        // Order matches plan order.
        let outcomes: Vec<_> = r.records.iter().map(|rec| rec.outcome_kind).collect();
        // First (included) applied; second (excluded) skipped.
        assert_eq!(outcomes[0], OutcomeKind::Applied);
        assert_eq!(outcomes[1], OutcomeKind::Skipped);
        // Filter message ends up in the skip detail.
        assert!(
            r.records[1]
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("filtered")),
            "got: {:?}",
            r.records[1].detail
        );
        assert_eq!(std::fs::read(&included).unwrap(), b"restored");
        // Excluded file was not touched.
        assert_eq!(std::fs::read(&excluded).unwrap(), b"current");
    }
}
