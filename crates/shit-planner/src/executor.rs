// SPDX-License-Identifier: AGPL-3.0-or-later

//! Executor trait + outcome types (S11 stage 1).
//!
//! The planner emits an [`UndoPlan`]. The executor applies it. This module
//! defines the abstract contract between them; concrete implementations
//! (the file-tier executor, future package/network/systemd executors)
//! live in `executor/` submodules.
//!
//! ## Why the executor lives in the planner crate
//!
//! Spec ([S11](.docs/sprints/S11-undo-executor.md)) places executor code
//! under `shit-planner` for two reasons:
//! 1. Co-location with the `InverseOp` types it consumes prevents the
//!    "executor crate has to re-export half of planner" problem.
//! 2. Avoids a circular crate dep — `shit-store` depends on `shit-planner`
//!    for event types, so `shit-planner` cannot depend on `shit-store`.
//!    The executor instead consumes an abstract [`BlobReader`] trait that
//!    callers (CLI, daemon) wire up against the real store.
//!
//! ## Purity / I/O boundary
//!
//! The planner crate remains pure for the types in `inverse.rs`,
//! `plan.rs`, etc. The executor is *the* I/O boundary inside this crate —
//! it's where syscalls happen. Concrete `FileExecutor` syscalls live in
//! the `executors/` submodule; the trait itself is pure.

use std::path::PathBuf;

use crate::inode::BlobHash;
use crate::inverse::{Conflict, InverseOp, UndoPlan};

/// Outcome of executing a single [`InverseOp`].
///
/// Matches the spec's enum exactly. `WouldApply` is the dry-run analogue
/// of `Applied`; the two never appear in the same report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Op mutated live state successfully.
    Applied,
    /// Dry-run: op *would* have applied. No mutation occurred.
    WouldApply,
    /// Op was deliberately skipped (e.g. `--on-conflict=skip` hit a
    /// soft conflict, or partial-undo filter excluded the path).
    Skipped { reason: String },
    /// Live state didn't match captured state; op cannot apply without
    /// the user choosing a conflict policy.
    Conflict { kind: Conflict },
    /// Hard failure mid-op. The FS may be in a partial state; the
    /// caller decides whether to abort or continue per
    /// `ConflictPolicy`. `err` is the underlying I/O error message.
    Failed { err: String },
}

impl ExecutionOutcome {
    /// True when this outcome means "nothing changed and we should
    /// continue trying the remaining ops." Excludes Failed because
    /// a partial-write may have happened.
    pub fn is_inert(&self) -> bool {
        matches!(
            self,
            Self::WouldApply | Self::Skipped { .. } | Self::Conflict { .. }
        )
    }

    pub fn verb_past_tense(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::WouldApply => "would apply",
            Self::Skipped { .. } => "skipped",
            Self::Conflict { .. } => "conflict",
            Self::Failed { .. } => "failed",
        }
    }
}

/// One row of an [`ExecutionReport`]. Cheap to clone; serializable so
/// the CLI can dump JSON for `--format=json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionRecord {
    /// Position in the input plan's `nodes` vec. Useful for cross-referencing
    /// with `shit show <id>`.
    pub op_index: usize,
    /// The op as the executor saw it — copied (not borrowed) so the record
    /// is self-contained.
    pub op: InverseOp,
    /// Tier label, denormalized for `shit show --exec` filtering.
    pub tier: crate::inverse::InverseTier,
    /// What happened.
    pub outcome_kind: OutcomeKind,
    /// Free-form detail for non-`Applied` outcomes (skip reason, conflict
    /// description, error message).
    pub detail: Option<String>,
}

/// Sidecar enum for serialization. `ExecutionOutcome` carries `Conflict`
/// which holds borrowed-ish data; this serializes flat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OutcomeKind {
    Applied,
    WouldApply,
    Skipped,
    ConflictSoft,
    ConflictHard,
    ConflictMissing,
    ConflictPhantom,
    Failed,
}

impl OutcomeKind {
    pub fn from_outcome(o: &ExecutionOutcome) -> Self {
        match o {
            ExecutionOutcome::Applied => Self::Applied,
            ExecutionOutcome::WouldApply => Self::WouldApply,
            ExecutionOutcome::Skipped { .. } => Self::Skipped,
            ExecutionOutcome::Conflict { kind } => match kind {
                Conflict::Soft { .. } => Self::ConflictSoft,
                Conflict::Hard { .. } => Self::ConflictHard,
                Conflict::Missing { .. } => Self::ConflictMissing,
                Conflict::Phantom { .. } => Self::ConflictPhantom,
            },
            ExecutionOutcome::Failed { .. } => Self::Failed,
        }
    }
}

/// What gets returned at the end of an orchestrator run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionReport {
    /// The undo we tried to apply. Carries the original command for
    /// rendering.
    pub plan_summary: PlanSummary,
    /// Per-op outcomes, in the same order as `UndoPlan.nodes`.
    pub records: Vec<ExecutionRecord>,
    /// True when `dry_run = true` was passed to the orchestrator.
    pub dry_run: bool,
    /// The conflict policy in force for this run.
    pub policy: ConflictPolicy,
}

impl ExecutionReport {
    /// Did every op apply (or `WouldApply` for dry-run)?
    pub fn fully_applied(&self) -> bool {
        self.records.iter().all(|r| {
            matches!(
                r.outcome_kind,
                OutcomeKind::Applied | OutcomeKind::WouldApply
            )
        })
    }

    /// Count of ops with a given outcome kind. Useful for the CLI's
    /// "applied N, skipped M, failed K" summary line.
    pub fn count_outcomes(&self, kind: OutcomeKind) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome_kind == kind)
            .count()
    }
}

/// Denormalized handle on the plan's identity. Kept separate from the
/// full `UndoPlan` so the report can be persisted/transmitted without
/// re-bundling the whole plan body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlanSummary {
    pub command_id: crate::events::CommandId,
    pub cmd_string: Option<String>,
    pub cwd: PathBuf,
    pub node_count: usize,
}

impl PlanSummary {
    pub fn from_plan(plan: &UndoPlan) -> Self {
        Self {
            command_id: plan.command.command,
            cmd_string: plan.command.cmd_string.clone(),
            cwd: plan.command.cwd.clone(),
            node_count: plan.nodes.len(),
        }
    }
}

/// How the orchestrator handles a per-op conflict.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConflictPolicy {
    /// Stop at the first hard conflict; report what was applied + what
    /// remains. **Default.** Safest.
    #[default]
    Abort,
    /// Skip conflicting ops (record as `Skipped`), continue with the rest.
    /// Use when you want maximum partial-undo coverage.
    Skip,
    /// Apply over conflicts. The CLI requires `--yes` for this; the
    /// orchestrator itself trusts the caller.
    Force,
}

/// Abstract content-by-hash reader. The CLI/daemon wires this up against
/// the real `shit-store::Blob` API; tests use an `InMemoryBlobReader`.
///
/// Returning `Vec<u8>` (not a stream) is deliberate for stage 1 — most
/// files we restore are small (config files, source code, dotfiles).
/// A streaming variant for large blobs lands in a follow-up sprint.
pub trait BlobReader {
    fn read(&self, hash: &BlobHash) -> Result<Vec<u8>, BlobReadError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BlobReadError {
    #[error("blob not found: {0}")]
    NotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("integrity: stored hash {stored} != computed {computed}")]
    Integrity { stored: String, computed: String },
}

/// In-memory blob reader for tests.
#[derive(Default, Debug, Clone)]
pub struct InMemoryBlobReader {
    map: std::collections::BTreeMap<BlobHash, Vec<u8>>,
}

impl InMemoryBlobReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, hash: BlobHash, content: Vec<u8>) {
        self.map.insert(hash, content);
    }
}

impl BlobReader for InMemoryBlobReader {
    fn read(&self, hash: &BlobHash) -> Result<Vec<u8>, BlobReadError> {
        self.map
            .get(hash)
            .cloned()
            .ok_or_else(|| BlobReadError::NotFound(format!("{hash:?}")))
    }
}

/// Tier-specific executor contract. Implementors handle a subset of
/// [`InverseOp`] variants identified by [`InverseTier`](crate::inverse::InverseTier).
///
/// **Sync, not async.** Stage 1 is sequential and FS-only; async lands
/// once we add helper-IPC routing for privileged ops (DR-15).
pub trait InverseOpExecutor {
    /// Does this executor handle `op`?
    fn supports(&self, op: &InverseOp) -> bool;

    /// Apply the op. The implementor is responsible for:
    /// - probing the live state and emitting `Conflict { .. }` when the
    ///   state isn't what was captured (subject to `policy`),
    /// - returning `WouldApply` when `dry_run = true`,
    /// - returning `Applied` or `Failed { err }` after the mutate.
    fn execute(&self, op: &InverseOp, dry_run: bool, policy: ConflictPolicy) -> ExecutionOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CommandId, CommandRecord};
    use uuid::Uuid;

    fn dummy_plan() -> UndoPlan {
        UndoPlan {
            command: CommandRecord {
                command: CommandId {
                    session: Uuid::nil(),
                    seq: 0,
                },
                cmd_string: Some("echo hi".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 1,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: crate::time::TimePoint::min(),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            },
            nodes: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn outcome_inert_classification() {
        assert!(ExecutionOutcome::WouldApply.is_inert());
        assert!(ExecutionOutcome::Skipped { reason: "x".into() }.is_inert());
        assert!(
            ExecutionOutcome::Conflict {
                kind: Conflict::Soft { detail: "x".into() }
            }
            .is_inert()
        );
        assert!(!ExecutionOutcome::Applied.is_inert());
        assert!(!ExecutionOutcome::Failed { err: "x".into() }.is_inert());
    }

    #[test]
    fn outcome_kind_round_trip() {
        let cases = [
            ExecutionOutcome::Applied,
            ExecutionOutcome::WouldApply,
            ExecutionOutcome::Skipped { reason: "x".into() },
            ExecutionOutcome::Conflict {
                kind: Conflict::Hard { detail: "x".into() },
            },
            ExecutionOutcome::Failed { err: "x".into() },
        ];
        for c in &cases {
            let k = OutcomeKind::from_outcome(c);
            // Round-trip serialize.
            let bytes = postcard::to_allocvec(&k).unwrap();
            let back: OutcomeKind = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn default_conflict_policy_is_abort() {
        assert_eq!(ConflictPolicy::default(), ConflictPolicy::Abort);
    }

    #[test]
    fn plan_summary_pulls_fields() {
        let p = dummy_plan();
        let s = PlanSummary::from_plan(&p);
        assert_eq!(s.command_id, p.command.command);
        assert_eq!(s.cmd_string, p.command.cmd_string);
        assert_eq!(s.node_count, 0);
    }

    #[test]
    fn execution_report_fully_applied_empty_is_true() {
        let p = dummy_plan();
        let r = ExecutionReport {
            plan_summary: PlanSummary::from_plan(&p),
            records: vec![],
            dry_run: false,
            policy: ConflictPolicy::default(),
        };
        assert!(r.fully_applied());
    }

    #[test]
    fn in_memory_blob_reader_round_trip() {
        let mut r = InMemoryBlobReader::new();
        let h = BlobHash::from_bytes([7; 32]);
        r.insert(h, b"hello".to_vec());
        assert_eq!(r.read(&h).unwrap(), b"hello");
        assert!(matches!(
            r.read(&BlobHash::from_bytes([0; 32])),
            Err(BlobReadError::NotFound(_))
        ));
    }
}
