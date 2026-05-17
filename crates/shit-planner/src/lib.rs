// SPDX-License-Identifier: AGPL-3.0-or-later

//! Undo planner and inverse-op DAG for `shit`.
//!
//! This crate is **pure**: no I/O, no syscalls. Inputs are `CaptureEvent`s
//! fetched from a `PlannerStore` plus a `StateProbe` over the live
//! filesystem. Output is an `UndoPlan` — a topologically-ordered DAG of
//! `InverseOp`s with conflict annotations.
//!
//! See `.docs/sprints/S03-undo-planner-spec.md` for the design and
//! `.docs/audits/planner-spec.md` for the longer rationale.

pub mod db;
pub mod env;
pub mod events;
pub mod exec_log;
pub mod executor;
pub mod executors;
pub mod inode;
pub mod inverse;
pub mod metadata;
pub mod network;
pub mod orchestrator;
pub mod plan;
pub mod probe;
pub mod probe_live;
pub mod proc;
pub mod services;
pub mod store;
pub mod time;

pub use plan::plan;

pub use env::{
    DEFAULT_IGNORE, DEFAULT_IGNORE_PREFIXES, DEFAULT_REDACT_SUBSTRINGS, EnvDiff, EnvFilter,
    canonicalize as env_canonicalize, diff_env_blocks, diff_env_maps, hash_env, hash_env_block,
    parse_block as env_parse_block, redact_value,
};
pub use events::{
    CaptureEvent, CaptureEventKind, CommandId, CommandRecord, EventId, NetworkTool, PackageManager,
    PackageOpKind, ProcessOpKind, ServiceState, SystemdScope, TreeOp,
};
pub use exec_log::{ExecLog, ExecLogError, default_dir as exec_log_default_dir, read_all};
pub use executor::{
    BlobReadError, BlobReader, ConflictPolicy, ExecutionOutcome, ExecutionRecord, ExecutionReport,
    InMemoryBlobReader, InverseOpExecutor, OutcomeKind, PlanSummary,
};
pub use executors::FileExecutor;
pub use inode::{BlobHash, InodeRef};
pub use inverse::{
    Conflict, DbEngine, InverseOp, InverseTier, PlanNode, PlanWarning, RollbackHint, UndoPlan,
};
pub use metadata::{FileKind, FileMetadata};
pub use network::{
    IP_MUTATING, IPTABLES_MUTATING, NFT_MUTATING, PFCTL_MUTATING, RestoreMethod, UFW_MUTATING,
    is_ip_mutating, is_iptables_mutating, is_nft_mutating, is_pfctl_mutating, is_ufw_mutating,
    restore_method,
};
pub use orchestrator::Orchestrator;
pub use probe::{ProbeStat, StateProbe};
pub use probe_live::{LiveStateProbe, hash_file};
pub use proc::{KillCommand, KillTarget, parse_kill, parse_pattern_kill};
pub use services::{
    LAUNCHCTL_MUTATING_VERBS, SYSTEMCTL_MUTATING_VERBS, is_launchctl_mutating,
    is_systemctl_mutating, parse_launchctl_print, parse_systemctl_show,
};
pub use store::PlannerStore;
pub use time::{SeqRange, TimePoint, TimeRange};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_wires_up() {
        assert_eq!(2 + 2, 4);
    }
}
