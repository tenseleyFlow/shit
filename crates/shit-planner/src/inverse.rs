// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inverse-op DAG types — what `shit undo` actually executes.
//!
//! An [`UndoPlan`] is a flat, topologically-ordered list of [`PlanNode`]s.
//! Each node carries one [`InverseOp`] plus optional conflict and cohort
//! annotations. Cohorts group ops that commute and may execute concurrently;
//! cross-cohort ordering is strict.
//!
//! The planner is pure — these types describe *intent*. The executor
//! ([S11](.docs/sprints/S11-undo-executor.md)) is what actually mutates the
//! system.

use crate::events::{
    CommandRecord, NetworkTool, PackageManager, PackageOpKind, ServiceState, SystemdScope,
};
use crate::inode::{BlobHash, InodeRef};
use crate::metadata::{FileKind, FileMetadata};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One reversal step. Variants map onto [`CaptureEvent`] kinds, but the
/// mapping isn't 1-to-1 — composition rules in the planner can collapse,
/// reorder, or drop ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InverseOp {
    /// Restore a file's content from a blob in the store. The blob is
    /// pre-validated to exist before the plan is emitted.
    RestoreContent {
        inode: InodeRef,
        path: PathBuf,
        blob: BlobHash,
    },
    /// Restore a file's metadata (perms / owner / xattrs / ACL). Used both
    /// alone (for `MetadataChange`) and in combination with `RestoreContent`
    /// (the executor applies metadata after content).
    RestoreMetadata {
        inode: InodeRef,
        path: PathBuf,
        target: FileMetadata,
    },
    /// Remove a file the original command created. No content is recovered;
    /// the inverse of "create" is "unlink".
    Unlink { path: PathBuf },
    /// Re-create a path the original command unlinked. For directories we
    /// only know the mode; for special files we know the kind. Used together
    /// with `RestoreContent` for regular files.
    RecreatePath {
        path: PathBuf,
        kind: FileKind,
        mode: u32,
    },
    /// Reverse a rename: rename `from` back to `to`. The planner orders
    /// renames to avoid stomping intermediate states.
    Rename { from: PathBuf, to: PathBuf },
    /// Create a symlink. Used to undo `unlink` of a symlink, or directly
    /// from a `TreeOp::Symlink` capture (rare; usually the original creation
    /// is undone via `Unlink`).
    CreateSymlink { target: String, path: PathBuf },
    /// Set an environment variable. Note: applied by emitting a shell-side
    /// snippet, not by mutating the live shell process — see S15.
    SetEnv { name: String, value: String },
    /// Unset an environment variable. Same caveat as `SetEnv`.
    UnsetEnv { name: String },
    /// Roll back a package-manager operation. The executor synthesizes the
    /// inverse invocation per manager.
    ///
    /// `repo_state_hint` is an opaque pre-capture token whose meaning is
    /// per-manager. For dnf it carries the `dnf history` transaction id
    /// so the executor can emit a single `dnf history undo <id>` (DR-26)
    /// instead of synthesizing per-package install/remove invocations.
    /// Other managers leave it `None` today.
    PackageRollback {
        manager: PackageManager,
        original_op: PackageOpKind,
        packages_before: BTreeMap<String, String>,
        packages_after: BTreeMap<String, String>,
        repo_state_hint: Option<String>,
        /// C02.7: optional native-tool dispatch. When present, the
        /// `PackageExecutor` runs the delegation argv (typically
        /// `apt history-rollback <id>` or `dnf history undo <id>`)
        /// instead of synthesizing per-package install/remove
        /// invocations. The inspector populates this when the running
        /// version of the manager exposes a native rollback verb.
        #[serde(default)]
        delegation: Option<NativeDelegation>,
    },
    /// Roll back a network-tool change. Reload-style tools (iptables-restore,
    /// nft -f, pfctl -f) use `before_state`; diff-style tools (`ip route`,
    /// `networksetup`) use `inverse_invocations`.
    NetworkRollback {
        tool: NetworkTool,
        before_state: Vec<u8>,
        inverse_invocations: Vec<Vec<String>>,
    },
    /// Roll back a systemd / launchd unit op (start↔stop, enable↔disable, etc.).
    SystemdRollback {
        scope: SystemdScope,
        unit: String,
        before: ServiceState,
        after: ServiceState,
    },
    /// Informational: cannot mechanically reverse, but the user may want to
    /// know what they killed and how to restart it.
    ProcessNote {
        argv: Vec<String>,
        cwd: PathBuf,
        env_summary: BTreeMap<String, String>,
        message: String,
    },
    /// C02: reverse-API descriptor application. The daemon captured a
    /// snapshot via the descriptor's pre/post commands and stored the
    /// extracted state; the executor re-interpolates `reverse_argv` from
    /// `captured_state` at apply time and runs it (privileged routes via
    /// helper). All cloud-CLI long-tail packs use this op; only the
    /// hand-coded wrappers in C03 emit their own ops.
    DescriptorReverse {
        descriptor_name: String,
        descriptor_version: u32,
        captured_state: BTreeMap<String, String>,
        /// Pre-rendered argv at capture time. Executor re-renders from
        /// `captured_state` defensively; falls back to this if the
        /// descriptor file has gone missing between capture and undo.
        reverse_argv: Vec<String>,
        privileged: bool,
        requires_confirmation: bool,
        /// Optional pre-execute guard: `(check_argv, expected_substring)`.
        /// The substring is matched after interpolation. None = no guard.
        #[serde(default)]
        guard: Option<DescriptorGuardOp>,
    },
    /// C03: kubectl resource reverse. Capture the resource YAML (via
    /// `kubectl get -o yaml`) before a destructive verb; on undo, run
    /// `kubectl apply -f -` against the captured manifest. Context is
    /// guard-checked at apply time (refuse if the active kube-context
    /// has changed since capture).
    KubectlReverse {
        context: String,
        namespace: Option<String>,
        op: KubectlOp,
        /// Captured `kubectl get -o yaml` output (managed-fields stripped).
        /// Stored verbatim; serialized as utf-8 bytes for round-trip
        /// fidelity across YAML producers.
        captured_yaml: Vec<u8>,
        requires_confirmation: bool,
    },
    /// C03: GitHub-CLI op reverse. Lightweight: captures the resource
    /// metadata as JSON, and on undo either re-creates (for delete
    /// verbs) or re-opens (for close verbs). Asset re-uploads are
    /// out of v1; the captured JSON describes what was deleted so the
    /// user can manually re-upload large assets.
    GhReverse {
        op: GhOp,
        captured_json: Vec<u8>,
        requires_confirmation: bool,
    },
    /// C03: aws-cli op reverse. Per-service shape; `service` discriminates
    /// (`s3`, `ec2`, `iam`). The capture is service-specific (S3 carries
    /// VersionId; EC2 carries an instance descriptor; IAM carries policy
    /// docs). The executor dispatches on `op` to synthesize the right
    /// reverse argv.
    AwsReverse {
        service: String,
        op: AwsOp,
        captured_state: BTreeMap<String, String>,
        /// Optional stashed object bytes for `s3 rm` of unversioned
        /// buckets where the only durable recovery is re-uploading.
        stashed_content_hash: Option<BlobHash>,
        requires_confirmation: bool,
    },
    /// C03: terraform apply/destroy reverse. The pre-state is captured
    /// via `terraform state pull`; the plan JSON from `terraform plan
    /// -out=plan.tfplan` describes the intended changes. Reverse runs
    /// `terraform state push` against the captured state file, then
    /// `terraform apply -refresh-only` to reconcile.
    TerraformReverse {
        /// Working directory the original `terraform` command ran in.
        workdir: PathBuf,
        op: TerraformOp,
        /// Captured `terraform state pull` output, zstd-compressed.
        prior_state: Vec<u8>,
        /// Captured `terraform show -json plan.tfplan` output. Optional
        /// because some applied operations (auto-approve without an
        /// explicit `-out`) miss the plan capture.
        plan_json: Option<Vec<u8>>,
        requires_confirmation: bool,
    },
    /// Informational (S19): record what statements crossed the DB shim.
    /// For sqlite3 the file is captured via the file tier and the
    /// `rollback_hint` carries the blob; for postgres/mysql we emit a
    /// human-readable rollback plan the user runs themselves.
    DbNote {
        engine: DbEngine,
        /// Connection target — DB name for psql/mysql; file path for sqlite3.
        target: String,
        statements: Vec<String>,
        rollback_hint: RollbackHint,
    },
}

/// C03: kubectl verb captured against a single resource (or a
/// declarative file). The executor dispatches on this to choose
/// `kubectl apply` vs `kubectl delete` for the reverse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KubectlOp {
    /// `kubectl delete <kind> <name>` (or `delete -f file.yaml`).
    /// Reverse: `kubectl apply -f -` with the captured YAML.
    Delete { kind: String, name: String },
    /// `kubectl apply -f file.yaml` against an existing resource.
    /// Reverse: `kubectl apply -f -` with the *pre-state* YAML.
    Apply { kind: String, name: String },
    /// `kubectl scale ...`. Reverse: `kubectl scale` with the old
    /// replica count from `captured_yaml`.
    Scale { kind: String, name: String },
    /// `kubectl rollout restart` / `rollout undo`. Reverse: the
    /// inverse rollout verb when supported.
    Rollout { kind: String, name: String },
}

/// C03: gh-cli verb captured against a remote resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GhOp {
    /// `gh release delete <tag>`. Reverse: `gh release create` with
    /// the captured tag + body. Assets are best-effort: the JSON
    /// includes asset URLs but reverse does not auto-download +
    /// re-upload (large binaries).
    ReleaseDelete { tag: String },
    /// `gh release delete-asset <tag> <name>`. Reverse:
    /// `gh release upload <tag> <local-path>` IF the asset bytes
    /// were stashed; otherwise informational.
    ReleaseDeleteAsset { tag: String, asset: String },
    /// `gh issue close <n>`. Reverse: `gh issue reopen <n>`.
    IssueClose { number: u64 },
    /// `gh pr close <n>`. Reverse: `gh pr reopen <n>`.
    PrClose { number: u64 },
}

/// C03: aws-cli verb captured against a service resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AwsOp {
    /// `aws s3 cp local s3://bucket/key`. Reverse:
    /// `aws s3api delete-object --version-id=<vid>` (when versioned)
    /// or `aws s3 rm` (unversioned).
    S3Cp { bucket: String, key: String },
    /// `aws s3 rm s3://bucket/key`. Reverse:
    /// `aws s3 cp <stashed>` if bytes were stashed; else
    /// `aws s3api delete-object --version-id=<vid>` to undelete
    /// when the bucket is versioned.
    S3Rm { bucket: String, key: String },
    /// `aws ec2 terminate-instances --instance-ids X`. Reverse:
    /// informational note only — re-launch needs the captured
    /// instance descriptor; we surface the `aws ec2 run-instances`
    /// argv but never auto-apply.
    Ec2Terminate { instance_id: String },
    /// `aws ec2 stop-instances`. Reverse: `aws ec2 start-instances`.
    Ec2Stop { instance_id: String },
}

/// C03: terraform op kind. Drives the executor's reverse strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerraformOp {
    /// `terraform apply` (with or without `-auto-approve`).
    Apply,
    /// `terraform destroy`.
    Destroy,
    /// `terraform state rm <addr>`.
    StateRm,
    /// `terraform import`.
    Import,
}

/// C02.7: native-tool dispatch carried by `InverseOp::PackageRollback`.
/// When set, the executor runs the delegation argv instead of
/// synthesizing per-package invocations.
///
/// The shape is intentionally narrower than the C02 descriptor format:
/// the value (the transaction id) is already extracted by the inspector,
/// so there is no template language or parser here — just an argv to run
/// and an optional guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeDelegation {
    pub argv: Vec<String>,
    pub privileged: bool,
    /// Optional pre-execute check. If `guard_command`'s stdout does not
    /// contain `guard_match`, the executor refuses with a clear error
    /// (defends against transaction-history drift since capture time).
    pub guard_command: Option<Vec<String>>,
    pub guard_match: Option<String>,
}

/// C02: guard for `InverseOp::DescriptorReverse`. Same shape as
/// [`NativeDelegation`]'s guard but lives on the descriptor variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorGuardOp {
    pub command: Vec<String>,
    /// `{{var}}` placeholders allowed; executor interpolates from
    /// `captured_state` before matching.
    pub expected_substring: String,
}

/// Which DB engine the captured statements belong to. Mirrors
/// [`shit_proto::DbEngineWire`] but lives planner-side so the inverse
/// op can be serialized without the wire dep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbEngine {
    Postgres,
    Mysql,
    Sqlite3,
}

impl DbEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "psql",
            Self::Mysql => "mysql",
            Self::Sqlite3 => "sqlite3",
        }
    }
}

/// Engine-specific rollback advice. Only [`RollbackHint::Sqlite`] is
/// actionable mechanically (via the file-tier blob restore); the
/// other two are *informational* — the executor renders them, never
/// invokes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollbackHint {
    /// SQLite is a regular file. The capture pipeline already
    /// snapshotted it; restoring is the file-tier inverse op
    /// against `path` and `file_blob`.
    Sqlite {
        path: PathBuf,
        file_blob: Option<BlobHash>,
    },
    /// Postgres: render a PITR + statements-for-review block.
    /// `binlog_position` is empty when the engine didn't expose
    /// one (typical for a SELECT-heavy session).
    Postgres {
        pitr_recommended: bool,
        wal_position: Option<String>,
        statements_for_review: Vec<String>,
    },
    /// MySQL: render a binlog-position rewind block. Same
    /// caveat — never auto-applied.
    Mysql {
        binlog_position: Option<String>,
        statements_for_review: Vec<String>,
    },
    /// Engine had no actionable advice (e.g., DDL on a database
    /// without binlog/PITR). Renderer surfaces "no rollback hint
    /// available; review statements manually."
    None,
}

impl InverseOp {
    /// The path this op targets, if any. Used for path-conflict detection
    /// during cohort assignment.
    pub fn primary_path(&self) -> Option<&std::path::Path> {
        match self {
            Self::RestoreContent { path, .. }
            | Self::RestoreMetadata { path, .. }
            | Self::Unlink { path, .. }
            | Self::RecreatePath { path, .. }
            | Self::CreateSymlink { path, .. } => Some(path),
            Self::Rename { to, .. } => Some(to),
            Self::SetEnv { .. }
            | Self::UnsetEnv { .. }
            | Self::PackageRollback { .. }
            | Self::NetworkRollback { .. }
            | Self::SystemdRollback { .. }
            | Self::ProcessNote { .. }
            | Self::DescriptorReverse { .. }
            | Self::KubectlReverse { .. }
            | Self::GhReverse { .. }
            | Self::AwsReverse { .. }
            | Self::TerraformReverse { .. }
            | Self::DbNote { .. } => None,
        }
    }

    /// Inode this op targets, if any. Used for conflict detection.
    pub fn primary_inode(&self) -> Option<InodeRef> {
        match self {
            Self::RestoreContent { inode, .. } | Self::RestoreMetadata { inode, .. } => {
                Some(*inode)
            }
            _ => None,
        }
    }

    /// Tier classification — useful for routing to per-tier executors.
    pub fn tier(&self) -> InverseTier {
        match self {
            Self::RestoreContent { .. }
            | Self::RestoreMetadata { .. }
            | Self::Unlink { .. }
            | Self::RecreatePath { .. }
            | Self::Rename { .. }
            | Self::CreateSymlink { .. } => InverseTier::Files,
            Self::SetEnv { .. } | Self::UnsetEnv { .. } => InverseTier::Env,
            Self::PackageRollback { .. } => InverseTier::Packages,
            Self::NetworkRollback { .. } => InverseTier::Network,
            Self::SystemdRollback { .. } => InverseTier::Services,
            Self::ProcessNote { .. } => InverseTier::Processes,
            Self::DescriptorReverse { .. } => InverseTier::Descriptor,
            Self::KubectlReverse { .. }
            | Self::GhReverse { .. }
            | Self::AwsReverse { .. }
            | Self::TerraformReverse { .. } => InverseTier::Cloud,
            Self::DbNote { .. } => InverseTier::Database,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InverseTier {
    Files,
    Env,
    Packages,
    Network,
    Services,
    Processes,
    Descriptor,
    Cloud,
    Database,
}

/// One step in the plan, with conflict/cohort decoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanNode {
    pub op: InverseOp,
    /// Cohort index. Nodes within the same cohort may execute concurrently;
    /// cohorts execute strictly in increasing-index order.
    pub cohort: u32,
    pub conflict: Option<Conflict>,
}

/// Conflict taxonomy. Four buckets, intentionally coarse — users need
/// "safe to apply" vs. "needs your attention", not 12 categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conflict {
    /// Target was modified since capture, but the *result* would still be
    /// the captured pre-image. Safe to apply with `--on-conflict=skip` or
    /// after user confirmation.
    Soft { detail: String },
    /// Target was modified to a state we cannot reconcile. Applying would
    /// overwrite the user's later changes. Requires `--on-conflict=force`.
    Hard { detail: String },
    /// Target no longer exists. We cannot restore content/metadata into a
    /// non-existent inode without also recreating the path.
    Missing { detail: String },
    /// Target exists now but didn't at capture. The captured state predates
    /// the file; restore would overwrite an unrelated file.
    Phantom { detail: String },
}

impl Conflict {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Hard { .. } | Self::Phantom { .. })
    }
}

/// Non-conflict advisory messages attached to the plan as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanWarning {
    /// One or more events in the input were marked partial — those events
    /// were dropped from the plan; user sees a "partial undo" notice.
    PartialEvents { dropped: usize },
    /// The original command did not finish (no `PostExec`). The plan may be
    /// incomplete because we missed events after the daemon stopped watching.
    UnclosedCommand,
    /// User-readable note about a tier that can't be fully undone (e.g.,
    /// process kills).
    Informational { tier: InverseTier, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoPlan {
    pub command: CommandRecord,
    pub nodes: Vec<PlanNode>,
    pub warnings: Vec<PlanWarning>,
}

impl UndoPlan {
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn has_blocking_conflicts(&self) -> bool {
        self.nodes
            .iter()
            .any(|n| matches!(&n.conflict, Some(c) if c.is_blocking()))
    }

    /// Total number of `RestoreContent` ops — used by `shit show` to
    /// summarize "this undo will restore N files".
    pub fn content_restore_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n.op, InverseOp::RestoreContent { .. }))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn dummy_inode() -> InodeRef {
        InodeRef::new(1, 1)
    }

    fn dummy_meta() -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
        }
    }

    #[test]
    fn primary_path_for_restore_content() {
        let op = InverseOp::RestoreContent {
            inode: dummy_inode(),
            path: PathBuf::from("/tmp/a"),
            blob: BlobHash::from_bytes([0; 32]),
        };
        assert_eq!(op.primary_path(), Some(Path::new("/tmp/a")));
    }

    #[test]
    fn primary_path_for_rename_returns_destination() {
        let op = InverseOp::Rename {
            from: PathBuf::from("/tmp/a"),
            to: PathBuf::from("/tmp/b"),
        };
        assert_eq!(op.primary_path(), Some(Path::new("/tmp/b")));
    }

    #[test]
    fn primary_path_none_for_env_ops() {
        let op = InverseOp::SetEnv {
            name: "X".into(),
            value: "y".into(),
        };
        assert_eq!(op.primary_path(), None);
    }

    #[test]
    fn primary_inode_only_for_file_inode_ops() {
        assert!(
            InverseOp::RestoreContent {
                inode: dummy_inode(),
                path: PathBuf::from("/x"),
                blob: BlobHash::from_bytes([0; 32]),
            }
            .primary_inode()
            .is_some()
        );
        assert!(
            InverseOp::Unlink {
                path: PathBuf::from("/x"),
            }
            .primary_inode()
            .is_none()
        );
    }

    #[test]
    fn conflict_hard_and_phantom_are_blocking() {
        assert!(Conflict::Hard { detail: "x".into() }.is_blocking());
        assert!(Conflict::Phantom { detail: "x".into() }.is_blocking());
        assert!(!Conflict::Soft { detail: "x".into() }.is_blocking());
        assert!(!Conflict::Missing { detail: "x".into() }.is_blocking());
    }

    #[test]
    fn inverse_op_postcard_roundtrip() {
        let op = InverseOp::RestoreMetadata {
            inode: dummy_inode(),
            path: PathBuf::from("/tmp/x"),
            target: dummy_meta(),
        };
        let bytes = postcard::to_allocvec(&op).unwrap();
        let back: InverseOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn db_note_classifies_as_database_tier() {
        let op = InverseOp::DbNote {
            engine: DbEngine::Postgres,
            target: "prod".into(),
            statements: vec!["INSERT INTO t VALUES (1)".into()],
            rollback_hint: RollbackHint::Postgres {
                pitr_recommended: true,
                wal_position: None,
                statements_for_review: vec!["INSERT INTO t VALUES (1)".into()],
            },
        };
        assert_eq!(op.tier(), InverseTier::Database);
        assert!(op.primary_path().is_none());
        assert!(op.primary_inode().is_none());
    }

    #[test]
    fn db_note_roundtrips_through_postcard() {
        let op = InverseOp::DbNote {
            engine: DbEngine::Sqlite3,
            target: "/tmp/test.db".into(),
            statements: vec!["CREATE TABLE t (id INT)".into()],
            rollback_hint: RollbackHint::Sqlite {
                path: PathBuf::from("/tmp/test.db"),
                file_blob: Some(BlobHash::from_bytes([5; 32])),
            },
        };
        let bytes = postcard::to_allocvec(&op).unwrap();
        let back: InverseOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn rollback_hint_none_for_unhinted_engines() {
        // Useful when the engine probe returned nothing — render
        // layer treats this as "no actionable advice."
        let h = RollbackHint::None;
        let bytes = postcard::to_allocvec(&h).unwrap();
        let back: RollbackHint = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn db_engine_as_str_matches_wire_form() {
        assert_eq!(DbEngine::Postgres.as_str(), "psql");
        assert_eq!(DbEngine::Mysql.as_str(), "mysql");
        assert_eq!(DbEngine::Sqlite3.as_str(), "sqlite3");
    }

    // ----- C03.1: cloud variants -----

    #[test]
    fn cloud_variants_classify_as_cloud_tier() {
        let ku = InverseOp::KubectlReverse {
            context: "ctx".into(),
            namespace: Some("ns".into()),
            op: KubectlOp::Delete {
                kind: "pod".into(),
                name: "p".into(),
            },
            captured_yaml: b"kind: Pod\n".to_vec(),
            requires_confirmation: true,
        };
        let gh = InverseOp::GhReverse {
            op: GhOp::ReleaseDelete { tag: "v1".into() },
            captured_json: b"{}".to_vec(),
            requires_confirmation: true,
        };
        let aws = InverseOp::AwsReverse {
            service: "s3".into(),
            op: AwsOp::S3Rm {
                bucket: "b".into(),
                key: "k".into(),
            },
            captured_state: BTreeMap::new(),
            stashed_content_hash: None,
            requires_confirmation: true,
        };
        let tf = InverseOp::TerraformReverse {
            workdir: PathBuf::from("/tmp/tf"),
            op: TerraformOp::Apply,
            prior_state: vec![],
            plan_json: None,
            requires_confirmation: true,
        };
        for op in &[ku, gh, aws, tf] {
            assert_eq!(op.tier(), InverseTier::Cloud);
            assert!(op.primary_path().is_none());
            assert!(op.primary_inode().is_none());
        }
    }

    #[test]
    fn cloud_variants_roundtrip_through_postcard() {
        let op = InverseOp::KubectlReverse {
            context: "kind-c1".into(),
            namespace: Some("prod".into()),
            op: KubectlOp::Delete {
                kind: "Deployment".into(),
                name: "api".into(),
            },
            captured_yaml: b"apiVersion: apps/v1\nkind: Deployment\n".to_vec(),
            requires_confirmation: true,
        };
        let bytes = postcard::to_allocvec(&op).unwrap();
        let back: InverseOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(op, back);
    }
}
