// SPDX-License-Identifier: AGPL-3.0-or-later

//! File-tier executor (S11 stage 1 skeleton).
//!
//! Handles every [`InverseTier::Files`](crate::inverse::InverseTier::Files)
//! variant: `RestoreContent`, `RestoreMetadata`, `Unlink`, `RecreatePath`,
//! `Rename`, `CreateSymlink`.
//!
//! ## Stage progression
//!
//! - **S11.2 (this file's initial state):** dispatch skeleton. Every
//!   variant returns `Failed { err: "S11.X: not yet implemented" }`
//!   except `WouldApply` for dry-runs. This validates the dispatch
//!   shape independent of any syscalls.
//! - **S11.3:** real `RestoreContent` via blob read + tmpfile + rename.
//! - **S11.4:** real `RestoreMetadata` (mode/uid/gid; xattrs deferred).
//! - **S11.5:** real `Unlink`, `RecreatePath`, `Rename`, `CreateSymlink`.
//!
//! ## Privileged ops
//!
//! When the captured `uid`/`gid` differs from the runtime uid the
//! executor would need `CAP_CHOWN`/`CAP_FOWNER` (or root) to apply.
//! Stage 1 returns `Failed { err: "needs helper-IPC privileged-op
//! routing (DR-15)" }` for those — no silent failure.

use crate::executor::{BlobReader, ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{InverseOp, InverseTier};

/// File-tier executor. Cheap to construct; holds a reference to the
/// blob reader so per-op calls don't pass it through.
pub struct FileExecutor<'a, R: BlobReader> {
    blob_reader: &'a R,
}

impl<'a, R: BlobReader> FileExecutor<'a, R> {
    pub fn new(blob_reader: &'a R) -> Self {
        Self { blob_reader }
    }
}

impl<R: BlobReader> InverseOpExecutor for FileExecutor<'_, R> {
    fn supports(&self, op: &InverseOp) -> bool {
        op.tier() == InverseTier::Files
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        if !self.supports(op) {
            return ExecutionOutcome::Failed {
                err: format!("FileExecutor cannot execute op of tier {:?}", op.tier()),
            };
        }
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        match op {
            InverseOp::RestoreContent { .. } => self.apply_restore_content(op),
            InverseOp::RestoreMetadata { .. } => self.apply_restore_metadata(op),
            InverseOp::Unlink { .. } => self.apply_unlink(op),
            InverseOp::RecreatePath { .. } => self.apply_recreate_path(op),
            InverseOp::Rename { .. } => self.apply_rename(op),
            InverseOp::CreateSymlink { .. } => self.apply_create_symlink(op),
            other => ExecutionOutcome::Failed {
                err: format!(
                    "FileExecutor: unexpected variant {other:?} after supports() said yes — bug?"
                ),
            },
        }
    }
}

impl<R: BlobReader> FileExecutor<'_, R> {
    fn apply_restore_content(&self, _op: &InverseOp) -> ExecutionOutcome {
        // S11.3 fills this in. Silence the unused-field warning until then.
        let _ = self.blob_reader;
        ExecutionOutcome::Failed {
            err: "S11.3: RestoreContent not yet implemented".into(),
        }
    }

    fn apply_restore_metadata(&self, _op: &InverseOp) -> ExecutionOutcome {
        ExecutionOutcome::Failed {
            err: "S11.4: RestoreMetadata not yet implemented".into(),
        }
    }

    fn apply_unlink(&self, _op: &InverseOp) -> ExecutionOutcome {
        ExecutionOutcome::Failed {
            err: "S11.5: Unlink not yet implemented".into(),
        }
    }

    fn apply_recreate_path(&self, _op: &InverseOp) -> ExecutionOutcome {
        ExecutionOutcome::Failed {
            err: "S11.5: RecreatePath not yet implemented".into(),
        }
    }

    fn apply_rename(&self, _op: &InverseOp) -> ExecutionOutcome {
        ExecutionOutcome::Failed {
            err: "S11.5: Rename not yet implemented".into(),
        }
    }

    fn apply_create_symlink(&self, _op: &InverseOp) -> ExecutionOutcome {
        ExecutionOutcome::Failed {
            err: "S11.5: CreateSymlink not yet implemented".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::InMemoryBlobReader;
    use crate::inode::{BlobHash, InodeRef};
    use std::path::PathBuf;

    fn file_op() -> InverseOp {
        InverseOp::Unlink {
            path: PathBuf::from("/tmp/x"),
        }
    }

    fn non_file_op() -> InverseOp {
        InverseOp::SetEnv {
            name: "X".into(),
            value: "y".into(),
        }
    }

    #[test]
    fn supports_only_file_tier() {
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        assert!(e.supports(&file_op()));
        assert!(!e.supports(&non_file_op()));
    }

    #[test]
    fn rejects_non_file_op_with_failed() {
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let out = e.execute(&non_file_op(), false, ConflictPolicy::default());
        assert!(matches!(out, ExecutionOutcome::Failed { .. }));
    }

    #[test]
    fn dry_run_short_circuits_to_would_apply() {
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: PathBuf::from("/tmp/x"),
            blob: BlobHash::from_bytes([0; 32]),
        };
        assert_eq!(
            e.execute(&op, true, ConflictPolicy::default()),
            ExecutionOutcome::WouldApply
        );
    }

    #[test]
    fn stage_1_real_run_returns_not_implemented_failed() {
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: PathBuf::from("/tmp/x"),
            blob: BlobHash::from_bytes([0; 32]),
        };
        match e.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("not yet implemented"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
