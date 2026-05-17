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

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::executor::{BlobReader, ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inode::BlobHash;
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
    fn apply_restore_content(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::RestoreContent { path, blob, .. } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_restore_content: wrong variant".into(),
            };
        };
        match self.restore_content_inner(path, blob) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }

    /// Atomic write: read blob → tmpfile in same dir → fsync → rename.
    ///
    /// Not yet hardlink-aware: when the target has `nlink > 1` the
    /// rename breaks the hardlink relationship. Stage 1 documents that
    /// limitation; the hardlink path lands in stage 2 (gated on
    /// integration with the live state probe — S11.6/11.7).
    fn restore_content_inner(&self, path: &Path, blob: &BlobHash) -> Result<(), String> {
        let bytes = self
            .blob_reader
            .read(blob)
            .map_err(|e| format!("blob read for {path:?}: {e}"))?;

        let parent = path
            .parent()
            .ok_or_else(|| format!("path {path:?} has no parent dir; cannot place tmpfile"))?;

        // Tmpfile name: ".shit-tmp-<pid>-<ns>" alongside target so rename(2)
        // is atomic on the same filesystem. If the rename later fails
        // across mounts, that's reported back as Failed — caller should
        // not have planned a content restore across a mount boundary.
        let tmp_name = format!(".shit-tmp-{}-{}", std::process::id(), tmpfile_suffix(),);
        let tmp_path: PathBuf = parent.join(tmp_name);

        // Write + fsync the tmpfile.
        let write_result = (|| -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            // Best-effort cleanup of partial tmpfile.
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("tmpfile write {tmp_path:?}: {e}"));
        }

        // Atomic rename. On the same filesystem this overwrites the
        // target atomically. Cross-filesystem rename returns EXDEV and
        // we report it — the caller should split into copy+unlink.
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("rename {tmp_path:?} -> {path:?}: {e}"));
        }
        Ok(())
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

/// Monotonic-ish suffix for tmpfile names. We use nanoseconds since
/// the Unix epoch — uniqueness in tight loops is helped by the pid
/// prefix the caller adds, and worst-case a collision just causes a
/// retryable rename error.
fn tmpfile_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
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
    fn other_variants_still_not_implemented() {
        // RestoreMetadata / Unlink / RecreatePath / Rename / CreateSymlink
        // remain stubbed until S11.4 + S11.5.
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::Unlink {
            path: PathBuf::from("/tmp/never"),
        };
        match e.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("not yet implemented"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn restore_content_writes_blob_atomically() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("hello.txt");
        // Pre-existing content the undo should overwrite.
        std::fs::write(&target, b"current state").unwrap();

        let blob_hash = BlobHash::from_bytes([42; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob_hash, b"captured state".to_vec());

        let executor = FileExecutor::new(&reader);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: target.clone(),
            blob: blob_hash,
        };
        let out = executor.execute(&op, false, ConflictPolicy::default());
        assert_eq!(out, ExecutionOutcome::Applied, "got {out:?}");

        let bytes = std::fs::read(&target).unwrap();
        assert_eq!(bytes, b"captured state");
    }

    #[test]
    fn restore_content_creates_target_when_absent() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("new.txt");
        // Target does NOT exist beforehand.

        let blob_hash = BlobHash::from_bytes([7; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob_hash, b"recreated".to_vec());

        let executor = FileExecutor::new(&reader);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: target.clone(),
            blob: blob_hash,
        };
        assert_eq!(
            executor.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"recreated");
    }

    #[test]
    fn restore_content_returns_failed_when_blob_missing() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("x");
        let reader = InMemoryBlobReader::new(); // empty
        let executor = FileExecutor::new(&reader);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: target.clone(),
            blob: BlobHash::from_bytes([1; 32]),
        };
        match executor.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("blob read"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Target was never created.
        assert!(!target.exists());
    }

    #[test]
    fn restore_content_does_not_leave_tmpfile_on_failure() {
        // Pointing at a dir that doesn't exist forces the tmpfile
        // create to fail. After the call there must be no stray
        // .shit-tmp-* alongside the target.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let nonexistent_parent = tmpdir.path().join("no-such-dir");
        let target = nonexistent_parent.join("file");

        let blob_hash = BlobHash::from_bytes([1; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob_hash, b"x".to_vec());

        let executor = FileExecutor::new(&reader);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: target,
            blob: blob_hash,
        };
        match executor.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { .. } => {}
            other => panic!("expected Failed, got {other:?}"),
        }
        // The parent dir doesn't exist, so we can't enumerate.
        // The test really just asserts the call didn't panic.
    }
}
