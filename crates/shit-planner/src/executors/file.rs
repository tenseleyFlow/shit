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

    fn apply_restore_metadata(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::RestoreMetadata { path, target, .. } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_restore_metadata: wrong variant".into(),
            };
        };
        match restore_metadata_inner(path, target) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }

    fn apply_unlink(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::Unlink { path } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_unlink: wrong variant".into(),
            };
        };
        match unlink_inner(path) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }

    fn apply_recreate_path(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::RecreatePath { path, kind, mode } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_recreate_path: wrong variant".into(),
            };
        };
        match recreate_path_inner(path, *kind, *mode) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }

    fn apply_rename(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::Rename { from, to } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_rename: wrong variant".into(),
            };
        };
        // std::fs::rename is atomic on same-fs; cross-fs returns EXDEV
        // (mapped to io::Error). Cross-fs renames are stage-2 work —
        // they need the copy+unlink fallback noted in the sprint plan.
        match fs::rename(from, to) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("rename {from:?} -> {to:?}: {e}"),
            },
        }
    }

    fn apply_create_symlink(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::CreateSymlink {
            target: link_target,
            path,
        } = op
        else {
            return ExecutionOutcome::Failed {
                err: "apply_create_symlink: wrong variant".into(),
            };
        };
        use std::os::unix::fs::symlink;
        match symlink(link_target, path) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("symlink {path:?} -> {link_target:?}: {e}"),
            },
        }
    }
}

/// Restore the captured mode/uid/gid/mtime onto `path`.
///
/// **What stage 1 restores:** mode (chmod), uid + gid (chown), mtime
/// (utimensat). **What it defers:** xattrs and ACLs — both need
/// per-platform handling we'd rather implement once we have a real
/// integration test pass (see DR-* in DEFERRED-RUNTIME.md).
///
/// **Privilege failure mode:** when the chown would require
/// CAP_CHOWN or root (target uid/gid differs from caller's), Linux
/// returns EPERM. We surface that as a `Failed { err }` mentioning
/// the helper-IPC privileged-op routing (DR-15). No silent skip.
fn restore_metadata_inner(
    path: &Path,
    target: &crate::metadata::FileMetadata,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    // Mode. Stripping the file-type bits is intentional — chmod takes
    // only the permission bits; the type lives in the inode and is
    // immutable from userspace.
    let mode_only = target.mode & 0o7777;
    let perms = std::fs::Permissions::from_mode(mode_only);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("chmod {path:?} -> {mode_only:o}: {e}"))?;

    // uid + gid. nix::unistd::chown follows symlinks (calls chown(2),
    // not lchown(2)). For a symlink target's metadata we'd want
    // lchown — defer that case until the integration sprint.
    let uid = Some(nix::unistd::Uid::from_raw(target.uid));
    let gid = Some(nix::unistd::Gid::from_raw(target.gid));
    nix::unistd::chown(path, uid, gid).map_err(|e| match e {
        nix::errno::Errno::EPERM => format!(
            "chown {path:?} -> uid={} gid={}: EPERM (needs helper-IPC privileged-op routing, DR-15)",
            target.uid, target.gid
        ),
        other => format!(
            "chown {path:?} -> uid={} gid={}: {other}",
            target.uid, target.gid
        ),
    })?;

    // mtime. Skip atime restoration — it's not captured.
    if target.mtime_unix_nanos > 0 {
        use nix::sys::stat::utimensat;
        use nix::sys::time::TimeSpec;
        let secs = target.mtime_unix_nanos.div_euclid(1_000_000_000);
        let nsecs = target.mtime_unix_nanos.rem_euclid(1_000_000_000);
        // i128 -> i64 cast: any mtime that doesn't fit in i64 seconds
        // is pre-1970 or far-future garbage. Cap rather than panic.
        let secs_i64: i64 = secs.try_into().unwrap_or(i64::MAX);
        let nsecs_i64: i64 = nsecs.try_into().unwrap_or(0);
        let ts = TimeSpec::new(secs_i64, nsecs_i64);
        // UTIME_OMIT for atime; only mtime is restored.
        let omit = TimeSpec::new(0, libc::UTIME_OMIT);
        utimensat(
            None,
            path,
            &omit,
            &ts,
            nix::sys::stat::UtimensatFlags::FollowSymlink,
        )
        .map_err(|e| format!("utimensat {path:?}: {e}"))?;
    }

    Ok(())
}

/// Remove `path`. Auto-detects file-vs-directory via lstat so the
/// caller doesn't need to pass `FileKind`.
///
/// For symlinks: removes the symlink itself, not the target — matches
/// the `unlink(2)` semantic.
///
/// For directories: only succeeds when the directory is empty. The
/// planner emits one `Unlink` per directory entry plus one per parent,
/// in post-order; if the planner emits an `Unlink` for a non-empty
/// dir, that's a planner bug surfaced here as a clear ENOTEMPTY.
fn unlink_inner(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("lstat {path:?}: {e}"))?;
    if meta.file_type().is_dir() {
        fs::remove_dir(path).map_err(|e| format!("rmdir {path:?}: {e}"))
    } else {
        fs::remove_file(path).map_err(|e| format!("unlink {path:?}: {e}"))
    }
}

/// Recreate a path the original command unlinked. Handles regular
/// files and directories; other kinds (fifo/socket/device) need
/// `mknod(2)` and are deferred — return a clear "needs DR-15 for
/// mknod helper routing" message.
fn recreate_path_inner(
    path: &Path,
    kind: crate::metadata::FileKind,
    mode: u32,
) -> Result<(), String> {
    use crate::metadata::FileKind;
    use std::os::unix::fs::PermissionsExt;

    let perm_bits = mode & 0o7777;
    match kind {
        FileKind::Regular => {
            // Create empty file; `RestoreContent` (if present in the
            // plan) fills it. Setting perms after create so umask
            // doesn't shave bits off.
            fs::File::create(path).map_err(|e| format!("create {path:?}: {e}"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(perm_bits))
                .map_err(|e| format!("chmod {path:?} -> {perm_bits:o}: {e}"))?;
            Ok(())
        }
        FileKind::Directory => {
            fs::create_dir(path).map_err(|e| format!("mkdir {path:?}: {e}"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(perm_bits))
                .map_err(|e| format!("chmod {path:?} -> {perm_bits:o}: {e}"))?;
            Ok(())
        }
        FileKind::Symlink => Err(format!(
            "RecreatePath for symlink at {path:?} is a planner bug — \
             use InverseOp::CreateSymlink which carries the target"
        )),
        // Fifo/Socket/BlockDevice/CharDevice need mknod(2). For named
        // pipes and sockets the helper has CAP_MKNOD by default;
        // for block/char devices it requires CAP_SYS_ADMIN even with
        // the right owner. Route through the helper once DR-15 lands.
        other => Err(format!(
            "RecreatePath for kind {other:?} at {path:?}: needs mknod(2) \
             via helper-IPC privileged-op routing (DR-15)"
        )),
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
    fn unlink_removes_regular_file() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("f");
        std::fs::write(&target, b"x").unwrap();

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::Unlink {
            path: target.clone(),
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert!(!target.exists());
    }

    #[test]
    fn unlink_removes_empty_directory() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("d");
        std::fs::create_dir(&target).unwrap();

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::Unlink {
            path: target.clone(),
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert!(!target.exists());
    }

    #[test]
    fn unlink_on_missing_path_returns_failed() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("nope");

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::Unlink { path: target };
        assert!(matches!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Failed { .. }
        ));
    }

    #[test]
    fn recreate_path_makes_directory_with_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("newdir");

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RecreatePath {
            path: target.clone(),
            kind: crate::metadata::FileKind::Directory,
            mode: 0o040711,
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert!(target.is_dir());
        let m = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o711);
    }

    #[test]
    fn recreate_path_makes_empty_regular_file_with_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("empty.bin");

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RecreatePath {
            path: target.clone(),
            kind: crate::metadata::FileKind::Regular,
            mode: 0o100640,
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert!(target.is_file());
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
        let m = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o640);
    }

    #[test]
    fn recreate_path_symlink_kind_is_planner_bug() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RecreatePath {
            path: tmpdir.path().join("link"),
            kind: crate::metadata::FileKind::Symlink,
            mode: 0o120777,
        };
        match e.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("CreateSymlink"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rename_round_trips() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let from = tmpdir.path().join("a");
        let to = tmpdir.path().join("b");
        std::fs::write(&from, b"hi").unwrap();

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::Rename {
            from: from.clone(),
            to: to.clone(),
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).unwrap(), b"hi");
    }

    #[test]
    fn create_symlink_creates_link() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let link = tmpdir.path().join("alink");

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::CreateSymlink {
            target: "/tmp/nonexistent-target".into(),
            path: link.clone(),
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            PathBuf::from("/tmp/nonexistent-target")
        );
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
    fn restore_metadata_restores_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("perms");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);

        // Pretend the captured mode was 0o600.
        let captured = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            size: 1,
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
        };
        let op = InverseOp::RestoreMetadata {
            inode: InodeRef::new(1, 1),
            path: target.clone(),
            target: captured,
        };
        let out = exec.execute(&op, false, ConflictPolicy::default());
        assert_eq!(out, ExecutionOutcome::Applied, "{out:?}");

        let m = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o600);
    }

    #[test]
    fn restore_metadata_to_different_uid_fails_with_dr15_message() {
        // Unprivileged tests can't chown to a uid we don't own, so this
        // exercise's the EPERM->DR-15 message path.
        if nix::unistd::geteuid().is_root() {
            // Running as root would actually succeed; skip.
            return;
        }
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("foreign");
        std::fs::write(&target, b"x").unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);

        // Pick a uid not equal to current uid. uid 0 is always a foreign
        // uid for an unprivileged caller.
        let foreign_uid = 0;
        let captured = crate::metadata::FileMetadata {
            mode: 0o100644,
            uid: foreign_uid,
            gid: nix::unistd::getgid().as_raw(),
            size: 1,
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
        };
        let op = InverseOp::RestoreMetadata {
            inode: InodeRef::new(1, 1),
            path: target,
            target: captured,
        };
        match exec.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("DR-15"), "got: {err}");
            }
            other => panic!("expected Failed (DR-15), got {other:?}"),
        }
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
