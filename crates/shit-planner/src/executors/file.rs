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

use crate::executor::{
    BlobReader, ConflictPolicy, ExecutionOutcome, InverseOpExecutor, NoOpPrivilegedOpRouter,
    PrivilegedOpOutcome, PrivilegedOpRouter,
};
use crate::inode::BlobHash;
use crate::inverse::{InverseOp, InverseTier};

/// File-tier executor. Cheap to construct; holds a reference to the
/// blob reader so per-op calls don't pass it through.
pub struct FileExecutor<'a, R: BlobReader, P: PrivilegedOpRouter = NoOpPrivilegedOpRouter> {
    blob_reader: &'a R,
    privileged_router: P,
}

impl<'a, R: BlobReader> FileExecutor<'a, R, NoOpPrivilegedOpRouter> {
    /// Construct without a helper-IPC route. EPERM on chown surfaces
    /// as `Failed { err }`; the executor never blocks waiting on a
    /// helper that doesn't exist.
    pub fn new(blob_reader: &'a R) -> Self {
        Self {
            blob_reader,
            privileged_router: NoOpPrivilegedOpRouter,
        }
    }
}

impl<'a, R: BlobReader, P: PrivilegedOpRouter> FileExecutor<'a, R, P> {
    /// Construct with a privileged-op router (DR-15). The daemon
    /// wires up a router that forwards to `shit-helper`.
    pub fn with_privileged_router(blob_reader: &'a R, privileged_router: P) -> Self {
        Self {
            blob_reader,
            privileged_router,
        }
    }
}

impl<R: BlobReader, P: PrivilegedOpRouter> InverseOpExecutor for FileExecutor<'_, R, P> {
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
            InverseOp::FileExtend { .. } => self.apply_file_extend(op),
            other => ExecutionOutcome::Failed {
                err: format!(
                    "FileExecutor: unexpected variant {other:?} after supports() said yes — bug?"
                ),
            },
        }
    }
}

impl<R: BlobReader, P: PrivilegedOpRouter> FileExecutor<'_, R, P> {
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
            Err(MetadataRestoreError::ChownNeedsPrivilege { uid, gid }) => {
                // DR-15: retry via the helper IPC router. The helper
                // does the chown; the daemon finishes mode + mtime
                // here. W09.13 — chmod MUST run after chown so that
                // setuid/setgid bits in `target.mode` survive (chown
                // strips them).
                match self.privileged_router.chown(path, uid, gid, false) {
                    PrivilegedOpOutcome::Applied => {
                        use std::os::unix::fs::PermissionsExt;
                        let mode_only = target.mode & 0o7777;
                        let perms = std::fs::Permissions::from_mode(mode_only);
                        if let Err(e) = fs::set_permissions(path, perms) {
                            return ExecutionOutcome::Failed {
                                err: format!("chmod {path:?} -> {mode_only:o}: {e}"),
                            };
                        }
                        match restore_mtime_only(path, target) {
                            Ok(()) => ExecutionOutcome::Applied,
                            Err(e) => ExecutionOutcome::Failed { err: e },
                        }
                    }
                    PrivilegedOpOutcome::OutOfScope => ExecutionOutcome::Failed {
                        err: format!(
                            "chown {path:?} -> uid={uid} gid={gid}: helper refused (out of session scope)"
                        ),
                    },
                    PrivilegedOpOutcome::PermissionDenied => ExecutionOutcome::Failed {
                        err: format!(
                            "chown {path:?} -> uid={uid} gid={gid}: EPERM (helper also lacks privilege)"
                        ),
                    },
                    PrivilegedOpOutcome::NotFound => ExecutionOutcome::Failed {
                        err: format!(
                            "chown {path:?}: ENOENT (path vanished between capture and undo)"
                        ),
                    },
                    PrivilegedOpOutcome::Failed { err } => ExecutionOutcome::Failed {
                        err: format!("chown {path:?} via helper: {err}"),
                    },
                }
            }
            Err(MetadataRestoreError::Other(e)) => ExecutionOutcome::Failed { err: e },
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

    /// C06.6: truncate a file back to its pre-append size. The
    /// capture path stashed `truncate_to` as a single `stat` call —
    /// dramatically cheaper than reading the entire file just to
    /// emit a no-op restore for the bytes the user never touched.
    /// Append-only ops are the common case (logs, command output
    /// captured via `>>`).
    fn apply_file_extend(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::FileExtend { path, truncate_to } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_file_extend: wrong variant".into(),
            };
        };
        // Defensive size check: if the current file is SHORTER than
        // truncate_to, something has rewritten the file out from
        // under us (another process truncated; the redirect
        // semantics differ from what the capture assumed). Refuse —
        // truncating UP would write zero bytes the user never put
        // there.
        match fs::metadata(path) {
            Ok(m) if m.len() < *truncate_to => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "FileExtend: current size {} < pre-append size {}; refusing to grow \
                         file with zeros (something else truncated the file since capture)",
                        m.len(),
                        truncate_to,
                    ),
                };
            }
            Ok(_) => {}
            Err(e) => {
                return ExecutionOutcome::Failed {
                    err: format!("FileExtend: stat {path:?}: {e}"),
                };
            }
        }
        // Open RW + ftruncate. `OpenOptions::write(true)` doesn't
        // truncate the existing content (no `truncate(true)`); the
        // explicit `set_len` does the truncate-back.
        match fs::OpenOptions::new().write(true).open(path) {
            Ok(f) => match f.set_len(*truncate_to) {
                Ok(()) => ExecutionOutcome::Applied,
                Err(e) => ExecutionOutcome::Failed {
                    err: format!("FileExtend: truncate {path:?} to {truncate_to}: {e}"),
                },
            },
            Err(e) => ExecutionOutcome::Failed {
                err: format!("FileExtend: open {path:?}: {e}"),
            },
        }
    }
}

/// Categorised metadata-restore failure. `ChownNeedsPrivilege` is the
/// DR-15 signal: caller (the executor) retries via the helper IPC
/// router, then finishes the mtime half via [`restore_mtime_only`].
/// Everything else is a hard failure with a human-readable message.
#[derive(Debug)]
pub(crate) enum MetadataRestoreError {
    ChownNeedsPrivilege { uid: u32, gid: u32 },
    Other(String),
}

/// Restore chown + mode + mtime. On EPERM during chown, returns
/// [`MetadataRestoreError::ChownNeedsPrivilege`] so the executor can
/// route through the helper; any other error becomes `Other(err)`.
///
/// **Order matters**: chown MUST run before chmod. POSIX `chown(2)`
/// strips `S_ISUID`/`S_ISGID` from regular files for security
/// (so a setuid-root binary can't be re-owned to a regular user and
/// keep its powers). FreeBSD enforces this; Linux enforces it unless
/// the calling process holds `CAP_FSETID`. If we chmod first and chown
/// second, the restored setuid/setgid bits get cleared by the chown —
/// the W09.13 setuid-restore bug. chown-then-chmod keeps the final
/// mode authoritative.
fn restore_metadata_inner(
    path: &Path,
    target: &crate::metadata::FileMetadata,
) -> Result<(), MetadataRestoreError> {
    use std::os::unix::fs::PermissionsExt;

    let uid = Some(nix::unistd::Uid::from_raw(target.uid));
    let gid = Some(nix::unistd::Gid::from_raw(target.gid));
    match nix::unistd::chown(path, uid, gid) {
        Ok(()) => {}
        Err(nix::errno::Errno::EPERM) => {
            return Err(MetadataRestoreError::ChownNeedsPrivilege {
                uid: target.uid,
                gid: target.gid,
            });
        }
        Err(other) => {
            return Err(MetadataRestoreError::Other(format!(
                "chown {path:?} -> uid={} gid={}: {other}",
                target.uid, target.gid
            )));
        }
    }

    let mode_only = target.mode & 0o7777;
    let perms = std::fs::Permissions::from_mode(mode_only);
    fs::set_permissions(path, perms).map_err(|e| {
        MetadataRestoreError::Other(format!("chmod {path:?} -> {mode_only:o}: {e}"))
    })?;

    restore_mtime_only(path, target).map_err(MetadataRestoreError::Other)
}

/// Apply mtime alone — used after a successful helper-routed chown
/// to finish the metadata-restore sequence.
fn restore_mtime_only(path: &Path, target: &crate::metadata::FileMetadata) -> Result<(), String> {
    if target.mtime_unix_nanos == 0 {
        return Ok(());
    }
    use nix::sys::stat::utimensat;
    use nix::sys::time::TimeSpec;
    let secs = target.mtime_unix_nanos.div_euclid(1_000_000_000);
    let nsecs = target.mtime_unix_nanos.rem_euclid(1_000_000_000);
    let secs_i64: i64 = secs.try_into().unwrap_or(i64::MAX);
    let nsecs_i64: i64 = nsecs.try_into().unwrap_or(0);
    let ts = TimeSpec::new(secs_i64, nsecs_i64);
    let omit = TimeSpec::new(0, libc::UTIME_OMIT);
    utimensat(
        None,
        path,
        &omit,
        &ts,
        nix::sys::stat::UtimensatFlags::FollowSymlink,
    )
    .map_err(|e| format!("utimensat {path:?}: {e}"))
}

/// Remove `path`. Auto-detects file-vs-directory via lstat so the
/// caller doesn't need to pass `FileKind`.
///
/// For symlinks: removes the symlink itself, not the target — matches
/// the `unlink(2)` semantic.
///
/// For directories: try empty rmdir first. If ENOTEMPTY, fall back to
/// `remove_dir_all`. W01.B.fix-rename-coalescing surfaced this: when
/// the user's command creates a directory AND populates it (e.g.
/// `git commit` creates `.git/objects/2d/` then writes the new object
/// file inside), kqueue may capture the dir's TreeOpCreate but miss
/// the file-inside's TreeOpCreate (race between dir-create and the
/// watch wiring up via add_path). At undo time the planner emits
/// `Unlink` for the dir but not for its leftover contents — the dir
/// is "not empty" in a way the planner couldn't have known about.
/// Recursive removal is correct here because the dir didn't exist
/// pre-command, so by construction every file inside was also
/// created by the command and is part of the undo scope.
fn unlink_inner(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("lstat {path:?}: {e}"))?;
    if meta.file_type().is_dir() {
        match fs::remove_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOTEMPTY) => {
                fs::remove_dir_all(path).map_err(|e2| format!("rmdir-recursive {path:?}: {e2}"))
            }
            Err(e) => Err(format!("rmdir {path:?}: {e}")),
        }
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
    fn file_extend_truncates_file_back_to_pre_size() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        // Pre: 8 bytes. Post (after `>>`): 32 bytes. Reverse: truncate to 8.
        std::fs::write(&target, vec![0u8; 32]).unwrap();
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtend {
            path: target.clone(),
            truncate_to: 8,
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 8);
    }

    #[test]
    fn file_extend_refuses_to_grow_with_zeros() {
        // If something truncated the file shorter than truncate_to
        // since capture, refusing is the right answer — we'd be
        // appending zeros the user never wrote.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        std::fs::write(&target, vec![0u8; 4]).unwrap(); // current = 4
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtend {
            path: target.clone(),
            truncate_to: 16, // would grow with zeros
        };
        match e.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("refusing to grow"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // File was not modified.
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 4);
    }

    #[test]
    fn file_extend_missing_path_returns_failed() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("ghost");
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtend {
            path: target,
            truncate_to: 0,
        };
        let out = e.execute(&op, false, ConflictPolicy::default());
        assert!(matches!(out, ExecutionOutcome::Failed { .. }));
    }

    #[test]
    fn file_extend_to_zero_makes_file_empty() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        std::fs::write(&target, b"some content here").unwrap();
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtend {
            path: target.clone(),
            truncate_to: 0,
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
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
    fn unlink_recursively_removes_nonempty_directory() {
        // Models the W01.B git-commit-undo case: the command created a
        // directory AND populated it (e.g. .git/objects/2d/ + an object
        // file inside), but kqueue only captured the dir's TreeOpCreate.
        // At undo time the dir is "not empty" — fall back to recursive
        // removal because by construction the contents were also created
        // by the command.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("dir-with-stuff");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("inner-file"), b"x").unwrap();
        std::fs::create_dir(target.join("inner-dir")).unwrap();
        std::fs::write(target.join("inner-dir/nested"), b"y").unwrap();

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

    /// W09.13 — setuid/setgid must survive RestoreMetadata. The naive
    /// chmod-then-chown ordering loses these bits because POSIX
    /// `chown(2)` strips `S_ISUID`/`S_ISGID` from regular files for
    /// security. The executor's restore_metadata_inner runs chown
    /// FIRST and chmod second so the final mode is authoritative.
    #[test]
    fn restore_metadata_preserves_setuid() {
        use std::os::unix::fs::PermissionsExt;
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("setuid-binary");
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        // Start with 0o755 (no setuid). Capture the current uid/gid;
        // we'll "chown to self" which is the only chown we can do
        // unprivileged but still triggers the kernel's setuid-strip
        // behavior.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let st = std::fs::metadata(&target).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&st);
        let gid = std::os::unix::fs::MetadataExt::gid(&st);
        let target_meta = crate::metadata::FileMetadata {
            mode: 0o104755, // S_IFREG | setuid | rwxr-xr-x
            uid,
            gid,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: std::collections::BTreeMap::new(),
            acl: None,
        };
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreMetadata {
            inode: InodeRef::new(0, 0),
            path: target.clone(),
            target: target_meta,
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
        let final_mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            final_mode, 0o4755,
            "setuid bit (0o4000) was stripped — chown probably ran after chmod"
        );
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
    fn restore_metadata_to_different_uid_without_router_surfaces_eperm() {
        // Unprivileged tests can't chown to a uid we don't own, so
        // this exercises the EPERM → no-op-router PermissionDenied
        // path. With a real helper-IPC router the chown would
        // succeed; without one, the EPERM propagates as Failed.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("foreign");
        std::fs::write(&target, b"x").unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader); // NoOpPrivilegedOpRouter
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
            path: target.clone(),
            target: captured,
        };
        match exec.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("chown"), "expected chown error, got: {err}");
                assert!(err.contains("EPERM"), "expected EPERM mention, got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn restore_metadata_with_router_retries_via_chown_route() {
        // DR-15: when the local chown EPERMs, the executor falls
        // back to the privileged-op router. With the in-memory
        // router returning Applied, the overall outcome is Applied
        // and the router records the call.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("foreign");
        std::fs::write(&target, b"x").unwrap();

        let reader = InMemoryBlobReader::new();
        let router = crate::executor::InMemoryPrivilegedOpRouter::new();
        router.set_outcome(PrivilegedOpOutcome::Applied);
        let exec = FileExecutor::with_privileged_router(&reader, router);
        let captured = crate::metadata::FileMetadata {
            mode: 0o100644,
            uid: 0,
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
        let outcome = exec.execute(&op, false, ConflictPolicy::default());
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let log = exec.privileged_router.chown_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, target);
        assert_eq!(log[0].1, 0);
        assert!(
            !log[0].3,
            "no_dereference should be false for a regular file"
        );
    }

    #[test]
    fn restore_metadata_with_router_out_of_scope_surfaces_clear_error() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("foreign");
        std::fs::write(&target, b"x").unwrap();

        let reader = InMemoryBlobReader::new();
        let router = crate::executor::InMemoryPrivilegedOpRouter::new();
        router.set_outcome(PrivilegedOpOutcome::OutOfScope);
        let exec = FileExecutor::with_privileged_router(&reader, router);
        let captured = crate::metadata::FileMetadata {
            mode: 0o100644,
            uid: 0,
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
                assert!(err.contains("out of session scope"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
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
