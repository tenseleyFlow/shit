// SPDX-License-Identifier: AGPL-3.0-or-later

//! File-tier executor (S11 stage 1 skeleton).
//!
//! Handles every [`InverseTier::Files`](crate::inverse::InverseTier::Files)
//! variant: `RestoreContent`, `RestoreMetadata`, `RestoreFlags`, `Unlink`,
//! `RecreatePath`, `Rename`, `CreateSymlink`, and append truncate-back ops.
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
//! Metadata replay uses descriptor-only syscalls. When `fchown` needs
//! `CAP_CHOWN`/root, replay fails closed: the current helper route accepts a
//! pathname and cannot preserve the verified descriptor identity. The router
//! remains available for non-metadata operations such as `mknod`.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::executor::{
    BlobReader, ConflictPolicy, ExecutionOutcome, InverseOpExecutor, NoOpPrivilegedOpRouter,
    PrivilegedOpOutcome, PrivilegedOpRouter,
};
use crate::inode::{BlobHash, InodeRef};
use crate::inverse::{Conflict, InverseOp, InverseTier};

/// Every filesystem address in a persisted inverse must be absolute. Relative
/// symlink *contents* remain valid, but a relative operation path would be
/// interpreted from the future undo process's cwd and could mutate unrelated
/// data. This is the final guard for old, malformed, or corrupt journals.
fn first_relative_file_operand(op: &InverseOp) -> Option<&Path> {
    match op {
        InverseOp::RestoreContent { path, .. }
        | InverseOp::RestoreMetadata { path, .. }
        | InverseOp::RestoreFlags { path, .. }
        | InverseOp::Unlink { path }
        | InverseOp::RecreatePath { path, .. }
        | InverseOp::CreateSymlink { path, .. }
        | InverseOp::FileExtend { path, .. }
        | InverseOp::FileExtendGuarded { path, .. } => {
            (!path.is_absolute()).then_some(path.as_path())
        }
        InverseOp::Rename { from, to } => [from.as_path(), to.as_path()]
            .into_iter()
            .find(|path| !path.is_absolute()),
        InverseOp::CreateHardlink { source, target } => [source.as_path(), target.as_path()]
            .into_iter()
            .find(|path| !path.is_absolute()),
        _ => None,
    }
}

/// File-tier executor. Cheap to construct; holds a reference to the
/// blob reader so per-op calls don't pass it through.
pub struct FileExecutor<'a, R: BlobReader, P: PrivilegedOpRouter = NoOpPrivilegedOpRouter> {
    blob_reader: &'a R,
    privileged_router: P,
    /// Descriptor-backed provenance for files installed by RestoreContent.
    /// The descriptor pins the actual inode, preventing inode-number reuse
    /// from turning provenance into authority over an unrelated object. A
    /// dry-run records only a projected replacement marker.
    restored_targets: Mutex<HashMap<(PathBuf, InodeRef), RestoredTarget>>,
    /// Validated content bytes pinned for one plan. RestoreContent execution
    /// uses these bytes so blob GC/corruption after preflight cannot turn a
    /// previously valid later node into a partial-undo failure.
    preflighted_blobs: Mutex<HashMap<BlobHash, Arc<[u8]>>>,
}

enum RestoredTarget {
    Open(File),
    Projected,
}

enum PreparedTarget {
    Open(File),
    Projected,
}

impl<'a, R: BlobReader> FileExecutor<'a, R, NoOpPrivilegedOpRouter> {
    /// Construct without a helper-IPC route. EPERM on chown surfaces
    /// as `Failed { err }`; the executor never blocks waiting on a
    /// helper that doesn't exist.
    pub fn new(blob_reader: &'a R) -> Self {
        Self {
            blob_reader,
            privileged_router: NoOpPrivilegedOpRouter,
            restored_targets: Mutex::new(HashMap::new()),
            preflighted_blobs: Mutex::new(HashMap::new()),
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
            restored_targets: Mutex::new(HashMap::new()),
            preflighted_blobs: Mutex::new(HashMap::new()),
        }
    }
}

impl<R: BlobReader, P: PrivilegedOpRouter> InverseOpExecutor for FileExecutor<'_, R, P> {
    fn begin_plan_execution(&self, _dry_run: bool) {
        if let Ok(mut provenance) = self.restored_targets.lock() {
            provenance.clear();
        }
        if let Ok(mut blobs) = self.preflighted_blobs.lock() {
            blobs.clear();
        }
    }

    fn finish_plan_execution(&self) {
        if let Ok(mut provenance) = self.restored_targets.lock() {
            provenance.clear();
        }
        if let Ok(mut blobs) = self.preflighted_blobs.lock() {
            blobs.clear();
        }
    }

    fn preflight(&self, op: &InverseOp) -> Result<(), String> {
        if let InverseOp::RestoreContent { path, blob, .. } = op {
            self.preflight_restore_content(path, blob)?;
        }
        Ok(())
    }

    fn supports(&self, op: &InverseOp) -> bool {
        op.tier() == InverseTier::Files
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        if !self.supports(op) {
            return ExecutionOutcome::Failed {
                err: format!("FileExecutor cannot execute op of tier {:?}", op.tier()),
            };
        }
        if let Some(path) = first_relative_file_operand(op) {
            return ExecutionOutcome::Failed {
                err: format!(
                    "refusing relative filesystem path {path:?}; undo targets must be absolute"
                ),
            };
        }
        // Persisted pre-guard append plans remain decodable, but cannot be
        // executed safely because they carry no captured inode. Report that
        // limitation even in dry-run mode; claiming WouldApply would be a lie.
        if matches!(op, InverseOp::FileExtend { .. }) {
            return self.apply_file_extend(op);
        }
        match op {
            InverseOp::RestoreContent { .. } => self.apply_restore_content(op, dry_run),
            InverseOp::RestoreMetadata { .. } => self.apply_restore_metadata(op, dry_run),
            InverseOp::RestoreFlags { .. } => self.apply_restore_flags(op, dry_run),
            InverseOp::FileExtendGuarded { .. } => self.apply_file_extend_guarded(op, dry_run),
            _ if dry_run => ExecutionOutcome::WouldApply,
            InverseOp::Unlink { .. } => self.apply_unlink(op),
            InverseOp::RecreatePath { .. } => self.apply_recreate_path(op),
            InverseOp::Rename { .. } => self.apply_rename(op),
            InverseOp::CreateSymlink { .. } => self.apply_create_symlink(op),
            InverseOp::CreateHardlink { .. } => self.apply_create_hardlink(op),
            other => ExecutionOutcome::Failed {
                err: format!(
                    "FileExecutor: unexpected variant {other:?} after supports() said yes — bug?"
                ),
            },
        }
    }
}

impl<R: BlobReader, P: PrivilegedOpRouter> FileExecutor<'_, R, P> {
    fn apply_restore_content(&self, op: &InverseOp, dry_run: bool) -> ExecutionOutcome {
        let InverseOp::RestoreContent { inode, path, blob } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_restore_content: wrong variant".into(),
            };
        };
        if dry_run {
            if let Err(e) = self.validate_restore_content(path, blob) {
                return ExecutionOutcome::Failed { err: e };
            }
            let Ok(mut provenance) = self.restored_targets.lock() else {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "restored-target provenance lock poisoned while validating {path:?}"
                    ),
                };
            };
            provenance.insert((path.clone(), *inode), RestoredTarget::Projected);
            return ExecutionOutcome::WouldApply;
        }
        match self.restore_content_inner(path, blob) {
            Ok(restored_file) => {
                let Ok(mut provenance) = self.restored_targets.lock() else {
                    return ExecutionOutcome::Failed {
                        err: format!(
                            "restored-target provenance lock poisoned after restoring {path:?}"
                        ),
                    };
                };
                provenance.insert((path.clone(), *inode), RestoredTarget::Open(restored_file));
                ExecutionOutcome::Applied
            }
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }

    fn preflight_restore_content(&self, path: &Path, blob: &BlobHash) -> Result<(), String> {
        self.validate_restore_target(path)?;
        {
            let blobs = self
                .preflighted_blobs
                .lock()
                .map_err(|_| "file preflight blob cache lock poisoned".to_string())?;
            if blobs.contains_key(blob) {
                return Ok(());
            }
        }

        let bytes = self
            .blob_reader
            .read(blob)
            .map_err(|e| format!("blob read for {path:?}: {e}"))?;
        self.preflighted_blobs
            .lock()
            .map_err(|_| "file preflight blob cache lock poisoned".to_string())?
            .insert(*blob, Arc::from(bytes));
        Ok(())
    }

    /// Prefer bytes pinned by whole-plan preflight. Direct executor callers
    /// that do not use lifecycle hooks retain the historical live-read path.
    fn preflighted_or_live_blob(&self, path: &Path, blob: &BlobHash) -> Result<Arc<[u8]>, String> {
        if let Some(bytes) = self
            .preflighted_blobs
            .lock()
            .map_err(|_| "file preflight blob cache lock poisoned".to_string())?
            .get(blob)
            .cloned()
        {
            return Ok(bytes);
        }
        self.blob_reader
            .read(blob)
            .map(Arc::from)
            .map_err(|e| format!("blob read for {path:?}: {e}"))
    }

    fn validate_restore_content(&self, path: &Path, blob: &BlobHash) -> Result<(), String> {
        self.preflighted_or_live_blob(path, blob)?;
        self.validate_restore_target(path)
    }

    fn validate_restore_target(&self, path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| format!("path {path:?} has no parent dir; cannot place tmpfile"))?;

        // An existing non-directory parent and an existing directory target
        // cannot be replaced by the regular-file tmpfile rename used below.
        if let Ok(meta) = fs::metadata(parent)
            && !meta.file_type().is_dir()
        {
            return Err(format!(
                "restore parent {parent:?} exists but is not a directory"
            ));
        }
        if let Ok(meta) = fs::symlink_metadata(path)
            && meta.file_type().is_dir()
        {
            return Err(format!(
                "restore target {path:?} is a directory; refusing regular-file replacement"
            ));
        }
        Ok(())
    }

    /// Atomic write: read blob → tmpfile in same dir → fsync → rename.
    ///
    /// Not yet hardlink-aware: when the target has `nlink > 1` the
    /// rename breaks the hardlink relationship. Stage 1 documents that
    /// limitation; the hardlink path lands in stage 2 (gated on
    /// integration with the live state probe — S11.6/11.7).
    fn restore_content_inner(&self, path: &Path, blob: &BlobHash) -> Result<File, String> {
        let bytes = self.preflighted_or_live_blob(path, blob)?;

        let parent = path
            .parent()
            .ok_or_else(|| format!("path {path:?} has no parent dir; cannot place tmpfile"))?;

        // G01.5 — if the parent dir was removed alongside this file
        // (e.g. `git clean -fd` rmdirs untracked directories after
        // unlinking their contents), recreate the ancestor chain
        // with default mode (0o755). Untracked dirs typically have
        // default mode anyway; if a future use case needs the
        // ORIGINAL mode we'd need to plumb kind+mode through the
        // wire (deferred — see G01 plan).
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir -p {parent:?}: {e}"))?;
        }

        // Tmpfile name: ".shit-tmp-<pid>-<ns>" alongside target so rename(2)
        // is atomic on the same filesystem. If the rename later fails
        // across mounts, that's reported back as Failed — caller should
        // not have planned a content restore across a mount boundary.
        let tmp_name = format!(".shit-tmp-{}-{}", std::process::id(), tmpfile_suffix(),);
        let tmp_path: PathBuf = parent.join(tmp_name);

        // Write + fsync the tmpfile.
        let write_result = (|| -> std::io::Result<File> {
            let mut f = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&tmp_path)?;
            f.write_all(bytes.as_ref())?;
            f.sync_all()?;
            Ok(f)
        })();
        let restored_file = match write_result {
            Ok(file) => file,
            Err(e) => {
                // Best-effort cleanup of partial tmpfile.
                let _ = fs::remove_file(&tmp_path);
                return Err(format!("tmpfile write {tmp_path:?}: {e}"));
            }
        };

        // Atomic rename. On the same filesystem this overwrites the
        // target atomically. Cross-filesystem rename returns EXDEV and
        // we report it — the caller should split into copy+unlink.
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("rename {tmp_path:?} -> {path:?}: {e}"));
        }
        let restored_meta = restored_file
            .metadata()
            .map_err(|e| format!("fstat restored target {path:?}: {e}"))?;
        let restored_inode = InodeRef::new(restored_meta.dev(), restored_meta.ino());
        match live_inode(path) {
            Ok(live) if live == restored_inode => Ok(restored_file),
            Ok(live) => Err(format!(
                "restore target {path:?} changed immediately after rename: live inode {live}, restored inode {restored_inode}"
            )),
            Err(e) => Err(format!("lstat restored target {path:?} after rename: {e}")),
        }
    }

    fn apply_restore_metadata(&self, op: &InverseOp, dry_run: bool) -> ExecutionOutcome {
        let InverseOp::RestoreMetadata {
            inode,
            path,
            target,
        } = op
        else {
            return ExecutionOutcome::Failed {
                err: "apply_restore_metadata: wrong variant".into(),
            };
        };
        let prepared = match self.prepare_inode_target(path, *inode, dry_run) {
            Ok(prepared) => prepared,
            Err(outcome) => return outcome,
        };
        match prepared {
            PreparedTarget::Projected => ExecutionOutcome::WouldApply,
            PreparedTarget::Open(_) if dry_run => ExecutionOutcome::WouldApply,
            PreparedTarget::Open(file) => match restore_metadata_fd(&file, path, target) {
                Ok(()) => ExecutionOutcome::Applied,
                Err(err) => ExecutionOutcome::Failed { err },
            },
        }
    }

    fn apply_restore_flags(&self, op: &InverseOp, dry_run: bool) -> ExecutionOutcome {
        let InverseOp::RestoreFlags { inode, path, flags } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_restore_flags: wrong variant".into(),
            };
        };
        let prepared = match self.prepare_inode_target(path, *inode, dry_run) {
            Ok(prepared) => prepared,
            Err(outcome) => return outcome,
        };
        if let Err(err) = flags_supported() {
            return ExecutionOutcome::Failed { err };
        }
        match prepared {
            PreparedTarget::Projected => ExecutionOutcome::WouldApply,
            PreparedTarget::Open(_) if dry_run => ExecutionOutcome::WouldApply,
            PreparedTarget::Open(file) => match restore_flags_fd(&file, path, *flags) {
                Ok(()) => ExecutionOutcome::Applied,
                Err(err) => ExecutionOutcome::Failed { err },
            },
        }
    }

    /// Acquire the one descriptor on which identity is checked and metadata
    /// is mutated. A retained RestoreContent descriptor is authoritative only
    /// while the live pathname still names that pinned inode.
    fn prepare_inode_target(
        &self,
        path: &Path,
        expected_inode: InodeRef,
        dry_run: bool,
    ) -> Result<PreparedTarget, ExecutionOutcome> {
        let retained = {
            let provenance =
                self.restored_targets
                    .lock()
                    .map_err(|_| ExecutionOutcome::Failed {
                        err: format!("restored-target provenance lock poisoned for {path:?}"),
                    })?;
            match provenance.get(&(path.to_path_buf(), expected_inode)) {
                Some(RestoredTarget::Projected) if dry_run => Some(PreparedTarget::Projected),
                Some(RestoredTarget::Open(file)) => {
                    Some(PreparedTarget::Open(file.try_clone().map_err(|e| {
                        ExecutionOutcome::Failed {
                            err: format!("dup retained restore descriptor for {path:?}: {e}"),
                        }
                    })?))
                }
                _ => None,
            }
        };

        if let Some(PreparedTarget::Projected) = retained {
            return Ok(PreparedTarget::Projected);
        }
        if let Some(PreparedTarget::Open(file)) = retained {
            verify_retained_path(&file, path)?;
            return Ok(PreparedTarget::Open(file));
        }
        open_verified_target(path, expected_inode).map(PreparedTarget::Open)
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
        use crate::metadata::FileKind;
        // AU22 — Fifo/Socket need mknod(2); dispatch through the
        // privileged-op router (the helper has CAP_MKNOD). The
        // local recreate_path_inner handles Regular/Directory only;
        // BlockDevice/CharDevice still require CAP_SYS_ADMIN and
        // stay refused at the helper.
        if matches!(kind, FileKind::Fifo | FileKind::Socket) {
            // G01.5 — same parent-tree guarantee as the regular path
            // (recreate_path_inner does this for us; we mirror it
            // here for the mknod branch).
            if let Some(parent) = path.parent()
                && !parent.exists()
                && let Err(e) = fs::create_dir_all(parent)
            {
                return ExecutionOutcome::Failed {
                    err: format!("mkdir -p {parent:?}: {e}"),
                };
            }
            // mode wire carries perm bits + S_IF* kind. The router
            // dispatches into the helper which calls libc::mknod
            // with S_IFIFO/S_IFSOCK | perm_bits.
            return match self.privileged_router.mknod(path, *mode, 0) {
                PrivilegedOpOutcome::Applied => ExecutionOutcome::Applied,
                PrivilegedOpOutcome::OutOfScope => ExecutionOutcome::Failed {
                    err: format!(
                        "mknod {path:?} kind={kind:?}: helper refused (out of session scope)"
                    ),
                },
                PrivilegedOpOutcome::PermissionDenied => ExecutionOutcome::Failed {
                    err: format!("mknod {path:?} kind={kind:?}: EPERM (helper lacks CAP_MKNOD?)"),
                },
                PrivilegedOpOutcome::NotFound => ExecutionOutcome::Failed {
                    err: format!("mknod {path:?} kind={kind:?}: parent path missing"),
                },
                PrivilegedOpOutcome::Failed { err } => ExecutionOutcome::Failed {
                    err: format!("mknod {path:?} kind={kind:?}: {err}"),
                },
            };
        }
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

    /// W09.20 — `link(source, target)`. Restores a hardlink: the
    /// surviving alias (`source`) is the still-live path; `target`
    /// is the freshly-dead path we want to re-alias to the same
    /// inode. POSIX `link(2)` preserves inode (no content copy);
    /// nlink on the inode increments to match the original
    /// pre-unlink count.
    fn apply_create_hardlink(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::CreateHardlink { source, target } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_create_hardlink: wrong variant".into(),
            };
        };
        match fs::hard_link(source, target) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("link {source:?} -> {target:?}: {e}"),
            },
        }
    }

    /// Legacy C06 append plans did not persist the captured inode. They remain
    /// deserializable for journal/exec-log compatibility, but executing one
    /// could truncate a replacement file at the same path, so fail closed.
    fn apply_file_extend(&self, op: &InverseOp) -> ExecutionOutcome {
        let InverseOp::FileExtend { path, .. } = op else {
            return ExecutionOutcome::Failed {
                err: "apply_file_extend: wrong variant".into(),
            };
        };
        ExecutionOutcome::Failed {
            err: format!(
                "FileExtend: refusing legacy append undo for {path:?}: persisted operation lacks \
                 a captured inode; regenerate the undo plan from a new capture"
            ),
        }
    }

    fn apply_file_extend_guarded(&self, op: &InverseOp, dry_run: bool) -> ExecutionOutcome {
        let InverseOp::FileExtendGuarded {
            inode,
            path,
            truncate_to,
        } = op
        else {
            return ExecutionOutcome::Failed {
                err: "apply_file_extend_guarded: wrong variant".into(),
            };
        };
        self.truncate_open_file(path, *truncate_to, *inode, dry_run)
    }

    /// Open the target without truncation, then validate its identity and size
    /// from that same descriptor immediately before `ftruncate`. Checking the
    /// descriptor (rather than `stat(path)` followed by `open(path)`) closes
    /// the pathname replacement race: even if the name changes after open, we
    /// cannot truncate the replacement inode.
    fn truncate_open_file(
        &self,
        path: &Path,
        truncate_to: u64,
        expected_inode: InodeRef,
        dry_run: bool,
    ) -> ExecutionOutcome {
        if let Err(outcome) = validate_safe_target_kind(path, false) {
            return outcome;
        }
        // `write(true)` does not truncate on open; only the later `set_len`
        // mutates the descriptor.
        let file = match fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return ExecutionOutcome::Conflict {
                    kind: Conflict::Missing {
                        detail: format!("{path:?} no longer exists"),
                    },
                };
            }
            Err(e) => {
                return ExecutionOutcome::Failed {
                    err: format!("FileExtendGuarded: open {path:?}: {e}"),
                };
            }
        };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(e) => {
                return ExecutionOutcome::Failed {
                    err: format!("FileExtendGuarded: fstat {path:?}: {e}"),
                };
            }
        };

        if !metadata.file_type().is_file() {
            return ExecutionOutcome::Failed {
                err: format!(
                    "FileExtendGuarded: refusing non-regular target {path:?} (mode {:o})",
                    metadata.mode()
                ),
            };
        }
        let actual = InodeRef::new(metadata.dev(), metadata.ino());
        if actual != expected_inode {
            return ExecutionOutcome::Conflict {
                kind: Conflict::Phantom {
                    detail: format!(
                        "{path:?} now refers to inode {actual}, expected {expected_inode}; refusing truncate"
                    ),
                },
            };
        }

        // If the file is now shorter than the captured pre-append size,
        // truncating UP would manufacture zero bytes that the user never put
        // there. This check and the mutation use the same descriptor.
        if metadata.len() < truncate_to {
            return ExecutionOutcome::Failed {
                err: format!(
                    "FileExtendGuarded: current size {} < pre-append size {}; refusing to grow \
                     file with zeros (something else truncated the file since capture)",
                    metadata.len(),
                    truncate_to,
                ),
            };
        }

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        match file.set_len(truncate_to) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("FileExtendGuarded: truncate {path:?} to {truncate_to}: {e}"),
            },
        }
    }
}

fn live_inode(path: &Path) -> std::io::Result<InodeRef> {
    let meta = fs::symlink_metadata(path)?;
    Ok(InodeRef::new(meta.dev(), meta.ino()))
}

fn validate_safe_target_kind(path: &Path, allow_directory: bool) -> Result<(), ExecutionOutcome> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ExecutionOutcome::Conflict {
                kind: Conflict::Missing {
                    detail: format!("{path:?} no longer exists"),
                },
            });
        }
        Err(e) => {
            return Err(ExecutionOutcome::Failed {
                err: format!("lstat {path:?} before descriptor open: {e}"),
            });
        }
    };
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(ExecutionOutcome::Failed {
            err: format!("refusing unsafe symlink target {path:?}"),
        });
    }
    if !(kind.is_file() || allow_directory && kind.is_dir()) {
        return Err(ExecutionOutcome::Failed {
            err: format!(
                "refusing unsafe special target {path:?} (mode {:o})",
                meta.mode()
            ),
        });
    }
    Ok(())
}

/// Open exactly once without following a final symlink, then establish both
/// safe-kind and inode identity from that descriptor. All mutations use the
/// returned descriptor, never `path`.
fn open_verified_target(path: &Path, expected_inode: InodeRef) -> Result<File, ExecutionOutcome> {
    validate_safe_target_kind(path, true)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ExecutionOutcome::Conflict {
                    kind: Conflict::Missing {
                        detail: format!("{path:?} vanished before descriptor open"),
                    },
                }
            } else {
                ExecutionOutcome::Failed {
                    err: format!(
                        "open {path:?} with O_NOFOLLOW for metadata restore: {e}; refusing unopenable target"
                    ),
                }
            }
        })?;
    let meta = file.metadata().map_err(|e| ExecutionOutcome::Failed {
        err: format!("fstat metadata target {path:?}: {e}"),
    })?;
    if !meta.file_type().is_file() && !meta.file_type().is_dir() {
        return Err(ExecutionOutcome::Failed {
            err: format!(
                "refusing unsafe special target {path:?} after open (mode {:o})",
                meta.mode()
            ),
        });
    }
    let actual = InodeRef::new(meta.dev(), meta.ino());
    if actual != expected_inode {
        return Err(ExecutionOutcome::Conflict {
            kind: Conflict::Phantom {
                detail: format!(
                    "{path:?} opened as inode {actual}, expected {expected_inode}; refusing inode-addressed mutation"
                ),
            },
        });
    }
    Ok(file)
}

fn verify_retained_path(file: &File, path: &Path) -> Result<(), ExecutionOutcome> {
    let fd_meta = file.metadata().map_err(|e| ExecutionOutcome::Failed {
        err: format!("fstat retained restore descriptor for {path:?}: {e}"),
    })?;
    if !fd_meta.file_type().is_file() {
        return Err(ExecutionOutcome::Failed {
            err: format!("retained RestoreContent target {path:?} is not a regular file"),
        });
    }
    validate_safe_target_kind(path, false)?;
    let live = live_inode(path).map_err(|e| ExecutionOutcome::Failed {
        err: format!("lstat retained restore path {path:?}: {e}"),
    })?;
    let retained = InodeRef::new(fd_meta.dev(), fd_meta.ino());
    if live != retained {
        return Err(ExecutionOutcome::Conflict {
            kind: Conflict::Phantom {
                detail: format!(
                    "{path:?} no longer names the inode installed by RestoreContent ({retained}); refusing metadata replay"
                ),
            },
        });
    }
    Ok(())
}

/// Restore ownership, mode, xattrs, timestamp, and finally BSD flags through
/// one already-verified descriptor. `fchown` EPERM fails closed: the existing
/// privileged router is pathname-only and cannot safely preserve identity.
fn restore_metadata_fd(
    file: &File,
    path: &Path,
    target: &crate::metadata::FileMetadata,
) -> Result<(), String> {
    let fd = file.as_raw_fd();

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    clear_blocking_flags_fd(file, path)?;

    let current = file
        .metadata()
        .map_err(|e| format!("fstat metadata target {path:?}: {e}"))?;
    if current.uid() != target.uid || current.gid() != target.gid {
        let uid = Some(nix::unistd::Uid::from_raw(target.uid));
        let gid = Some(nix::unistd::Gid::from_raw(target.gid));
        nix::unistd::fchown(fd, uid, gid).map_err(|e| {
            if e == nix::errno::Errno::EPERM {
                format!(
                    "fchown {path:?} -> uid={} gid={}: EPERM; refusing unsafe path-based helper fallback",
                    target.uid, target.gid
                )
            } else {
                format!(
                    "fchown {path:?} -> uid={} gid={}: {e}",
                    target.uid, target.gid
                )
            }
        })?;
    }

    // Every list/get/set/delete syscall is bound to this descriptor and every
    // error is fatal: reporting Applied after partial xattr convergence would
    // be false. Do this before final fchmod because xattr mutation can clear
    // set-id bits on some kernels.
    crate::executors::xattr::restore_user_xattrs_fd(fd, path, &target.xattrs)
        .map_err(|e| format!("fd xattr restore for {path:?}: {e}"))?;

    restore_mtime_fd(file, path, target)?;

    // chown and xattr mutation can clear setuid/setgid, so the captured mode
    // is the final mutation before immutable/append flags are installed.
    let mode_only = target.mode & 0o7777;
    nix::sys::stat::fchmod(
        fd,
        nix::sys::stat::Mode::from_bits_truncate(mode_only as libc::mode_t),
    )
    .map_err(|e| format!("fchmod {path:?} -> {mode_only:o}: {e}"))?;

    // Immutable/append flags are always last: setting them earlier can make
    // fchmod, fxattr, or futimens fail on the very descriptor we verified.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    restore_flags_fd(file, path, target.flags)?;
    Ok(())
}

fn restore_mtime_fd(
    file: &File,
    path: &Path,
    target: &crate::metadata::FileMetadata,
) -> Result<(), String> {
    if target.mtime_unix_nanos == 0 {
        return Ok(());
    }
    use nix::sys::stat::futimens;
    use nix::sys::time::TimeSpec;
    let secs = target.mtime_unix_nanos.div_euclid(1_000_000_000);
    let nsecs = target.mtime_unix_nanos.rem_euclid(1_000_000_000);
    let secs_i64: i64 = secs.try_into().unwrap_or(i64::MAX);
    let nsecs_i64: i64 = nsecs.try_into().unwrap_or(0);
    let ts = TimeSpec::new(secs_i64, nsecs_i64);
    let omit = TimeSpec::new(0, libc::UTIME_OMIT);
    futimens(file.as_raw_fd(), &omit, &ts).map_err(|e| format!("futimens {path:?}: {e}"))
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn current_flags_fd(file: &File, path: &Path) -> Result<u32, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a live descriptor and `st` is writable.
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(format!(
            "fstat for fchflags probe {path:?}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(st.st_flags as u32)
}

#[cfg(target_os = "macos")]
fn set_flags_fd(file: &File, path: &Path, flags: u32) -> Result<(), String> {
    // SAFETY: `file` owns a live descriptor; flags has libc's exact width.
    if unsafe { libc::fchflags(file.as_raw_fd(), flags as libc::c_uint) } != 0 {
        return Err(format!(
            "fchflags {path:?} -> 0x{flags:x}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn set_flags_fd(file: &File, path: &Path, flags: u32) -> Result<(), String> {
    // SAFETY: `file` owns a live descriptor; widening u32 is lossless.
    if unsafe { libc::fchflags(file.as_raw_fd(), libc::c_ulong::from(flags)) } != 0 {
        return Err(format!(
            "fchflags {path:?} -> 0x{flags:x}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn clear_blocking_flags_fd(file: &File, path: &Path) -> Result<(), String> {
    let current = current_flags_fd(file, path)?;
    #[cfg(target_os = "macos")]
    let blocking = libc::UF_IMMUTABLE | libc::UF_APPEND | libc::SF_IMMUTABLE | libc::SF_APPEND;
    #[cfg(target_os = "freebsd")]
    let blocking = (libc::UF_IMMUTABLE as u32)
        | (libc::UF_APPEND as u32)
        | (libc::SF_IMMUTABLE as u32)
        | (libc::SF_APPEND as u32);
    let writable = current & !blocking;
    if writable != current {
        set_flags_fd(file, path, writable)?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn restore_flags_fd(file: &File, path: &Path, target_flags: u32) -> Result<(), String> {
    if current_flags_fd(file, path)? == target_flags {
        return Ok(());
    }
    set_flags_fd(file, path, target_flags)
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
fn restore_flags_fd(_file: &File, _path: &Path, _target_flags: u32) -> Result<(), String> {
    Err("RestoreFlags is unsupported on this operating system".into())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn flags_supported() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
fn flags_supported() -> Result<(), String> {
    Err("RestoreFlags is unsupported on this operating system".into())
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
/// files, directories, and (post-AU22) BlockDevice/CharDevice fail
/// with a DR-15.2 message — those need CAP_SYS_ADMIN even with the
/// right owner. Fifo/Socket are NOT routed here; the executor
/// dispatches those through the PrivilegedOpRouter::mknod before
/// reaching this function (see apply_recreate_path's AU22 branch).
fn recreate_path_inner(
    path: &Path,
    kind: crate::metadata::FileKind,
    mode: u32,
) -> Result<(), String> {
    use crate::metadata::FileKind;
    use std::os::unix::fs::PermissionsExt;

    let perm_bits = mode & 0o7777;
    // G01.5 — mkdir -p the parent if it's gone. Same rationale as
    // restore_content_inner: a recursive `rm -rf` (or `git clean -fd`)
    // leaves nested files orphaned from their dir tree at undo time.
    // Untracked / build-cache dirs typically had default mode; if the
    // user needs the original mode of an intermediate, a future wire
    // change to TreeOpWire::Unlink carrying kind+mode would let the
    // planner emit dedicated dir RecreatePath ops first (deferred,
    // see G01 plan).
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir -p {parent:?}: {e}"))?;
    }
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
            // G03 — recreate_path for a Directory may run AFTER a
            // child's RestoreContent has already `mkdir -p`'d this
            // path at default umask. Treat AlreadyExists-and-is-dir
            // as success and just chmod to the captured mode; any
            // other AlreadyExists kind (file/symlink in our place)
            // is a real conflict and bubbles up.
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        && fs::symlink_metadata(path)
                            .map(|m| m.file_type().is_dir())
                            .unwrap_or(false) => {}
                Err(e) => return Err(format!("mkdir {path:?}: {e}")),
            }
            fs::set_permissions(path, fs::Permissions::from_mode(perm_bits))
                .map_err(|e| format!("chmod {path:?} -> {perm_bits:o}: {e}"))?;
            Ok(())
        }
        FileKind::Symlink => Err(format!(
            "RecreatePath for symlink at {path:?} is a planner bug — \
             use InverseOp::CreateSymlink which carries the target"
        )),
        // BlockDevice/CharDevice need mknod(2) with CAP_SYS_ADMIN
        // even when owned by the requestor; the helper holds
        // CAP_MKNOD but not CAP_SYS_ADMIN by default. Deferred to
        // DR-15.2 (separate policy review for granting CAP_SYS_ADMIN
        // to the helper). Fifo/Socket are handled upstream by
        // apply_recreate_path's AU22 branch and never reach here.
        other => Err(format!(
            "RecreatePath for kind {other:?} at {path:?}: needs mknod(2) \
             with CAP_SYS_ADMIN — deferred to DR-15.2"
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

    fn actual_inode(path: &Path) -> InodeRef {
        live_inode(path).expect("lstat test fixture")
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
    fn dry_run_validates_blob_then_reports_would_apply() {
        let blob = BlobHash::from_bytes([0; 32]);
        let mut r = InMemoryBlobReader::new();
        r.insert(blob, b"captured".to_vec());
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: PathBuf::from("/tmp/x"),
            blob,
        };
        assert_eq!(
            e.execute(&op, true, ConflictPolicy::default()),
            ExecutionOutcome::WouldApply
        );
    }

    #[test]
    fn rejects_relative_operands_for_every_file_inverse_shape() {
        use crate::metadata::{FileKind, FileMetadata};
        use std::collections::BTreeMap;

        let inode = InodeRef::new(1, 1);
        let blob = BlobHash::from_bytes([0; 32]);
        let meta = FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
            flags: 0,
        };
        let ops = vec![
            InverseOp::RestoreContent {
                inode,
                path: "relative".into(),
                blob,
            },
            InverseOp::RestoreMetadata {
                inode,
                path: "relative".into(),
                target: meta,
            },
            InverseOp::RestoreFlags {
                inode,
                path: "relative".into(),
                flags: 0,
            },
            InverseOp::Unlink {
                path: "relative".into(),
            },
            InverseOp::RecreatePath {
                path: "relative".into(),
                kind: FileKind::Regular,
                mode: 0o644,
            },
            InverseOp::Rename {
                from: "relative".into(),
                to: "/absolute".into(),
            },
            InverseOp::CreateSymlink {
                target: "../valid-relative-target".into(),
                path: "relative".into(),
            },
            InverseOp::CreateHardlink {
                source: "relative".into(),
                target: "/absolute".into(),
            },
            InverseOp::FileExtend {
                path: "relative".into(),
                truncate_to: 0,
            },
            InverseOp::FileExtendGuarded {
                inode,
                path: "relative".into(),
                truncate_to: 0,
            },
        ];

        for op in &ops {
            assert!(
                first_relative_file_operand(op).is_some(),
                "relative operand escaped guard: {op:?}"
            );
        }

        let valid_relative_symlink_target = InverseOp::CreateSymlink {
            target: "../target".into(),
            path: "/absolute/link".into(),
        };
        assert!(first_relative_file_operand(&valid_relative_symlink_target).is_none());
    }

    #[test]
    fn execute_refuses_relative_path_before_dispatch() {
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let out = e.execute(
            &InverseOp::Unlink {
                path: "must-not-be-unlinked".into(),
            },
            false,
            ConflictPolicy::default(),
        );
        assert!(matches!(
            out,
            ExecutionOutcome::Failed { err } if err.contains("refusing relative filesystem path")
        ));
    }

    #[test]
    fn restore_flags_is_a_file_tier_dry_run() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("flags-dry-run");
        std::fs::write(&path, b"x").expect("write");
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreFlags {
            inode: actual_inode(&path),
            path,
            flags: 0,
        };
        assert!(e.supports(&op));
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        assert_eq!(
            e.execute(&op, true, ConflictPolicy::default()),
            ExecutionOutcome::WouldApply
        );
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        assert!(matches!(
            e.execute(&op, true, ConflictPolicy::default()),
            ExecutionOutcome::Failed { err } if err.contains("unsupported")
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn restore_flags_dispatches_on_supported_platform() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("flags");
        std::fs::write(&path, b"x").expect("write");
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreFlags {
            inode: actual_inode(&path),
            path: path.clone(),
            flags: 0,
        };
        assert_eq!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Applied
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    #[test]
    fn restore_flags_fails_honestly_on_unsupported_platform() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("flags");
        std::fs::write(&path, b"x").expect("write");
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreFlags {
            inode: actual_inode(&path),
            path,
            flags: 0,
        };
        assert!(matches!(
            e.execute(&op, false, ConflictPolicy::default()),
            ExecutionOutcome::Failed { err } if err.contains("unsupported")
        ));
    }

    #[test]
    fn legacy_file_extend_fails_closed_without_mutating() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        std::fs::write(&target, vec![0u8; 32]).unwrap();
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtend {
            path: target.clone(),
            truncate_to: 8,
        };
        for dry_run in [true, false] {
            assert!(matches!(
                e.execute(&op, dry_run, ConflictPolicy::Force),
                ExecutionOutcome::Failed { err }
                    if err.contains("lacks a captured inode") && err.contains("regenerate")
            ));
            assert_eq!(std::fs::metadata(&target).unwrap().len(), 32);
        }
    }

    #[test]
    fn guarded_file_extend_truncates_matching_inode() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        std::fs::write(&target, vec![0u8; 32]).unwrap();
        let captured_inode = actual_inode(&target);
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtendGuarded {
            inode: captured_inode,
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
    fn guarded_file_extend_force_refuses_replacement_inode() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        let original = tmpdir.path().join("log.rotated");
        std::fs::write(&target, b"captured inode plus appended bytes").unwrap();
        let captured_inode = actual_inode(&target);

        // Keep the captured inode allocated so the new file cannot reuse its
        // inode number, then replace the path with unrelated user data.
        std::fs::rename(&target, &original).unwrap();
        std::fs::write(&target, b"replacement must remain intact").unwrap();
        assert_ne!(actual_inode(&target), captured_inode);

        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtendGuarded {
            inode: captured_inode,
            path: target.clone(),
            truncate_to: 8,
        };
        for dry_run in [true, false] {
            let out = e.execute(&op, dry_run, ConflictPolicy::Force);
            assert!(matches!(
                out,
                ExecutionOutcome::Conflict {
                    kind: Conflict::Phantom { .. }
                }
            ));
        }
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"replacement must remain intact"
        );
        assert_eq!(
            std::fs::read(&original).unwrap(),
            b"captured inode plus appended bytes"
        );
    }

    #[test]
    fn guarded_file_extend_refuses_to_grow_with_zeros() {
        // If something truncated the file shorter than truncate_to
        // since capture, refusing is the right answer — we'd be
        // appending zeros the user never wrote.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        std::fs::write(&target, vec![0u8; 4]).unwrap(); // current = 4
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtendGuarded {
            inode: actual_inode(&target),
            path: target.clone(),
            truncate_to: 16, // would grow with zeros
        };
        for dry_run in [true, false] {
            match e.execute(&op, dry_run, ConflictPolicy::default()) {
                ExecutionOutcome::Failed { err } => {
                    assert!(err.contains("refusing to grow"), "got: {err}");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
        }
        // File was not modified.
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 4);
    }

    #[test]
    fn guarded_file_extend_missing_path_returns_conflict() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("ghost");
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtendGuarded {
            inode: InodeRef::new(1, 1),
            path: target,
            truncate_to: 0,
        };
        let out = e.execute(&op, false, ConflictPolicy::default());
        assert!(matches!(
            out,
            ExecutionOutcome::Conflict {
                kind: Conflict::Missing { .. }
            }
        ));
    }

    #[test]
    fn guarded_file_extend_to_zero_makes_file_empty() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("log");
        std::fs::write(&target, b"some content here").unwrap();
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::FileExtendGuarded {
            inode: actual_inode(&target),
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
        // Some filesystems/sandboxes refuse or silently strip set-id bits for
        // unprivileged callers. Probe that capability so this remains an
        // ordering test rather than a host-policy test.
        if std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o4755)).is_err()
            || std::fs::metadata(&target).unwrap().permissions().mode() & 0o4000 == 0
        {
            return;
        }
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
            flags: 0,
        };
        let r = InMemoryBlobReader::new();
        let e = FileExecutor::new(&r);
        let op = InverseOp::RestoreMetadata {
            inode: actual_inode(&target),
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
    fn restore_metadata_restores_mode_on_same_inode() {
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
            flags: 0,
        };
        let op = InverseOp::RestoreMetadata {
            inode: actual_inode(&target),
            path: target.clone(),
            target: captured,
        };
        let out = exec.execute(&op, false, ConflictPolicy::default());
        assert_eq!(out, ExecutionOutcome::Applied, "{out:?}");

        let m = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o600);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn restore_metadata_propagates_fd_xattr_errors_before_final_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("xattr-error");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let live = std::fs::metadata(&target).unwrap();
        let mut xattrs = std::collections::BTreeMap::new();
        xattrs.insert("bad\0name".to_string(), b"value".to_vec());
        let metadata = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: live.uid(),
            gid: live.gid(),
            size: live.len(),
            mtime_unix_nanos: 0,
            xattrs,
            acl: None,
            flags: 0,
        };
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let outcome = exec.execute(
            &InverseOp::RestoreMetadata {
                inode: actual_inode(&target),
                path: target.clone(),
                target: metadata,
            },
            false,
            ConflictPolicy::Abort,
        );
        assert!(matches!(
            outcome,
            ExecutionOutcome::Failed { err }
                if err.contains("xattr") && err.contains("unrepresentable")
        ));
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640,
            "fchmod must not run after xattr convergence failed"
        );
    }

    #[test]
    fn restore_metadata_refuses_replacement_inode_even_with_force() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("metadata-target");
        let displaced = tmpdir.path().join("metadata-target.old");
        std::fs::write(&target, b"captured inode").unwrap();
        let captured_inode = actual_inode(&target);

        // Replace the pathname with a distinct inode after capture.
        std::fs::rename(&target, &displaced).unwrap();
        std::fs::write(&target, b"unrelated replacement").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_ne!(actual_inode(&target), captured_inode);

        let live = std::fs::metadata(&target).unwrap();
        let target_meta = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: std::os::unix::fs::MetadataExt::uid(&live),
            gid: std::os::unix::fs::MetadataExt::gid(&live),
            size: live.len(),
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
            flags: 0,
        };
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let outcome = exec.execute(
            &InverseOp::RestoreMetadata {
                inode: captured_inode,
                path: target.clone(),
                target: target_meta,
            },
            false,
            ConflictPolicy::Force,
        );

        assert!(matches!(
            outcome,
            ExecutionOutcome::Conflict {
                kind: Conflict::Phantom { .. }
            }
        ));
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640,
            "the unrelated replacement must remain untouched"
        );
    }

    #[test]
    fn metadata_accepts_inode_installed_by_matching_content_restore() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("paired-restore");
        std::fs::write(&target, b"post-command bytes").unwrap();
        let captured_inode = actual_inode(&target);

        let blob = BlobHash::from_bytes([0x5a; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob, b"pre-command bytes".to_vec());
        let exec = FileExecutor::new(&reader);
        assert_eq!(
            exec.execute(
                &InverseOp::RestoreContent {
                    inode: captured_inode,
                    path: target.clone(),
                    blob,
                },
                false,
                ConflictPolicy::Abort,
            ),
            ExecutionOutcome::Applied
        );
        let restored_inode = actual_inode(&target);
        assert_ne!(restored_inode, captured_inode);

        let live = std::fs::metadata(&target).unwrap();
        let metadata = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: std::os::unix::fs::MetadataExt::uid(&live),
            gid: std::os::unix::fs::MetadataExt::gid(&live),
            size: live.len(),
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
            flags: 0,
        };
        assert_eq!(
            exec.execute(
                &InverseOp::RestoreMetadata {
                    inode: captured_inode,
                    path: target.clone(),
                    target: metadata,
                },
                false,
                ConflictPolicy::Abort,
            ),
            ExecutionOutcome::Applied
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn dry_run_models_content_then_metadata_without_mutating() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("paired-dry-run");
        std::fs::write(&target, b"post-command bytes").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

        let captured_inode = InodeRef::new(u64::MAX - 1, u64::MAX - 2);
        let blob = BlobHash::from_bytes([0x6b; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob, b"pre-command bytes".to_vec());
        let exec = FileExecutor::new(&reader);
        assert_eq!(
            exec.execute(
                &InverseOp::RestoreContent {
                    inode: captured_inode,
                    path: target.clone(),
                    blob,
                },
                true,
                ConflictPolicy::Force,
            ),
            ExecutionOutcome::WouldApply
        );

        let live = std::fs::metadata(&target).unwrap();
        let metadata = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: live.uid(),
            gid: live.gid(),
            size: live.len(),
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
            flags: 0,
        };
        assert_eq!(
            exec.execute(
                &InverseOp::RestoreMetadata {
                    inode: captured_inode,
                    path: target.clone(),
                    target: metadata,
                },
                true,
                ConflictPolicy::Force,
            ),
            ExecutionOutcome::WouldApply
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"post-command bytes");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    #[test]
    fn retained_content_descriptor_refuses_later_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("paired-race");
        let displaced = tmpdir.path().join("paired-race.displaced");
        std::fs::write(&target, b"post-command").unwrap();
        let captured_inode = actual_inode(&target);

        let blob = BlobHash::from_bytes([0x7c; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob, b"restored bytes".to_vec());
        let exec = FileExecutor::new(&reader);
        assert_eq!(
            exec.execute(
                &InverseOp::RestoreContent {
                    inode: captured_inode,
                    path: target.clone(),
                    blob,
                },
                false,
                ConflictPolicy::Abort,
            ),
            ExecutionOutcome::Applied
        );

        std::fs::rename(&target, &displaced).unwrap();
        std::fs::write(&target, b"unrelated replacement").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let live = std::fs::metadata(&target).unwrap();
        let metadata = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: live.uid(),
            gid: live.gid(),
            size: live.len(),
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
            flags: 0,
        };
        let outcome = exec.execute(
            &InverseOp::RestoreMetadata {
                inode: captured_inode,
                path: target.clone(),
                target: metadata,
            },
            false,
            ConflictPolicy::Force,
        );
        assert!(matches!(
            outcome,
            ExecutionOutcome::Conflict {
                kind: Conflict::Phantom { .. }
            }
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"unrelated replacement");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    #[test]
    fn restore_metadata_refuses_symlink_without_touching_referent() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let referent = tmpdir.path().join("referent");
        let link = tmpdir.path().join("link");
        std::fs::write(&referent, b"data").unwrap();
        std::fs::set_permissions(&referent, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&referent, &link).unwrap();
        let referent_meta = std::fs::metadata(&referent).unwrap();
        let target = crate::metadata::FileMetadata {
            mode: 0o100600,
            uid: referent_meta.uid(),
            gid: referent_meta.gid(),
            size: referent_meta.len(),
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
            flags: 0,
        };
        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let op = InverseOp::RestoreMetadata {
            inode: actual_inode(&link),
            path: link,
            target,
        };
        for dry_run in [true, false] {
            assert!(matches!(
                exec.execute(&op, dry_run, ConflictPolicy::Force),
                ExecutionOutcome::Failed { err } if err.contains("symlink")
            ));
        }
        assert_eq!(
            std::fs::metadata(&referent).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    #[test]
    fn restore_flags_runtime_guard_refuses_replacement_inode() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("flags-target");
        let displaced = tmpdir.path().join("flags-target.old");
        std::fs::write(&target, b"captured inode").unwrap();
        let captured_inode = actual_inode(&target);
        std::fs::rename(&target, displaced).unwrap();
        std::fs::write(&target, b"replacement").unwrap();

        let reader = InMemoryBlobReader::new();
        let exec = FileExecutor::new(&reader);
        let outcome = exec.execute(
            &InverseOp::RestoreFlags {
                inode: captured_inode,
                path: target,
                flags: 0,
            },
            false,
            ConflictPolicy::Force,
        );
        assert!(matches!(
            outcome,
            ExecutionOutcome::Conflict {
                kind: Conflict::Phantom { .. }
            }
        ));
    }

    #[test]
    fn restore_metadata_to_different_uid_without_router_surfaces_eperm() {
        // Unprivileged tests can't fchown to a uid we don't own. The
        // descriptor-safe implementation fails closed on EPERM because the
        // existing privileged router accepts only a pathname.
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
            flags: 0,
        };
        let op = InverseOp::RestoreMetadata {
            inode: actual_inode(&target),
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
    fn restore_metadata_never_falls_back_to_path_chown_router() {
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
            flags: 0,
        };
        let op = InverseOp::RestoreMetadata {
            inode: actual_inode(&target),
            path: target.clone(),
            target: captured,
        };
        let outcome = exec.execute(&op, false, ConflictPolicy::default());
        assert!(matches!(
            outcome,
            ExecutionOutcome::Failed { err }
                if err.contains("EPERM") && err.contains("unsafe path-based helper fallback")
        ));
        assert!(
            exec.privileged_router.chown_log().is_empty(),
            "descriptor replay must not hand a pathname to the chown router"
        );
    }

    #[test]
    fn restore_metadata_path_router_outcome_cannot_override_fchown_failure() {
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
            flags: 0,
        };
        let op = InverseOp::RestoreMetadata {
            inode: actual_inode(&target),
            path: target.clone(),
            target: captured,
        };
        match exec.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Failed { err } => {
                assert!(
                    err.contains("unsafe path-based helper fallback"),
                    "got: {err}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(exec.privileged_router.chown_log().is_empty());
    }

    #[test]
    fn restore_content_recreates_missing_parent_dir() {
        // G01.5: when the parent dir is gone (e.g. `git clean -fd`
        // rmdir'd it after unlinking contents), RestoreContent
        // should `mkdir -p` the chain and complete successfully.
        // Pre-G01.5 this test asserted Failed; the new behavior is
        // Applied because the executor recreates missing ancestors
        // with default mode (0o755).
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let nonexistent_parent = tmpdir.path().join("nested-a").join("nested-b");
        let target = nonexistent_parent.join("file");

        let blob_hash = BlobHash::from_bytes([1; 32]);
        let mut reader = InMemoryBlobReader::new();
        reader.insert(blob_hash, b"hello".to_vec());

        let executor = FileExecutor::new(&reader);
        let op = InverseOp::RestoreContent {
            inode: InodeRef::new(1, 1),
            path: target.clone(),
            blob: blob_hash,
        };
        match executor.execute(&op, false, ConflictPolicy::default()) {
            ExecutionOutcome::Applied => {}
            other => panic!("expected Applied, got {other:?}"),
        }
        // File now exists with the expected content; parents were
        // created.
        let body = std::fs::read(&target).expect("read restored file");
        assert_eq!(body, b"hello");
    }
}
