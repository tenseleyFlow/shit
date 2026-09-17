// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-side xattr capture (W09.21 capsicum fix).
//!
//! The helper runs under `cap_enter(2)` by default on FreeBSD (B05).
//! FreeBSD kernel rejects `extattr_*_fd(2)` in capability mode with
//! `ECAPMODE` regardless of `cap_rights_limit` — the syscall is
//! gated at the capability-mode level, not by per-fd rights (verified
//! empirically on shit-fbsd 14.4: `extattr_list_fd` returns -1
//! errno=94 "Not permitted in capability mode" after `cap_enter()`
//! even when no `cap_rights_limit` is applied).
//!
//! So xattr capture has to happen in a process that hasn't entered
//! capability mode. The daemon is the natural home: it owns the
//! `LiveBaseline` cache, has the absolute path on the wire, and is
//! never `cap_enter`'d.
//!
//! This module reads user-namespace xattrs by absolute path
//! (path-based open, not fd-passing — the helper's fd is no use to
//! us since we want the daemon to do the open itself in its
//! unrestricted address space).

use std::collections::BTreeMap;
use std::path::Path;

/// Strict xattr reader used whenever an empty map would be interpreted as
/// authoritative replay state. It preserves read/list/encoding failures so
/// callers can journal a refusal instead of deleting attributes they failed
/// to capture.
pub fn try_read_user_xattrs_at_path(path: &Path) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read(path)
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = path;
        Ok(BTreeMap::new())
    }
}

/// Strict baseline capture bound to the helper-observed inode identity.
/// FreeBSD opens with `O_NOFOLLOW|O_NONBLOCK`, verifies the descriptor before
/// and after listing/reading attributes, and refuses path replacement races.
pub fn try_read_user_xattrs_at_path_for_inode(
    path: &Path,
    expected_dev: u64,
    expected_inode: u64,
) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read_for_inode(path, expected_dev, expected_inode)
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "baseline xattr path is not a regular file",
            ));
        }
        if metadata.dev() != expected_dev || metadata.ino() != expected_inode {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "baseline path identity changed: expected ({expected_dev}, {expected_inode}), opened ({}, {})",
                    metadata.dev(),
                    metadata.ino()
                ),
            ));
        }
        try_read_user_xattrs_at_path(path)
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    pub fn read(path: &Path) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
        let file = open_nonblocking_nofollow(path)?;
        read_fd(file.as_raw_fd())
    }

    pub fn read_for_inode(
        path: &Path,
        expected_dev: u64,
        expected_inode: u64,
    ) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
        let file = open_nonblocking_nofollow(path)?;
        let fd = file.as_raw_fd();
        verify_identity(fd, expected_dev, expected_inode)?;
        let attrs = read_fd(fd)?;
        verify_identity(fd, expected_dev, expected_inode)?;
        Ok(attrs)
    }

    fn open_nonblocking_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    fn verify_identity(
        fd: libc::c_int,
        expected_dev: u64,
        expected_inode: u64,
    ) -> std::io::Result<()> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "baseline xattr descriptor is not a regular file",
            ));
        }
        if stat.st_dev as u64 != expected_dev || stat.st_ino as u64 != expected_inode {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "baseline path identity changed: expected ({expected_dev}, {expected_inode}), opened ({}, {})",
                    stat.st_dev, stat.st_ino
                ),
            ));
        }
        Ok(())
    }

    fn read_fd(fd: libc::c_int) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
        const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;
        let ns = libc::EXTATTR_NAMESPACE_USER;
        let list_size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if list_size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if list_size == 0 {
            return Ok(BTreeMap::new());
        }
        let list_size = usize::try_from(list_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name-list length does not fit usize",
            )
        })?;
        if list_size > XATTR_CAPTURE_CAP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "xattr name list is {list_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
                ),
            ));
        }
        let mut buf = vec![0u8; list_size];
        let n = unsafe { libc::extattr_list_fd(fd, ns, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n as usize != list_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("xattr name list changed during capture (expected {list_size}, read {n})"),
            ));
        }
        let mut out = BTreeMap::new();
        let mut total = list_size;
        let mut i = 0usize;
        let end = n as usize;
        // FreeBSD extattr_list_fd encoding: <u8 namelen><name…> repeating,
        // no terminator. Parse one entry at a time.
        while i < end {
            let len = buf[i] as usize;
            i += 1;
            if i + len > end {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed FreeBSD xattr name list",
                ));
            }
            let name_bytes = &buf[i..i + len];
            i += len;
            let name = std::str::from_utf8(name_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr name is not valid UTF-8",
                )
            })?;
            let cname = CString::new(name).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr name contains NUL: {e}"),
                )
            })?;
            let val_size =
                unsafe { libc::extattr_get_fd(fd, ns, cname.as_ptr(), std::ptr::null_mut(), 0) };
            if val_size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let val_size = usize::try_from(val_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr {name:?} length does not fit usize"),
                )
            })?;
            total = total.checked_add(val_size).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr capture length overflow",
                )
            })?;
            if total > XATTR_CAPTURE_CAP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xattr capture exceeds the {XATTR_CAPTURE_CAP}-byte aggregate cap"),
                ));
            }
            let mut val = vec![0u8; val_size];
            let m = unsafe {
                libc::extattr_get_fd(fd, ns, cname.as_ptr(), val.as_mut_ptr().cast(), val.len())
            };
            if m < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if m as usize != val_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xattr {name:?} changed during capture (expected {val_size}, read {m})"
                    ),
                ));
            }
            out.insert(name.to_string(), val);
        }
        Ok(out)
    }
}

/// PostExec sweep: for each cached file in the cwd's LiveBaseline,
/// re-read xattrs from disk and diff against the cached baseline
/// xattrs. Any path whose xattrs changed gets a synthetic
/// `MetadataChange` event journaled, so the planner can emit a
/// `RestoreMetadata` inverse that puts the xattrs back.
///
/// Why this exists: kqueue's `NOTE_ATTRIB` does fire when a user
/// runs `setextattr`, but the helper is `cap_enter`'d and so its
/// `fstat_meta` returns empty xattrs both before and after — the
/// helper's `handle_attrib` sees `before == after` and drops the
/// event. The daemon isn't capsicum'd and can read xattrs; the
/// PostExec sweep is when it does that final compare.
///
/// A sweep error is never silently skipped. If reading or validating a path,
/// or journaling its metadata event, fails, the function first persists a
/// command-scoped `CaptureRefused`. A successful refusal is a complete safety
/// outcome (undo will fail closed); an error is returned only when even that
/// refusal could not be made durable. Other StatMeta fields are already
/// covered by the helper's normal NOTE_ATTRIB path.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PostExecSweepOutcome {
    pub metadata_events: usize,
    pub durable_refusals: usize,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "post-exec xattr sweep could not persist CaptureRefused for {path:?}: {refusal_error}; capture failure: {detail}"
)]
pub struct PostExecSweepError {
    pub path: std::path::PathBuf,
    pub detail: String,
    #[source]
    pub refusal_error: shit_store::IndexError,
}

pub fn post_exec_sweep(
    cwd: &std::path::Path,
    command: shit_planner::events::CommandId,
    live_baseline: &crate::baseline::LiveBaseline,
    index: &shit_store::Index,
) -> Result<PostExecSweepOutcome, PostExecSweepError> {
    let mut outcome = PostExecSweepOutcome::default();
    let Some(cache) = live_baseline.get_cwd(cwd) else {
        return Ok(outcome);
    };
    let entries = cache.snapshot_entries();
    if entries.is_empty() {
        return Ok(outcome);
    }
    for (path, entry) in entries {
        let current =
            match try_read_user_xattrs_at_path_for_inode(&path, entry.inode.dev, entry.inode.inode)
            {
                Ok(current) => current,
                Err(error) => {
                    if baseline_entry_was_durably_deleted(index, command, &path, entry.inode) {
                        // The path is intentionally gone and its complete
                        // pre-image (including baseline xattrs) is already in
                        // the journal. It is no longer a sweep target.
                        continue;
                    }
                    let detail = format!(
                        "post-exec xattr read or identity validation failed for {}: {error}",
                        path.display()
                    );
                    persist_sweep_refusal(index, command, &path, detail, &mut outcome)?;
                    continue;
                }
            };
        if current == entry.xattrs {
            continue;
        }
        // Build a MetadataChange event. Only xattrs differ — other
        // FileMetadata fields are filled with the live values so
        // the planner's RestoreMetadata inverse doesn't touch them
        // (target equals current ⇒ executor sees mode/uid/gid/mtime
        // unchanged and skips them).
        let live_stat = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                if baseline_entry_was_durably_deleted(index, command, &path, entry.inode) {
                    // The path is intentionally gone and its complete
                    // pre-image (including baseline xattrs) is already in the
                    // journal. It is no longer a post-state sweep target.
                    continue;
                }
                let detail = format!(
                    "post-exec metadata read failed for xattr-changed path {}: {error}",
                    path.display()
                );
                persist_sweep_refusal(index, command, &path, detail, &mut outcome)?;
                continue;
            }
        };
        use std::os::unix::fs::MetadataExt;
        if !live_stat.file_type().is_file()
            || live_stat.dev() != entry.inode.dev
            || live_stat.ino() != entry.inode.inode
        {
            let detail = format!(
                "post-exec xattr path identity changed for {}: expected ({}, {}), observed ({}, {})",
                path.display(),
                entry.inode.dev,
                entry.inode.inode,
                live_stat.dev(),
                live_stat.ino()
            );
            persist_sweep_refusal(index, command, &path, detail, &mut outcome)?;
            continue;
        }
        let live_mode = live_stat.mode();
        let live_uid = live_stat.uid();
        let live_gid = live_stat.gid();
        let live_size = live_stat.size();
        let live_mtime_nanos =
            (live_stat.mtime() as i128) * 1_000_000_000 + (live_stat.mtime_nsec() as i128);
        let inode_ref = shit_planner::InodeRef::new(live_stat.dev(), live_stat.ino());
        // M03.x.SETATTR — the xattr-drift sweep is xattr-only; it
        // doesn't probe st_flags. Flag-change capture flows through
        // the dedicated MetadataChange path (M03.1.I.D + chflags-side
        // shim interposers), not through this sweep. Leave 0 here.
        let before = shit_planner::metadata::FileMetadata {
            mode: live_mode,
            uid: live_uid,
            gid: live_gid,
            size: live_size,
            mtime_unix_nanos: live_mtime_nanos,
            xattrs: entry.xattrs.clone(),
            acl: None,
            flags: 0,
        };
        let after = shit_planner::metadata::FileMetadata {
            mode: live_mode,
            uid: live_uid,
            gid: live_gid,
            size: live_size,
            mtime_unix_nanos: live_mtime_nanos,
            xattrs: current,
            acl: None,
            flags: 0,
        };
        let ts = crate::server::next_ts();
        let event = shit_planner::events::CaptureEvent {
            id: shit_planner::events::EventId(0),
            command,
            ts,
            partial: false,
            kind: shit_planner::events::CaptureEventKind::MetadataChange {
                inode: inode_ref,
                path: path.clone(),
                before,
                after,
            },
        };
        if let Err(e) = index.put_event(&event) {
            let detail = format!(
                "post-exec xattr MetadataChange journal failed for {}: {e}",
                path.display()
            );
            persist_sweep_refusal(index, command, &path, detail, &mut outcome)?;
            continue;
        }
        outcome.metadata_events += 1;
    }
    if outcome.metadata_events > 0 || outcome.durable_refusals > 0 {
        tracing::info!(
            cwd = %cwd.display(),
            ?command,
            emitted = outcome.metadata_events,
            refused = outcome.durable_refusals,
            "post-exec xattr sweep completed"
        );
    }
    Ok(outcome)
}

fn baseline_entry_was_durably_deleted(
    index: &shit_store::Index,
    command: shit_planner::events::CommandId,
    path: &Path,
    inode: shit_planner::InodeRef,
) -> bool {
    use shit_planner::PlannerStore;
    use shit_planner::events::CaptureEventKind;
    use shit_planner::events::TreeOp;

    let events = index.events_for_command(command);
    let has_pre_image = events.iter().any(|event| {
        matches!(
            &event.kind,
            CaptureEventKind::FilePreImage {
                inode: captured_inode,
                path: captured_path,
                ..
            } if *captured_inode == inode && captured_path == path
        )
    });
    let has_unlink = events.iter().any(|event| {
        matches!(
            &event.kind,
            CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: captured_inode,
                path: captured_path,
                ..
            }) if *captured_inode == inode && captured_path == path
        )
    });
    has_pre_image && has_unlink
}

fn persist_sweep_refusal(
    index: &shit_store::Index,
    command: shit_planner::events::CommandId,
    path: &Path,
    detail: String,
    outcome: &mut PostExecSweepOutcome,
) -> Result<(), PostExecSweepError> {
    match crate::helper_link::journal_helper_capture_refused(
        index,
        command,
        Some(path.to_path_buf()),
        detail.clone(),
    ) {
        Ok(()) => {
            outcome.durable_refusals += 1;
            tracing::warn!(%command, path = %path.display(), %detail, "post-exec xattr sweep refused command");
            Ok(())
        }
        Err(refusal_error) => Err(PostExecSweepError {
            path: path.to_path_buf(),
            detail,
            refusal_error,
        }),
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;
    use shit_planner::events::{CommandId, CommandRecord};
    use shit_planner::inode::{BlobHash, InodeRef};
    use shit_planner::{PlannerStore, TimePoint};
    use std::os::unix::fs::MetadataExt;
    use uuid::Uuid;

    fn register_command(index: &shit_store::Index, command: CommandId, cwd: &Path) {
        index
            .put_session(command.session, "bash", 100, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("xattr test".into()),
                cwd: cwd.to_path_buf(),
                pid: 100,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: Vec::new(),
            })
            .unwrap();
    }

    fn insert_baseline(
        live: &crate::baseline::LiveBaseline,
        cwd: &Path,
        path: std::path::PathBuf,
        inode: InodeRef,
    ) {
        let mut xattrs = BTreeMap::new();
        xattrs.insert("user.before".into(), b"baseline".to_vec());
        live.entry_for_cwd(cwd).insert(
            path,
            crate::baseline::BaselineEntry::new(
                inode,
                BlobHash::from_bytes([7; 32]),
                0,
                0o100600,
                1,
                1,
                0,
                xattrs,
                0,
            ),
        );
    }

    #[test]
    fn missing_sweep_path_is_a_durable_command_refusal() {
        let temp = tempfile::tempdir().unwrap();
        let index = shit_store::Index::open(temp.path().join("index.sqlite")).unwrap();
        let command = CommandId {
            session: Uuid::from_u128(0xA771),
            seq: 1,
        };
        register_command(&index, command, temp.path());
        let live = crate::baseline::LiveBaseline::new();
        let missing = temp.path().join("missing");
        insert_baseline(&live, temp.path(), missing.clone(), InodeRef::new(1, 2));

        let outcome = post_exec_sweep(temp.path(), command, &live, &index).unwrap();
        assert_eq!(outcome.metadata_events, 0);
        assert_eq!(outcome.durable_refusals, 1);
        assert!(matches!(
            &index.events_for_command(command)[..],
            [shit_planner::CaptureEvent {
                kind: shit_planner::CaptureEventKind::CaptureRefused { path, detail, .. },
                ..
            }] if path == &missing && detail.contains("read or identity")
        ));
    }

    #[test]
    fn missing_sweep_path_errors_when_refusal_is_not_durable() {
        let temp = tempfile::tempdir().unwrap();
        let index = shit_store::Index::open(temp.path().join("index.sqlite")).unwrap();
        let command = CommandId {
            session: Uuid::from_u128(0xA772),
            seq: 1,
        };
        let live = crate::baseline::LiveBaseline::new();
        let missing = temp.path().join("missing");
        insert_baseline(&live, temp.path(), missing.clone(), InodeRef::new(1, 2));

        let error = post_exec_sweep(temp.path(), command, &live, &index).unwrap_err();
        assert_eq!(error.path, missing);
        assert!(error.detail.contains("read or identity"));
    }

    #[test]
    fn fully_journaled_deletion_is_not_a_sweep_read_failure() {
        use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId, TreeOp};
        use shit_planner::metadata::{FileKind, FileMetadata};

        let temp = tempfile::tempdir().unwrap();
        let index = shit_store::Index::open(temp.path().join("index.sqlite")).unwrap();
        let command = CommandId {
            session: Uuid::from_u128(0xA774),
            seq: 1,
        };
        register_command(&index, command, temp.path());
        let path = temp.path().join("deleted");
        let inode = InodeRef::new(9, 10);
        let blob = BlobHash::from_bytes([7; 32]);
        index
            .put_blob_record(blob, 0, false, TimePoint::new(2, 0))
            .unwrap();
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(3, 0),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode,
                    path: path.clone(),
                    blob,
                    meta: FileMetadata {
                        mode: 0o100600,
                        uid: 1,
                        gid: 1,
                        size: 0,
                        mtime_unix_nanos: 0,
                        xattrs: BTreeMap::from([("user.before".into(), b"baseline".to_vec())]),
                        acl: None,
                        flags: 0,
                    },
                    post_content_hash: None,
                    source: shit_planner::events::FilePreImageSource::BaselineCachePromote,
                },
            })
            .unwrap();
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(4, 0),
                partial: false,
                kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                    inode,
                    path: path.clone(),
                    kind: FileKind::Regular,
                    mode: 0o100600,
                }),
            })
            .unwrap();
        let live = crate::baseline::LiveBaseline::new();
        insert_baseline(&live, temp.path(), path, inode);

        let outcome = post_exec_sweep(temp.path(), command, &live, &index).unwrap();
        assert_eq!(outcome, PostExecSweepOutcome::default());
        assert_eq!(index.events_for_command(command).len(), 2);
    }

    #[test]
    fn metadata_journal_error_falls_back_to_durable_refusal() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        std::fs::write(&path, b"content").unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let inode = InodeRef::new(metadata.dev(), metadata.ino());
        let index = shit_store::Index::open(temp.path().join("index.sqlite")).unwrap();
        let command = CommandId {
            session: Uuid::from_u128(0xA773),
            seq: 1,
        };
        register_command(&index, command, temp.path());
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_xattr_metadata
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'MetadataChange'
                 BEGIN SELECT RAISE(FAIL, 'injected xattr metadata failure'); END;",
            )
            .unwrap();
        let live = crate::baseline::LiveBaseline::new();
        insert_baseline(&live, temp.path(), path, inode);

        let outcome = post_exec_sweep(temp.path(), command, &live, &index).unwrap();
        assert_eq!(outcome.metadata_events, 0);
        assert_eq!(outcome.durable_refusals, 1);
        assert!(matches!(
            &index.events_for_command(command)[..],
            [shit_planner::CaptureEvent {
                kind: shit_planner::CaptureEventKind::CaptureRefused { detail, .. },
                ..
            }] if detail.contains("MetadataChange journal failed")
        ));
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn empty_file_has_no_xattrs() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let got = try_read_user_xattrs_at_path(f.path()).unwrap();
        assert!(got.is_empty(), "unexpected xattrs: {got:?}");
    }

    #[test]
    fn missing_path_returns_empty() {
        assert!(try_read_user_xattrs_at_path(Path::new("/no/such/path/shit-xattr-test")).is_err());
    }

    #[test]
    fn strict_baseline_xattrs_require_the_expected_inode_identity() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let metadata = file.as_file().metadata().unwrap();
        let attrs =
            try_read_user_xattrs_at_path_for_inode(file.path(), metadata.dev(), metadata.ino())
                .expect("matching identity");
        assert!(attrs.is_empty());

        let error = try_read_user_xattrs_at_path_for_inode(
            file.path(),
            metadata.dev(),
            metadata.ino().wrapping_add(1),
        )
        .expect_err("mismatched identity must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
