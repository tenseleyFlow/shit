// SPDX-License-Identifier: AGPL-3.0-or-later

//! L5 — journaling for a directory rename's walk and for the shim's
//! post-syscall rename outcome.
//!
//! The walk's file pre-images are journaled as before
//! (`ShimRenameSubtree`), now with the xattrs the shim read before the
//! syscall. One [`CaptureEventKind::RenameWalk`] follows them. It is
//! marked complete only if the shim said so and every one of the walk's
//! pre-images was journaled, so the planner can treat a complete walk as
//! the whole subtree.

use shit_planner::events::{CaptureEvent, CaptureEventKind, CommandId, EventId, WalkEntry};
use shit_planner::inode::InodeRef;
use shit_planner::metadata::{FileKind, FileMetadata};
use shit_planner::time::TimePoint;
use shit_proto::{ShimNotification, ShimRenameOutcome, ShimWalkEntry};
use shit_store::{BlobStore, Index};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use tracing::{debug, warn};

fn entry_xattrs(e: &ShimWalkEntry) -> Option<BTreeMap<String, Vec<u8>>> {
    e.xattrs.as_ref().map(|v| v.iter().cloned().collect())
}

fn walk_entry(e: &ShimWalkEntry, size: u64) -> Option<WalkEntry> {
    let kind = FileKind::from_mode(e.mode)?;
    Some(WalkEntry {
        path: PathBuf::from(&e.path),
        inode: InodeRef::new(e.dev, e.inode),
        kind,
        meta: FileMetadata {
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            size,
            mtime_unix_nanos: e.mtime_unix_nanos,
            xattrs: entry_xattrs(e).unwrap_or_default(),
            acl: None,
            flags: e.flags,
        },
        xattrs_read: e.xattrs.is_some(),
    })
}

/// Journal a rename notification's walk: its file pre-images, then its
/// [`CaptureEventKind::RenameWalk`].
pub(crate) fn ingest_walk(
    note: &ShimNotification,
    command: CommandId,
    ts: TimePoint,
    index: &Index,
    blob_store: &BlobStore,
) {
    let by_path: HashMap<&str, &ShimWalkEntry> = note
        .walk
        .iter()
        .flat_map(|w| w.entries.iter())
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut journaled = 0u64;
    let mut failed = 0u64;
    for pre in &note.extra_pre_images {
        let xattrs = by_path.get(pre.path.as_str()).and_then(|e| entry_xattrs(e));
        match crate::shim_listener::ingest_pre_image_full(
            command,
            pre,
            index,
            blob_store,
            shit_planner::FilePreImageSource::ShimRenameSubtree,
            ts,
            xattrs,
        ) {
            Ok(()) => journaled += 1,
            Err(e) => {
                failed += 1;
                warn!(err = %e, pid = note.pid, path = %pre.path, "shim notify: recursive pre-image ingest failed");
            }
        }
    }
    debug!(
        pid = note.pid,
        session = %command.session,
        seq = command.seq,
        n = note.extra_pre_images.len(),
        journaled,
        failed,
        "shim notify: recursive rename pre-images ingested (DR-CR-54)"
    );
    let Some(walk) = &note.walk else {
        return;
    };
    let Some((from, _)) = note.arg.split_once('\t') else {
        return;
    };
    let sizes: HashMap<&str, u64> = note
        .extra_pre_images
        .iter()
        .map(|p| (p.path.as_str(), p.size))
        .collect();
    let entries: Vec<WalkEntry> = walk
        .entries
        .iter()
        .filter_map(|e| walk_entry(e, sizes.get(e.path.as_str()).copied().unwrap_or(0)))
        .collect();
    // The proof of a whole subtree breaks as soon as one entry is
    // missing from the journal, whatever the shim saw.
    let complete = walk.complete
        && failed == 0
        && journaled == u64::from(walk.files)
        && entries.len() == walk.entries.len()
        && entries.first().is_some_and(|e| e.path.as_os_str() == from);
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::RenameWalk {
            root: PathBuf::from(from),
            complete,
            files: walk.files,
            entries,
        },
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, pid = note.pid, "shim notify: RenameWalk journal failed");
    }
}

/// Journal a rename's post-syscall outcome.
pub(crate) fn ingest_outcome(
    note: &ShimNotification,
    outcome: &ShimRenameOutcome,
    command: CommandId,
    ts: TimePoint,
    index: &Index,
) {
    let Some((from, to)) = note.arg.split_once('\t') else {
        debug!(pid = note.pid, arg = %note.arg, "shim notify: rename outcome without from\\tto; dropping");
        return;
    };
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::RenameOutcome {
            from: PathBuf::from(from),
            to: PathBuf::from(to),
            errno: outcome.errno,
            source: InodeRef::new(outcome.source_dev, outcome.source_inode),
            dest: InodeRef::new(outcome.dest_dev, outcome.dest_inode),
        },
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, pid = note.pid, "shim notify: RenameOutcome journal failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::LiveBaseline;
    use shit_planner::store::PlannerStore;
    use shit_proto::{ShimPreImage, ShimWalk};

    fn fixture() -> (tempfile::TempDir, Index, BlobStore, CommandId) {
        use shit_planner::events::CommandRecord;
        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let blob_store = BlobStore::open(tmp.path().join("blobs")).unwrap();
        let session = uuid::Uuid::nil();
        index
            .put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        let command = CommandId { session, seq: 1 };
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("mv d t".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        (tmp, index, blob_store, command)
    }

    fn entry(path: &str, mode: u32, inode: u64) -> ShimWalkEntry {
        ShimWalkEntry {
            path: path.into(),
            dev: 64,
            inode,
            mode,
            uid: 1000,
            gid: 1000,
            mtime_unix_nanos: 7,
            flags: 0,
            xattrs: Some(vec![("user.k".into(), b"v".to_vec())]),
        }
    }

    fn pre(path: &str, bytes: &[u8], inode: u64) -> ShimPreImage {
        ShimPreImage {
            path: path.into(),
            dev: 64,
            inode,
            mode: 0o100640,
            uid: 1000,
            gid: 1000,
            size: bytes.len() as u64,
            mtime_unix_nanos: 0,
            bytes: bytes.to_vec(),
            xattr: None,
            flags: 0,
        }
    }

    fn note(walk: Option<ShimWalk>, outcome: Option<ShimRenameOutcome>) -> ShimNotification {
        ShimNotification {
            pid: 4242,
            syscall: "rename".into(),
            arg: "/tmp/l5/d\t/tmp/l5/t".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: if outcome.is_some() {
                Vec::new()
            } else {
                vec![pre("/tmp/l5/d/f", b"f", 11)]
            },
            failure: None,
            walk,
            outcome,
            pre_stat: None,
        }
    }

    fn ingest(n: &ShimNotification) -> Vec<CaptureEventKind> {
        let (_tmp, index, blobs, command) = fixture();
        crate::shim_listener::ingest_notification_for_test(
            n,
            Some(command),
            TimePoint::new(5, 0),
            &index,
            &blobs,
            &LiveBaseline::new(),
        );
        index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn complete_walk_journals_pre_images_walk_and_rename_in_order() {
        let walk = ShimWalk {
            complete: true,
            files: 1,
            entries: vec![
                entry("/tmp/l5/d", 0o040700, 10),
                entry("/tmp/l5/d/f", 0o100640, 11),
            ],
        };
        let kinds = ingest(&note(Some(walk), None));
        assert_eq!(kinds.len(), 3, "{kinds:#?}");
        match &kinds[0] {
            CaptureEventKind::FilePreImage { meta, .. } => {
                assert_eq!(
                    meta.xattrs.get("user.k").map(Vec::as_slice),
                    Some(&b"v"[..])
                );
            }
            k => panic!("{k:?}"),
        }
        match &kinds[1] {
            CaptureEventKind::RenameWalk {
                root,
                complete,
                files,
                entries,
            } => {
                assert_eq!(root, &PathBuf::from("/tmp/l5/d"));
                assert!(complete);
                assert_eq!(*files, 1);
                assert_eq!(entries[0].kind, FileKind::Directory);
                assert_eq!(entries[0].meta.mode, 0o040700);
                assert_eq!(entries[1].meta.size, 1);
            }
            k => panic!("{k:?}"),
        }
        assert!(matches!(
            &kinds[2],
            CaptureEventKind::TreeOp(shit_planner::TreeOp::Rename { .. })
        ));
    }

    #[test]
    fn walk_whose_count_does_not_match_is_journaled_incomplete() {
        let walk = ShimWalk {
            complete: true,
            files: 2,
            entries: vec![entry("/tmp/l5/d", 0o040700, 10)],
        };
        let kinds = ingest(&note(Some(walk), None));
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                CaptureEventKind::RenameWalk {
                    complete: false,
                    ..
                }
            )),
            "{kinds:#?}"
        );
    }

    #[test]
    fn outcome_journals_only_a_rename_outcome() {
        let out = ShimRenameOutcome {
            errno: libc::ENOTEMPTY,
            source_dev: 64,
            source_inode: 10,
            dest_dev: 0,
            dest_inode: 0,
        };
        let kinds = ingest(&note(None, Some(out)));
        assert_eq!(kinds.len(), 1, "{kinds:#?}");
        match &kinds[0] {
            CaptureEventKind::RenameOutcome {
                from,
                to,
                errno,
                source,
                dest,
            } => {
                assert_eq!(from, &PathBuf::from("/tmp/l5/d"));
                assert_eq!(to, &PathBuf::from("/tmp/l5/t"));
                assert_eq!(*errno, libc::ENOTEMPTY);
                assert_eq!(*source, InodeRef::new(64, 10));
                assert_eq!(*dest, InodeRef::new(0, 0));
            }
            k => panic!("{k:?}"),
        }
    }
}
