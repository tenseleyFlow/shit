// SPDX-License-Identifier: AGPL-3.0-or-later

//! B6 - the daemon's side of ZFS snapshot pre-images.
//!
//! At PreExec the daemon snapshots the dataset holding the command's cwd
//! (when the user may) and hands the snapshot to the helper with the
//! `WatchTree`. The BSD helper answers a write or delete of a file the
//! snapshot holds with `SnapshotPreImage`, and [`journal_pre_image`]
//! reads the pre-image from the snapshot. Files up to
//! [`COPY_INTO_STORE_MAX`] are also copied into the blob store, so their
//! undo survives the snapshot's release; larger ones stay only in the
//! snapshot, and undo reads them back from it ([`SnapshotBlobs`]).
//!
//! The snapshot policy lives in [`shit_capture::zfs_snapshot`]. The
//! manager is process-wide: it is set up once at start, where it also
//! releases the snapshots of commands no longer in the journal.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use shit_capture::zfs_snapshot::{
    DEFAULT_SNAPSHOT_CAP, PreImageSource, SnapshotManager, SystemZfs, Taken, copy_checked,
    hash_stream, open_in_snapshot,
};
use shit_planner::events::{CaptureEvent, CaptureEventKind, CommandId, EventId};
use shit_planner::metadata::FileMetadata;
use shit_planner::{BlobHash, FilePreImageSource, InodeRef};
use shit_store::{BlobStore, Index};

/// Pre-images up to this size are copied into the blob store as well.
pub const COPY_INTO_STORE_MAX: u64 = 8 * 1024 * 1024;

static MANAGER: OnceLock<SnapshotManager> = OnceLock::new();

/// Whether this build takes snapshots at all: only the BSD helper reads
/// them.
const SUPPORTED: bool = cfg!(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
));

/// Set up the manager and release snapshots whose command is gone (a
/// prune, or a crash before the command was journaled). Off with
/// `SHIT_ZFS_SNAPSHOTS=0`; `SHIT_ZFS_SNAPSHOT_CAP` overrides the cap.
pub fn init(state_dir: &Path, index: &Index) {
    if !SUPPORTED || std::env::var("SHIT_ZFS_SNAPSHOTS").as_deref() == Ok("0") {
        return;
    }
    if !Path::new("/sbin/zfs").exists() {
        return;
    }
    let owner = match shit_capture::zfs_snapshot::load_owner_id(state_dir) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(err = %e, "zfs snapshot owner id unavailable; pre-images stay read-time");
            return;
        }
    };
    let cap = std::env::var("SHIT_ZFS_SNAPSHOT_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SNAPSHOT_CAP);
    let m = MANAGER.get_or_init(|| SnapshotManager::new(SystemZfs, owner, cap));
    reconcile_with(m, index);
}

fn manager() -> Option<&'static SnapshotManager> {
    MANAGER.get()
}

fn reconcile_with<Z: shit_capture::zfs_snapshot::ZfsOps>(m: &SnapshotManager<Z>, index: &Index) {
    use shit_planner::PlannerStore;
    match m.reconcile(|c| index.command_by_id(c).is_some()) {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            released = n,
            "released zfs snapshots of commands no longer journaled"
        ),
        Err(e) => tracing::warn!(err = %e, "zfs snapshot reconcile failed"),
    }
}

/// After a prune: release the snapshots of dropped commands.
pub fn after_prune(index: &Index) {
    if let Some(m) = manager() {
        reconcile_with(m, index);
    }
}

/// Snapshot the cwd's dataset for `command`, before it runs. `None`
/// keeps the command on read-time pre-images; the reason is logged.
pub fn take(command: CommandId, cwd: &Path) -> Option<shit_proto::ZfsSnapshotRef> {
    let m = manager()?;
    match m.take(command, cwd) {
        PreImageSource::Snapshot(t) => {
            tracing::info!(
                %command,
                snapshot = %format!("{}@{}", t.id.dataset, t.id.name),
                "pre-image source: zfs snapshot"
            );
            Some(shit_proto::ZfsSnapshotRef {
                dataset: t.id.dataset,
                name: t.id.name,
                mountpoint: shit_proto::wire_path::encode(&t.mountpoint),
                dev: t.dev,
            })
        }
        PreImageSource::ReadTime(why) => {
            tracing::debug!(%command, %why, "pre-image source: read-time");
            None
        }
    }
}

/// Arguments of a `SnapshotPreImage`.
pub struct SnapshotPreImage {
    pub command: CommandId,
    pub dev: u64,
    pub inode: u64,
    pub path: PathBuf,
    pub post_content_hash: Option<[u8; 32]>,
    pub xattrs: std::collections::BTreeMap<String, Vec<u8>>,
}

/// Journal the pre-image of `ev` from the command's snapshot and return
/// the file's mode there. `Err` is the reason it could not, for the
/// caller to journal as a gap.
pub fn journal_pre_image(
    ev: &SnapshotPreImage,
    index: &Index,
    blob_store: &BlobStore,
) -> Result<u32, String> {
    let taken = manager()
        .and_then(|m| m.snapshot_for(ev.command))
        .ok_or_else(|| format!("the snapshot for {} is gone", ev.command))?;
    journal_from(&taken, ev, index, blob_store)
}

fn journal_from(
    taken: &Taken,
    ev: &SnapshotPreImage,
    index: &Index,
    blob_store: &BlobStore,
) -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;
    let f = open_in_snapshot(taken, &ev.path, Some(ev.inode)).map_err(|e| e.to_string())?;
    let meta = f.meta.clone();
    let ts = crate::server::next_ts();
    let blob = if meta.len() <= COPY_INTO_STORE_MAX {
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        std::io::Read::read_to_end(&mut &f.file, &mut bytes)
            .map_err(|e| format!("{}: {e}", f.path.display()))?;
        let (hash, stat) = blob_store
            .put(&bytes)
            .map_err(|e| format!("blob put: {e}"))?;
        index
            .put_blob_record(hash, stat.stored_bytes, stat.compressed, ts)
            .map_err(|e| format!("put_blob_record: {e}"))?;
        hash
    } else {
        // Kept only in the snapshot: the record carries the size so the
        // planner sees the blob, and undo reads the bytes back.
        let (hash, len) = hash_stream(std::io::BufReader::new(&f.file))
            .map_err(|e| format!("{}: {e}", f.path.display()))?;
        index
            .put_blob_record(hash, len, false, ts)
            .map_err(|e| format!("put_blob_record: {e}"))?;
        hash
    };
    let mtime = i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec());
    let inode = InodeRef::new(ev.dev, ev.inode);
    let pre = CaptureEvent {
        id: EventId(0),
        command: ev.command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode,
            path: ev.path.clone(),
            blob,
            meta: FileMetadata {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                size: meta.len(),
                mtime_unix_nanos: mtime,
                xattrs: ev.xattrs.clone(),
                acl: None,
                flags: file_flags(&meta),
            },
            post_content_hash: ev.post_content_hash.map(BlobHash),
            source: FilePreImageSource::ZfsSnapshot,
        },
    };
    index
        .put_event(&pre)
        .map_err(|e| format!("put_event: {e}"))?;
    tracing::info!(
        command = %ev.command,
        path = %ev.path.display(),
        bytes = meta.len(),
        copied = meta.len() <= COPY_INTO_STORE_MAX,
        "pre-image from zfs snapshot"
    );
    Ok(meta.mode())
}

/// `st_flags` of the snapshot's file (chflags), 0 where there is none.
fn file_flags(meta: &std::fs::Metadata) -> u32 {
    #[cfg(target_os = "freebsd")]
    {
        std::os::freebsd::fs::MetadataExt::st_flags(meta)
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = meta;
        0
    }
}

/// Undo's view of pre-images kept only in a snapshot: blob hash to the
/// command and path whose snapshot holds the bytes.
#[derive(Default)]
pub struct SnapshotBlobs {
    by_hash: Mutex<HashMap<BlobHash, (CommandId, PathBuf)>>,
}

impl SnapshotBlobs {
    /// Remember the snapshot pre-images among `events`.
    pub fn note_events(&self, events: &[CaptureEvent]) {
        let mut map = self.by_hash.lock().unwrap();
        for ev in events {
            if let CaptureEventKind::FilePreImage {
                path,
                blob,
                source: FilePreImageSource::ZfsSnapshot,
                ..
            } = &ev.kind
            {
                map.insert(*blob, (ev.command, path.clone()));
            }
        }
    }

    /// Stream `hash` out of the snapshot that holds it.
    pub fn copy_to(
        &self,
        hash: &BlobHash,
        out: &mut dyn std::io::Write,
    ) -> Result<(), shit_planner::BlobReadError> {
        let not_found = |why: String| shit_planner::BlobReadError::NotFound(why);
        let (command, path) = self
            .by_hash
            .lock()
            .unwrap()
            .get(hash)
            .cloned()
            .ok_or_else(|| not_found(format!("{hash:?}")))?;
        let taken = manager()
            .and_then(|m| m.snapshot_for(command))
            .ok_or_else(|| {
                not_found(format!(
                    "{hash:?}: the zfs snapshot that held {} was released",
                    path.display()
                ))
            })?;
        copy_checked(&taken, &path, *hash, out).map_err(|e| not_found(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_capture::zfs_snapshot::SnapshotId;
    use shit_planner::time::TimePoint;

    fn setup(dir: &Path) -> (Index, BlobStore, Taken, CommandId) {
        let index = Index::open(dir.join("db.sqlite")).unwrap();
        let blobs = BlobStore::open(dir.join("blobs")).unwrap();
        let command = CommandId {
            session: uuid::Uuid::nil(),
            seq: 1,
        };
        index
            .put_session(command.session, "bash", 1, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&shit_planner::events::CommandRecord {
                command,
                cmd_string: None,
                cwd: dir.to_path_buf(),
                pid: 1,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        let taken = Taken {
            id: SnapshotId {
                dataset: "pool/w".into(),
                name: "s".into(),
            },
            mountpoint: dir.join("w"),
            dev: 7,
        };
        std::fs::create_dir_all(dir.join("w/.zfs/snapshot/s")).unwrap();
        (index, blobs, taken, command)
    }

    fn pre_images(index: &Index, command: CommandId) -> Vec<(BlobHash, u32, FilePreImageSource)> {
        use shit_planner::PlannerStore;
        index
            .events_for_command(command)
            .into_iter()
            .filter_map(|e| match e.kind {
                CaptureEventKind::FilePreImage {
                    blob, meta, source, ..
                } => Some((blob, meta.mode, source)),
                _ => None,
            })
            .collect()
    }

    /// The pre-image is the snapshot's bytes and mode, not the live
    /// file's, and is journaled with its source.
    #[test]
    fn small_pre_image_comes_from_the_snapshot_and_is_stored() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let (index, blobs, taken, command) = setup(dir.path());
        let snap_file = dir.path().join("w/.zfs/snapshot/s/f");
        std::fs::write(&snap_file, b"before").unwrap();
        std::fs::set_permissions(&snap_file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let ino = std::fs::metadata(&snap_file).unwrap().ino();
        let ev = SnapshotPreImage {
            command,
            dev: 7,
            inode: ino,
            path: dir.path().join("w/f"),
            post_content_hash: Some([9; 32]),
            xattrs: Default::default(),
        };
        journal_from(&taken, &ev, &index, &blobs).unwrap();
        let got = pre_images(&index, command);
        let want = BlobHash::from_bytes(*blake3::hash(b"before").as_bytes());
        assert_eq!(got, vec![(want, 0o100640, FilePreImageSource::ZfsSnapshot)]);
        assert_eq!(blobs.get(want).unwrap(), b"before");

        // A name that now points at another inode is not this file's
        // pre-image.
        let other = SnapshotPreImage {
            inode: ino + 1,
            ..ev
        };
        let err = journal_from(&taken, &other, &index, &blobs).unwrap_err();
        assert!(err.contains("not the event's inode"), "{err}");
    }

    /// A pre-image past the copy limit stays in the snapshot; undo
    /// streams it back from there and checks its hash.
    #[test]
    fn large_pre_image_stays_in_the_snapshot_for_undo() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let (index, blobs, taken, command) = setup(dir.path());
        let snap_file = dir.path().join("w/.zfs/snapshot/s/big");
        let f = std::fs::File::create(&snap_file).unwrap();
        f.set_len(COPY_INTO_STORE_MAX + 1).unwrap();
        let ino = std::fs::metadata(&snap_file).unwrap().ino();
        let ev = SnapshotPreImage {
            command,
            dev: 7,
            inode: ino,
            path: dir.path().join("w/big"),
            post_content_hash: None,
            xattrs: Default::default(),
        };
        journal_from(&taken, &ev, &index, &blobs).unwrap();
        let got = pre_images(&index, command);
        assert_eq!(got.len(), 1);
        let hash = got[0].0;
        assert!(
            blobs.get(hash).is_err(),
            "large pre-image copied into the store"
        );
        use shit_planner::PlannerStore;
        assert_eq!(index.blob_size_hint(hash), Some(COPY_INTO_STORE_MAX + 1));

        let mut out = Vec::new();
        copy_checked(&taken, &ev.path, hash, &mut out).unwrap();
        assert_eq!(out.len() as u64, COPY_INTO_STORE_MAX + 1);
        let sb = SnapshotBlobs::default();
        sb.note_events(&index.events_for_command(command));
        assert!(sb.by_hash.lock().unwrap().contains_key(&hash));
    }
}
