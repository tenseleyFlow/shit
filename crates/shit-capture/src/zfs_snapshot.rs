// SPDX-License-Identifier: AGPL-3.0-or-later

//! B6 - per-command ZFS snapshots as the pre-image source.
//!
//! On BSD the kqueue tier hears about a write after it happened, so a
//! pre-image read at event time can be post-write bytes. When the
//! command's cwd is on a ZFS dataset the user may snapshot (delegated
//! `zfs allow snapshot,destroy,mount`, or root), the daemon takes a
//! snapshot at PreExec, before the command runs, and reads pre-images
//! from it instead. Everywhere else capture keeps the read-time path.
//!
//! Snapshots are named `shitd-<owner>-<session>-<seq>`. `owner` is a
//! random id kept in the daemon's state dir, so a daemon only ever
//! destroys its own snapshots. The daemon keeps a snapshot while its
//! command is in the journal, up to a cap on live snapshots; at start
//! and after every prune it destroys the rest ([`SnapshotManager::reconcile`]).
//! A crash between taking a snapshot and journaling anything leaves a
//! snapshot whose command is not in the journal, which the next start
//! destroys.
//!
//! The `zfs(8)` calls go through [`ZfsOps`] so the policy is tested on
//! every platform. [`SystemZfs`] shells out to `/sbin/zfs`; where that
//! does not exist every call fails and capture stays read-time.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::BlobHash;
use shit_planner::events::CommandId;
use uuid::Uuid;

/// Prefix of every snapshot the daemon takes.
pub const SNAPSHOT_PREFIX: &str = "shitd-";

/// Default cap on live snapshots per daemon.
pub const DEFAULT_SNAPSHOT_CAP: usize = 64;

/// How long a dataset the daemon could not snapshot stays on read-time
/// capture before the daemon tries again (the user may delegate the
/// permission meanwhile).
const DENIED_RETRY: Duration = Duration::from_secs(60);

/// A ZFS dataset and where it is mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub name: String,
    pub mountpoint: PathBuf,
}

/// One snapshot, as `zfs list` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotId {
    pub dataset: String,
    /// The part after `@`.
    pub name: String,
}

/// The `zfs(8)` operations the manager needs.
pub trait ZfsOps {
    /// The mounted dataset that holds `path`, or `None` when `path` is
    /// not on ZFS.
    fn dataset_for(&self, path: &Path) -> Result<Option<Dataset>, String>;
    /// The mountpoint of `dataset`, `None` when it has none.
    fn mountpoint(&self, dataset: &str) -> Result<Option<PathBuf>, String>;
    fn snapshot(&self, id: &SnapshotId) -> Result<(), String>;
    fn destroy(&self, id: &SnapshotId) -> Result<(), String>;
    /// Every snapshot whose name starts with [`SNAPSHOT_PREFIX`], oldest
    /// first.
    fn list(&self) -> Result<Vec<SnapshotId>, String>;
}

/// `zfs(8)` at its base-system path; absent off the BSDs.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemZfs;

const ZFS_BIN: &str = "/sbin/zfs";

fn zfs(args: &[&std::ffi::OsStr]) -> Result<String, String> {
    if !Path::new(ZFS_BIN).exists() {
        return Err(format!("{ZFS_BIN} is not installed"));
    }
    let out = std::process::Command::new(ZFS_BIN)
        .args(args)
        .output()
        .map_err(|e| format!("{ZFS_BIN}: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn mountpoint_value(s: &str) -> Option<PathBuf> {
    let s = s.trim();
    (s.starts_with('/')).then(|| PathBuf::from(s))
}

impl ZfsOps for SystemZfs {
    fn dataset_for(&self, path: &Path) -> Result<Option<Dataset>, String> {
        let out = match zfs(&[
            "list".as_ref(),
            "-H".as_ref(),
            "-o".as_ref(),
            "name,mountpoint,mounted".as_ref(),
            path.as_os_str(),
        ]) {
            Ok(out) => out,
            // `zfs list <path>` fails for a path on another filesystem.
            Err(e) if e.contains("not a ZFS filesystem") => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(line) = out.lines().next() else {
            return Ok(None);
        };
        let mut cols = line.split('\t');
        let (Some(name), Some(mp), Some(mounted)) = (cols.next(), cols.next(), cols.next()) else {
            return Err(format!("unexpected zfs list output: {line:?}"));
        };
        if mounted.trim() != "yes" {
            return Ok(None);
        }
        Ok(mountpoint_value(mp).map(|mountpoint| Dataset {
            name: name.to_string(),
            mountpoint,
        }))
    }

    fn mountpoint(&self, dataset: &str) -> Result<Option<PathBuf>, String> {
        let out = zfs(&[
            "get".as_ref(),
            "-H".as_ref(),
            "-o".as_ref(),
            "value".as_ref(),
            "mountpoint".as_ref(),
            dataset.as_ref(),
        ])?;
        Ok(mountpoint_value(&out))
    }

    fn snapshot(&self, id: &SnapshotId) -> Result<(), String> {
        let full = format!("{}@{}", id.dataset, id.name);
        zfs(&["snapshot".as_ref(), full.as_ref()]).map(|_| ())
    }

    fn destroy(&self, id: &SnapshotId) -> Result<(), String> {
        let full = format!("{}@{}", id.dataset, id.name);
        zfs(&["destroy".as_ref(), full.as_ref()]).map(|_| ())
    }

    fn list(&self) -> Result<Vec<SnapshotId>, String> {
        let out = zfs(&[
            "list".as_ref(),
            "-H".as_ref(),
            "-t".as_ref(),
            "snapshot".as_ref(),
            "-o".as_ref(),
            "name".as_ref(),
            "-s".as_ref(),
            "createtxg".as_ref(),
        ])?;
        Ok(out
            .lines()
            .filter_map(|l| l.trim().split_once('@'))
            .filter(|(_, name)| name.starts_with(SNAPSHOT_PREFIX))
            .map(|(dataset, name)| SnapshotId {
                dataset: dataset.to_string(),
                name: name.to_string(),
            })
            .collect())
    }
}

/// The snapshot name for `command`, owned by `owner`.
pub fn snapshot_name(owner: &str, command: CommandId) -> String {
    format!(
        "{SNAPSHOT_PREFIX}{owner}-{}-{}",
        command.session.simple(),
        command.seq
    )
}

/// Parse a name [`snapshot_name`] made back into its owner and command.
pub fn parse_snapshot_name(name: &str) -> Option<(&str, CommandId)> {
    let rest = name.strip_prefix(SNAPSHOT_PREFIX)?;
    let mut parts = rest.splitn(3, '-');
    let owner = parts.next()?;
    let session = parts.next()?;
    let seq = parts.next()?;
    if !is_owner_id(owner) || session.len() != 32 {
        return None;
    }
    let session = Uuid::try_parse(session).ok()?;
    let seq = seq.parse().ok()?;
    Some((owner, CommandId { session, seq }))
}

fn is_owner_id(s: &str) -> bool {
    s.len() == 8
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Read the owner id kept in `state_dir`, or make one.
pub fn load_owner_id(state_dir: &Path) -> std::io::Result<String> {
    let path = state_dir.join("zfs-snapshot-owner");
    match std::fs::read_to_string(&path) {
        Ok(s) if is_owner_id(s.trim()) => return Ok(s.trim().to_string()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let simple = Uuid::now_v7().simple().to_string();
    let id = simple[simple.len() - 8..].to_string();
    std::fs::write(&path, format!("{id}\n"))?;
    Ok(id)
}

/// A snapshot taken for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken {
    pub id: SnapshotId,
    pub mountpoint: PathBuf,
    /// `st_dev` of files on the dataset.
    pub dev: u64,
}

impl Taken {
    /// Where the snapshot holds the file now at `live`, or `None` when
    /// `live` is not under the dataset's mountpoint.
    pub fn path_in_snapshot(&self, live: &Path) -> Option<PathBuf> {
        let rel = live.strip_prefix(&self.mountpoint).ok()?;
        if rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return None;
        }
        Some(
            self.mountpoint
                .join(".zfs")
                .join("snapshot")
                .join(&self.id.name)
                .join(rel),
        )
    }
}

/// Where a command's pre-images come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreImageSource {
    Snapshot(Taken),
    /// Read at event time, and why.
    ReadTime(String),
}

/// Takes, tracks and releases the daemon's snapshots.
pub struct SnapshotManager<Z: ZfsOps = SystemZfs> {
    zfs: Z,
    owner: String,
    cap: usize,
    /// Datasets the last snapshot attempt failed on, with the reason.
    denied: Mutex<HashMap<String, (Instant, String)>>,
    taken: Mutex<HashMap<CommandId, Taken>>,
}

impl<Z: ZfsOps> SnapshotManager<Z> {
    pub fn new(zfs: Z, owner: String, cap: usize) -> Self {
        Self {
            zfs,
            owner,
            cap: cap.max(1),
            denied: Mutex::new(HashMap::new()),
            taken: Mutex::new(HashMap::new()),
        }
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Snapshot the dataset holding `cwd` for `command`, before it runs.
    /// Also releases the oldest snapshots past the cap.
    pub fn take(&self, command: CommandId, cwd: &Path) -> PreImageSource {
        let dataset = match self.zfs.dataset_for(cwd) {
            Ok(Some(d)) => d,
            Ok(None) => {
                return PreImageSource::ReadTime(format!("{} is not on ZFS", cwd.display()));
            }
            Err(e) => return PreImageSource::ReadTime(format!("zfs list failed: {e}")),
        };
        if let Some((at, why)) = self.denied.lock().unwrap().get(&dataset.name)
            && at.elapsed() < DENIED_RETRY
        {
            return PreImageSource::ReadTime(why.clone());
        }
        let dev = match std::fs::metadata(&dataset.mountpoint) {
            Ok(m) => std::os::unix::fs::MetadataExt::dev(&m),
            Err(e) => {
                return PreImageSource::ReadTime(format!(
                    "cannot stat {}: {e}",
                    dataset.mountpoint.display()
                ));
            }
        };
        let id = SnapshotId {
            dataset: dataset.name.clone(),
            name: snapshot_name(&self.owner, command),
        };
        if let Err(e) = self.zfs.snapshot(&id) {
            let why = format!("cannot snapshot {}: {e}", dataset.name);
            self.denied
                .lock()
                .unwrap()
                .insert(dataset.name, (Instant::now(), why.clone()));
            return PreImageSource::ReadTime(why);
        }
        self.denied.lock().unwrap().remove(&dataset.name);
        let taken = Taken {
            id,
            mountpoint: dataset.mountpoint,
            dev,
        };
        self.taken.lock().unwrap().insert(command, taken.clone());
        self.enforce_cap();
        PreImageSource::Snapshot(taken)
    }

    /// The snapshot taken for `command`, if it is still live. After a
    /// restart the daemon finds it by name.
    pub fn snapshot_for(&self, command: CommandId) -> Option<Taken> {
        if let Some(t) = self.taken.lock().unwrap().get(&command) {
            return Some(t.clone());
        }
        let name = snapshot_name(&self.owner, command);
        let id = self.zfs.list().ok()?.into_iter().find(|s| s.name == name)?;
        let mountpoint = self.zfs.mountpoint(&id.dataset).ok()??;
        let dev = std::os::unix::fs::MetadataExt::dev(&std::fs::metadata(&mountpoint).ok()?);
        let taken = Taken {
            id,
            mountpoint,
            dev,
        };
        self.taken.lock().unwrap().insert(command, taken.clone());
        Some(taken)
    }

    /// This daemon's snapshots, oldest first.
    fn ours(&self) -> Result<Vec<(SnapshotId, CommandId)>, String> {
        Ok(self
            .zfs
            .list()?
            .into_iter()
            .filter_map(|id| {
                let (owner, command) = parse_snapshot_name(&id.name)?;
                (owner == self.owner).then_some((id, command))
            })
            .collect())
    }

    fn release(&self, id: &SnapshotId, command: CommandId) -> bool {
        match self.zfs.destroy(id) {
            Ok(()) => {
                self.taken.lock().unwrap().remove(&command);
                tracing::info!(snapshot = %format!("{}@{}", id.dataset, id.name), "released zfs snapshot");
                true
            }
            Err(e) => {
                tracing::warn!(snapshot = %format!("{}@{}", id.dataset, id.name), err = %e, "zfs snapshot destroy failed");
                false
            }
        }
    }

    /// Destroy the oldest snapshots past the cap.
    fn enforce_cap(&self) -> usize {
        let Ok(ours) = self.ours() else {
            return 0;
        };
        let over = ours.len().saturating_sub(self.cap);
        ours.iter()
            .take(over)
            .filter(|(id, command)| self.release(id, *command))
            .count()
    }

    /// Destroy every snapshot of this daemon whose command `keep` says
    /// is gone, then enforce the cap. Run at daemon start and after a
    /// prune. Returns how many were destroyed.
    pub fn reconcile(&self, keep: impl Fn(CommandId) -> bool) -> Result<usize, String> {
        let ours = self.ours()?;
        let gone = ours
            .iter()
            .filter(|(_, command)| !keep(*command))
            .filter(|(id, command)| self.release(id, *command))
            .count();
        Ok(gone + self.enforce_cap())
    }
}

/// Why a snapshot pre-image could not be used.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotReadError {
    #[error("{0} is not under the snapshot's dataset")]
    OffDataset(PathBuf),
    #[error("{path}: {err}")]
    Io { path: PathBuf, err: std::io::Error },
    #[error("{0} in the snapshot is not a regular file")]
    NotRegular(PathBuf),
    #[error("{path} in the snapshot is inode {found}, not the event's inode {expected}")]
    OtherInode {
        path: PathBuf,
        found: u64,
        expected: u64,
    },
    #[error("{path} in the snapshot hashes to {found}, not {expected}")]
    Hash {
        path: PathBuf,
        found: BlobHash,
        expected: BlobHash,
    },
}

/// A file's state in a snapshot, opened.
#[derive(Debug)]
pub struct SnapshotFile {
    pub path: PathBuf,
    pub file: std::fs::File,
    pub meta: std::fs::Metadata,
}

/// Open the snapshot's copy of the file at `live`. When `inode` is
/// given, the snapshot's file must be that inode: ZFS keeps object
/// numbers in a snapshot, so a different number means `live` names a
/// different file than it did when the snapshot was taken.
pub fn open_in_snapshot(
    taken: &Taken,
    live: &Path,
    inode: Option<u64>,
) -> Result<SnapshotFile, SnapshotReadError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = taken
        .path_in_snapshot(live)
        .ok_or_else(|| SnapshotReadError::OffDataset(live.to_path_buf()))?;
    let io = |err| SnapshotReadError::Io {
        path: path.clone(),
        err,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.file_type().is_file() {
        return Err(SnapshotReadError::NotRegular(path));
    }
    if let Some(expected) = inode
        && meta.ino() != expected
    {
        return Err(SnapshotReadError::OtherInode {
            path,
            found: meta.ino(),
            expected,
        });
    }
    Ok(SnapshotFile { path, file, meta })
}

/// blake3 of everything `r` yields, and its length.
pub fn hash_stream(mut r: impl Read) -> std::io::Result<(BlobHash, u64)> {
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut len = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        len += n as u64;
    }
    Ok((BlobHash::from_bytes(*h.finalize().as_bytes()), len))
}

/// Copy the snapshot's copy of `live` to `out`, checking that it still
/// hashes to `expected` (undo's read of a pre-image kept only in the
/// snapshot). Bytes reach `out` before the check completes; the caller
/// discards `out` on error.
pub fn copy_checked(
    taken: &Taken,
    live: &Path,
    expected: BlobHash,
    out: &mut dyn std::io::Write,
) -> Result<(), SnapshotReadError> {
    let f = open_in_snapshot(taken, live, None)?;
    let path = f.path.clone();
    let io = |err| SnapshotReadError::Io {
        path: path.clone(),
        err,
    };
    let mut reader = std::io::BufReader::with_capacity(256 * 1024, f.file);
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(e)),
        };
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(io)?;
    }
    let found = BlobHash::from_bytes(*h.finalize().as_bytes());
    if found != expected {
        return Err(SnapshotReadError::Hash {
            path,
            found,
            expected,
        });
    }
    Ok(())
}

/// Doctor's view: would a command in `cwd` get snapshot pre-images?
/// Takes and destroys a probe snapshot, since `zfs allow` output does
/// not show group or root rights in one place.
pub fn probe_source(zfs: &impl ZfsOps, cwd: &Path) -> PreImageSource {
    let dataset = match zfs.dataset_for(cwd) {
        Ok(Some(d)) => d,
        Ok(None) => return PreImageSource::ReadTime(format!("{} is not on ZFS", cwd.display())),
        Err(e) => return PreImageSource::ReadTime(format!("zfs list failed: {e}")),
    };
    let id = SnapshotId {
        dataset: dataset.name.clone(),
        name: format!("{SNAPSHOT_PREFIX}doctor-{}", std::process::id()),
    };
    if let Err(e) = zfs.snapshot(&id) {
        return PreImageSource::ReadTime(format!(
            "cannot snapshot {}: {e} (delegate with `zfs allow -u <user> snapshot,destroy,mount {}`)",
            dataset.name, dataset.name
        ));
    }
    if let Err(e) = zfs.destroy(&id) {
        return PreImageSource::ReadTime(format!(
            "can snapshot {} but not destroy the snapshot: {e}",
            dataset.name
        ));
    }
    let dev = std::fs::metadata(&dataset.mountpoint)
        .map(|m| std::os::unix::fs::MetadataExt::dev(&m))
        .unwrap_or(0);
    PreImageSource::Snapshot(Taken {
        id: SnapshotId {
            dataset: dataset.name,
            name: String::new(),
        },
        mountpoint: dataset.mountpoint,
        dev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory `zfs`: one dataset mounted at `root`, snapshots kept
    /// in creation order. `deny` makes `snapshot` fail.
    struct FakeZfs {
        root: PathBuf,
        snaps: Mutex<Vec<SnapshotId>>,
        deny: bool,
    }

    impl FakeZfs {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(),
                snaps: Mutex::new(Vec::new()),
                deny: false,
            }
        }
        fn names(&self) -> Vec<String> {
            self.snaps
                .lock()
                .unwrap()
                .iter()
                .map(|s| s.name.clone())
                .collect()
        }
    }

    impl ZfsOps for FakeZfs {
        fn dataset_for(&self, path: &Path) -> Result<Option<Dataset>, String> {
            Ok(path.starts_with(&self.root).then(|| Dataset {
                name: "pool/w".into(),
                mountpoint: self.root.clone(),
            }))
        }
        fn mountpoint(&self, _: &str) -> Result<Option<PathBuf>, String> {
            Ok(Some(self.root.clone()))
        }
        fn snapshot(&self, id: &SnapshotId) -> Result<(), String> {
            if self.deny {
                return Err("permission denied".into());
            }
            self.snaps.lock().unwrap().push(id.clone());
            Ok(())
        }
        fn destroy(&self, id: &SnapshotId) -> Result<(), String> {
            let mut s = self.snaps.lock().unwrap();
            let before = s.len();
            s.retain(|x| x != id);
            if s.len() == before {
                return Err("no such snapshot".into());
            }
            Ok(())
        }
        fn list(&self) -> Result<Vec<SnapshotId>, String> {
            Ok(self.snaps.lock().unwrap().clone())
        }
    }

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::from_u128(0xabcdef),
            seq,
        }
    }

    #[test]
    fn names_round_trip_and_reject_foreign_names() {
        let name = snapshot_name("0a1b2c3d", cmd(7));
        assert_eq!(name, "shitd-0a1b2c3d-00000000000000000000000000abcdef-7");
        assert_eq!(parse_snapshot_name(&name), Some(("0a1b2c3d", cmd(7))));
        for foreign in [
            "shit-01970000-00000042",
            "shitd-doctor-1234",
            "shitd-0A1B2C3D-00000000000000000000000000abcdef-7",
            "shitd-0a1b2c3d-abcdef-7",
            "shitd-0a1b2c3d-00000000000000000000000000abcdef-x",
        ] {
            assert_eq!(parse_snapshot_name(foreign), None, "{foreign}");
        }
    }

    #[test]
    fn owner_id_persists_in_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_owner_id(dir.path()).unwrap();
        assert!(is_owner_id(&a), "{a}");
        assert_eq!(load_owner_id(dir.path()).unwrap(), a);
    }

    #[test]
    fn take_snapshots_a_zfs_cwd_and_maps_paths_into_it() {
        let dir = tempfile::tempdir().unwrap();
        let m = SnapshotManager::new(FakeZfs::new(dir.path()), "0a1b2c3d".into(), 8);
        let PreImageSource::Snapshot(t) = m.take(cmd(1), dir.path()) else {
            panic!("expected a snapshot");
        };
        assert_eq!(m.zfs.names(), vec![snapshot_name("0a1b2c3d", cmd(1))]);
        assert_eq!(
            t.path_in_snapshot(&dir.path().join("a/b")),
            Some(
                dir.path()
                    .join(".zfs/snapshot")
                    .join(&t.id.name)
                    .join("a/b")
            )
        );
        assert_eq!(t.path_in_snapshot(Path::new("/elsewhere/f")), None);
        assert_eq!(t.path_in_snapshot(&dir.path().join("a/../../x")), None);
        assert_eq!(m.snapshot_for(cmd(1)), Some(t));
    }

    #[test]
    fn off_zfs_and_denied_datasets_stay_read_time() {
        let dir = tempfile::tempdir().unwrap();
        let m = SnapshotManager::new(FakeZfs::new(dir.path()), "0a1b2c3d".into(), 8);
        assert!(matches!(
            m.take(cmd(1), Path::new("/not/zfs")),
            PreImageSource::ReadTime(why) if why.contains("not on ZFS")
        ));
        let mut z = FakeZfs::new(dir.path());
        z.deny = true;
        let m = SnapshotManager::new(z, "0a1b2c3d".into(), 8);
        assert!(matches!(
            m.take(cmd(1), dir.path()),
            PreImageSource::ReadTime(why) if why.contains("permission denied")
        ));
        assert!(m.snapshot_for(cmd(1)).is_none());
    }

    #[test]
    fn the_cap_releases_the_oldest_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let m = SnapshotManager::new(FakeZfs::new(dir.path()), "0a1b2c3d".into(), 2);
        for seq in 1..=4 {
            assert!(matches!(
                m.take(cmd(seq), dir.path()),
                PreImageSource::Snapshot(_)
            ));
        }
        assert_eq!(
            m.zfs.names(),
            vec![
                snapshot_name("0a1b2c3d", cmd(3)),
                snapshot_name("0a1b2c3d", cmd(4))
            ]
        );
        assert!(m.taken.lock().unwrap().get(&cmd(1)).is_none());
    }

    #[test]
    fn reconcile_releases_pruned_commands_and_leaves_other_owners_alone() {
        let dir = tempfile::tempdir().unwrap();
        let z = FakeZfs::new(dir.path());
        let other = SnapshotId {
            dataset: "pool/w".into(),
            name: snapshot_name("99999999", cmd(1)),
        };
        let foreign = SnapshotId {
            dataset: "pool/w".into(),
            name: "shitd-doctor-1".into(),
        };
        z.snaps.lock().unwrap().push(other.clone());
        z.snaps.lock().unwrap().push(foreign.clone());
        let m = SnapshotManager::new(z, "0a1b2c3d".into(), 8);
        for seq in 1..=3 {
            m.take(cmd(seq), dir.path());
        }
        // A crash after the snapshot of seq 3, before it was journaled,
        // and a prune of seq 1: only seq 2 is in the journal.
        assert_eq!(m.reconcile(|c| c == cmd(2)), Ok(2));
        assert_eq!(
            m.zfs.names(),
            vec![other.name, foreign.name, snapshot_name("0a1b2c3d", cmd(2))]
        );
    }

    #[test]
    fn snapshot_reads_check_inode_and_hash() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let taken = Taken {
            id: SnapshotId {
                dataset: "pool/w".into(),
                name: "s".into(),
            },
            mountpoint: dir.path().to_path_buf(),
            dev: 0,
        };
        // Stand in for the snapshot directory ZFS would provide.
        let snap_dir = dir.path().join(".zfs/snapshot/s");
        std::fs::create_dir_all(&snap_dir).unwrap();
        std::fs::write(snap_dir.join("f"), b"before").unwrap();
        let ino = std::fs::metadata(snap_dir.join("f")).unwrap().ino();
        let live = dir.path().join("f");

        let f = open_in_snapshot(&taken, &live, Some(ino)).unwrap();
        let (hash, len) = hash_stream(f.file).unwrap();
        assert_eq!(len, 6);
        assert_eq!(
            hash,
            BlobHash::from_bytes(*blake3::hash(b"before").as_bytes())
        );
        assert!(matches!(
            open_in_snapshot(&taken, &live, Some(ino + 1)),
            Err(SnapshotReadError::OtherInode { .. })
        ));
        assert!(matches!(
            open_in_snapshot(&taken, &dir.path().join("missing"), None),
            Err(SnapshotReadError::Io { .. })
        ));

        let mut out = Vec::new();
        copy_checked(&taken, &live, hash, &mut out).unwrap();
        assert_eq!(out, b"before");
        let wrong = BlobHash::from_bytes([0; 32]);
        assert!(matches!(
            copy_checked(&taken, &live, wrong, &mut Vec::new()),
            Err(SnapshotReadError::Hash { .. })
        ));
    }

    #[test]
    fn probe_reports_the_dataset_or_why_not() {
        let dir = tempfile::tempdir().unwrap();
        let z = FakeZfs::new(dir.path());
        assert!(matches!(
            probe_source(&z, dir.path()),
            PreImageSource::Snapshot(t) if t.id.dataset == "pool/w"
        ));
        assert!(z.names().is_empty(), "probe snapshot left behind");
        let mut z = FakeZfs::new(dir.path());
        z.deny = true;
        assert!(matches!(
            probe_source(&z, dir.path()),
            PreImageSource::ReadTime(why) if why.contains("zfs allow")
        ));
    }
}
