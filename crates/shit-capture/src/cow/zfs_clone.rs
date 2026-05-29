// SPDX-License-Identifier: AGPL-3.0-or-later

//! ZFS clone capture tier.
//!
//! Moved here from `crates/shit-helper/src/zfs.rs` at AU01.A. The
//! helper had no in-crate callers; the engine consumes it, so it now
//! lives next to the other COW tiers.
//!
//! ## What this tier does
//!
//! 1. Resolve the source path to its containing ZFS dataset.
//! 2. Snapshot the dataset (`zfs snapshot dataset@<id>`).
//! 3. Clone the snapshot to a hidden target
//!    (`<pool>/.shit-clones/<id>`) with an explicit
//!    `-o mountpoint=/tmp/.shit-clones/<id>` so the bytes are
//!    readable without futzing with `mountpoint=none` parents.
//! 4. Read the pre-image bytes from the clone path, hash, and put
//!    into the blob store.
//! 5. Tear down clone + snapshot in dependency order.
//!
//! Any failure in steps 1–3 returns [`CowError::TierUnsupported`]
//! so the engine falls through to the next tier in the FS matrix.
//! Hash mismatch is fatal — the source mutated between snapshot
//! creation and our read of the clone, which violates the snapshot
//! contract and must surface loudly.
//!
//! ## Why per-event clones, not per-command dataset snapshots
//!
//! S24.E spec'd per-command dataset rollback as the BSD coverage
//! story. That's still the right *bulk* primitive — see
//! [`snapshot_create`] / [`snapshot_rollback`]. AU01 adds per-event
//! granularity so the COW engine can capture single-file pre-images
//! without snapshotting the whole dataset on every syscall.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use shit_planner::BlobHash;
use shit_store::BlobStore;

use crate::bsd_probe::{ZfsProbe, dataset_for_path, probe_zfs};

use super::error::CowError;
use super::{CaptureOutcome, CowTier};

/// Path the BSD base system installs `zfs(8)` at. We shell out to
/// the absolute path so PATH manipulation can't redirect us
/// mid-undo.
const ZFS_BIN: &str = "/sbin/zfs";

/// Where clones get mounted. `/tmp` is world-writable on every BSD
/// host; the dot-prefix matches the existing tooling convention so
/// `zfs list` default output stays readable.
const CLONE_MNT_ROOT: &str = "/tmp/.shit-clones";

// ---------------------------------------------------------------
// Stage-1 primitives (moved from shit-helper/zfs.rs unchanged).
// ---------------------------------------------------------------

/// Build a deterministic snapshot name from a session UUID and a
/// command sequence number. Same shape as `shit-<session>-<seq>`
/// per the sprint plan.
pub fn snapshot_name(session_uuid: &str, command_seq: u64) -> String {
    let short = session_uuid.split('-').next().unwrap_or(session_uuid);
    format!("shit-{short}-{command_seq:08}")
}

/// Resolve a path to the dataset it lives on. Returns None on
/// non-ZFS paths or when `zfs` isn't on PATH.
pub fn resolve_dataset(path: &Path) -> Option<String> {
    dataset_for_path(path)
}

/// Re-probe ZFS — the daemon may want to refresh after a tier
/// flip (pool import/export between commands, etc.).
pub fn refresh() -> ZfsProbe {
    probe_zfs()
}

/// Errors from the `zfs(8)` shell-outs.
#[derive(Debug, thiserror::Error)]
pub enum ZfsError {
    #[error("zfs(8) not on PATH and not at /sbin/zfs")]
    NotInstalled,
    #[error("zfs invocation failed: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("zfs exited with status {status}: {stderr}")]
    NonZero { status: i32, stderr: String },
}

fn zfs_exec(args: &[&str]) -> Result<std::process::Output, ZfsError> {
    if !std::path::Path::new(ZFS_BIN).exists() {
        return Err(ZfsError::NotInstalled);
    }
    let out = std::process::Command::new(ZFS_BIN).args(args).output()?;
    if !out.status.success() {
        return Err(ZfsError::NonZero {
            status: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(out)
}

/// Create a snapshot of `dataset` named `name`.
pub fn snapshot_create(dataset: &str, name: &str) -> Result<(), ZfsError> {
    let snap = format!("{dataset}@{name}");
    zfs_exec(&["snapshot", &snap]).map(|_| ())
}

/// List `shit-` snapshots under `dataset`.
pub fn snapshot_list(dataset: &str) -> Result<Vec<String>, ZfsError> {
    let out = zfs_exec(&["list", "-t", "snapshot", "-H", "-o", "name", "-r", dataset])?;
    let names = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.split_once('@')
                .and_then(|(_ds, snap)| snap.starts_with("shit-").then_some(line.to_string()))
        })
        .collect();
    Ok(names)
}

/// Roll the dataset back to `snap`.
pub fn snapshot_rollback(snap: &str) -> Result<(), ZfsError> {
    zfs_exec(&["rollback", "-r", snap]).map(|_| ())
}

/// Clone a snapshot into `target` with no mountpoint override —
/// the clone inherits its parent's mountpoint property. Use
/// [`clone_create_with_mountpoint`] when the parent is
/// `mountpoint=none`.
pub fn clone_create(snap: &str, target: &str) -> Result<(), ZfsError> {
    zfs_exec(&["clone", snap, target]).map(|_| ())
}

/// Clone a snapshot into `target` with an explicit mountpoint. The
/// AU01.A wire uses this form unconditionally so capture works
/// against pool-root datasets where the parent dataset carries
/// `mountpoint=none` (CI's `zroot` does).
pub fn clone_create_with_mountpoint(
    snap: &str,
    target: &str,
    mountpoint: &Path,
) -> Result<(), ZfsError> {
    let mp = format!("mountpoint={}", mountpoint.display());
    zfs_exec(&["clone", "-o", &mp, snap, target]).map(|_| ())
}

/// Destroy a clone (or any dataset). `-r` recursively destroys
/// child snapshots; `-f` forces unmount.
pub fn clone_destroy(dataset: &str) -> Result<(), ZfsError> {
    zfs_exec(&["destroy", "-rf", dataset]).map(|_| ())
}

/// Destroy a single snapshot. `-d` defers if dependents exist.
pub fn snapshot_destroy(snap: &str) -> Result<(), ZfsError> {
    zfs_exec(&["destroy", "-d", snap]).map(|_| ())
}

/// Return the dataset's mountpoint property. `Some(None)` means
/// the property is set to `none` or `legacy` — caller should
/// surface as TierUnsupported.
pub fn dataset_mountpoint(dataset: &str) -> Result<Option<PathBuf>, ZfsError> {
    let out = zfs_exec(&["get", "-H", "-o", "value", "mountpoint", dataset])?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "-" || s == "none" || s == "legacy" {
        Ok(None)
    } else {
        Ok(Some(PathBuf::from(s)))
    }
}

/// Map a file path on the source dataset to its path inside a
/// clone's mountpoint. Returns `None` if the path doesn't live
/// under the source mountpoint.
pub fn clone_pre_image_path(
    file_path: &Path,
    source_mountpoint: &Path,
    clone_mountpoint: &Path,
) -> Option<std::path::PathBuf> {
    let rel = file_path.strip_prefix(source_mountpoint).ok()?;
    Some(clone_mountpoint.join(rel))
}

/// Compute the clone target dataset name for an event. Convention:
/// `<parent-of-source>/.shit-clones-<short-id>` — a sibling of the
/// source dataset, not a child of a `.shit-clones/` parent dataset
/// (which wouldn't exist on stock `zroot`).
///
/// `source_dataset` — the dataset the source file lives on
/// (e.g. `zroot/tmp`). The clone lands at
/// `zroot/.shit-clones-<id>`. Pool-root sources (`zroot`) clone to
/// `zroot/.shit-clones-<id>` (same pool, no slash to strip).
pub fn clone_dataset_name(source_dataset: &str, event_id: &str) -> String {
    let parent = source_dataset
        .rsplit_once('/')
        .map(|(p, _)| p)
        .unwrap_or(source_dataset);
    let short = event_id.split('-').next().unwrap_or(event_id);
    let short = &short[..short.len().min(8)];
    format!("{parent}/.shit-clones-{short}")
}

// ---------------------------------------------------------------
// AU01.A capture wire.
// ---------------------------------------------------------------

/// Capture the file behind `src_fd` via the ZFS clone tier.
///
/// `src_fd` is informational here — the bytes come from the cloned
/// snapshot, not the live fd. The fd is held only to keep the
/// inode pinned across the snapshot call so the caller's idea of
/// "this file" can't disappear mid-capture.
///
/// Returns [`CowError::TierUnsupported`] for any host-state
/// problem (no zfs, non-ZFS path, `mountpoint=none` source, clone
/// failed). Engine falls through to the next tier in those cases.
/// Returns [`CowError::HashMismatch`] only when the blob store's
/// re-hash of the bytes we read disagrees with our streaming
/// hash — i.e. memory corruption mid-capture, which must hard-fail.
pub fn capture_zfs_clone(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    // src_fd is unused after this point — the clone provides the
    // bytes. Drop the binding explicitly so future refactors don't
    // assume it's load-bearing.
    let _ = src_fd;

    let Some(dataset) = resolve_dataset(src_path) else {
        return Err(CowError::TierUnsupported {
            tier: "zfs-clone",
            detail: format!("path {src_path:?} not on a ZFS dataset"),
        });
    };

    let src_mp = match dataset_mountpoint(&dataset) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(CowError::TierUnsupported {
                tier: "zfs-clone",
                detail: format!("dataset {dataset} has mountpoint=none|legacy"),
            });
        }
        Err(e) => {
            return Err(CowError::TierUnsupported {
                tier: "zfs-clone",
                detail: format!("zfs get mountpoint failed: {e}"),
            });
        }
    };

    let id = fresh_clone_id();
    let snap_name = snapshot_name(&id, 0);
    let snap = format!("{dataset}@{snap_name}");
    let clone_ds = clone_dataset_name(&dataset, &id);
    let clone_mp = PathBuf::from(format!("{CLONE_MNT_ROOT}/{id}"));

    if let Err(e) = snapshot_create(&dataset, &snap_name) {
        return Err(CowError::TierUnsupported {
            tier: "zfs-clone",
            detail: format!("snapshot {snap} failed: {e}"),
        });
    }

    if let Err(e) = clone_create_with_mountpoint(&snap, &clone_ds, &clone_mp) {
        let _ = snapshot_destroy(&snap);
        return Err(CowError::TierUnsupported {
            tier: "zfs-clone",
            detail: format!("clone {clone_ds} failed: {e}"),
        });
    }

    let Some(clone_file) = clone_pre_image_path(src_path, &src_mp, &clone_mp) else {
        let _ = clone_destroy(&clone_ds);
        let _ = snapshot_destroy(&snap);
        return Err(CowError::TierUnsupported {
            tier: "zfs-clone",
            detail: format!("path {src_path:?} doesn't live under dataset mountpoint {src_mp:?}",),
        });
    };

    let result = read_and_store(&clone_file, blob_root);

    // Best-effort teardown. Cleanup errors are logged but do not
    // mask the capture result — leaked clones surface on the next
    // smoke run.
    if let Err(e) = clone_destroy(&clone_ds) {
        tracing::warn!(clone = %clone_ds, err = %e, "zfs clone destroy failed");
    }
    if let Err(e) = snapshot_destroy(&snap) {
        tracing::warn!(snap = %snap, err = %e, "zfs snapshot destroy failed");
    }

    result
}

fn read_and_store(path: &Path, blob_root: &Path) -> Result<CaptureOutcome, CowError> {
    let store = BlobStore::open(blob_root)?;
    let bytes = std::fs::read(path)?;
    let streaming_hash = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
    let (stored_hash, stat) = store.put(&bytes)?;
    if stored_hash != streaming_hash {
        return Err(CowError::HashMismatch {
            expected: streaming_hash,
            actual: stored_hash,
        });
    }
    Ok(CaptureOutcome {
        hash: stored_hash,
        tier: CowTier::ZfsClone,
        stored_bytes: stat.stored_bytes,
    })
}

fn fresh_clone_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = nix::unistd::getpid().as_raw() as u64;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // 16 hex chars is wide enough for collision-free run within a
    // single command (clones live for milliseconds).
    let mut hex = format!("{nanos:012x}{pid:04x}{n:04x}");
    hex.truncate(16);
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_name_is_stable() {
        let n = snapshot_name("01970000-deca-dafb-ad00-000000000000", 42);
        assert_eq!(n, "shit-01970000-00000042");
    }

    #[test]
    fn snapshot_name_with_no_dashes_uses_full_input() {
        let n = snapshot_name("nouuid", 7);
        assert_eq!(n, "shit-nouuid-00000007");
    }

    #[test]
    fn snapshot_name_pads_seq_to_eight_digits() {
        assert_eq!(snapshot_name("abcd", 1), "shit-abcd-00000001");
        assert_eq!(snapshot_name("abcd", 12345678), "shit-abcd-12345678");
    }

    #[test]
    fn clone_pre_image_path_maps_correctly() {
        let p = clone_pre_image_path(
            Path::new("/home/user/scratch/foo.txt"),
            Path::new("/home"),
            Path::new("/.shit-clones/abc12345"),
        );
        assert_eq!(
            p,
            Some(std::path::PathBuf::from(
                "/.shit-clones/abc12345/user/scratch/foo.txt"
            ))
        );
    }

    #[test]
    fn clone_pre_image_path_returns_none_off_dataset() {
        let p = clone_pre_image_path(
            Path::new("/etc/passwd"),
            Path::new("/home"),
            Path::new("/.shit-clones/abc12345"),
        );
        assert_eq!(p, None);
    }

    #[test]
    fn clone_pre_image_path_root_mountpoint() {
        let p = clone_pre_image_path(
            Path::new("/var/log/messages"),
            Path::new("/"),
            Path::new("/.shit-clones/abc12345"),
        );
        assert_eq!(
            p,
            Some(std::path::PathBuf::from(
                "/.shit-clones/abc12345/var/log/messages"
            ))
        );
    }

    #[test]
    fn clone_dataset_name_uses_short_event_id() {
        // source dataset has a parent -> clone is parent's sibling.
        let n = clone_dataset_name("zroot/tmp", "abc12345-deca-dafb-ad00-000000000000");
        assert_eq!(n, "zroot/.shit-clones-abc12345");
    }

    #[test]
    fn clone_dataset_name_pool_root_source() {
        // Source is the pool root itself — no slash to strip.
        let n = clone_dataset_name("zroot", "abc12345");
        assert_eq!(n, "zroot/.shit-clones-abc12345");
    }

    #[test]
    fn clone_dataset_name_nested_source() {
        // Source is two levels deep — clone lands as a sibling of
        // the deepest dataset.
        let n = clone_dataset_name("zroot/home/user", "abc12345");
        assert_eq!(n, "zroot/home/.shit-clones-abc12345");
    }

    #[test]
    fn clone_dataset_name_handles_short_input() {
        let n = clone_dataset_name("rpool/data", "short");
        assert_eq!(n, "rpool/.shit-clones-short");
    }

    #[test]
    fn clone_dataset_name_truncates_long_first_segment() {
        let n = clone_dataset_name("zroot/data", "thisisaverylongidentifier");
        assert_eq!(n, "zroot/.shit-clones-thisisav");
    }

    #[test]
    fn zfs_not_installed_is_surfaced() {
        if std::path::Path::new(ZFS_BIN).exists() {
            return;
        }
        let err = snapshot_create("rpool/test", "shit-probe-1").unwrap_err();
        assert!(matches!(err, ZfsError::NotInstalled));
    }

    #[test]
    fn fresh_clone_id_is_unique_and_bounded() {
        let a = fresh_clone_id();
        let b = fresh_clone_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 16);
        // No characters outside [0-9a-f].
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn capture_zfs_clone_falls_through_when_path_not_zfs() {
        // On a host without /sbin/zfs this exercises the
        // resolve_dataset early-return. On a host with zfs but on a
        // non-ZFS tmpfile it exercises the same branch via
        // dataset_for_path returning None.
        if std::path::Path::new(ZFS_BIN).exists() {
            // dataset_for_path on a non-ZFS path returns None on
            // most setups, but ZFS-rooted hosts can be ambiguous.
            // Skip when we can't be sure.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("x.txt");
        std::fs::write(&src, b"hi").unwrap();
        let f = std::fs::File::open(&src).unwrap();
        use std::os::fd::AsRawFd;
        let err = capture_zfs_clone(f.as_raw_fd(), &src, tmp.path()).unwrap_err();
        assert!(err.is_fallthrough(), "expected fallthrough, got {err:?}");
    }
}
