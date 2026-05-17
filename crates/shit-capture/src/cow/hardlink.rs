// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hardlink tier — `link(2)` the source inode into the blob store.
//!
//! **Source-doomed only.** A hardlink shares the inode; if the caller's
//! command writes through the source path *after* capture, the captured
//! blob mutates with it. The engine must only choose this tier when the
//! caller can promise the source path will be removed or replaced
//! (e.g. `rm`, `mv` overwrite). The `CaptureOpts::source_doomed` flag is
//! the gate; it's checked again here as a belt-and-braces guard.
//!
//! Layout: hardlink into `blobs/tmp/<random>`, hash + stat through that
//! handle, then rename atomically into the CAS path. We then unlink the
//! tmp link only if a rename collision left it orphaned.

use std::fs::{self, File};
use std::io::Read;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use shit_planner::BlobHash;

use super::error::CowError;
use super::verify::{SourceFingerprint, assert_stable};
use super::{CaptureOutcome, CowTier};

/// Hardlink the file behind `src_fd` (also addressable via `src_path`)
/// into the blob store rooted at `blob_root`. Caller must have set
/// `source_doomed` — verified by the dispatcher; reasserted here.
pub fn capture_hardlink(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
    source_doomed: bool,
) -> Result<CaptureOutcome, CowError> {
    if !source_doomed {
        return Err(CowError::TierUnsupported {
            tier: "hardlink",
            detail: "caller did not promise source_doomed".into(),
        });
    }
    let before = SourceFingerprint::of_fd(src_fd)?;

    let tmp_dir = blob_root.join("tmp");
    fs::create_dir_all(&tmp_dir)?;
    let tmp_path = unique_tmp(&tmp_dir);

    // Hardlink is cheap but fails across mounts and on filesystems that
    // disallow it (e.g. files with the `c` flag on btrfs nodatacow chains
    // can still be linked, but cross-fs is the common one). Translate
    // EXDEV / EPERM into TierUnsupported so the engine falls through.
    if let Err(e) = fs::hard_link(src_path, &tmp_path) {
        return Err(match e.raw_os_error() {
            Some(libc::EXDEV) => CowError::TierUnsupported {
                tier: "hardlink",
                detail: "cross-device link".into(),
            },
            Some(libc::EPERM) => CowError::TierUnsupported {
                tier: "hardlink",
                detail: "EPERM (likely fs disallows hardlink)".into(),
            },
            _ => CowError::Io(e),
        });
    }

    // Hash via the tmp path (same inode → same bytes as the source).
    let hash = match hash_file(&tmp_path) {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    let after = SourceFingerprint::of_fd(src_fd)?;
    if let Err(e) = assert_stable(before, after) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    let final_path = super::blob_path(blob_root, &hash);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // If the blob is already present, drop the temp link (refcount is
    // managed by the index, not by inode link count).
    if final_path.exists() {
        let _ = fs::remove_file(&tmp_path);
        let stored_bytes = fs::metadata(&final_path)?.len();
        return Ok(CaptureOutcome {
            hash,
            tier: CowTier::Hardlink,
            stored_bytes,
        });
    }

    // Rename the tmp link into place. The hardlink tier stores the raw
    // bytes — no compression flag byte prefix like `BlobStore::put`
    // produces, because we can't rewrite the inode without breaking the
    // share. This is the documented quirk of the hardlink tier: blobs
    // captured via hardlink are byte-identical to the source on disk and
    // skip the store's compression flag.
    fs::rename(&tmp_path, &final_path)?;
    let stored_bytes = fs::metadata(&final_path)?.len();

    Ok(CaptureOutcome {
        hash,
        tier: CowTier::Hardlink,
        stored_bytes,
    })
}

fn hash_file(path: &Path) -> Result<BlobHash, CowError> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(BlobHash::from_bytes(*hasher.finalize().as_bytes()))
}

fn unique_tmp(dir: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    dir.join(format!("hardlink-{pid}-{n:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn hardlink_captures_file_when_source_doomed() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        let mut src = File::create(&src_path).unwrap();
        src.write_all(b"hardlink content").unwrap();
        src.flush().unwrap();
        drop(src);

        let f = File::open(&src_path).unwrap();
        let outcome = capture_hardlink(f.as_raw_fd(), &src_path, tmp.path(), true).unwrap();
        assert_eq!(outcome.tier, CowTier::Hardlink);

        let stored = super::super::blob_path(tmp.path(), &outcome.hash);
        let bytes = std::fs::read(&stored).unwrap();
        assert_eq!(bytes, b"hardlink content");
    }

    #[test]
    fn hardlink_refuses_when_source_not_doomed() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        File::create(&src_path).unwrap().write_all(b"x").unwrap();
        let f = File::open(&src_path).unwrap();
        let err = capture_hardlink(f.as_raw_fd(), &src_path, tmp.path(), false).unwrap_err();
        assert!(matches!(
            err,
            CowError::TierUnsupported {
                tier: "hardlink",
                ..
            }
        ));
    }

    #[test]
    fn hardlink_dedups_on_recapture() {
        let tmp = tempfile::tempdir().unwrap();
        let src1 = tmp.path().join("a.txt");
        let src2 = tmp.path().join("b.txt");
        File::create(&src1)
            .unwrap()
            .write_all(b"same bytes")
            .unwrap();
        File::create(&src2)
            .unwrap()
            .write_all(b"same bytes")
            .unwrap();
        let f1 = File::open(&src1).unwrap();
        let a = capture_hardlink(f1.as_raw_fd(), &src1, tmp.path(), true).unwrap();
        let f2 = File::open(&src2).unwrap();
        let b = capture_hardlink(f2.as_raw_fd(), &src2, tmp.path(), true).unwrap();
        assert_eq!(a.hash, b.hash);
    }
}
