// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux `FICLONE` ioctl — kernel-side reflink on btrfs, XFS-with-reflink,
//! and bcachefs.
//!
//! Same-volume only; cross-volume returns EXDEV (we surface as
//! `TierUnsupported` so the engine falls through). XFS without
//! `reflink=1` returns EOPNOTSUPP — same treatment.
//!
//! The parent `cow::mod` gates this module with `#[cfg(target_os =
//! "linux")]`; we don't repeat the inner `#![cfg]` here because
//! rustc's `duplicated_attributes` warns on it (CI fails with
//! `-D warnings`).

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use shit_planner::BlobHash;

use super::error::CowError;
use super::verify::{SourceFingerprint, assert_stable};
use super::{CaptureOutcome, CowTier};

// FICLONE = _IOW(0x94, 9, int). Encoded as 0x40049409 on Linux.
const FICLONE: libc::c_ulong = 0x4004_9409;

/// FICLONE the file behind `src_fd` into a fresh path inside the blob
/// store. We open a writable dest fd, ioctl(FICLONE, src_fd), hash, then
/// rename into the CAS path.
pub fn capture_ficlone(
    src_fd: RawFd,
    _src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    let before = SourceFingerprint::of_fd(src_fd)?;

    let tmp_dir = blob_root.join("tmp");
    fs::create_dir_all(&tmp_dir)?;
    let tmp_path = unique_tmp(&tmp_dir);

    let dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;

    let rc = unsafe { libc::ioctl(dst.as_raw_fd(), FICLONE, src_fd) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        drop(dst);
        let _ = fs::remove_file(&tmp_path);
        return Err(match err.raw_os_error() {
            Some(libc::EXDEV) => CowError::TierUnsupported {
                tier: "reflink",
                detail: "cross-device".into(),
            },
            Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => CowError::TierUnsupported {
                tier: "reflink",
                detail: "fs does not support FICLONE (XFS w/o reflink, ext4, etc.)".into(),
            },
            _ => CowError::Io(err),
        });
    }
    drop(dst);

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

    if final_path.exists() {
        let _ = fs::remove_file(&tmp_path);
        let stored_bytes = fs::metadata(&final_path)?.len();
        return Ok(CaptureOutcome {
            hash,
            tier: CowTier::Reflink,
            stored_bytes,
        });
    }

    fs::rename(&tmp_path, &final_path)?;
    let stored_bytes = fs::metadata(&final_path)?.len();
    Ok(CaptureOutcome {
        hash,
        tier: CowTier::Reflink,
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
    dir.join(format!("ficlone-{pid}-{n:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn ficlone_falls_through_on_unsupported_fs() {
        // Most CI runners use ext4/tmpfs for $TMPDIR. We expect
        // TierUnsupported, not success, unless the runner is btrfs/xfs.
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        let mut src = File::create(&src_path).unwrap();
        src.write_all(b"ficlone content").unwrap();
        src.flush().unwrap();
        drop(src);
        let f = File::open(&src_path).unwrap();
        match capture_ficlone(f.as_raw_fd(), &src_path, tmp.path()) {
            Ok(outcome) => assert_eq!(outcome.tier, CowTier::Reflink),
            Err(CowError::TierUnsupported { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
