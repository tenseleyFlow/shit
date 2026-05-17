// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS `clonefile(2)` — APFS atomic clone. Same-volume only;
//! cross-volume is rejected by the kernel.
//!
//! The clone shares extents with the source. Subsequent writes to either
//! file diverge via COW. Hash through the clone (cheap on a hot cache,
//! and the kernel guarantees byte-identity to the source at the moment
//! of the clone call).

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use shit_planner::BlobHash;

use super::error::CowError;
use super::verify::{SourceFingerprint, assert_stable};
use super::{CaptureOutcome, CowTier};

unsafe extern "C" {
    fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32) -> libc::c_int;
}

const CLONE_NOFOLLOW: u32 = 0x0001;
const CLONE_NOOWNERCOPY: u32 = 0x0002;

/// Clone the file behind `src_fd` (also `src_path`) into the blob store.
///
/// Returns `TierUnsupported` on cross-volume or non-APFS errors so the
/// engine falls through to the next tier.
pub fn capture_clonefile(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    let before = SourceFingerprint::of_fd(src_fd)?;

    let tmp_dir = blob_root.join("tmp");
    fs::create_dir_all(&tmp_dir)?;
    let tmp_path = unique_tmp(&tmp_dir);

    let c_src =
        CString::new(src_path.as_os_str().as_bytes()).map_err(|_| CowError::TierUnsupported {
            tier: "clonefile",
            detail: "src path contains NUL".into(),
        })?;
    let c_dst =
        CString::new(tmp_path.as_os_str().as_bytes()).map_err(|_| CowError::TierUnsupported {
            tier: "clonefile",
            detail: "dst path contains NUL".into(),
        })?;

    let rc = unsafe {
        clonefile(
            c_src.as_ptr(),
            c_dst.as_ptr(),
            CLONE_NOFOLLOW | CLONE_NOOWNERCOPY,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EXDEV) => CowError::TierUnsupported {
                tier: "clonefile",
                detail: "cross-device".into(),
            },
            Some(libc::ENOTSUP) | Some(libc::EOPNOTSUPP) => CowError::TierUnsupported {
                tier: "clonefile",
                detail: "fs does not support clonefile".into(),
            },
            _ => CowError::Io(err),
        });
    }

    let hash = match hash_file(&tmp_path) {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    let after = SourceFingerprint::of_fd(src_fd)?;
    // The clone is a kernel-atomic snapshot of the source's extents.
    // We still re-fingerprint to make sure the source identity (ino/dev)
    // hadn't already been swapped under us before the clone call.
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
            tier: CowTier::Clonefile,
            stored_bytes,
        });
    }

    fs::rename(&tmp_path, &final_path)?;
    let stored_bytes = fs::metadata(&final_path)?.len();
    Ok(CaptureOutcome {
        hash,
        tier: CowTier::Clonefile,
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
    dir.join(format!("clonefile-{pid}-{n:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn clonefile_captures_on_apfs() {
        // The runner's tempdir may live on tmpfs in CI; on the dev mac
        // it's APFS so clonefile succeeds. If the fs doesn't support
        // clonefile we get TierUnsupported and skip.
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        let mut src = File::create(&src_path).unwrap();
        src.write_all(b"clonefile content").unwrap();
        src.flush().unwrap();
        drop(src);

        let f = File::open(&src_path).unwrap();
        match capture_clonefile(f.as_raw_fd(), &src_path, tmp.path()) {
            Ok(outcome) => {
                assert_eq!(outcome.tier, CowTier::Clonefile);
                let stored = super::super::blob_path(tmp.path(), &outcome.hash);
                let bytes = std::fs::read(&stored).unwrap();
                assert_eq!(bytes, b"clonefile content");
            }
            Err(CowError::TierUnsupported { .. }) => {
                eprintln!("skipping: clonefile unsupported on this fs");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
