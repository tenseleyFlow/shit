// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux / FreeBSD `copy_file_range(2)` — kernel-side block copy.
//! Not as good as a reflink, but it skips userspace `read/write` and on
//! many filesystems is materially faster. On btrfs/XFS it may even do
//! a reflink internally.
//!
//! Quirks:
//! - Linux <5.3: syscall absent → EOPNOTSUPP/ENOSYS at runtime.
//! - Old kernels: cross-mount returns EXDEV.
//! - FreeBSD 13+: `copy_file_range(2)` available; semantics broadly
//!   match Linux's.

#![cfg(any(target_os = "linux", target_os = "freebsd"))]

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use shit_planner::BlobHash;

use super::error::CowError;
use super::verify::{SourceFingerprint, assert_stable};
use super::{CaptureOutcome, CowTier};

const COPY_CHUNK: usize = 1024 * 1024;

pub fn capture_copy_file_range(
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

    let total = before.size;
    let mut remaining = total as isize;
    let mut src_off: i64 = 0;
    let mut dst_off: i64 = 0;

    while remaining > 0 {
        let want = remaining.min(COPY_CHUNK as isize) as usize;
        let n = unsafe { cfr(src_fd, &mut src_off, dst.as_raw_fd(), &mut dst_off, want, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            drop(dst);
            let _ = fs::remove_file(&tmp_path);
            return Err(match err.raw_os_error() {
                Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => CowError::TierUnsupported {
                    tier: "copy_file_range",
                    detail: "syscall absent or fs unsupported".into(),
                },
                Some(libc::EXDEV) => CowError::TierUnsupported {
                    tier: "copy_file_range",
                    detail: "cross-device".into(),
                },
                _ => CowError::Io(err),
            });
        }
        if n == 0 {
            // EOF before declared size: source shrunk under us.
            drop(dst);
            let _ = fs::remove_file(&tmp_path);
            return Err(CowError::SourceMutated);
        }
        remaining -= n;
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
            tier: CowTier::CopyFileRange,
            stored_bytes,
        });
    }

    fs::rename(&tmp_path, &final_path)?;
    let stored_bytes = fs::metadata(&final_path)?.len();
    Ok(CaptureOutcome {
        hash,
        tier: CowTier::CopyFileRange,
        stored_bytes,
    })
}

#[cfg(target_os = "linux")]
unsafe fn cfr(
    src_fd: RawFd,
    src_off: *mut i64,
    dst_fd: RawFd,
    dst_off: *mut i64,
    len: usize,
    flags: u32,
) -> isize {
    // Linux: SYS_copy_file_range = 326 on x86_64; libc::copy_file_range
    // is gated by version, so we call the syscall directly.
    unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            src_fd,
            src_off,
            dst_fd,
            dst_off,
            len,
            flags,
        ) as isize
    }
}

#[cfg(target_os = "freebsd")]
unsafe fn cfr(
    src_fd: RawFd,
    src_off: *mut i64,
    dst_fd: RawFd,
    dst_off: *mut i64,
    len: usize,
    flags: u32,
) -> isize {
    // FreeBSD 13+ exposes copy_file_range as a libc function.
    unsafe { libc::copy_file_range(src_fd, src_off, dst_fd, dst_off, len, flags) as isize }
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
    dir.join(format!("cfr-{pid}-{n:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn copy_file_range_captures_or_falls_through() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        let mut src = File::create(&src_path).unwrap();
        src.write_all(b"copy_file_range content").unwrap();
        src.flush().unwrap();
        drop(src);
        let f = File::open(&src_path).unwrap();
        match capture_copy_file_range(f.as_raw_fd(), &src_path, tmp.path()) {
            Ok(outcome) => assert_eq!(outcome.tier, CowTier::CopyFileRange),
            Err(CowError::TierUnsupported { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
