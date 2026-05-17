// SPDX-License-Identifier: AGPL-3.0-or-later

//! Userspace streaming-copy fallback. Always works — at the cost of
//! reading every byte through userspace.
//!
//! The fd is dup'd so we can rewind without disturbing the caller's
//! position. We hash incrementally with blake3 as bytes flow into the
//! blob store, then verify the source fd is unchanged before and after
//! (size + mtime + ino + dev). Mid-copy mutation → `SourceMutated`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::RawFd;
use std::path::Path;

use shit_planner::BlobHash;
use shit_store::BlobStore;

use super::error::CowError;
use super::verify::{SourceFingerprint, assert_stable};
use super::{CaptureOutcome, CowTier};

const READ_BUF_BYTES: usize = 64 * 1024;

/// Stream the file behind `src_fd` into the blob store rooted at
/// `blob_root`. The fd's position is restored to 0 on entry; the caller
/// keeps ownership.
pub fn capture_streaming(
    src_fd: RawFd,
    _src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    let store = BlobStore::open(blob_root)?;

    let before = SourceFingerprint::of_fd(src_fd)?;

    let mut file = clone_fd_for_reading(src_fd)?;
    file.seek(SeekFrom::Start(0))?;

    // Pre-allocate to the known size when we have one; for small files
    // this avoids any realloc, for large ones it pre-sizes once.
    let mut buf: Vec<u8> = Vec::with_capacity(before.size as usize);
    let mut hasher = blake3::Hasher::new();
    let mut scratch = vec![0u8; READ_BUF_BYTES];

    loop {
        let n = file.read(&mut scratch)?;
        if n == 0 {
            break;
        }
        hasher.update(&scratch[..n]);
        buf.extend_from_slice(&scratch[..n]);
    }

    let after = SourceFingerprint::of_fd(src_fd)?;
    assert_stable(before, after)?;

    let incremental_hash = BlobHash::from_bytes(*hasher.finalize().as_bytes());
    let (stored_hash, stat) = store.put(&buf)?;
    if stored_hash != incremental_hash {
        // Should not happen — the blob store hashes the same bytes we
        // already hashed. Surface the mismatch loudly rather than silently
        // trusting one side.
        return Err(CowError::HashMismatch {
            expected: incremental_hash,
            actual: stored_hash,
        });
    }

    Ok(CaptureOutcome {
        hash: stored_hash,
        tier: CowTier::StreamingCopy,
        stored_bytes: stat.stored_bytes,
    })
}

/// `dup(2)` the source fd into a fresh `File` we can `seek` and `read`
/// without disturbing whatever position the caller's fd was at. The
/// returned `File` closes on drop; the original fd stays open with the
/// caller.
fn clone_fd_for_reading(src_fd: RawFd) -> Result<File, CowError> {
    use std::os::fd::FromRawFd;
    let dup_fd = nix::unistd::dup(src_fd)?;
    // SAFETY: dup just returned a fresh fd we own. File takes ownership
    // and closes it on drop.
    Ok(unsafe { File::from_raw_fd(dup_fd) })
}

/// Convenience that accepts an already-open `File` (tests use this).
#[allow(dead_code)]
pub fn capture_streaming_from_file(
    file: &mut File,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    let store = BlobStore::open(blob_root)?;
    file.seek(SeekFrom::Start(0))?;
    let md = file.metadata()?;
    let before = SourceFingerprint::of_metadata(&md);

    let mut buf: Vec<u8> = Vec::with_capacity(before.size as usize);
    let mut hasher = blake3::Hasher::new();
    let mut scratch = vec![0u8; READ_BUF_BYTES];
    loop {
        let n = file.read(&mut scratch)?;
        if n == 0 {
            break;
        }
        hasher.update(&scratch[..n]);
        buf.extend_from_slice(&scratch[..n]);
    }
    let after = SourceFingerprint::of_metadata(&file.metadata()?);
    assert_stable(before, after)?;

    let incremental_hash = BlobHash::from_bytes(*hasher.finalize().as_bytes());
    let (stored_hash, stat) = store.put(&buf)?;
    if stored_hash != incremental_hash {
        return Err(CowError::HashMismatch {
            expected: incremental_hash,
            actual: stored_hash,
        });
    }
    Ok(CaptureOutcome {
        hash: stored_hash,
        tier: CowTier::StreamingCopy,
        stored_bytes: stat.stored_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn streaming_captures_small_file() {
        let tmp = tempfile::tempdir().unwrap();
        let mut src = tempfile::NamedTempFile::new().unwrap();
        src.write_all(b"hello, world").unwrap();
        src.flush().unwrap();

        let mut f = std::fs::File::open(src.path()).unwrap();
        let outcome = capture_streaming_from_file(&mut f, tmp.path()).unwrap();
        assert_eq!(outcome.tier, CowTier::StreamingCopy);
        let store = BlobStore::open(tmp.path()).unwrap();
        assert!(store.contains(&outcome.hash));
        let bytes = store.get(outcome.hash).unwrap();
        assert_eq!(bytes, b"hello, world");
    }

    #[test]
    fn streaming_dedups_on_recapture() {
        let tmp = tempfile::tempdir().unwrap();
        let mut src = tempfile::NamedTempFile::new().unwrap();
        src.write_all(b"the same content").unwrap();
        src.flush().unwrap();

        let mut f = std::fs::File::open(src.path()).unwrap();
        let a = capture_streaming_from_file(&mut f, tmp.path()).unwrap();
        let mut f = std::fs::File::open(src.path()).unwrap();
        let b = capture_streaming_from_file(&mut f, tmp.path()).unwrap();
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn streaming_captures_one_megabyte() {
        let tmp = tempfile::tempdir().unwrap();
        let mut src = tempfile::NamedTempFile::new().unwrap();
        let payload = vec![0xABu8; 1_000_000];
        src.write_all(&payload).unwrap();
        src.flush().unwrap();

        let mut f = std::fs::File::open(src.path()).unwrap();
        let outcome = capture_streaming_from_file(&mut f, tmp.path()).unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        assert_eq!(store.get(outcome.hash).unwrap(), payload);
    }

    #[test]
    fn streaming_via_raw_fd() {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        let mut src = tempfile::NamedTempFile::new().unwrap();
        src.write_all(b"raw fd path").unwrap();
        src.flush().unwrap();
        let f = std::fs::File::open(src.path()).unwrap();
        let outcome = capture_streaming(f.as_raw_fd(), src.path(), tmp.path()).unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        assert_eq!(store.get(outcome.hash).unwrap(), b"raw fd path");
    }
}
