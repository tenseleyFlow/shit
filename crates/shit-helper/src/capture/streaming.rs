// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming pre-image primitives (AU25).
//!
//! Both the BSD/kqueue producer (W07.A.1) and the Linux/LSM producer
//! (AU25.2) need to capture a file's pre-mutation content into a
//! staging file with an in-flight blake3 hash, without materializing
//! the bytes in a userspace `Vec<u8>`. This module provides the
//! shared primitives:
//!
//! - [`stream_copy_to_staging_at`] — open-relative-to-fd variant.
//!   Used by BSD/kqueue where the producer holds an O_PATH dir fd
//!   to the staging directory (Capsicum-safe).
//! - [`stream_copy_to_staging_path`] — path-based variant. Used by
//!   Linux/LSM where the producer holds a `PathBuf` to the staging
//!   directory (matches the existing `staging_dir` field on
//!   `LinuxCaptureSink`).
//!
//! Both share an inner `pread` loop in [`stream_into_fd`] that
//! reads in 64 KiB chunks, hashes each chunk, and writes it to the
//! destination fd. No per-call allocation grows with file size.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::path::Path;

/// Errors surfaced by the streaming pre-image path. BSD's
/// `kqueue::capture` re-exports this under the legacy
/// `CaptureError` name so existing call sites compile unchanged.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("pread(2): {0}")]
    Pread(std::io::Error),
    #[error("write(2): {0}")]
    Write(std::io::Error),
    /// Surfaced by [`stream_copy_to_staging_at`] (BSD's fd-pinned
    /// staging-dir variant). Linux uses [`StreamError::Open`].
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    #[error("openat(2): {0}")]
    Openat(std::io::Error),
    /// Surfaced by [`stream_copy_to_staging_path`] (Linux's
    /// path-based variant). BSD uses [`StreamError::Openat`].
    #[cfg(target_os = "linux")]
    #[error("open(2): {0}")]
    Open(std::io::Error),
    #[error("fstat(2): {0}")]
    Fstat(std::io::Error),
    #[error("inode size {0} exceeds cap (use streaming path or refuse)")]
    TooLargeForBuffer(u64),
}

// PRE_IMAGE_INLINE_CAP lives in `kqueue/capture.rs` (BSD's
// small-file inline `read_pre_image` boundary) — keeping it there
// keeps the B07.6 lib facade self-contained. Linux's inline-vs-
// stream boundary is [`super::linux::MAX_PRE_IMAGE_BYTES`].

/// Hard cap on the streaming path's source size. 1 GiB on both
/// BSD (W07.A.1) and Linux (AU25.3). Files above this cap skip
/// capture and surface a doctor warn.
pub const STREAM_COPY_CAP: u64 = 1024 * 1024 * 1024;

/// Userspace buffer size for the streaming copy. 64 KiB matches
/// coreutils `cp` and is comfortably below readahead-defeating
/// values on UFS / ZFS / ext4 / btrfs.
const STREAM_COPY_CHUNK: usize = 64 * 1024;

/// `fstat(fd).st_size` as `u64`. Used both as the streaming cap
/// pre-check and by [`super::xattr`]'s baseline-walk size budget.
pub fn inode_size(fd: RawFd) -> Result<u64, StreamError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid open RawFd per caller contract; st is a
    // valid writable struct.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc < 0 {
        return Err(StreamError::Fstat(std::io::Error::last_os_error()));
    }
    Ok(st.st_size as u64)
}

/// Generate a unique staging filename. `{pid}-{nanos}-stream` —
/// the `-stream` suffix differentiates streamed captures from the
/// legacy `write_to_staging` path so the two never collide if
/// both ever run against the same staging dir simultaneously.
fn staging_name() -> String {
    format!(
        "{}-{}-stream",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    )
}

/// Inner `pread` → hash + `write` loop. Reads up to `cap` bytes
/// from `src_fd` (starting at offset 0, via `pread` so the fd's
/// seek pointer is undisturbed) and writes them into `write_fd`,
/// hashing each chunk inline. Returns (blake3 hash, bytes copied).
///
/// `cap` is the maximum bytes to copy; the caller has already
/// verified `inode_size(src_fd) <= cap`. If the file shrinks under
/// us mid-copy, the loop stops early and ships what we have —
/// symmetric with the inline `read_pre_image` truncation guard.
fn stream_into_fd(
    src_fd: RawFd,
    write_fd: RawFd,
    cap: u64,
) -> Result<([u8; 32], u64), StreamError> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; STREAM_COPY_CHUNK];
    let target = cap as i64;
    let mut offset = 0i64;

    while offset < target {
        let want = ((target - offset) as usize).min(STREAM_COPY_CHUNK);
        // SAFETY: buf is a writable slice of len >= want; src_fd valid per caller.
        let n = unsafe { libc::pread(src_fd, buf.as_mut_ptr().cast(), want, offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(StreamError::Pread(err));
        }
        if n == 0 {
            // EOF before cap — file shrunk between caller's
            // inode_size() and this read. Ship what we have.
            break;
        }
        let n_usize = n as usize;
        hasher.update(&buf[..n_usize]);

        let mut written = 0usize;
        while written < n_usize {
            // SAFETY: buf valid; write_fd valid until caller closes it.
            let wrc = unsafe {
                libc::write(
                    write_fd,
                    buf.as_ptr().add(written).cast(),
                    (n_usize - written) as libc::size_t,
                )
            };
            if wrc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(StreamError::Write(err));
            }
            written += wrc as usize;
        }
        offset += n as i64;
    }

    Ok((*hasher.finalize().as_bytes(), offset as u64))
}

/// Stream `src_fd` into a fresh staging file opened relative to
/// `staging_dir_fd`, returning an `O_RDONLY` fd ready for
/// SCM_RIGHTS hand-off, the blake3 hash, and the byte count.
///
/// BSD's preferred variant — `openat(staging_dir_fd, …)` is the
/// Capsicum-safe shape that the kqueue producer relies on after
/// `cap_enter()`. Linux has no equivalent sandbox today; see
/// [`stream_copy_to_staging_path`].
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub fn stream_copy_to_staging_at(
    src_fd: RawFd,
    staging_dir_fd: RawFd,
    cap: u64,
) -> Result<(OwnedFd, [u8; 32], u64), StreamError> {
    let size = inode_size(src_fd)?;
    if size > cap {
        return Err(StreamError::TooLargeForBuffer(size));
    }

    let name = staging_name();
    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        StreamError::Openat(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging name NUL",
        ))
    })?;

    // O_EXCL so we never clobber a concurrent stream's file;
    // mode 0o600 keeps pre-image content owner-only.
    let wflags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: staging_dir_fd alive per caller; name_c is NUL-terminated.
    let wfd = unsafe { libc::openat(staging_dir_fd, name_c.as_ptr(), wflags, 0o600) };
    if wfd < 0 {
        return Err(StreamError::Openat(std::io::Error::last_os_error()));
    }

    let result = stream_into_fd(src_fd, wfd, size);

    // fsync so the daemon's ingest reads a fully-on-disk file,
    // then close before the read-handle reopen.
    unsafe {
        libc::fsync(wfd);
        libc::close(wfd);
    }

    let (hash, copied) = result?;

    let rflags = libc::O_RDONLY | libc::O_CLOEXEC;
    let rfd = unsafe { libc::openat(staging_dir_fd, name_c.as_ptr(), rflags, 0) };
    if rfd < 0 {
        return Err(StreamError::Openat(std::io::Error::last_os_error()));
    }
    // SAFETY: rfd is a fresh kernel-allocated fd we now own.
    Ok((unsafe { OwnedFd::from_raw_fd(rfd) }, hash, copied))
}

/// Path-based variant for Linux/LSM (AU25.2). The producer holds
/// `staging_dir: PathBuf`; we open the staging file by the joined
/// path with `O_CREAT|O_EXCL|O_CLOEXEC`, stream, fsync, reopen
/// read-only.
///
/// No `openat` dance — Linux's staging dir lives in
/// `$XDG_STATE_HOME/shit/staging/<uid>/`, owned by the helper, and
/// the producer is not Capsicum-sandboxed. A symlink-race here
/// would require an attacker who can write to that owner-only
/// staging dir, which already implies code-exec as the helper user.
#[cfg(target_os = "linux")]
pub fn stream_copy_to_staging_path(
    src_fd: RawFd,
    staging_dir: &Path,
    cap: u64,
) -> Result<(OwnedFd, [u8; 32], u64), StreamError> {
    let size = inode_size(src_fd)?;
    if size > cap {
        return Err(StreamError::TooLargeForBuffer(size));
    }

    let path = staging_dir.join(staging_name());

    use std::os::unix::ffi::OsStrExt;
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        StreamError::Open(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging path NUL",
        ))
    })?;

    let wflags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: path_c is NUL-terminated.
    let wfd = unsafe { libc::open(path_c.as_ptr(), wflags, 0o600) };
    if wfd < 0 {
        return Err(StreamError::Open(std::io::Error::last_os_error()));
    }

    let result = stream_into_fd(src_fd, wfd, size);

    unsafe {
        libc::fsync(wfd);
        libc::close(wfd);
    }

    let (hash, copied) = match result {
        Ok(v) => v,
        Err(e) => {
            // Clean up the partially-written staging file. Best
            // effort: a leftover file just delays the helper's GC
            // pass; it doesn't break correctness.
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };

    let rflags = libc::O_RDONLY | libc::O_CLOEXEC;
    // SAFETY: path_c is NUL-terminated.
    let rfd = unsafe { libc::open(path_c.as_ptr(), rflags) };
    if rfd < 0 {
        let err = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(&path);
        return Err(StreamError::Open(err));
    }
    // SAFETY: rfd is a fresh kernel-allocated fd we now own.
    Ok((unsafe { OwnedFd::from_raw_fd(rfd) }, hash, copied))
}

// Tests exercise the Linux Path-based variant; gated to keep the
// BSD compile path warning-clean (Openat / stream_copy_to_staging_at
// is BSD-only and covered by `kqueue/capture_tests.rs`).
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    fn write_tmp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(bytes).expect("write");
        f.flush().expect("flush");
        f.as_file_mut()
            .seek(SeekFrom::Start(0))
            .expect("rewind src");
        f
    }

    #[test]
    fn stream_copy_to_staging_path_round_trips_small_file() {
        let dir = tempfile::tempdir().expect("staging tmpdir");
        let src = write_tmp(b"hello AU25");

        let (rfd, hash, bytes) =
            stream_copy_to_staging_path(src.as_file().as_raw_fd(), dir.path(), STREAM_COPY_CAP)
                .expect("stream ok");
        assert_eq!(bytes, 10);
        assert_eq!(hash, *blake3::hash(b"hello AU25").as_bytes());

        let mut f = std::fs::File::from(rfd);
        let mut out = Vec::new();
        f.read_to_end(&mut out).expect("read staging");
        assert_eq!(out, b"hello AU25");
    }

    #[test]
    fn stream_copy_to_staging_path_refuses_above_cap() {
        let dir = tempfile::tempdir().expect("staging tmpdir");
        let src = write_tmp(b"AAAAAAAAAAAAAAAA"); // 16 bytes

        let err = stream_copy_to_staging_path(src.as_file().as_raw_fd(), dir.path(), 8)
            .expect_err("expected TooLargeForBuffer");
        match err {
            StreamError::TooLargeForBuffer(n) => assert_eq!(n, 16),
            other => panic!("expected TooLargeForBuffer, got {other:?}"),
        }
    }

    #[test]
    fn stream_copy_to_staging_path_handles_64kib_plus_chunked() {
        // 200 KiB — forces multiple STREAM_COPY_CHUNK (64 KiB) passes.
        let payload: Vec<u8> = (0..200 * 1024).map(|i| (i as u8).wrapping_mul(7)).collect();
        let expected_hash = *blake3::hash(&payload).as_bytes();
        let dir = tempfile::tempdir().expect("staging tmpdir");
        let src = write_tmp(&payload);

        let (rfd, hash, bytes) =
            stream_copy_to_staging_path(src.as_file().as_raw_fd(), dir.path(), STREAM_COPY_CAP)
                .expect("stream ok");
        assert_eq!(bytes, payload.len() as u64);
        assert_eq!(hash, expected_hash);

        let mut f = std::fs::File::from(rfd);
        let mut out = Vec::new();
        f.read_to_end(&mut out).expect("read staging");
        assert_eq!(out, payload);
    }

    #[test]
    fn stream_copy_to_staging_path_preserves_src_offset() {
        // The pread-based loop must not disturb the source fd's
        // seek offset — Linux's `pre_open_tree` and BSD's snapshot
        // walk both depend on this.
        let dir = tempfile::tempdir().expect("staging tmpdir");
        let mut src = write_tmp(b"0123456789");
        src.as_file_mut().seek(SeekFrom::Start(3)).expect("seek");

        stream_copy_to_staging_path(src.as_file().as_raw_fd(), dir.path(), STREAM_COPY_CAP)
            .expect("stream ok");

        let pos = src
            .as_file_mut()
            .stream_position()
            .expect("stream_position");
        assert_eq!(pos, 3);
    }

    #[test]
    fn inode_size_matches_fstat() {
        let src = write_tmp(b"twelve-bytes");
        let n = inode_size(src.as_file().as_raw_fd()).expect("inode_size");
        assert_eq!(n, 12);
    }
}
