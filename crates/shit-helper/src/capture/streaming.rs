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

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
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
    #[error("fsync(2): {0}")]
    Fsync(std::io::Error),
    #[error("lseek(2): {0}")]
    Seek(std::io::Error),
    #[error("source ended before its initial size of {expected} bytes (copied {copied})")]
    UnexpectedEof { expected: u64, copied: u64 },
    #[error(
        "source identity, size, or timestamps changed while it was staged (before dev={before_dev} ino={before_ino} size={before_size}; after dev={after_dev} ino={after_ino} size={after_size})"
    )]
    SourceChanged {
        before_dev: u64,
        before_ino: u64,
        before_size: u64,
        after_dev: u64,
        after_ino: u64,
        after_size: u64,
    },
    #[error("staging unlink: {0}")]
    Unlink(std::io::Error),
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
    Ok(source_identity(fd)?.size)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

// libc intentionally exposes target-specific aliases for stat fields. The
// explicit casts keep this shared Linux/BSD module type-stable even when a
// given target aliases them to the destination type already.
#[allow(clippy::unnecessary_cast)]
fn source_identity(fd: RawFd) -> Result<SourceIdentity, StreamError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid open RawFd per caller contract; st is a
    // valid writable struct.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc < 0 {
        return Err(StreamError::Fstat(std::io::Error::last_os_error()));
    }
    if st.st_size < 0 {
        return Err(StreamError::Fstat(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fstat returned a negative file size",
        )));
    }
    Ok(SourceIdentity {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        size: st.st_size as u64,
        mtime_sec: st.st_mtime as i64,
        mtime_nsec: st.st_mtime_nsec as i64,
        ctime_sec: st.st_ctime as i64,
        ctime_nsec: st.st_ctime_nsec as i64,
    })
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
    write_fd: Option<RawFd>,
    expected_size: u64,
) -> Result<([u8; 32], u64), StreamError> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; STREAM_COPY_CHUNK];
    let mut offset = 0u64;

    while offset < expected_size {
        let want = (expected_size - offset).min(STREAM_COPY_CHUNK as u64) as usize;
        // SAFETY: buf is a writable slice of len >= want; src_fd valid per caller.
        let n =
            unsafe { libc::pread(src_fd, buf.as_mut_ptr().cast(), want, offset as libc::off_t) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(StreamError::Pread(err));
        }
        if n == 0 {
            return Err(StreamError::UnexpectedEof {
                expected: expected_size,
                copied: offset,
            });
        }
        let n_usize = n as usize;
        hasher.update(&buf[..n_usize]);

        if let Some(write_fd) = write_fd {
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
                if wrc == 0 {
                    return Err(StreamError::Write(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "staging write returned zero",
                    )));
                }
                written += wrc as usize;
            }
        }
        offset += n as u64;
    }

    Ok((*hasher.finalize().as_bytes(), offset))
}

fn verify_source_unchanged(
    before: SourceIdentity,
    after: SourceIdentity,
) -> Result<(), StreamError> {
    if before == after {
        return Ok(());
    }
    Err(StreamError::SourceChanged {
        before_dev: before.dev,
        before_ino: before.ino,
        before_size: before.size,
        after_dev: after.dev,
        after_ino: after.ino,
        after_size: after.size,
    })
}

/// Hash a stable view of `src_fd` with the same fixed 64 KiB buffer and
/// before/after identity checks used by staging. This is used for Linux's
/// release-time post-image hash so a large file is never materialized in a
/// `Vec<u8>` merely to compare it with its pre-image.
pub fn hash_fd_contents(src_fd: RawFd, cap: u64) -> Result<([u8; 32], u64), StreamError> {
    let before = source_identity(src_fd)?;
    if before.size > cap {
        return Err(StreamError::TooLargeForBuffer(before.size));
    }
    let result = stream_into_fd(src_fd, None, before.size)?;
    let after = source_identity(src_fd)?;
    verify_source_unchanged(before, after)?;
    Ok(result)
}

/// Stream `src_fd` into a fresh staging file opened relative to
/// `staging_dir_fd`, returning the exact unlinked `O_RDWR` fd ready for
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
    let before = source_identity(src_fd)?;
    if before.size > cap {
        return Err(StreamError::TooLargeForBuffer(before.size));
    }

    let name = staging_name();
    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        StreamError::Openat(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging name NUL",
        ))
    })?;

    // O_EXCL so we never clobber a concurrent stream's file; O_RDWR lets us
    // return this exact descriptor for daemon ingest instead of reopening by
    // a replaceable pathname. Mode 0o600 keeps pre-image content owner-only.
    let wflags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: staging_dir_fd alive per caller; name_c is NUL-terminated.
    let wfd = unsafe { libc::openat(staging_dir_fd, name_c.as_ptr(), wflags, 0o600) };
    if wfd < 0 {
        return Err(StreamError::Openat(std::io::Error::last_os_error()));
    }

    // SAFETY: wfd is a fresh kernel-allocated fd we now own.
    let wfd = unsafe { OwnedFd::from_raw_fd(wfd) };
    // Remove the only pathname before copying any source bytes. The descriptor
    // pins the exact inode through streaming and SCM_RIGHTS hand-off, leaving
    // no close/reopen substitution window and no crash-leftover pathname.
    if unsafe { libc::unlinkat(staging_dir_fd, name_c.as_ptr(), 0) } != 0 {
        return Err(StreamError::Unlink(std::io::Error::last_os_error()));
    }
    let result = stream_into_fd(src_fd, Some(wfd.as_raw_fd()), before.size);

    if result.is_ok() && unsafe { libc::fsync(wfd.as_raw_fd()) } != 0 {
        return Err(StreamError::Fsync(std::io::Error::last_os_error()));
    }
    let (hash, copied) = result?;
    let after = source_identity(src_fd)?;
    verify_source_unchanged(before, after)?;
    if unsafe { libc::lseek(wfd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(StreamError::Seek(std::io::Error::last_os_error()));
    }
    Ok((wfd, hash, copied))
}

/// Path-based variant for Linux/LSM (AU25.2). The producer holds
/// `staging_dir: PathBuf`; we open the staging file by the joined
/// path with `O_CREAT|O_EXCL|O_CLOEXEC`, unlink immediately, stream, fsync,
/// rewind, and return that exact `O_RDWR` descriptor. No pathname reopen is
/// needed, so a same-uid process cannot substitute a different staging inode.
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
    let before = source_identity(src_fd)?;
    if before.size > cap {
        return Err(StreamError::TooLargeForBuffer(before.size));
    }

    let path = staging_dir.join(staging_name());

    use std::os::unix::ffi::OsStrExt;
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        StreamError::Open(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging path NUL",
        ))
    })?;

    let wflags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: path_c is NUL-terminated.
    let wfd = unsafe { libc::open(path_c.as_ptr(), wflags, 0o600) };
    if wfd < 0 {
        return Err(StreamError::Open(std::io::Error::last_os_error()));
    }

    // SAFETY: wfd is a fresh kernel-allocated fd we now own.
    let wfd = unsafe { OwnedFd::from_raw_fd(wfd) };
    // Remove the directory entry before copying any source bytes. Keeping the
    // descriptor open pins the staging inode and lets us return that exact fd,
    // avoiding the close/reopen pathname race entirely.
    if unsafe { libc::unlinkat(libc::AT_FDCWD, path_c.as_ptr(), 0) } != 0 {
        return Err(StreamError::Unlink(std::io::Error::last_os_error()));
    }
    let result = stream_into_fd(src_fd, Some(wfd.as_raw_fd()), before.size);

    if result.is_ok() && unsafe { libc::fsync(wfd.as_raw_fd()) } != 0 {
        return Err(StreamError::Fsync(std::io::Error::last_os_error()));
    }

    let (hash, copied) = result?;
    let after = source_identity(src_fd)?;
    verify_source_unchanged(before, after)?;
    if unsafe { libc::lseek(wfd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(StreamError::Seek(std::io::Error::last_os_error()));
    }
    Ok((wfd, hash, copied))
}

/// Prepare the dedicated helper staging directory before sandbox / Capsicum
/// entry and remove only regular files bearing a legacy helper-generated
/// staging name. The directory itself must be a real directory owned by the
/// authenticated daemon uid; it is tightened to mode 0700 before inspection.
/// Symlinks and directories are never followed or recursively removed.
pub fn prepare_staging_dir(path: &std::path::Path, expected_uid: u32) -> std::io::Result<()> {
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
    }

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging path contains NUL",
        )
    })?;
    let raw = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: raw is a fresh kernel-allocated descriptor.
    let dir_fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir_fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR || stat.st_uid != expected_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "helper staging directory must be a real directory owned by uid {expected_uid}"
            ),
        ));
    }
    if stat.st_mode & 0o7777 != 0o700 && unsafe { libc::fchmod(dir_fd.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        if !is_legacy_staging_name(name.as_os_str()) {
            continue;
        }
        let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staging entry contains NUL",
            )
        })?;
        let mut entry_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                name_c.as_ptr(),
                &mut entry_stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            return Err(error);
        }
        if (entry_stat.st_mode & libc::S_IFMT) != libc::S_IFREG
            || entry_stat.st_uid != expected_uid
            || entry_stat.st_nlink != 1
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to remove suspicious helper staging entry {name:?}"),
            ));
        }
        if unsafe { libc::unlinkat(dir_fd.as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn is_legacy_staging_name(name: &std::ffi::OsStr) -> bool {
    let bytes = name.as_bytes();
    let stem = bytes.strip_suffix(b"-stream").unwrap_or(bytes);
    let Some(separator) = stem.iter().position(|byte| *byte == b'-') else {
        return false;
    };
    let (pid, suffix) = stem.split_at(separator);
    let nanos = &suffix[1..];
    !pid.is_empty()
        && !nanos.is_empty()
        && pid.iter().all(u8::is_ascii_digit)
        && nanos.iter().all(u8::is_ascii_digit)
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
        assert_eq!(
            std::fs::read_dir(dir.path())
                .expect("read staging dir")
                .count(),
            0,
            "successful staging must leave no pathname behind"
        );
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
