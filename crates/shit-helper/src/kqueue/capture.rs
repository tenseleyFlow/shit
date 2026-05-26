// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pre-image reader for kqueue-driven capture (S23.4, rescoped).
//!
//! The load-bearing claim of the kqueue-only capture tier is that we
//! can recover a file's pre-mutation content *after* the user's
//! `unlink(2)` or `truncate(2)`, simply because the helper holds an
//! `O_RDONLY` fd to the inode (opened by the [`vnode::register_subtree`]
//! walk) and the BSD kernel keeps the inode reachable while any fd
//! references it. This module validates the claim and exposes the
//! single function the S24 producer needs:
//!
//! ```ignore
//! let bytes = read_pre_image(fd)?;
//! // bytes is the file's content at the moment we opened the fd,
//! // regardless of any subsequent unlink / truncate / overwrite.
//! ```
//!
//! See the tests for the empirical proof on FreeBSD. The S24 producer
//! will compose this with blake3 hashing + `HelperRequest::CaptureEvent`
//! IPC to ship the bytes to the daemon's blob store.
//!
//! **Limits.** This trick covers `rm`, `truncate`, `> file` and most
//! interactive editor writes. It does NOT cover:
//! - mmap-based writes where the kernel never updates the inode's
//!   data blocks until msync (we miss the modification window).
//! - rapid `create-write-close-unlink` cycles where we miss the
//!   `open` because our subtree walk hadn't picked up the new file
//!   yet. Lazy expansion (S24.D, via preload-shim or directory
//!   NOTE_WRITE events) closes that gap.
//!
//! Documented in `.docs/audits/bsd-coverage.md`.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::os::fd::{OwnedFd, RawFd};

/// Errors surfaced by [`read_pre_image`] and [`stream_copy_to_staging`].
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("pread(2): {0}")]
    Pread(std::io::Error),
    #[error("write(2): {0}")]
    Write(std::io::Error),
    #[error("openat(2): {0}")]
    Openat(std::io::Error),
    #[error("fstat(2): {0}")]
    Fstat(std::io::Error),
    #[error("inode size {0} exceeds cap (use streaming path or refuse)")]
    TooLargeForBuffer(u64),
}

/// Soft cap on in-memory pre-image read size. Files larger than this
/// must use [`stream_copy_to_staging`]. 64 MiB matches the project's
/// general "small file" boundary; the inline path stays for tiny
/// files where the per-call allocation is cheaper than the streaming
/// setup.
pub const PRE_IMAGE_INLINE_CAP: u64 = 64 * 1024 * 1024;

/// Hard cap on the streaming path's source size. 1 GiB for this
/// sprint (W07.A.1). The final cap (configurable, surfaced via the
/// user-visible refusal contract) lands in W07.A.3.
pub const STREAM_COPY_CAP: u64 = 1024 * 1024 * 1024;

/// Userspace buffer size for the streaming copy. 64 KiB matches
/// coreutils `cp` and is comfortably below readahead-defeating values
/// on UFS / ZFS / ext4 / btrfs.
const STREAM_COPY_CHUNK: usize = 64 * 1024;

/// Read the pre-mutation content of the inode referenced by `fd`.
///
/// `fd` must be the helper's O_RDONLY fd from the subtree walk — NOT
/// a fresh `open(path)` after the mutation, which would see the
/// post-mutation state. Reads are `pread`-based so we don't disturb
/// the fd's seek offset (other code paths may rely on the fd).
///
/// Returns the full file content. For files >`PRE_IMAGE_INLINE_CAP`,
/// returns [`CaptureError::TooLargeForBuffer`] — S24 will plumb a
/// streaming variant for those.
pub fn read_pre_image(fd: RawFd) -> Result<Vec<u8>, CaptureError> {
    let size = inode_size(fd)?;
    if size > PRE_IMAGE_INLINE_CAP {
        return Err(CaptureError::TooLargeForBuffer(size));
    }
    let mut out = vec![0u8; size as usize];
    let mut offset = 0i64;
    while offset < size as i64 {
        // SAFETY: out is a valid writable slice of len `size`; fd is
        // expected to be a valid open RawFd (caller contract).
        let n = unsafe {
            libc::pread(
                fd,
                out[offset as usize..].as_mut_ptr().cast(),
                (size as i64 - offset) as libc::size_t,
                offset,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(CaptureError::Pread(err));
        }
        if n == 0 {
            // EOF earlier than fstat reported — file was truncated
            // between our fstat and our reads. Trim and return what
            // we got; the bytes up to `offset` are still the
            // pre-truncation content for the part we already read.
            out.truncate(offset as usize);
            return Ok(out);
        }
        offset += n as i64;
    }
    Ok(out)
}

/// Stream the pre-mutation content of `src_fd` into a fresh staging
/// file under `staging_dir_fd`, returning an `O_RDONLY` fd ready for
/// SCM_RIGHTS, the blake3 hash of the data, and the total bytes
/// copied.
///
/// Unlike [`read_pre_image`], this never materializes the file
/// contents in a userspace `Vec<u8>` — chunks flow src_fd → 64 KiB
/// userspace buffer → staging_fd, with blake3 incremental hashing
/// per chunk. Suitable for files up to `cap` (callers should pass
/// [`STREAM_COPY_CAP`] until the W07.A.3 cap-relax lands).
///
/// `src_fd` must be the helper's `O_RDONLY` fd from the subtree walk
/// (same contract as [`read_pre_image`]). Reads use `pread(2)` so
/// the fd's seek offset isn't disturbed.
pub fn stream_copy_to_staging(
    src_fd: RawFd,
    staging_dir_fd: RawFd,
    cap: u64,
) -> Result<(OwnedFd, [u8; 32], u64), CaptureError> {
    let size = inode_size(src_fd)?;
    if size > cap {
        return Err(CaptureError::TooLargeForBuffer(size));
    }

    let name = staging_name();
    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        CaptureError::Openat(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging name NUL",
        ))
    })?;

    // Open write handle into staging dir. O_EXCL so we never clobber
    // a concurrent stream's file; mode 0o600 keeps pre-image content
    // owner-only.
    let wflags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: staging_dir_fd alive per caller; name_c is NUL-terminated.
    let wfd = unsafe { libc::openat(staging_dir_fd, name_c.as_ptr(), wflags, 0o600) };
    if wfd < 0 {
        return Err(CaptureError::Openat(std::io::Error::last_os_error()));
    }

    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; STREAM_COPY_CHUNK];
    let mut offset = 0i64;
    let target = size as i64;

    while offset < target {
        let want = ((target - offset) as usize).min(STREAM_COPY_CHUNK);
        // SAFETY: buf is a writable slice of len >= want; src_fd valid per caller.
        let n = unsafe { libc::pread(src_fd, buf.as_mut_ptr().cast(), want, offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(wfd) };
            return Err(CaptureError::Pread(err));
        }
        if n == 0 {
            // File truncated under us between fstat and now. Stop
            // and ship what we have — symmetric with read_pre_image.
            break;
        }
        let n_usize = n as usize;
        hasher.update(&buf[..n_usize]);

        let mut written = 0usize;
        while written < n_usize {
            // SAFETY: buf valid; wfd valid until we close it below.
            let wrc = unsafe {
                libc::write(
                    wfd,
                    buf.as_ptr().add(written).cast(),
                    (n_usize - written) as libc::size_t,
                )
            };
            if wrc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                unsafe { libc::close(wfd) };
                return Err(CaptureError::Write(err));
            }
            written += wrc as usize;
        }
        offset += n as i64;
    }

    // fsync so the daemon's ingest reads a fully-on-disk file.
    unsafe { libc::fsync(wfd) };
    unsafe { libc::close(wfd) };

    // Reopen read-only for the SCM_RIGHTS hand-off. Same two-step
    // pattern as `write_to_staging` in capture/bsd.rs.
    let rflags = libc::O_RDONLY | libc::O_CLOEXEC;
    let rfd = unsafe { libc::openat(staging_dir_fd, name_c.as_ptr(), rflags, 0) };
    if rfd < 0 {
        return Err(CaptureError::Openat(std::io::Error::last_os_error()));
    }

    use std::os::fd::FromRawFd;
    let hash = *hasher.finalize().as_bytes();
    // SAFETY: rfd is a fresh kernel-allocated fd we now own.
    Ok((unsafe { OwnedFd::from_raw_fd(rfd) }, hash, offset as u64))
}

/// Unique staging filename. Matches `write_to_staging`'s pattern in
/// `capture/bsd.rs` (pid + nanos) with a `-stream` suffix so the two
/// paths never collide in the same staging dir.
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

/// Get the inode's logical size via `fstat(2)`. Used to size the
/// pre-image buffer before reading.
fn inode_size(fd: RawFd) -> Result<u64, CaptureError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid open RawFd per caller contract; st is a
    // valid writable struct.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc < 0 {
        return Err(CaptureError::Fstat(std::io::Error::last_os_error()));
    }
    Ok(st.st_size as u64)
}

// Note: integration-shape tests live in `capture_tests.rs` (declared
// from `kqueue/mod.rs`) rather than inline here so the B07.6 lib
// facade — which `#[path]`-includes only this file — doesn't try
// to compile tests that depend on `crate::kqueue::{init,
// register_subtree}` paths that only resolve under main.rs's mod
// tree. See `src/lib.rs` for the facade's design notes.
