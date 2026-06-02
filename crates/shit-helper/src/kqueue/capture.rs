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

use std::os::fd::RawFd;

// AU25 — the streaming primitives + error type moved to
// `crate::capture::streaming` so the Linux/LSM producer can share
// them. The legacy `CaptureError` / `stream_copy_to_staging` /
// `PRE_IMAGE_INLINE_CAP` / `STREAM_COPY_CAP` names are kept as
// re-exports so existing BSD call sites (capture/bsd.rs,
// kqueue/capture_tests.rs, kqueue/mod.rs) compile unchanged.
pub use crate::capture::streaming::{
    PRE_IMAGE_INLINE_CAP, STREAM_COPY_CAP, StreamError as CaptureError, inode_size,
    stream_copy_to_staging_at as stream_copy_to_staging,
};

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

// `stream_copy_to_staging` + `staging_name` + `inode_size` moved
// to `crate::capture::streaming` (AU25) and re-exported above.

// Note: integration-shape tests live in `capture_tests.rs` (declared
// from `kqueue/mod.rs`) rather than inline here so the B07.6 lib
// facade — which `#[path]`-includes only this file — doesn't try
// to compile tests that depend on `crate::kqueue::{init,
// register_subtree}` paths that only resolve under main.rs's mod
// tree. See `src/lib.rs` for the facade's design notes.
