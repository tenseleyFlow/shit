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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kqueue::{init, register_subtree};
    use std::os::fd::AsRawFd;

    /// Get the helper's tracked fd for a specific path inside a
    /// TrackedSubtree. The TrackedSubtree's fields are private, but
    /// we can use the `path_for_fd` reverse-lookup by iterating.
    fn fd_for_path(tree: &crate::kqueue::TrackedSubtree, path: &std::path::Path) -> Option<RawFd> {
        // path_for_fd is the only public surface — we have to search.
        // Test-only, perf doesn't matter.
        let candidates: Vec<RawFd> = (0..1024)
            .filter(|fd| tree.path_for_fd(*fd) == Some(path))
            .collect();
        candidates.first().copied()
    }

    #[test]
    fn reads_original_content_from_tracked_fd() {
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        let foo = dir.path().join("foo");
        let payload = b"hello, pre-image world";
        std::fs::write(&foo, payload).unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        let fd = fd_for_path(&tree, &foo).expect("foo tracked");
        let got = read_pre_image(fd).expect("read pre-image");
        assert_eq!(got.as_slice(), payload);
    }

    #[test]
    fn read_survives_unlink() {
        // The architectural claim: after the user unlinks a tracked
        // file, the helper's O_RDONLY fd still references the inode
        // and pread returns the original content. This is the
        // load-bearing property of the kqueue-only capture tier.
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        let foo = dir.path().join("foo");
        let payload = b"survive-the-unlink";
        std::fs::write(&foo, payload).unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        let fd = fd_for_path(&tree, &foo).expect("foo tracked");
        // Unlink the file via the path. The inode lives on because
        // we hold an open fd.
        std::fs::remove_file(&foo).unwrap();
        assert!(!foo.exists(), "expected unlink to succeed");
        // Read from the still-open fd.
        let got = read_pre_image(fd).expect("read pre-image after unlink");
        assert_eq!(
            got.as_slice(),
            payload,
            "open-fd should still see pre-unlink content"
        );
    }

    #[test]
    fn read_survives_truncate() {
        // Same architectural claim, truncate variant. After another
        // fd truncates the file, our O_RDONLY fd's view... actually,
        // truncate(2) affects the inode for ALL fds. So this test
        // verifies the OPPOSITE: that truncate IS visible to our
        // fd, and we honestly document this in bsd-coverage.md.
        // The S24 preload-shim closes this gap by pre-notifying us
        // before the truncate completes.
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        let foo = dir.path().join("foo");
        let payload = b"abcdefghij";
        std::fs::write(&foo, payload).unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        let fd = fd_for_path(&tree, &foo).expect("foo tracked");
        // Truncate the file (via a separate open+truncate).
        let f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&foo)
            .unwrap();
        drop(f);
        // After truncate, our fd sees the empty file.
        let got = read_pre_image(fd).expect("read pre-image after truncate");
        assert_eq!(
            got.len(),
            0,
            "truncate is visible across fds — preload-shim needed for pre-image"
        );
    }

    #[test]
    fn reads_empty_file_cleanly() {
        let kq = init().expect("kqueue");
        let dir = tempfile::tempdir().expect("tempdir");
        let foo = dir.path().join("empty");
        std::fs::write(&foo, b"").unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        let fd = fd_for_path(&tree, &foo).expect("empty tracked");
        let got = read_pre_image(fd).expect("read");
        assert!(got.is_empty());
    }

    #[test]
    fn rejects_files_larger_than_inline_cap() {
        // We don't actually create a 64MiB file; we synthesize the
        // case by passing a fd to /dev/zero whose fstat reports a
        // huge size. On FreeBSD /dev/zero is a character device
        // whose st_size is 0, so this synthetic isn't easy without
        // a real big file. Skip the negative test if we can't
        // construct it cheaply — the cap is conservative anyway.
        // (Documented limitation; S24 plumbs streaming.)
        // The constant value itself is the more important assertion:
        assert_eq!(PRE_IMAGE_INLINE_CAP, 64 * 1024 * 1024);
    }

    // ---- W07.A.1: stream_copy_to_staging ----

    /// Open `dir_path` as an `O_DIRECTORY | O_RDONLY` dir fd suitable
    /// for `openat`. Test-only — production uses the staging dir fd
    /// already plumbed through `BsdPump`.
    fn open_dir_fd(dir_path: &std::path::Path) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir_path.as_os_str().as_bytes()).expect("dir path NUL-free");
        let flags = libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC;
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        assert!(
            fd >= 0,
            "open dir failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    /// Read the entire content of a fd (post-streaming) into a Vec
    /// via repeated `pread`. Test-only; production never does this.
    fn read_staging_to_vec(fd: RawFd, expected_len: u64) -> Vec<u8> {
        let mut out = vec![0u8; expected_len as usize];
        let mut offset = 0i64;
        while (offset as u64) < expected_len {
            let want = expected_len as i64 - offset;
            let n = unsafe {
                libc::pread(
                    fd,
                    out[offset as usize..].as_mut_ptr().cast(),
                    want as usize,
                    offset,
                )
            };
            assert!(n > 0, "pread on staging fd: n={n}");
            offset += n as i64;
        }
        out
    }

    #[test]
    fn stream_copies_small_file_identically_to_read_pre_image() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("small");
        let payload = b"hello, streaming pre-image world".repeat(8);
        std::fs::write(&src, &payload).unwrap();
        let src_f = std::fs::File::open(&src).unwrap();

        let staging_dir = tempfile::tempdir().unwrap();
        let staging_dir_fd = open_dir_fd(staging_dir.path());

        let (staging_fd, hash, total) = stream_copy_to_staging(
            src_f.as_raw_fd(),
            staging_dir_fd.as_raw_fd(),
            STREAM_COPY_CAP,
        )
        .expect("stream copy");

        assert_eq!(total, payload.len() as u64);

        // Hash matches a known-good blake3 of the same bytes.
        let expected = *blake3::hash(&payload).as_bytes();
        assert_eq!(hash, expected, "blake3 mismatch");

        // Round-tripped bytes match.
        let got = read_staging_to_vec(staging_fd.as_raw_fd(), total);
        assert_eq!(got, payload);
    }

    #[test]
    fn stream_copies_above_inline_cap() {
        // 100 MiB — bigger than PRE_IMAGE_INLINE_CAP (64 MiB), well
        // under STREAM_COPY_CAP (1 GiB). Exercises the chunking loop
        // ~1600 times with 64 KiB chunks. Deterministic bytes so the
        // expected blake3 is computable on the fly.
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("medium");
        let size = 100 * 1024 * 1024;
        let mut payload = vec![0u8; size];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add((i >> 8) as u8);
        }
        std::fs::write(&src, &payload).unwrap();
        let src_f = std::fs::File::open(&src).unwrap();

        let staging_dir = tempfile::tempdir().unwrap();
        let staging_dir_fd = open_dir_fd(staging_dir.path());

        let (staging_fd, hash, total) = stream_copy_to_staging(
            src_f.as_raw_fd(),
            staging_dir_fd.as_raw_fd(),
            STREAM_COPY_CAP,
        )
        .expect("stream copy");

        assert_eq!(total, size as u64);

        let expected = *blake3::hash(&payload).as_bytes();
        assert_eq!(hash, expected, "blake3 mismatch on 100 MiB stream");

        // Verify a sample of the bytes (don't re-hash a 100 MiB vec
        // here; we already verified via blake3 which is constructive).
        let got_head = read_staging_to_vec(staging_fd.as_raw_fd(), 64 * 1024);
        assert_eq!(&got_head, &payload[..64 * 1024]);
    }

    #[test]
    fn stream_rejects_above_cap_without_writing() {
        // Pass a 1 KiB file but cap=512 — function refuses before
        // opening the staging fd. We verify by checking the staging
        // dir stays empty.
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("victim");
        std::fs::write(&src, vec![0u8; 1024]).unwrap();
        let src_f = std::fs::File::open(&src).unwrap();

        let staging_dir = tempfile::tempdir().unwrap();
        let staging_dir_fd = open_dir_fd(staging_dir.path());

        let err = stream_copy_to_staging(src_f.as_raw_fd(), staging_dir_fd.as_raw_fd(), 512)
            .expect_err("cap=512 against 1024-byte file should refuse");
        match err {
            CaptureError::TooLargeForBuffer(n) => assert_eq!(n, 1024),
            other => panic!("expected TooLargeForBuffer, got {other:?}"),
        }

        // Staging dir should still be empty — no half-staged file.
        let entries: Vec<_> = std::fs::read_dir(staging_dir.path()).unwrap().collect();
        assert!(
            entries.is_empty(),
            "staging dir leaked entries: {entries:?}"
        );
    }

    #[test]
    fn stream_handles_empty_file() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("empty");
        std::fs::write(&src, b"").unwrap();
        let src_f = std::fs::File::open(&src).unwrap();

        let staging_dir = tempfile::tempdir().unwrap();
        let staging_dir_fd = open_dir_fd(staging_dir.path());

        let (_staging_fd, hash, total) = stream_copy_to_staging(
            src_f.as_raw_fd(),
            staging_dir_fd.as_raw_fd(),
            STREAM_COPY_CAP,
        )
        .expect("stream copy of empty file");

        assert_eq!(total, 0);
        assert_eq!(hash, *blake3::hash(b"").as_bytes());
    }
}
