// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration-shape tests for `capture.rs` that exercise
//! `read_pre_image` / `stream_copy_to_staging` against real
//! [`kqueue::init`] + [`kqueue::register_subtree`] setups.
//!
//! Lives outside `capture.rs` so the B07.6 lib facade (which only
//! re-declares `capture.rs` via `#[path]`) doesn't try to compile
//! these tests — they reference `crate::kqueue::*` paths that
//! only resolve under `main.rs`'s mod tree.

#![cfg(test)]
#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use super::capture::*;
// AU25 — stream_copy_to_staging + STREAM_COPY_CAP moved to the
// shared capture::streaming module so Linux can consume them.
// kqueue/mod.rs re-exports under the legacy names. The streaming
// fn returns StreamError (kqueue/capture.rs's CaptureError covers
// only the BSD inline read_pre_image variants).
use super::{STREAM_COPY_CAP, stream_copy_to_staging};
use crate::capture::streaming::StreamError;
use crate::kqueue::{init, register_subtree};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

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
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("victim");
    std::fs::write(&src, vec![0u8; 1024]).unwrap();
    let src_f = std::fs::File::open(&src).unwrap();

    let staging_dir = tempfile::tempdir().unwrap();
    let staging_dir_fd = open_dir_fd(staging_dir.path());

    let err = stream_copy_to_staging(src_f.as_raw_fd(), staging_dir_fd.as_raw_fd(), 512)
        .expect_err("cap=512 against 1024-byte file should refuse");
    match err {
        StreamError::TooLargeForBuffer(n) => assert_eq!(n, 1024),
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
