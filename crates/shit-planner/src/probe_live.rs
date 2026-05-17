// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live-filesystem [`StateProbe`] implementation (S11.6).
//!
//! Real syscalls — `lstat(2)` / `symlink_metadata` for stat, fully
//! streamed `blake3::Hasher::update_reader` for content hash. Used by
//! the orchestrator's per-op conflict re-detection (S11.7).
//!
//! ## Why we re-probe at execute time
//!
//! The planner's plan-time conflict scan ([S03](crate)) is
//! best-effort: it consults whatever `StateProbe` the daemon had
//! around at plan-build time, which may be stale by the time the
//! user accepts the plan. Re-probing right before mutation is the
//! authoritative answer.

use std::io;
use std::path::Path;

use crate::inode::{BlobHash, InodeRef};
use crate::metadata::FileMetadata;
use crate::probe::{ProbeStat, StateProbe};

/// Stat + hash the live filesystem.
#[derive(Default, Debug, Clone, Copy)]
pub struct LiveStateProbe;

impl LiveStateProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl StateProbe for LiveStateProbe {
    fn stat(&self, path: &Path) -> Option<ProbeStat> {
        use std::os::unix::fs::MetadataExt;

        let meta = std::fs::symlink_metadata(path).ok()?;
        let inode = InodeRef::new(meta.dev(), meta.ino());
        // mtime: MetadataExt gives sec + nsec; combine into i128.
        let mtime_ns = (meta.mtime() as i128) * 1_000_000_000 + (meta.mtime_nsec() as i128);
        let fm = FileMetadata {
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            size: meta.size(),
            mtime_unix_nanos: mtime_ns,
            // xattrs/ACL not read at probe time — the planner only
            // uses them for content equality checks, which already
            // bottoms out at content_hash for the common case.
            xattrs: Default::default(),
            acl: None,
        };
        Some(ProbeStat { inode, meta: fm })
    }

    fn content_hash(&self, path: &Path) -> Option<BlobHash> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        hash_file(path).ok()
    }
}

/// Stream the file through blake3. Used by tests and by the
/// orchestrator's conflict check.
pub fn hash_file(path: &Path) -> io::Result<BlobHash> {
    let f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut reader = std::io::BufReader::new(f);
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(BlobHash::from_bytes(*hasher.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_missing_path_is_none() {
        let p = LiveStateProbe::new();
        assert!(p.stat(Path::new("/no/such/path/shit-test")).is_none());
        assert!(!p.exists(Path::new("/no/such/path/shit-test")));
    }

    #[test]
    fn stat_real_file_returns_inode_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"hello").unwrap();
        let p = LiveStateProbe::new();
        let s = p.stat(&path).expect("stat present");
        assert_eq!(s.meta.size, 5);
        assert_eq!(s.meta.mode & 0o100000, 0o100000); // regular file bit
    }

    #[test]
    fn content_hash_of_known_blob_is_blake3_of_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"hello").unwrap();
        let got = LiveStateProbe.content_hash(&path).expect("hash");
        let expected = BlobHash::from_bytes(*blake3::hash(b"hello").as_bytes());
        assert_eq!(got, expected);
    }

    #[test]
    fn content_hash_on_directory_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(LiveStateProbe.content_hash(dir.path()).is_none());
    }

    #[test]
    fn content_hash_on_symlink_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // content_hash uses lstat — a symlink is not a regular file.
        assert!(LiveStateProbe.content_hash(&link).is_none());
    }
}
