// SPDX-License-Identifier: AGPL-3.0-or-later

//! `StateProbe` — read-only abstraction over current filesystem state.
//!
//! Production probes are thin wrappers over `statx`/`fstatat`; tests use an
//! in-memory state machine. The planner uses the probe to answer "is the
//! current state still consistent with what we recorded?" and to
//! classify conflicts.

use crate::inode::{BlobHash, InodeRef};
use crate::metadata::FileMetadata;
use std::path::Path;

pub trait StateProbe {
    /// Stat the path. Returns `None` when the path doesn't exist.
    fn stat(&self, path: &Path) -> Option<ProbeStat>;

    /// Hash the current content of the path (blake3). Returns `None` when
    /// the path doesn't exist or isn't a regular file.
    fn content_hash(&self, path: &Path) -> Option<BlobHash>;

    /// Cheap existence check; defaults to `stat(...).is_some()` but can be
    /// implemented more efficiently per-backend.
    fn exists(&self, path: &Path) -> bool {
        self.stat(path).is_some()
    }
}

/// Result of a [`StateProbe::stat`] call: enough to identify and classify
/// the file. We intentionally don't return raw `std::fs::Metadata` so the
/// trait stays platform-portable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStat {
    pub inode: InodeRef,
    pub meta: FileMetadata,
}

/// In-memory probe for tests. Maps paths to `ProbeStat` + (optional) content
/// hash. Useful for property tests around conflict detection.
pub mod mock {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[derive(Default, Debug, Clone)]
    pub struct InMemoryProbe {
        pub by_path: BTreeMap<PathBuf, (ProbeStat, Option<BlobHash>)>,
    }

    impl InMemoryProbe {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn insert(&mut self, path: PathBuf, stat: ProbeStat, hash: Option<BlobHash>) {
            self.by_path.insert(path, (stat, hash));
        }

        pub fn remove(&mut self, path: &Path) {
            self.by_path.remove(path);
        }
    }

    impl StateProbe for InMemoryProbe {
        fn stat(&self, path: &Path) -> Option<ProbeStat> {
            self.by_path.get(path).map(|(s, _)| s.clone())
        }

        fn content_hash(&self, path: &Path) -> Option<BlobHash> {
            self.by_path.get(path).and_then(|(_, h)| *h)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::InMemoryProbe;
    use super::*;
    use crate::metadata::FileMetadata;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_stat() -> ProbeStat {
        ProbeStat {
            inode: InodeRef::new(1, 42),
            meta: FileMetadata {
                mode: 0o100644,
                uid: 0,
                gid: 0,
                size: 100,
                mtime_unix_nanos: 0,
                xattrs: BTreeMap::new(),
                acl: None,
            },
        }
    }

    #[test]
    fn probe_finds_inserted() {
        let mut p = InMemoryProbe::new();
        let path = PathBuf::from("/tmp/x");
        let stat = sample_stat();
        p.insert(
            path.clone(),
            stat.clone(),
            Some(BlobHash::from_bytes([1; 32])),
        );
        assert_eq!(p.stat(&path), Some(stat));
        assert!(p.exists(&path));
        assert_eq!(p.content_hash(&path), Some(BlobHash::from_bytes([1; 32])));
    }

    #[test]
    fn probe_missing_returns_none() {
        let p = InMemoryProbe::new();
        assert!(p.stat(Path::new("/nope")).is_none());
        assert!(!p.exists(Path::new("/nope")));
        assert!(p.content_hash(Path::new("/nope")).is_none());
    }
}
