// SPDX-License-Identifier: AGPL-3.0-or-later

//! File metadata snapshot used by capture and inverse-op planning.
//!
//! Captures the subset of file attributes the planner can plausibly restore:
//! `mode`, `uid`/`gid`, size, mtime, xattrs, ACL. Bytes-of-ACL are OS-specific
//! and opaque to the planner; the executor (S11) interprets them per platform.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Snapshot of restorable file attributes at a single point in time.
///
/// Ordering: `xattrs` is a `BTreeMap` (not `HashMap`) so two snapshots with
/// identical attribute sets serialize byte-identically. That's important for
/// deduplication and for testing equality semantically rather than by
/// reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_unix_nanos: i128,
    pub xattrs: BTreeMap<String, Vec<u8>>,
    /// OS-specific opaque blob (POSIX ACL bytes on Linux, NFSv4 ACL on
    /// macOS/BSD). `None` means "not captured on this platform" — distinct
    /// from "no ACL".
    pub acl: Option<Vec<u8>>,
    /// BSD/macOS `st_flags`: the chflags(2) attribute bitmap
    /// (UF_IMMUTABLE, UF_HIDDEN, SF_NOUNLINK, …). 0 on Linux (no such
    /// concept) and on captures predating M03.x.SETATTR — `#[serde(default)]`
    /// keeps those decodable.
    #[serde(default)]
    pub flags: u32,
}

impl FileMetadata {
    /// Coarse equality used for "are we still in the captured state?" probes.
    /// Excludes `mtime`, which legitimately changes for read-only opens on
    /// some filesystems; size+mode+xattrs is the practical identity.
    pub fn semantically_equal(&self, other: &FileMetadata) -> bool {
        self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.size == other.size
            && self.xattrs == other.xattrs
            && self.acl == other.acl
            && self.flags == other.flags
    }
}

/// Kinds of filesystem entries we distinguish for tree-op events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
}

impl FileKind {
    pub fn from_mode(mode: u32) -> Option<Self> {
        const S_IFMT: u32 = 0o170000;
        const S_IFREG: u32 = 0o100000;
        const S_IFDIR: u32 = 0o040000;
        const S_IFLNK: u32 = 0o120000;
        const S_IFIFO: u32 = 0o010000;
        const S_IFSOCK: u32 = 0o140000;
        const S_IFBLK: u32 = 0o060000;
        const S_IFCHR: u32 = 0o020000;
        match mode & S_IFMT {
            S_IFREG => Some(Self::Regular),
            S_IFDIR => Some(Self::Directory),
            S_IFLNK => Some(Self::Symlink),
            S_IFIFO => Some(Self::Fifo),
            S_IFSOCK => Some(Self::Socket),
            S_IFBLK => Some(Self::BlockDevice),
            S_IFCHR => Some(Self::CharDevice),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(size: u64, mtime: i128) -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size,
            mtime_unix_nanos: mtime,
            xattrs: BTreeMap::new(),
            acl: None,
            flags: 0,
        }
    }

    #[test]
    fn semantically_equal_ignores_mtime() {
        let a = sample(100, 1);
        let b = sample(100, 999);
        assert!(a.semantically_equal(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn semantically_equal_catches_size_change() {
        let a = sample(100, 1);
        let b = sample(200, 1);
        assert!(!a.semantically_equal(&b));
    }

    #[test]
    fn file_kind_decodes_regular() {
        assert_eq!(FileKind::from_mode(0o100644), Some(FileKind::Regular));
        assert_eq!(FileKind::from_mode(0o040755), Some(FileKind::Directory));
        assert_eq!(FileKind::from_mode(0o120777), Some(FileKind::Symlink));
    }
}
