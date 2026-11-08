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

/// L4b - the helper's proof that it saw a device node unlinked: the id
/// of the helper process that issued it and an HMAC under that
/// process's secret key. Opaque to the daemon and planner, which store
/// it and hand it back; only the issuing helper can check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureToken {
    pub helper: [u8; 16],
    pub mac: [u8; 32],
}

/// What a block or char device node needs beyond its path to be
/// recreated, and the evidence the helper wants before it will do so.
/// Every field comes from the helper's `fstat` of the held fd before
/// the unlink committed; the planner copies it from the journaled
/// `DeviceNodeMeta` and never fills any of it in itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceNode {
    /// `st_rdev`, glibc-encoded. This is the `dev_t` `mknod(2)` takes.
    pub rdev: u64,
    /// Full `st_mode` (kind and permission bits) at capture.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// `(st_dev, st_ino)` of the removed node.
    pub inode: crate::inode::InodeRef,
    /// The command that removed the node (not the undo).
    pub removed_by: crate::events::CommandId,
    /// `None` when the helper would not vouch for the capture.
    pub token: Option<CaptureToken>,
    /// Why there is no token, when the helper said.
    pub untrusted: Option<UntrustedSource>,
}

/// L4b - why the helper issued no token for a device-node capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UntrustedSource {
    Nodev,
    Unknown,
}

impl UntrustedSource {
    pub fn reason(self) -> &'static str {
        match self {
            UntrustedSource::Nodev => "source filesystem does not allow device nodes",
            UntrustedSource::Unknown => {
                "could not determine whether the source filesystem allows device nodes"
            }
        }
    }
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

    /// True when `other` differs only in the BSD/macOS flags bitmap.
    /// This lets the planner choose the field-specific `RestoreFlags`
    /// inverse and avoid unrelated ownership, mode, xattr, or mtime
    /// syscalls for a pure `chflags(2)` mutation.
    pub fn only_flags_changed(&self, other: &FileMetadata) -> bool {
        self.flags != other.flags
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.size == other.size
            && self.mtime_unix_nanos == other.mtime_unix_nanos
            && self.xattrs == other.xattrs
            && self.acl == other.acl
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
    fn only_flags_changed_rejects_other_metadata_drift() {
        let before = sample(100, 1);
        let mut flags_after = before.clone();
        flags_after.flags = 0x2;
        assert!(before.only_flags_changed(&flags_after));

        flags_after.mode = 0o100600;
        assert!(!before.only_flags_changed(&flags_after));
    }

    #[test]
    fn file_kind_decodes_regular() {
        assert_eq!(FileKind::from_mode(0o100644), Some(FileKind::Regular));
        assert_eq!(FileKind::from_mode(0o040755), Some(FileKind::Directory));
        assert_eq!(FileKind::from_mode(0o120777), Some(FileKind::Symlink));
    }
}
