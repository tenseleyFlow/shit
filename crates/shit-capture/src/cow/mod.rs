// SPDX-License-Identifier: AGPL-3.0-or-later

//! Copy-on-write capture engine.
//!
//! Per-platform tiers — reflink/clonefile when the FS supports it, falling
//! through to `copy_file_range`, hardlink, then a userspace streaming copy.
//! The [`CowEngine`] trait is the abstraction the helper layer drives.
//!
//! See `.docs/sprints/S05-cow-engine.md` for design.

use shit_planner::BlobHash;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub mod clonefile_macos;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub mod copy_file_range;
pub mod engine;
mod error;
#[cfg(target_os = "linux")]
pub mod ficlone_linux;
pub mod hardlink;
pub mod streaming;
pub mod verify;

pub use engine::{DefaultEngine, would_pick};
pub use error::CowError;

/// Which strategy actually produced the captured blob.
///
/// Order matches the preferred-tier sort: cheaper first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CowTier {
    /// macOS `clonefile(2)`: APFS atomic clone, kernel-guaranteed identity.
    Clonefile,
    /// Linux `FICLONE` ioctl: btrfs / XFS-reflink / bcachefs.
    Reflink,
    /// ZFS `zfs clone` — coarse (dataset-granularity); only used by the
    /// optional snapper-style integration deferred from v1.
    ZfsClone,
    /// Linux/FreeBSD `copy_file_range(2)`: kernel-side block copy.
    CopyFileRange,
    /// `link(2)` — only valid when the source is guaranteed to be removed
    /// or replaced. Enforced at the call site, not in the tier.
    Hardlink,
    /// Userspace `read`/`write` loop with incremental hashing.
    StreamingCopy,
}

impl CowTier {
    pub fn as_str(self) -> &'static str {
        match self {
            CowTier::Clonefile => "clonefile",
            CowTier::Reflink => "reflink",
            CowTier::ZfsClone => "zfs-clone",
            CowTier::CopyFileRange => "copy_file_range",
            CowTier::Hardlink => "hardlink",
            CowTier::StreamingCopy => "streaming",
        }
    }
}

impl std::fmt::Display for CowTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of a successful capture.
#[derive(Debug, Clone)]
pub struct CaptureOutcome {
    pub hash: BlobHash,
    pub tier: CowTier,
    /// On-disk bytes the blob occupies. May be smaller than logical size
    /// when the tier is reflink/clonefile (shared extents).
    pub stored_bytes: u64,
}

/// Capture options the call site may toggle.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureOpts {
    /// True when the caller can promise the source inode is about to be
    /// unlinked or replaced. Unlocks the [`CowTier::Hardlink`] tier.
    pub source_doomed: bool,
}

/// Abstract COW engine. The default impl picks per filesystem; tests can
/// drop in a stub.
pub trait CowEngine {
    /// Capture the file referenced by `src_fd` into the blob store at
    /// `blob_root`. Returns the content hash and which tier produced it.
    ///
    /// `src_path` is informational — used for FS detection. The actual
    /// bytes come from `src_fd` because that's what the kernel hooks
    /// hand us (defeats TOCTOU between path resolution and capture).
    fn capture(
        &self,
        src_fd: RawFd,
        src_path: &Path,
        blob_root: &Path,
        opts: CaptureOpts,
    ) -> Result<CaptureOutcome, CowError>;
}

/// Path inside the blob store for a given hash. Mirrors `shit_store::BlobStore`
/// layout: `blobs/<aa>/<bb>/<aabbcc...>`.
pub(crate) fn blob_path(root: &Path, hash: &BlobHash) -> PathBuf {
    let hex = hash.to_hex();
    let (aa, rest) = hex.split_at(2);
    let (bb, _) = rest.split_at(2);
    root.join("blobs").join(aa).join(bb).join(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_display_round_trip() {
        for t in [
            CowTier::Clonefile,
            CowTier::Reflink,
            CowTier::ZfsClone,
            CowTier::CopyFileRange,
            CowTier::Hardlink,
            CowTier::StreamingCopy,
        ] {
            assert!(!t.as_str().is_empty());
            assert_eq!(t.to_string(), t.as_str());
        }
    }

    #[test]
    fn blob_path_shards_two_levels() {
        let hash = BlobHash::from_bytes([0xAB; 32]);
        let p = blob_path(Path::new("/root"), &hash);
        assert!(p.starts_with("/root/blobs/ab/ab/"));
        assert!(p.to_string_lossy().ends_with(&"ab".repeat(32)));
    }
}
