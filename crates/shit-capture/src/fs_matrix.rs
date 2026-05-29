// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime filesystem-support matrix.
//!
//! Tier choice depends on the actual filesystem mounted at a path — users
//! attach external drives, mount network shares, run on tmpfs, etc. We
//! detect via `statfs(2)` (mac/BSD use `f_fstypename`; Linux uses the
//! magic number from `f_type`), cache per mount point, and surface a
//! per-FS preference list.

use crate::cow::CowTier;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FsKind {
    Apfs,
    Hfs,
    Btrfs,
    Xfs,
    Ext4,
    Ext3,
    Ext2,
    Zfs,
    Ufs,
    Tmpfs,
    Nfs,
    Smb,
    Sshfs,
    Fuse,
    Procfs,
    Sysfs,
    Devfs,
    Overlayfs,
    Other(String),
}

impl FsKind {
    pub fn as_str(&self) -> &str {
        match self {
            FsKind::Apfs => "apfs",
            FsKind::Hfs => "hfs",
            FsKind::Btrfs => "btrfs",
            FsKind::Xfs => "xfs",
            FsKind::Ext4 => "ext4",
            FsKind::Ext3 => "ext3",
            FsKind::Ext2 => "ext2",
            FsKind::Zfs => "zfs",
            FsKind::Ufs => "ufs",
            FsKind::Tmpfs => "tmpfs",
            FsKind::Nfs => "nfs",
            FsKind::Smb => "smb",
            FsKind::Sshfs => "sshfs",
            FsKind::Fuse => "fuse",
            FsKind::Procfs => "procfs",
            FsKind::Sysfs => "sysfs",
            FsKind::Devfs => "devfs",
            FsKind::Overlayfs => "overlayfs",
            FsKind::Other(s) => s,
        }
    }

    /// True when capture against this FS is unsafe or pointless — we
    /// refuse the syscall when hard-fail is on.
    pub fn is_synthetic(&self) -> bool {
        matches!(self, FsKind::Procfs | FsKind::Sysfs | FsKind::Devfs)
    }

    /// True when capture pays a real network round-trip per read.
    pub fn is_network(&self) -> bool {
        matches!(self, FsKind::Nfs | FsKind::Smb | FsKind::Sshfs)
    }
}

/// Per-FS tier preference, highest-priority first.
///
/// The default engine attempts tiers in this order, falling through on
/// `CowError::TierUnsupported`. Streaming is always the terminal fallback
/// for non-synthetic filesystems.
pub fn supported_tiers(fs: &FsKind) -> Vec<CowTier> {
    match fs {
        FsKind::Apfs => vec![
            CowTier::Clonefile,
            CowTier::Hardlink,
            CowTier::StreamingCopy,
        ],
        FsKind::Btrfs => vec![
            CowTier::Reflink,
            CowTier::CopyFileRange,
            CowTier::Hardlink,
            CowTier::StreamingCopy,
        ],
        FsKind::Xfs => vec![
            // Reflink only when the volume was made with `mkfs.xfs -m reflink=1`.
            // We surface it as available; the FICLONE attempt fails fast on
            // non-reflink XFS and the engine falls through.
            CowTier::Reflink,
            CowTier::CopyFileRange,
            CowTier::Hardlink,
            CowTier::StreamingCopy,
        ],
        FsKind::Ext4 | FsKind::Ext3 | FsKind::Ext2 => vec![
            CowTier::CopyFileRange,
            CowTier::Hardlink,
            CowTier::StreamingCopy,
        ],
        FsKind::Zfs => {
            // AU01.A: per-event clone tier on BSDs (snapshot → clone
            // → read → destroy). Engine falls through to hardlink /
            // streaming on non-ZFS hosts or when /sbin/zfs isn't
            // installed. On non-BSD targets the dispatch returns
            // TierUnsupported, so omit ZfsClone here to skip a
            // round-trip.
            #[cfg(any(
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "dragonfly",
            ))]
            {
                vec![
                    CowTier::ZfsClone,
                    CowTier::Hardlink,
                    CowTier::StreamingCopy,
                ]
            }
            #[cfg(not(any(
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "dragonfly",
            )))]
            {
                vec![CowTier::Hardlink, CowTier::StreamingCopy]
            }
        }
        FsKind::Ufs => vec![
            CowTier::CopyFileRange,
            CowTier::Hardlink,
            CowTier::StreamingCopy,
        ],
        FsKind::Hfs | FsKind::Tmpfs | FsKind::Fuse | FsKind::Overlayfs => {
            vec![CowTier::Hardlink, CowTier::StreamingCopy]
        }
        FsKind::Nfs | FsKind::Smb | FsKind::Sshfs => vec![CowTier::StreamingCopy],
        FsKind::Procfs | FsKind::Sysfs | FsKind::Devfs => vec![],
        FsKind::Other(_) => vec![CowTier::StreamingCopy],
    }
}

/// Picks the best tier supported by *both* source and destination
/// filesystems. Reflink/clonefile/copy_file_range require same-volume
/// when the kernel says so; if the FS kinds differ we drop to a tier
/// that doesn't care about volume identity.
pub fn pick_tier(src_fs: &FsKind, dest_fs: &FsKind, src_doomed: bool) -> Option<CowTier> {
    let src_tiers = supported_tiers(src_fs);
    let dest_tiers = supported_tiers(dest_fs);
    let cross_volume = src_fs != dest_fs;

    for tier in src_tiers {
        // Hardlink tier needs the caller to have promised the source is
        // doomed (S05 design note: hardlink corrupts the source if it
        // outlives capture).
        if tier == CowTier::Hardlink && !src_doomed {
            continue;
        }
        if !dest_tiers.contains(&tier) {
            continue;
        }
        // Same-volume requirement for the kernel-side-clone tiers.
        if cross_volume
            && matches!(
                tier,
                CowTier::Clonefile | CowTier::Reflink | CowTier::ZfsClone
            )
        {
            continue;
        }
        return Some(tier);
    }
    None
}

/// Detect the filesystem kind backing `path`. Result is cached per
/// device id (`st_dev`) so repeated capture against the same mount only
/// pays one statfs.
pub fn detect_fs(path: &Path) -> io::Result<FsKind> {
    let dev = std::fs::metadata(path).map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.dev()
    })?;
    if let Some(cached) = CACHE.lock().unwrap().get(&dev).cloned() {
        return Ok(cached);
    }
    let kind = detect_fs_uncached(path)?;
    CACHE.lock().unwrap().insert(dev, kind.clone());
    Ok(kind)
}

/// Wipe the per-mount cache. Call this on mount/umount; for now exposed
/// for tests and for `shit doctor --refresh`.
pub fn invalidate_cache() {
    CACHE.lock().unwrap().clear();
}

static CACHE: Mutex<CacheMap> = Mutex::new(CacheMap::new());

struct CacheMap(Option<HashMap<u64, FsKind>>);

impl CacheMap {
    const fn new() -> Self {
        Self(None)
    }
    fn get(&mut self, k: &u64) -> Option<&FsKind> {
        self.0.as_ref().and_then(|m| m.get(k))
    }
    fn insert(&mut self, k: u64, v: FsKind) {
        self.0.get_or_insert_with(HashMap::new).insert(k, v);
    }
    fn clear(&mut self) {
        if let Some(m) = self.0.as_mut() {
            m.clear();
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_fs_uncached(path: &Path) -> io::Result<FsKind> {
    let s = nix::sys::statfs::statfs(path).map_err(io::Error::from)?;
    Ok(map_linux_fs_type(s.filesystem_type()))
}

#[cfg(target_os = "linux")]
fn map_linux_fs_type(t: nix::sys::statfs::FsType) -> FsKind {
    use nix::sys::statfs;
    if t == statfs::BTRFS_SUPER_MAGIC {
        FsKind::Btrfs
    } else if t == statfs::XFS_SUPER_MAGIC {
        FsKind::Xfs
    } else if t == statfs::EXT4_SUPER_MAGIC {
        // EXT2/3/4 all share this magic; distinguishing requires mountinfo.
        FsKind::Ext4
    } else if t == statfs::TMPFS_MAGIC {
        FsKind::Tmpfs
    } else if t == statfs::PROC_SUPER_MAGIC {
        FsKind::Procfs
    } else if t == statfs::SYSFS_MAGIC {
        FsKind::Sysfs
    } else if t == statfs::NFS_SUPER_MAGIC {
        FsKind::Nfs
    } else if t == statfs::SMB_SUPER_MAGIC {
        FsKind::Smb
    } else if t == statfs::OVERLAYFS_SUPER_MAGIC {
        FsKind::Overlayfs
    } else if t == statfs::FUSE_SUPER_MAGIC {
        FsKind::Fuse
    } else {
        FsKind::Other(format!("magic={:#x}", t.0))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn detect_fs_uncached(path: &Path) -> io::Result<FsKind> {
    use nix::sys::statfs;
    let s = statfs::statfs(path).map_err(io::Error::from)?;
    Ok(map_name(s.filesystem_type_name()))
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn detect_fs_uncached(path: &Path) -> io::Result<FsKind> {
    use nix::sys::statfs;
    let s = statfs::statfs(path).map_err(io::Error::from)?;
    Ok(map_name(s.filesystem_type_name()))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn detect_fs_uncached(_path: &Path) -> io::Result<FsKind> {
    Ok(FsKind::Other("unsupported-os".into()))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
#[allow(dead_code)]
fn map_name(name: &str) -> FsKind {
    // f_fstypename returns lowercase short names: "apfs", "hfs", "ufs", "zfs",
    // "tmpfs", "devfs", "nfs", "smbfs", etc.
    match name {
        "apfs" => FsKind::Apfs,
        "hfs" => FsKind::Hfs,
        "ufs" => FsKind::Ufs,
        "zfs" => FsKind::Zfs,
        "tmpfs" => FsKind::Tmpfs,
        "devfs" => FsKind::Devfs,
        "procfs" | "proc" => FsKind::Procfs,
        "nfs" => FsKind::Nfs,
        "smbfs" | "smb" | "cifs" => FsKind::Smb,
        "fuse" | "osxfuse" | "macfuse" | "fuse.sshfs" | "sshfs" => {
            if name.contains("sshfs") {
                FsKind::Sshfs
            } else {
                FsKind::Fuse
            }
        }
        other => FsKind::Other(other.to_string()),
    }
}

/// Convenience: detect on a (presumably-existing) path with informative
/// errors when statfs fails.
pub fn detect_or_default(path: &Path) -> FsKind {
    match detect_fs(path) {
        Ok(k) => k,
        Err(e) => {
            tracing::debug!(path = %path.display(), err = %e, "fs detect failed; treating as Other");
            FsKind::Other("unknown".into())
        }
    }
}

/// Public alias for tests: stat-and-cache a directory we know exists.
pub fn detected_kind_of(path: &Path) -> io::Result<FsKind> {
    detect_fs(path)
}

#[doc(hidden)]
pub fn _force_cached(dev: u64, kind: FsKind) {
    CACHE.lock().unwrap().insert(dev, kind);
}

#[allow(dead_code)]
pub(crate) fn _path_buf(p: &Path) -> PathBuf {
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_and_network_classification() {
        assert!(FsKind::Procfs.is_synthetic());
        assert!(FsKind::Sysfs.is_synthetic());
        assert!(FsKind::Devfs.is_synthetic());
        assert!(!FsKind::Apfs.is_synthetic());
        assert!(FsKind::Nfs.is_network());
        assert!(FsKind::Smb.is_network());
        assert!(!FsKind::Apfs.is_network());
    }

    #[test]
    fn supported_tiers_for_apfs_includes_clonefile() {
        let t = supported_tiers(&FsKind::Apfs);
        assert_eq!(t.first(), Some(&CowTier::Clonefile));
        assert!(t.contains(&CowTier::StreamingCopy));
    }

    #[test]
    fn supported_tiers_for_btrfs_includes_reflink() {
        let t = supported_tiers(&FsKind::Btrfs);
        assert_eq!(t.first(), Some(&CowTier::Reflink));
    }

    #[test]
    fn supported_tiers_for_ext4_starts_with_copy_file_range() {
        let t = supported_tiers(&FsKind::Ext4);
        assert_eq!(t.first(), Some(&CowTier::CopyFileRange));
        assert!(!t.contains(&CowTier::Reflink));
    }

    #[test]
    fn synthetic_fs_has_no_tiers() {
        assert!(supported_tiers(&FsKind::Procfs).is_empty());
        assert!(supported_tiers(&FsKind::Sysfs).is_empty());
        assert!(supported_tiers(&FsKind::Devfs).is_empty());
    }

    #[test]
    fn pick_tier_same_fs_apfs() {
        let t = pick_tier(&FsKind::Apfs, &FsKind::Apfs, false);
        assert_eq!(t, Some(CowTier::Clonefile));
    }

    #[test]
    fn pick_tier_cross_volume_drops_kernel_clone() {
        // APFS source, ext4 dest: cross-volume + ext4 has no clonefile.
        let t = pick_tier(&FsKind::Apfs, &FsKind::Ext4, false);
        // Falls through to streaming since Apfs preference list doesn't
        // include copy_file_range and hardlink across volumes is OS-no.
        assert_eq!(t, Some(CowTier::StreamingCopy));
    }

    #[test]
    fn pick_tier_synthetic_yields_none() {
        assert_eq!(pick_tier(&FsKind::Procfs, &FsKind::Apfs, false), None);
    }

    #[test]
    fn pick_tier_doomed_unlocks_hardlink_on_zfs() {
        // ZFS preference is [Hardlink, StreamingCopy].
        let with_doom = pick_tier(&FsKind::Zfs, &FsKind::Zfs, true);
        let without = pick_tier(&FsKind::Zfs, &FsKind::Zfs, false);
        assert_eq!(with_doom, Some(CowTier::Hardlink));
        assert_eq!(without, Some(CowTier::StreamingCopy));
    }

    #[test]
    fn detect_fs_on_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let kind = detect_fs(tmp.path()).unwrap();
        // On the dev macbook this is Apfs; on Linux CI runners typically
        // Ext4/Btrfs/Tmpfs; on FreeBSD UFS or ZFS. Just assert non-empty.
        assert!(!kind.as_str().is_empty());
    }
}
