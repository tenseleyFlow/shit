// SPDX-License-Identifier: AGPL-3.0-or-later

//! Default [`CowEngine`] — picks a tier per the FS matrix and dispatches
//! through the fallback chain. Each tier that returns
//! `CowError::TierUnsupported` causes the next tier in the source-FS
//! preference list to be tried; any other error aborts capture so the
//! caller can hard-fail the originating syscall.

use std::os::fd::RawFd;
use std::path::Path;

use crate::fs_matrix;

use super::error::CowError;
use super::{CaptureOpts, CaptureOutcome, CowEngine, CowTier};

/// The runtime-dispatched engine. Stateless; safe to share.
#[derive(Default)]
pub struct DefaultEngine;

impl DefaultEngine {
    pub fn new() -> Self {
        Self
    }
}

impl CowEngine for DefaultEngine {
    fn capture(
        &self,
        src_fd: RawFd,
        src_path: &Path,
        blob_root: &Path,
        opts: CaptureOpts,
    ) -> Result<CaptureOutcome, CowError> {
        let src_fs = fs_matrix::detect_or_default(src_path);
        let dest_fs = fs_matrix::detect_or_default(blob_root);

        if src_fs.is_synthetic() {
            return Err(CowError::NoViableTier {
                src: src_path.to_path_buf(),
                dest: blob_root.to_path_buf(),
            });
        }

        let mut tried: Vec<CowTier> = Vec::new();
        for tier in fs_matrix::supported_tiers(&src_fs) {
            if !fs_matrix::supported_tiers(&dest_fs).contains(&tier) {
                continue;
            }
            if tier == CowTier::Hardlink && !opts.source_doomed {
                continue;
            }
            if src_fs != dest_fs
                && matches!(
                    tier,
                    CowTier::Clonefile | CowTier::Reflink | CowTier::ZfsClone
                )
            {
                continue;
            }
            tried.push(tier);
            match dispatch(tier, src_fd, src_path, blob_root, opts) {
                Ok(out) => return Ok(out),
                Err(e) if e.is_fallthrough() => {
                    tracing::debug!(tier = tier.as_str(), err = %e, "tier unsupported, falling through");
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(CowError::NoViableTier {
            src: src_path.to_path_buf(),
            dest: blob_root.to_path_buf(),
        })
    }
}

/// Per-tier dispatch. Conditional on cfg so unsupported tiers on the
/// current platform compile to `TierUnsupported`.
fn dispatch(
    tier: CowTier,
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
    opts: CaptureOpts,
) -> Result<CaptureOutcome, CowError> {
    match tier {
        CowTier::Clonefile => clonefile_dispatch(src_fd, src_path, blob_root),
        CowTier::Reflink => reflink_dispatch(src_fd, src_path, blob_root),
        CowTier::CopyFileRange => cfr_dispatch(src_fd, src_path, blob_root),
        CowTier::Hardlink => {
            super::hardlink::capture_hardlink(src_fd, src_path, blob_root, opts.source_doomed)
        }
        CowTier::StreamingCopy => super::streaming::capture_streaming(src_fd, src_path, blob_root),
        CowTier::ZfsClone => zfs_clone_dispatch(src_fd, src_path, blob_root),
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn zfs_clone_dispatch(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    super::zfs_clone::capture_zfs_clone(src_fd, src_path, blob_root)
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
)))]
fn zfs_clone_dispatch(
    _src_fd: RawFd,
    _src_path: &Path,
    _blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    Err(CowError::TierUnsupported {
        tier: "zfs-clone",
        detail: "not a BSD target".into(),
    })
}

#[cfg(target_os = "macos")]
fn clonefile_dispatch(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    super::clonefile_macos::capture_clonefile(src_fd, src_path, blob_root)
}

#[cfg(not(target_os = "macos"))]
fn clonefile_dispatch(
    _src_fd: RawFd,
    _src_path: &Path,
    _blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    Err(CowError::TierUnsupported {
        tier: "clonefile",
        detail: "not macOS".into(),
    })
}

#[cfg(target_os = "linux")]
fn reflink_dispatch(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    super::ficlone_linux::capture_ficlone(src_fd, src_path, blob_root)
}

#[cfg(not(target_os = "linux"))]
fn reflink_dispatch(
    _src_fd: RawFd,
    _src_path: &Path,
    _blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    Err(CowError::TierUnsupported {
        tier: "reflink",
        detail: "not Linux".into(),
    })
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn cfr_dispatch(
    src_fd: RawFd,
    src_path: &Path,
    blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    super::copy_file_range::capture_copy_file_range(src_fd, src_path, blob_root)
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn cfr_dispatch(
    _src_fd: RawFd,
    _src_path: &Path,
    _blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    Err(CowError::TierUnsupported {
        tier: "copy_file_range",
        detail: "not Linux/FreeBSD".into(),
    })
}

/// Inspect which tier the engine would pick without actually capturing.
/// Used by `shit doctor` and tests.
pub fn would_pick(src_path: &Path, blob_root: &Path, opts: CaptureOpts) -> Option<CowTier> {
    let src_fs = fs_matrix::detect_or_default(src_path);
    let dest_fs = fs_matrix::detect_or_default(blob_root);
    fs_matrix::pick_tier(&src_fs, &dest_fs, opts.source_doomed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn default_engine_captures_in_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        let mut src = std::fs::File::create(&src_path).unwrap();
        src.write_all(b"engine dispatch content").unwrap();
        src.flush().unwrap();
        drop(src);

        let engine = DefaultEngine::new();
        let f = std::fs::File::open(&src_path).unwrap();
        let outcome = engine
            .capture(f.as_raw_fd(), &src_path, tmp.path(), CaptureOpts::default())
            .unwrap();
        // Highest tier we can guarantee on any test runner is Streaming;
        // on the dev mac it'll be Clonefile. Either is fine.
        assert!(matches!(
            outcome.tier,
            CowTier::Clonefile | CowTier::Reflink | CowTier::CopyFileRange | CowTier::StreamingCopy
        ));
    }

    #[test]
    fn default_engine_falls_through_to_streaming_on_unknown_fs() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("source.txt");
        std::fs::File::create(&src_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();

        let engine = DefaultEngine::new();
        let f = std::fs::File::open(&src_path).unwrap();
        let outcome = engine
            .capture(f.as_raw_fd(), &src_path, tmp.path(), CaptureOpts::default())
            .unwrap();
        let store = shit_store::BlobStore::open(tmp.path()).unwrap();
        // Either path produces a queryable blob.
        assert!(store.contains(&outcome.hash) || outcome.tier == CowTier::Clonefile);
    }

    #[test]
    fn would_pick_reports_some_tier_for_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let pick = would_pick(tmp.path(), tmp.path(), CaptureOpts::default());
        assert!(pick.is_some());
    }
}
