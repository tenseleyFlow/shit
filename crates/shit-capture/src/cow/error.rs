// SPDX-License-Identifier: AGPL-3.0-or-later

use shit_planner::BlobHash;
use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CowError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("hash mismatch: source mutated mid-capture (expected {expected}, got {actual})")]
    HashMismatch {
        expected: BlobHash,
        actual: BlobHash,
    },
    #[error("source mutated mid-capture: mtime/size/inode changed")]
    SourceMutated,
    #[error("no viable cow tier for src={src:?} dest={dest:?}")]
    NoViableTier { src: PathBuf, dest: PathBuf },
    /// The tier was attempted but the kernel said no. Caller falls through
    /// to the next tier in its preference list.
    #[error("tier {tier} not supported on this fs: {detail}")]
    TierUnsupported { tier: &'static str, detail: String },
    #[error("blob store error: {0}")]
    Store(#[from] shit_store::BlobError),
}

impl CowError {
    /// True when the caller should try the next tier rather than abort.
    pub fn is_fallthrough(&self) -> bool {
        matches!(self, CowError::TierUnsupported { .. })
    }
}
