// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-mutation detection. The COW tiers that can't promise byte
//! identity (streaming, copy_file_range with concurrent writers, hardlink)
//! must snapshot the source's identity before and after copy and bail if
//! they don't match.

use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;

use super::error::CowError;

/// Fingerprint of the source fd at a given moment. Compared via `==`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceFingerprint {
    pub ino: u64,
    pub dev: u64,
    pub size: u64,
    pub mtime_secs: i64,
    pub mtime_nsecs: i64,
}

impl SourceFingerprint {
    /// Take a fingerprint of an open fd. Uses `fstat` so the kernel hands
    /// us metadata for the *fd's* inode, not any path that may now point
    /// at a different inode.
    pub fn of_fd(fd: RawFd) -> Result<Self, CowError> {
        // SAFETY: fstat is safe to call on any fd; the kernel returns
        // EBADF on an invalid one which nix maps to Errno::EBADF.
        let stat = nix::sys::stat::fstat(fd)?;
        Ok(Self {
            ino: stat.st_ino as u64,
            dev: stat.st_dev as u64,
            size: stat.st_size as u64,
            mtime_secs: stat.st_mtime,
            mtime_nsecs: stat.st_mtime_nsec as i64,
        })
    }

    /// Convenience: from a `std::fs::Metadata`.
    pub fn of_metadata(md: &std::fs::Metadata) -> Self {
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok());
        Self {
            ino: md.ino(),
            dev: md.dev(),
            size: md.len(),
            mtime_secs: mtime.map(|d| d.as_secs() as i64).unwrap_or(0),
            mtime_nsecs: mtime.map(|d| d.subsec_nanos() as i64).unwrap_or(0),
        }
    }
}

/// Compare two fingerprints, returning `Err(SourceMutated)` if they
/// differ. Used pre- and post-capture for non-atomic tiers.
pub fn assert_stable(before: SourceFingerprint, after: SourceFingerprint) -> Result<(), CowError> {
    if before == after {
        Ok(())
    } else {
        Err(CowError::SourceMutated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn fingerprint_stable_for_unchanged_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hello").unwrap();
        f.flush().unwrap();
        let fp1 = SourceFingerprint::of_fd(f.as_file().as_raw_fd()).unwrap();
        let fp2 = SourceFingerprint::of_fd(f.as_file().as_raw_fd()).unwrap();
        assert_stable(fp1, fp2).unwrap();
    }
}
