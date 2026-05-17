// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming-copy fallback. Full implementation in S05.3.

use std::os::fd::RawFd;
use std::path::Path;

use super::{CaptureOutcome, CowError};

/// Stub: full streaming implementation lands in S05.3.
pub fn capture_streaming(
    _src_fd: RawFd,
    _src_path: &Path,
    _blob_root: &Path,
) -> Result<CaptureOutcome, CowError> {
    Err(CowError::TierUnsupported {
        tier: "streaming",
        detail: "not yet implemented (S05.3)".into(),
    })
}
