// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inode-stable identity for files we've captured.
//!
//! Paths lie. A `rename(2)` between captures means the path you saw at capture
//! time may now name a different file. `(dev, inode)` survives renames within
//! a filesystem; we use it as the planner's primary key. Paths are denormalized
//! into events for human-facing reports but the planner never trusts them for
//! identity matching.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InodeRef {
    pub dev: u64,
    pub inode: u64,
}

impl InodeRef {
    pub const fn new(dev: u64, inode: u64) -> Self {
        Self { dev, inode }
    }
}

impl std::fmt::Display for InodeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.dev, self.inode)
    }
}

/// Content-addressed blob handle. Hashing is blake3 throughout the project;
/// the byte array is the raw 256-bit digest. Hex rendering is provided by
/// `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlobHash(pub [u8; 32]);

impl BlobHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

impl std::fmt::Display for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_display_is_dev_colon_inode() {
        let i = InodeRef::new(16777220, 99999);
        assert_eq!(format!("{i}"), "16777220:99999");
    }

    #[test]
    fn blob_hash_hex_is_64_chars() {
        let b = BlobHash::from_bytes([0xAB; 32]);
        assert_eq!(b.to_hex().len(), 64);
        assert_eq!(b.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn blob_hash_display_matches_to_hex() {
        let b = BlobHash::from_bytes([0xCD; 32]);
        assert_eq!(format!("{b}"), b.to_hex());
    }
}
