// SPDX-License-Identifier: AGPL-3.0-or-later

//! `.caibx`-style chunk index for large-object pre-images.
//!
//! Spec: `.docs/sprints/C01-foundational-refit.md` and `.docs/audits/fan-pre-modify.md`.
//!
//! A `ChunkIndex` describes a large file as `[(offset, length, blake3)]`.
//! The index itself is small (≈48 bytes per chunk; ~16 KiB for a 1 GiB blob
//! with 2 MiB chunks). The chunks' actual byte contents may or may not be
//! materialized in the blob store at the time the index is written —
//! C01.6's `large_objects` API tracks materialization status per chunk.
//!
//! Wire format: postcard-encoded `ChunkIndex`. Stored alongside the blob
//! file as `<blob-hex>.caibx`.

use serde::{Deserialize, Serialize};
use shit_planner::BlobHash;

/// One range within a large object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkRef {
    /// Byte offset of this chunk within the parent blob.
    pub offset: u64,
    /// Chunk length in bytes. `u32` caps individual chunks at 4 GiB, which
    /// is well above any sensible chunker output (target ~2 MiB, max ~8 MiB).
    pub length: u32,
    /// blake3 of this chunk's content.
    pub hash: BlobHash,
}

impl ChunkRef {
    pub const fn new(offset: u64, length: u32, hash: BlobHash) -> Self {
        Self {
            offset,
            length,
            hash,
        }
    }

    pub fn end(&self) -> u64 {
        self.offset + self.length as u64
    }
}

/// Wire-format magic. Distinguishes a `.caibx` payload from a raw blob if
/// the two ever get confused on disk. Four bytes so it doubles as a poor-
/// man's version tag (`shit-caibx\x01` truncated to 4: `s`,`h`,`i`,`t`).
const MAGIC: [u8; 4] = *b"shit";

/// Chunk-index file-format version. Bumped on any layout change.
pub const VERSION: u16 = 1;

/// The on-disk chunk index for one large object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkIndex {
    magic: [u8; 4],
    version: u16,
    /// blake3 of the *whole* logical blob — same identity the rest of the
    /// store uses. Lets us cross-check that an index file matches its
    /// parent blob entry.
    pub parent_hash: BlobHash,
    /// Total logical size of the parent blob, in bytes.
    pub total_size: u64,
    /// Chunks, in offset order. Adjacent chunks must be contiguous;
    /// `validate()` enforces this.
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaibxError {
    #[error("postcard: {0}")]
    Encode(#[from] postcard::Error),
    #[error("bad magic: expected `shit`, got {0:?}")]
    BadMagic([u8; 4]),
    #[error("version {actual} not supported (this build understands {supported})")]
    BadVersion { actual: u16, supported: u16 },
    #[error("chunks not contiguous at idx {idx}: prev ends at {prev_end}, next starts at {next_offset}")]
    NonContiguous {
        idx: usize,
        prev_end: u64,
        next_offset: u64,
    },
    #[error("chunk index total ({chunked}) does not match declared total_size ({total})")]
    SizeMismatch { chunked: u64, total: u64 },
    #[error("empty chunk index for non-zero total_size {total}")]
    EmptyIndex { total: u64 },
}

impl ChunkIndex {
    /// Build an index from chunks in offset order. Validates immediately.
    pub fn new(parent_hash: BlobHash, chunks: Vec<ChunkRef>) -> Result<Self, CaibxError> {
        let total_size = chunks.iter().map(|c| c.length as u64).sum();
        let idx = Self {
            magic: MAGIC,
            version: VERSION,
            parent_hash,
            total_size,
            chunks,
        };
        idx.validate()?;
        Ok(idx)
    }

    /// Build an index with an explicit declared total size. Allows trailing
    /// zero-length holes if the chunker decides to emit them (it usually
    /// doesn't, but the encoding doesn't forbid it).
    pub fn with_total_size(
        parent_hash: BlobHash,
        total_size: u64,
        chunks: Vec<ChunkRef>,
    ) -> Result<Self, CaibxError> {
        let idx = Self {
            magic: MAGIC,
            version: VERSION,
            parent_hash,
            total_size,
            chunks,
        };
        idx.validate()?;
        Ok(idx)
    }

    pub fn validate(&self) -> Result<(), CaibxError> {
        if self.magic != MAGIC {
            return Err(CaibxError::BadMagic(self.magic));
        }
        if self.version != VERSION {
            return Err(CaibxError::BadVersion {
                actual: self.version,
                supported: VERSION,
            });
        }
        if self.chunks.is_empty() {
            if self.total_size != 0 {
                return Err(CaibxError::EmptyIndex {
                    total: self.total_size,
                });
            }
            return Ok(());
        }
        let mut cursor = 0u64;
        for (i, chunk) in self.chunks.iter().enumerate() {
            if chunk.offset != cursor {
                return Err(CaibxError::NonContiguous {
                    idx: i,
                    prev_end: cursor,
                    next_offset: chunk.offset,
                });
            }
            cursor = chunk.end();
        }
        if cursor != self.total_size {
            return Err(CaibxError::SizeMismatch {
                chunked: cursor,
                total: self.total_size,
            });
        }
        Ok(())
    }

    /// Postcard-encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CaibxError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Decode + validate.
    pub fn decode(bytes: &[u8]) -> Result<Self, CaibxError> {
        let idx: Self = postcard::from_bytes(bytes)?;
        idx.validate()?;
        Ok(idx)
    }

    /// Locate the chunk(s) covering the range `[start, start+len)`. Returns
    /// indices into `self.chunks` — callers fetch / materialize those chunks
    /// to satisfy a partial read. Empty `len` returns an empty range.
    pub fn chunks_for_range(&self, start: u64, len: u64) -> std::ops::Range<usize> {
        if len == 0 || self.chunks.is_empty() {
            return 0..0;
        }
        let end = start + len;
        // Linear scan is fine: typical chunk counts are <500 per GiB.
        let mut first = self.chunks.len();
        let mut last = 0usize;
        for (i, chunk) in self.chunks.iter().enumerate() {
            if chunk.end() <= start {
                continue;
            }
            if chunk.offset >= end {
                break;
            }
            first = first.min(i);
            last = last.max(i);
        }
        if first == self.chunks.len() {
            return 0..0;
        }
        first..(last + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> BlobHash {
        BlobHash([byte; 32])
    }

    fn parent() -> BlobHash {
        h(0xff)
    }

    #[test]
    fn round_trip_empty_index() {
        let idx = ChunkIndex::new(parent(), vec![]).unwrap();
        let bytes = idx.encode().unwrap();
        let decoded = ChunkIndex::decode(&bytes).unwrap();
        assert_eq!(idx, decoded);
        assert_eq!(decoded.total_size, 0);
    }

    #[test]
    fn round_trip_multi_chunk() {
        let chunks = vec![
            ChunkRef::new(0, 100, h(1)),
            ChunkRef::new(100, 200, h(2)),
            ChunkRef::new(300, 50, h(3)),
        ];
        let idx = ChunkIndex::new(parent(), chunks).unwrap();
        assert_eq!(idx.total_size, 350);
        let bytes = idx.encode().unwrap();
        let decoded = ChunkIndex::decode(&bytes).unwrap();
        assert_eq!(idx, decoded);
    }

    #[test]
    fn rejects_non_contiguous_chunks() {
        // Gap between chunk 0 and chunk 1.
        let err = ChunkIndex::new(
            parent(),
            vec![ChunkRef::new(0, 100, h(1)), ChunkRef::new(150, 100, h(2))],
        )
        .unwrap_err();
        assert!(matches!(err, CaibxError::NonContiguous { idx: 1, .. }));
    }

    #[test]
    fn rejects_overlapping_chunks() {
        // Chunk 1 starts before chunk 0 ends.
        let err = ChunkIndex::new(
            parent(),
            vec![ChunkRef::new(0, 100, h(1)), ChunkRef::new(50, 100, h(2))],
        )
        .unwrap_err();
        // Overlap manifests as "next_offset < prev_end".
        assert!(matches!(err, CaibxError::NonContiguous { idx: 1, .. }));
    }

    #[test]
    fn rejects_unexpected_magic_after_tamper() {
        let idx = ChunkIndex::new(parent(), vec![ChunkRef::new(0, 10, h(1))]).unwrap();
        let mut bytes = idx.encode().unwrap();
        // The first byte of postcard's encoding for a [u8; 4] is the first
        // byte of the array. Flip it.
        bytes[0] ^= 0xff;
        let err = ChunkIndex::decode(&bytes).unwrap_err();
        assert!(matches!(err, CaibxError::BadMagic(_)));
    }

    #[test]
    fn chunks_for_range_locates_single_chunk() {
        let idx = ChunkIndex::new(
            parent(),
            vec![
                ChunkRef::new(0, 100, h(1)),
                ChunkRef::new(100, 100, h(2)),
                ChunkRef::new(200, 100, h(3)),
            ],
        )
        .unwrap();
        // Range fully inside chunk 1.
        assert_eq!(idx.chunks_for_range(120, 30), 1..2);
    }

    #[test]
    fn chunks_for_range_spans_multiple_chunks() {
        let idx = ChunkIndex::new(
            parent(),
            vec![
                ChunkRef::new(0, 100, h(1)),
                ChunkRef::new(100, 100, h(2)),
                ChunkRef::new(200, 100, h(3)),
            ],
        )
        .unwrap();
        // Range covers tail of chunk 0, all of chunk 1, head of chunk 2.
        assert_eq!(idx.chunks_for_range(50, 200), 0..3);
    }

    #[test]
    fn chunks_for_range_empty_len() {
        let idx = ChunkIndex::new(parent(), vec![ChunkRef::new(0, 100, h(1))]).unwrap();
        assert_eq!(idx.chunks_for_range(0, 0), 0..0);
    }

    #[test]
    fn chunks_for_range_beyond_eof_is_empty() {
        let idx = ChunkIndex::new(parent(), vec![ChunkRef::new(0, 100, h(1))]).unwrap();
        assert_eq!(idx.chunks_for_range(200, 50), 0..0);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        // Construct an index, encode it, then surgically rewrite the
        // version field. Postcard encodes u16 as a varint; VERSION=1 is
        // a single byte `0x01`. We rewrite it to `0x7f` (still a valid
        // single-byte varint).
        let idx = ChunkIndex::new(parent(), vec![]).unwrap();
        let mut bytes = idx.encode().unwrap();
        // Layout: [magic (4 bytes)][version varint]...
        bytes[4] = 0x7f;
        let err = ChunkIndex::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CaibxError::BadVersion {
                actual: 0x7f,
                supported: 1
            }
        ));
    }
}
