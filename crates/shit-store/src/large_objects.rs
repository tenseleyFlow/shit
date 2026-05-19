// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL-facing companion to [`crate::caibx`]. Stores the chunk index in
//! `large_objects` + `chunks` (schema v3, migration 0003).
//!
//! Materialization is two-tier:
//!
//! - `large_objects.materialized = 0` while at least one chunk's bytes are
//!   not yet in the blob store. Set to `1` once every `chunks.materialized`
//!   is `1`.
//! - `chunks.materialized = 0/1` per-chunk.
//!
//! Setting a chunk to materialized doesn't store bytes — the caller writes
//! the chunk bytes via [`crate::BlobStore`] under the chunk's hash, then
//! flips the bit here. The split lets the daemon resume materialization
//! after a crash: the index tells us *which* chunks remain, the store
//! tells us *whether* a chunk's bytes are durable.
//!
//! C01 scope: insert / lookup / per-chunk and whole-blob materialization
//! flips. The eager-fetch-on-undo and GC-pressure paths are deferred to
//! C04 (consumer) and S13 amendments respectively.

use crate::caibx::{ChunkIndex, ChunkRef};
use crate::index::{Index, IndexError};
use rusqlite::{Connection, OptionalExtension, params};
use shit_planner::BlobHash;

#[derive(Debug, thiserror::Error)]
pub enum LargeObjectError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("index: {0}")]
    Index(#[from] IndexError),
    #[error("chunk idx {idx} not found for blob {hash}")]
    ChunkNotFound { hash: BlobHash, idx: u32 },
    #[error("large object not found: {0}")]
    NotFound(BlobHash),
}

/// Status of a stored large object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeObjectStat {
    pub blob_hash: BlobHash,
    pub total_size: u64,
    pub chunk_count: u32,
    pub materialized: bool,
    pub created_logical: u64,
}

/// Per-chunk materialization status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkStat {
    pub idx: u32,
    pub offset: u64,
    pub length: u32,
    pub hash: BlobHash,
    pub materialized: bool,
}

/// Insert (or no-op if already present) the chunk index for a large object.
///
/// `materialized_chunks` is the set of chunk indices whose bytes are already
/// in the blob store at insert time — typically empty when the daemon emits
/// a deferred capture, and the full set `0..chunk_count` for the eager path.
///
/// Idempotent on `(blob_hash, idx)` via `ON CONFLICT DO NOTHING`: if the
/// caller retries after a partial crash, existing rows are preserved.
pub fn insert(
    index: &Index,
    chunk_index: &ChunkIndex,
    created_logical: u64,
    materialized_chunks: &[u32],
) -> Result<(), LargeObjectError> {
    let conn = index.conn().lock().unwrap();
    insert_with_conn(&conn, chunk_index, created_logical, materialized_chunks)
}

pub(crate) fn insert_with_conn(
    conn: &Connection,
    chunk_index: &ChunkIndex,
    created_logical: u64,
    materialized_chunks: &[u32],
) -> Result<(), LargeObjectError> {
    let chunk_count = chunk_index.chunks.len() as u32;
    let all_materialized = (materialized_chunks.len() as u32) == chunk_count && chunk_count > 0;

    conn.execute(
        "INSERT INTO large_objects
            (blob_hash, total_size, chunk_count, materialized, created_logical)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(blob_hash) DO NOTHING",
        params![
            chunk_index.parent_hash.as_bytes().as_slice(),
            chunk_index.total_size as i64,
            chunk_count as i64,
            i64::from(all_materialized),
            created_logical as i64,
        ],
    )?;

    let mat_set: std::collections::HashSet<u32> = materialized_chunks.iter().copied().collect();
    for (i, chunk) in chunk_index.chunks.iter().enumerate() {
        let idx = i as u32;
        let materialized = mat_set.contains(&idx);
        conn.execute(
            "INSERT INTO chunks (blob_hash, idx, offset, length, hash, materialized)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(blob_hash, idx) DO NOTHING",
            params![
                chunk_index.parent_hash.as_bytes().as_slice(),
                idx as i64,
                chunk.offset as i64,
                chunk.length as i64,
                chunk.hash.as_bytes().as_slice(),
                i64::from(materialized),
            ],
        )?;
    }
    Ok(())
}

/// Look up the chunk index for a stored large object. Returns `None` if no
/// row exists.
pub fn lookup(index: &Index, blob_hash: BlobHash) -> Result<Option<ChunkIndex>, LargeObjectError> {
    let conn = index.conn().lock().unwrap();
    lookup_with_conn(&conn, blob_hash)
}

pub(crate) fn lookup_with_conn(
    conn: &Connection,
    blob_hash: BlobHash,
) -> Result<Option<ChunkIndex>, LargeObjectError> {
    let parent: Option<(i64,)> = conn
        .query_row(
            "SELECT total_size FROM large_objects WHERE blob_hash = ?1",
            params![blob_hash.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?,)),
        )
        .optional()?;
    let total_size = match parent {
        Some((t,)) => t as u64,
        None => return Ok(None),
    };

    let mut stmt = conn
        .prepare("SELECT offset, length, hash FROM chunks WHERE blob_hash = ?1 ORDER BY idx ASC")?;
    let rows = stmt.query_map(params![blob_hash.as_bytes().as_slice()], |row| {
        let offset: i64 = row.get(0)?;
        let length: i64 = row.get(1)?;
        let hash_bytes: Vec<u8> = row.get(2)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);
        Ok(ChunkRef {
            offset: offset as u64,
            length: length as u32,
            hash: BlobHash(h),
        })
    })?;
    let chunks: Vec<ChunkRef> = rows.collect::<Result<_, _>>()?;

    let idx = ChunkIndex::with_total_size(blob_hash, total_size, chunks)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    Ok(Some(idx))
}

/// Status (without the chunk list).
pub fn stat(
    index: &Index,
    blob_hash: BlobHash,
) -> Result<Option<LargeObjectStat>, LargeObjectError> {
    let conn = index.conn().lock().unwrap();
    let row = conn
        .query_row(
            "SELECT total_size, chunk_count, materialized, created_logical
             FROM large_objects WHERE blob_hash = ?1",
            params![blob_hash.as_bytes().as_slice()],
            |row| {
                Ok(LargeObjectStat {
                    blob_hash,
                    total_size: row.get::<_, i64>(0)? as u64,
                    chunk_count: row.get::<_, i64>(1)? as u32,
                    materialized: row.get::<_, i64>(2)? != 0,
                    created_logical: row.get::<_, i64>(3)? as u64,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Mark a specific chunk's bytes as durable. If this completes the set,
/// the parent `large_objects.materialized` flips to `1` as well.
pub fn mark_chunk_materialized(
    index: &Index,
    blob_hash: BlobHash,
    chunk_idx: u32,
) -> Result<(), LargeObjectError> {
    let conn = index.conn().lock().unwrap();
    let rows = conn.execute(
        "UPDATE chunks SET materialized = 1
         WHERE blob_hash = ?1 AND idx = ?2",
        params![blob_hash.as_bytes().as_slice(), chunk_idx as i64],
    )?;
    if rows == 0 {
        return Err(LargeObjectError::ChunkNotFound {
            hash: blob_hash,
            idx: chunk_idx,
        });
    }

    let unmaterialized_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chunks WHERE blob_hash = ?1 AND materialized = 0",
        params![blob_hash.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if unmaterialized_count == 0 {
        conn.execute(
            "UPDATE large_objects SET materialized = 1 WHERE blob_hash = ?1",
            params![blob_hash.as_bytes().as_slice()],
        )?;
    }
    Ok(())
}

/// Return the indices of chunks whose bytes are not yet in the blob store.
pub fn unmaterialized_chunks(
    index: &Index,
    blob_hash: BlobHash,
) -> Result<Vec<ChunkStat>, LargeObjectError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT idx, offset, length, hash FROM chunks
         WHERE blob_hash = ?1 AND materialized = 0
         ORDER BY idx ASC",
    )?;
    let rows = stmt.query_map(params![blob_hash.as_bytes().as_slice()], |row| {
        let idx: i64 = row.get(0)?;
        let offset: i64 = row.get(1)?;
        let length: i64 = row.get(2)?;
        let hash_bytes: Vec<u8> = row.get(3)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);
        Ok(ChunkStat {
            idx: idx as u32,
            offset: offset as u64,
            length: length as u32,
            hash: BlobHash(h),
            materialized: false,
        })
    })?;
    let chunks: Vec<ChunkStat> = rows.collect::<Result<_, _>>()?;
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caibx::ChunkRef;

    fn h(byte: u8) -> BlobHash {
        BlobHash([byte; 32])
    }

    fn fresh_index() -> Index {
        let tmp = tempfile::tempdir().unwrap();
        Index::open(tmp.path().join("idx.sqlite")).unwrap()
    }

    fn sample_index() -> ChunkIndex {
        ChunkIndex::new(
            h(0xff),
            vec![
                ChunkRef::new(0, 100, h(1)),
                ChunkRef::new(100, 200, h(2)),
                ChunkRef::new(300, 50, h(3)),
            ],
        )
        .unwrap()
    }

    #[test]
    fn insert_then_stat_returns_unmaterialized() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 42, &[]).unwrap();
        let s = stat(&idx, h(0xff)).unwrap().unwrap();
        assert_eq!(s.total_size, 350);
        assert_eq!(s.chunk_count, 3);
        assert!(!s.materialized);
        assert_eq!(s.created_logical, 42);
    }

    #[test]
    fn insert_then_lookup_returns_same_index() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 1, &[]).unwrap();
        let got = lookup(&idx, h(0xff)).unwrap().unwrap();
        assert_eq!(got.parent_hash, ci.parent_hash);
        assert_eq!(got.total_size, ci.total_size);
        assert_eq!(got.chunks, ci.chunks);
    }

    #[test]
    fn mark_chunk_materialized_promotes_to_whole_object() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 1, &[]).unwrap();

        mark_chunk_materialized(&idx, h(0xff), 0).unwrap();
        assert!(!stat(&idx, h(0xff)).unwrap().unwrap().materialized);

        mark_chunk_materialized(&idx, h(0xff), 1).unwrap();
        assert!(!stat(&idx, h(0xff)).unwrap().unwrap().materialized);

        mark_chunk_materialized(&idx, h(0xff), 2).unwrap();
        assert!(stat(&idx, h(0xff)).unwrap().unwrap().materialized);
    }

    #[test]
    fn unmaterialized_chunks_lists_pending() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 1, &[0, 2]).unwrap();
        let pending = unmaterialized_chunks(&idx, h(0xff)).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].idx, 1);
    }

    #[test]
    fn insert_is_idempotent() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 1, &[]).unwrap();
        // Re-insert should not error and should not produce dup chunks.
        insert(&idx, &ci, 1, &[]).unwrap();
        let s = stat(&idx, h(0xff)).unwrap().unwrap();
        assert_eq!(s.chunk_count, 3);
    }

    #[test]
    fn insert_with_all_materialized_flips_parent() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 1, &[0, 1, 2]).unwrap();
        let s = stat(&idx, h(0xff)).unwrap().unwrap();
        assert!(s.materialized);
    }

    #[test]
    fn lookup_returns_none_for_unknown_blob() {
        let idx = fresh_index();
        assert!(lookup(&idx, h(0xff)).unwrap().is_none());
        assert!(stat(&idx, h(0xff)).unwrap().is_none());
    }

    #[test]
    fn mark_chunk_materialized_errors_for_unknown_chunk() {
        let idx = fresh_index();
        let ci = sample_index();
        insert(&idx, &ci, 1, &[]).unwrap();
        let err = mark_chunk_materialized(&idx, h(0xff), 99).unwrap_err();
        assert!(matches!(err, LargeObjectError::ChunkNotFound { .. }));
    }
}
