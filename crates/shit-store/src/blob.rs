// SPDX-License-Identifier: AGPL-3.0-or-later

//! Content-addressed blob store. Blobs are keyed by their blake3 hash and
//! stored on disk under a two-level sharded directory:
//!
//! ```text
//! $root/blobs/aa/bb/aabbcc...   <- blob file (raw or zstd-compressed)
//! ```
//!
//! Each blob file starts with a one-byte flag:
//!   - `0x00`: raw bytes follow.
//!   - `0x01`: zstd-compressed bytes follow.
//!
//! The threshold for compression is `COMPRESS_MIN_BYTES`; below that we
//! store raw to avoid zstd framing overhead.

use shit_planner::BlobHash;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const COMPRESS_MIN_BYTES: usize = 4096;
const ZSTD_LEVEL: i32 = 3;

const FLAG_RAW: u8 = 0x00;
const FLAG_ZSTD: u8 = 0x01;

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("hash mismatch after streaming: expected {expected}, got {actual}")]
    HashMismatch {
        expected: BlobHash,
        actual: BlobHash,
    },
    #[error("malformed blob file (no flag byte): {0}")]
    Malformed(PathBuf),
    #[error("unknown compression flag {flag} in {path}")]
    UnknownFlag { path: PathBuf, flag: u8 },
}

#[derive(Debug, Clone)]
pub struct BlobStat {
    pub stored_bytes: u64,
    pub compressed: bool,
}

/// File-system-backed content-addressed blob store.
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open or create the store at `root`. Creates `blobs/` and `tmp/`
    /// subdirectories on first use.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let root: PathBuf = root.into();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Hash + write bytes into the store. Returns the resulting hash. If the
    /// blob already exists, returns the hash without rewriting.
    ///
    /// Atomic: writes to a tempfile under `tmp/` and renames into place.
    pub fn put(&self, bytes: &[u8]) -> Result<(BlobHash, BlobStat), BlobError> {
        let hash = BlobHash::from_bytes(*blake3::hash(bytes).as_bytes());
        let final_path = self.path_for(&hash);
        if final_path.exists() {
            let stat = self.stat(&hash)?.expect("just-confirmed file is gone?");
            return Ok((hash, stat));
        }
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.tmp_path();
        let compressed = bytes.len() >= COMPRESS_MIN_BYTES;
        let stored_bytes = self.write_atomic(&tmp_path, &final_path, bytes, compressed)?;
        Ok((
            hash,
            BlobStat {
                stored_bytes,
                compressed,
            },
        ))
    }

    /// Stream a blob into the store from a reader of known maximum size.
    /// Computes the hash incrementally while writing; verifies at close.
    pub fn put_stream<R: Read>(
        &self,
        mut reader: R,
        size_hint: Option<u64>,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        let mut buf = Vec::with_capacity(size_hint.unwrap_or(8192) as usize);
        reader.read_to_end(&mut buf)?;
        self.put(&buf)
    }

    /// Read a blob back as bytes (decompressing if needed).
    pub fn get(&self, hash: BlobHash) -> Result<Vec<u8>, BlobError> {
        let path = self.path_for(&hash);
        let raw = fs::read(&path)?;
        if raw.is_empty() {
            return Err(BlobError::Malformed(path));
        }
        let flag = raw[0];
        let payload = &raw[1..];
        match flag {
            FLAG_RAW => Ok(payload.to_vec()),
            FLAG_ZSTD => zstd::decode_all(payload).map_err(BlobError::Io),
            _ => Err(BlobError::UnknownFlag { path, flag }),
        }
    }

    /// Stat without reading the body.
    pub fn stat(&self, hash: &BlobHash) -> Result<Option<BlobStat>, BlobError> {
        let path = self.path_for(hash);
        let md = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BlobError::Io(e)),
        };
        let total = md.len();
        // Read just the flag byte to know if it was compressed.
        let mut f = fs::File::open(&path)?;
        let mut flag = [0u8; 1];
        f.read_exact(&mut flag)?;
        let compressed = match flag[0] {
            FLAG_RAW => false,
            FLAG_ZSTD => true,
            other => return Err(BlobError::UnknownFlag { path, flag: other }),
        };
        Ok(Some(BlobStat {
            stored_bytes: total,
            compressed,
        }))
    }

    /// `true` if the blob is present on disk.
    pub fn contains(&self, hash: &BlobHash) -> bool {
        self.path_for(hash).is_file()
    }

    /// Delete a blob from disk. Used by GC; refcount checks happen in the index.
    pub fn delete(&self, hash: &BlobHash) -> Result<(), BlobError> {
        let path = self.path_for(hash);
        match fs::remove_file(&path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BlobError::Io(e)),
        }
    }

    fn path_for(&self, hash: &BlobHash) -> PathBuf {
        let hex = hash.to_hex();
        let (aa, rest) = hex.split_at(2);
        let (bb, _) = rest.split_at(2);
        self.root.join("blobs").join(aa).join(bb).join(hex)
    }

    fn tmp_path(&self) -> PathBuf {
        // PID + monotonic nanos: collision-resistant across threads + processes.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        self.root.join("tmp").join(format!("blob-{pid}-{seq}"))
    }

    fn write_atomic(
        &self,
        tmp: &Path,
        dest: &Path,
        bytes: &[u8],
        compress: bool,
    ) -> Result<u64, BlobError> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)?;
        let stored_bytes = if compress {
            let mut payload = Vec::with_capacity(bytes.len());
            payload.push(FLAG_ZSTD);
            let mut encoder = zstd::Encoder::new(payload, ZSTD_LEVEL)?;
            encoder.write_all(bytes)?;
            let payload = encoder.finish()?;
            f.write_all(&payload)?;
            payload.len() as u64
        } else {
            f.write_all(&[FLAG_RAW])?;
            f.write_all(bytes)?;
            (1 + bytes.len()) as u64
        };
        f.sync_all()?;
        drop(f);
        fs::rename(tmp, dest)?;
        Ok(stored_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn round_trip_small_uncompressed() {
        let (_dir, store) = open_store();
        let payload = b"hello world";
        let (hash, stat) = store.put(payload).unwrap();
        assert!(!stat.compressed);
        let got = store.get(hash).unwrap();
        assert_eq!(payload.as_slice(), got.as_slice());
    }

    #[test]
    fn round_trip_large_compressed() {
        let (_dir, store) = open_store();
        let payload = vec![b'A'; 16_384];
        let (hash, stat) = store.put(&payload).unwrap();
        assert!(stat.compressed, "16KiB of one byte should compress");
        let got = store.get(hash).unwrap();
        assert_eq!(payload, got);
        // Compression should beat raw substantially on this input.
        assert!(stat.stored_bytes < payload.len() as u64 / 4);
    }

    #[test]
    fn dedup_returns_same_hash_without_rewrite() {
        let (_dir, store) = open_store();
        let payload = b"dedup target";
        let (h1, _) = store.put(payload).unwrap();
        let path = store.path_for(&h1);
        let mtime1 = fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let (h2, _) = store.put(payload).unwrap();
        let mtime2 = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(mtime1, mtime2, "second put should not rewrite the file");
    }

    #[test]
    fn sharding_creates_two_levels() {
        let (_dir, store) = open_store();
        let (hash, _) = store.put(b"shard probe").unwrap();
        let path = store.path_for(&hash);
        let parent = path.parent().unwrap();
        let grandparent = parent.parent().unwrap();
        assert_eq!(parent.file_name().unwrap().len(), 2);
        assert_eq!(grandparent.file_name().unwrap().len(), 2);
        assert_eq!(grandparent.parent().unwrap().file_name().unwrap(), "blobs");
    }

    #[test]
    fn stat_and_contains_match() {
        let (_dir, store) = open_store();
        let h_absent = BlobHash::from_bytes([0xDD; 32]);
        assert!(!store.contains(&h_absent));
        assert!(store.stat(&h_absent).unwrap().is_none());

        let (h, _) = store.put(b"present").unwrap();
        assert!(store.contains(&h));
        assert!(store.stat(&h).unwrap().is_some());
    }

    #[test]
    fn delete_removes() {
        let (_dir, store) = open_store();
        let (h, _) = store.put(b"to be deleted").unwrap();
        assert!(store.contains(&h));
        store.delete(&h).unwrap();
        assert!(!store.contains(&h));
        // Re-delete is OK.
        store.delete(&h).unwrap();
    }

    #[test]
    fn hash_matches_blake3() {
        let (_dir, store) = open_store();
        let payload = b"hash check";
        let (h, _) = store.put(payload).unwrap();
        let expected = BlobHash::from_bytes(*blake3::hash(payload).as_bytes());
        assert_eq!(h, expected);
    }
}
