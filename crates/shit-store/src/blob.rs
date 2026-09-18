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
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

const COMPRESS_MIN_BYTES: usize = 4096;
const STREAM_BUF_BYTES: usize = 64 * 1024;
const ZSTD_LEVEL: i32 = 3;

const FLAG_RAW: u8 = 0x00;
const FLAG_ZSTD: u8 = 0x01;

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("blob hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        expected: BlobHash,
        actual: BlobHash,
    },
    #[error("blob stream length mismatch: expected exactly {expected} bytes, observed {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("blob stream exceeded its {max}-byte limit (observed at least {actual} bytes)")]
    SizeLimitExceeded { max: u64, actual: u64 },
    #[error("malformed blob file (no flag byte): {0}")]
    Malformed(PathBuf),
    #[error("unknown compression flag {flag} in {path}")]
    UnknownFlag { path: PathBuf, flag: u8 },
    #[error("could not decode compressed blob {path}: {source}")]
    Decode { path: PathBuf, source: io::Error },
}

struct TempCleanup<'a>(&'a Path);

impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

#[derive(Clone, Copy)]
struct StreamContract {
    expected_hash: Option<BlobHash>,
    expected_size: Option<u64>,
    max_size: u64,
}

/// Create `path` and every missing ancestor, making each new directory entry
/// durable before returning.
///
/// `create_dir_all` alone does not fsync the parent directories whose entries
/// it creates. A crash after publishing a blob into a newly-created shard can
/// therefore lose the shard even though both the blob and its immediate
/// directory were synced. Creating one component at a time lets us sync the
/// new directory itself and then the parent entry that names it.
fn create_dir_all_durable(path: &Path) -> io::Result<()> {
    match fs::metadata(path) {
        // Re-sync an existing directory and its entry as well. Besides making
        // this helper safely retryable after a prior sync error, this closes a
        // race with another process that has completed mkdir but has not yet
        // synced the new entry.
        Ok(metadata) if metadata.is_dir() => return sync_directory_entry(path),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a directory", path.display()),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if parent != path {
        create_dir_all_durable(parent)?;
    }

    match fs::create_dir(path) {
        Ok(()) => {}
        // Preserve create_dir_all's tolerance of another writer winning the
        // mkdir race, but only when it really created a directory.
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
                return Err(err);
            }
        }
        Err(err) => return Err(err),
    }

    sync_directory_entry(path)
}

fn sync_directory_entry(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if parent != path {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct BlobStat {
    pub stored_bytes: u64,
    pub compressed: bool,
}

/// File-system-backed content-addressed blob store.
///
/// Lifecycle locking coordinates users of this specific instance. Callers for
/// one root must share the same instance (normally through `Arc`); the lock is
/// neither cross-process nor shared by separately opened `BlobStore`s.
pub struct BlobStore {
    root: PathBuf,
    lifecycle: RwLock<()>,
}

/// Shared blob lifecycle ownership. File reads/installs performed through this
/// guard cannot race an in-process GC unlink on the same `BlobStore` instance.
///
/// When sqlite work must be part of the publication/read lifetime, acquire
/// this guard first and call the `Index` second. The global lock order is
/// blob lifecycle -> Index connection.
pub struct BlobSharedGuard<'a> {
    store: &'a BlobStore,
    _guard: RwLockReadGuard<'a, ()>,
}

/// Exclusive blob lifecycle ownership, used by GC for authoritative recheck
/// plus unlink. Acquire this before entering the Index connection.
pub struct BlobExclusiveGuard<'a> {
    store: &'a BlobStore,
    _guard: RwLockWriteGuard<'a, ()>,
}

impl BlobStore {
    /// Open or create the store at `root`. Creates `blobs/` and `tmp/`
    /// subdirectories on first use.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let root: PathBuf = root.into();
        create_dir_all_durable(&root.join("blobs"))?;
        create_dir_all_durable(&root.join("tmp"))?;
        Ok(Self {
            root,
            lifecycle: RwLock::new(()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Acquire shared lifecycle ownership. Use the returned guard's methods;
    /// calling a convenience method on `BlobStore` while holding it would
    /// attempt to lock recursively and can deadlock behind a waiting writer.
    pub fn shared_guard(&self) -> BlobSharedGuard<'_> {
        BlobSharedGuard {
            store: self,
            _guard: self
                .lifecycle
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Acquire exclusive lifecycle ownership. GC holds this across its Index
    /// recheck/delete and the subsequent physical unlink.
    pub fn exclusive_guard(&self) -> BlobExclusiveGuard<'_> {
        BlobExclusiveGuard {
            store: self,
            _guard: self
                .lifecycle
                .write()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Hash + write bytes into the store. Returns the resulting hash. If the
    /// blob already exists, returns the hash without rewriting.
    ///
    /// Atomic: writes to a tempfile under `tmp/` and renames into place.
    pub fn put(&self, bytes: &[u8]) -> Result<(BlobHash, BlobStat), BlobError> {
        self.shared_guard().put(bytes)
    }

    fn put_unlocked(&self, bytes: &[u8]) -> Result<(BlobHash, BlobStat), BlobError> {
        let hash = BlobHash::from_bytes(*blake3::hash(bytes).as_bytes());
        let size = bytes.len() as u64;
        self.put_stream_unlocked(
            io::Cursor::new(bytes),
            StreamContract {
                expected_hash: Some(hash),
                expected_size: Some(size),
                max_size: size,
            },
        )
    }

    /// Stream a blob into the store using a fixed-size buffer. `size_hint`,
    /// when present, is a hard upper bound rather than a reservation hint.
    /// The hash is computed incrementally and publication is atomic.
    pub fn put_stream<R: Read>(
        &self,
        reader: R,
        size_hint: Option<u64>,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        self.shared_guard().put_stream(reader, size_hint)
    }

    /// Stream exactly `expected_size` bytes while computing the content hash.
    /// Nothing is published unless the reader reaches EOF at precisely that
    /// length and the declared size is within `max_size`.
    pub fn put_stream_exact<R: Read>(
        &self,
        reader: R,
        expected_size: u64,
        max_size: u64,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        self.shared_guard()
            .put_stream_exact(reader, expected_size, max_size)
    }

    /// Stream exactly `expected_size` bytes and require their digest to equal
    /// `expected_hash`. Nothing is published at the canonical path until the
    /// length, limit, and hash have all been verified.
    pub fn put_verified_exact<R: Read>(
        &self,
        reader: R,
        expected_hash: BlobHash,
        expected_size: u64,
        max_size: u64,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        self.shared_guard()
            .put_verified_exact(reader, expected_hash, expected_size, max_size)
    }

    /// Read a blob back as bytes (decompressing if needed).
    pub fn get(&self, hash: BlobHash) -> Result<Vec<u8>, BlobError> {
        self.shared_guard().get(hash)
    }

    /// Stat without reading the body.
    pub fn stat(&self, hash: &BlobHash) -> Result<Option<BlobStat>, BlobError> {
        self.shared_guard().stat(hash)
    }

    fn stat_unlocked(&self, hash: &BlobHash) -> Result<Option<BlobStat>, BlobError> {
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
        self.shared_guard().contains(hash)
    }

    /// Delete a blob from disk. Used by GC; refcount checks happen in the index.
    pub fn delete(&self, hash: &BlobHash) -> Result<(), BlobError> {
        self.exclusive_guard().delete(hash)
    }

    fn delete_unlocked(&self, hash: &BlobHash) -> Result<(), BlobError> {
        let path = self.path_for(hash);
        match fs::remove_file(&path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    fs::File::open(parent)?.sync_all()?;
                }
                Ok(())
            }
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

    fn read_verified(&self, hash: BlobHash) -> Result<(Vec<u8>, BlobStat), BlobError> {
        let path = self.path_for(&hash);
        let raw = fs::read(&path)?;
        if raw.is_empty() {
            return Err(BlobError::Malformed(path));
        }
        let (bytes, compressed) = match raw[0] {
            FLAG_RAW => (raw[1..].to_vec(), false),
            FLAG_ZSTD => (
                zstd::decode_all(&raw[1..]).map_err(|source| BlobError::Decode {
                    path: path.clone(),
                    source,
                })?,
                true,
            ),
            flag => return Err(BlobError::UnknownFlag { path, flag }),
        };
        let actual = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
        if actual != hash {
            return Err(BlobError::HashMismatch {
                expected: hash,
                actual,
            });
        }
        Ok((
            bytes,
            BlobStat {
                stored_bytes: raw.len() as u64,
                compressed,
            },
        ))
    }

    /// Validate an on-disk blob without materializing its decoded contents.
    /// Startup reconciliation calls this for every canonical file, including
    /// multi-GiB container archives; an allocating decode there would let one
    /// large valid blob (or a compressed expansion bomb) exhaust the daemon.
    fn validate_streaming(&self, hash: BlobHash) -> Result<BlobStat, BlobError> {
        const VALIDATE_BUF_BYTES: usize = 64 * 1024;

        let path = self.path_for(&hash);
        let mut file = fs::File::open(&path)?;
        let stored_bytes = file.metadata()?.len();
        let mut flag = [0_u8; 1];
        match file.read_exact(&mut flag) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(BlobError::Malformed(path));
            }
            Err(error) => return Err(error.into()),
        }

        let compressed = match flag[0] {
            FLAG_RAW => false,
            FLAG_ZSTD => true,
            flag => return Err(BlobError::UnknownFlag { path, flag }),
        };
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; VALIDATE_BUF_BYTES];
        if compressed {
            let mut decoder = zstd::Decoder::new(file).map_err(|source| BlobError::Decode {
                path: path.clone(),
                source,
            })?;
            loop {
                let read = decoder
                    .read(&mut buffer)
                    .map_err(|source| BlobError::Decode {
                        path: path.clone(),
                        source,
                    })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else {
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        }
        let actual = BlobHash::from_bytes(*hasher.finalize().as_bytes());
        if actual != hash {
            return Err(BlobError::HashMismatch {
                expected: hash,
                actual,
            });
        }
        Ok(BlobStat {
            stored_bytes,
            compressed,
        })
    }

    fn put_stream_unlocked<R: Read>(
        &self,
        mut reader: R,
        contract: StreamContract,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        if let Some(expected_size) = contract.expected_size
            && expected_size > contract.max_size
        {
            return Err(BlobError::SizeLimitExceeded {
                max: contract.max_size,
                actual: expected_size,
            });
        }

        let compressed = contract
            .expected_size
            .or((contract.max_size != u64::MAX).then_some(contract.max_size))
            .is_some_and(|size| size >= COMPRESS_MIN_BYTES as u64);
        let tmp = self.tmp_path();

        // S20.9 fault-injection point before the atomic write. Once a
        // tempfile is created, every error path unwinds through its cleanup
        // guard; a wrong length or hash can never leave a canonical file.
        shit_proto::fault_inject::maybe_inject("blob_store.put.before_atomic_write");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let _cleanup = TempCleanup(&tmp);

        let (actual_hash, file) = if compressed {
            file.write_all(&[FLAG_ZSTD])?;
            let mut encoder = zstd::Encoder::new(file, ZSTD_LEVEL)?;
            let (hash, _size) = copy_hashed_bounded(&mut reader, &mut encoder, contract)?;
            (hash, encoder.finish()?)
        } else {
            file.write_all(&[FLAG_RAW])?;
            let (hash, _size) = copy_hashed_bounded(&mut reader, &mut file, contract)?;
            (hash, file)
        };

        if let Some(expected_hash) = contract.expected_hash
            && actual_hash != expected_hash
        {
            return Err(BlobError::HashMismatch {
                expected: expected_hash,
                actual: actual_hash,
            });
        }

        file.sync_all()?;
        let stored_bytes = file.metadata()?.len();
        drop(file);

        let dest = self.path_for(&actual_hash);
        match self.validate_streaming(actual_hash) {
            Ok(stat) => return Ok((actual_hash, stat)),
            Err(BlobError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {}
            Err(BlobError::HashMismatch { .. })
            | Err(BlobError::Malformed(_))
            | Err(BlobError::UnknownFlag { .. })
            | Err(BlobError::Decode { .. }) => {
                // This stream hashes to the canonical path, so replacing its
                // malformed contents is a safe atomic repair.
            }
            Err(err) => return Err(err),
        }
        if let Some(parent) = dest.parent() {
            create_dir_all_durable(parent)?;
        }
        fs::rename(&tmp, &dest)?;
        if let Some(parent) = dest.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        if let Some(parent) = tmp.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        shit_proto::fault_inject::maybe_inject("blob_store.put.after_atomic_write");
        Ok((
            actual_hash,
            BlobStat {
                stored_bytes,
                compressed,
            },
        ))
    }
}

fn copy_hashed_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    contract: StreamContract,
) -> Result<(BlobHash, u64), BlobError> {
    let read_limit = contract.expected_size.unwrap_or(contract.max_size);
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; STREAM_BUF_BYTES];

    loop {
        // Read one byte past the contract boundary so an input that is longer
        // than advertised cannot be mistaken for an exact match. The extra
        // byte is neither hashed nor written.
        let remaining = read_limit.saturating_sub(total);
        let read_len = if remaining >= STREAM_BUF_BYTES as u64 {
            STREAM_BUF_BYTES
        } else {
            usize::try_from(remaining).expect("remaining is smaller than the buffer") + 1
        };
        let read = match reader.read(&mut buffer[..read_len]) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if read == 0 {
            break;
        }
        let observed = total
            .checked_add(read as u64)
            .ok_or(BlobError::SizeLimitExceeded {
                max: contract.max_size,
                actual: u64::MAX,
            })?;
        if observed > read_limit {
            return match contract.expected_size {
                Some(expected) => Err(BlobError::LengthMismatch {
                    expected,
                    actual: observed,
                }),
                None => Err(BlobError::SizeLimitExceeded {
                    max: contract.max_size,
                    actual: observed,
                }),
            };
        }
        hasher.update(&buffer[..read]);
        writer.write_all(&buffer[..read])?;
        total = observed;
    }

    if let Some(expected) = contract.expected_size
        && total != expected
    {
        return Err(BlobError::LengthMismatch {
            expected,
            actual: total,
        });
    }
    let hash = BlobHash::from_bytes(*hasher.finalize().as_bytes());
    Ok((hash, total))
}

impl BlobSharedGuard<'_> {
    pub fn put(&self, bytes: &[u8]) -> Result<(BlobHash, BlobStat), BlobError> {
        self.store.put_unlocked(bytes)
    }

    pub fn put_stream<R: Read>(
        &self,
        reader: R,
        size_hint: Option<u64>,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        self.store.put_stream_unlocked(
            reader,
            StreamContract {
                expected_hash: None,
                expected_size: None,
                max_size: size_hint.unwrap_or(u64::MAX),
            },
        )
    }

    /// Publish a stream only after proving its exact byte length. The digest
    /// is derived incrementally from the stream rather than supplied by the
    /// caller.
    pub fn put_stream_exact<R: Read>(
        &self,
        reader: R,
        expected_size: u64,
        max_size: u64,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        self.store.put_stream_unlocked(
            reader,
            StreamContract {
                expected_hash: None,
                expected_size: Some(expected_size),
                max_size,
            },
        )
    }

    /// Publish a stream only after proving its exact byte length and digest.
    /// The shared lifecycle lock remains held by this guard, allowing callers
    /// to keep the physical blob protected until its Index owner or lease is
    /// durable.
    pub fn put_verified_exact<R: Read>(
        &self,
        reader: R,
        expected_hash: BlobHash,
        expected_size: u64,
        max_size: u64,
    ) -> Result<(BlobHash, BlobStat), BlobError> {
        self.store.put_stream_unlocked(
            reader,
            StreamContract {
                expected_hash: Some(expected_hash),
                expected_size: Some(expected_size),
                max_size,
            },
        )
    }

    pub fn get(&self, hash: BlobHash) -> Result<Vec<u8>, BlobError> {
        self.store.read_verified(hash).map(|(bytes, _stat)| bytes)
    }

    /// Stream, decode, and hash a canonical blob while retaining shared
    /// lifecycle ownership. Callers can keep this guard alive across a later
    /// Index transaction so GC cannot unlink the bytes between validation and
    /// durable publication/confirmation.
    pub fn validate(&self, hash: BlobHash) -> Result<BlobStat, BlobError> {
        self.store.validate_streaming(hash)
    }

    pub fn stat(&self, hash: &BlobHash) -> Result<Option<BlobStat>, BlobError> {
        self.store.stat_unlocked(hash)
    }

    pub fn contains(&self, hash: &BlobHash) -> bool {
        self.store.path_for(hash).is_file()
    }
}

impl BlobExclusiveGuard<'_> {
    pub(crate) fn validate(&self, hash: BlobHash) -> Result<BlobStat, BlobError> {
        self.store.validate_streaming(hash)
    }

    pub fn get(&self, hash: BlobHash) -> Result<Vec<u8>, BlobError> {
        self.store.read_verified(hash).map(|(bytes, _stat)| bytes)
    }

    pub fn stat(&self, hash: &BlobHash) -> Result<Option<BlobStat>, BlobError> {
        self.store.stat_unlocked(hash)
    }

    pub fn contains(&self, hash: &BlobHash) -> bool {
        self.store.path_for(hash).is_file()
    }

    pub fn delete(&self, hash: &BlobHash) -> Result<(), BlobError> {
        self.store.delete_unlocked(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChunkBoundedReader<R> {
        inner: R,
        max_request: usize,
        largest_request: usize,
    }

    impl<R> ChunkBoundedReader<R> {
        fn new(inner: R, max_request: usize) -> Self {
            Self {
                inner,
                max_request,
                largest_request: 0,
            }
        }
    }

    impl<R: Read> Read for ChunkBoundedReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(
                buffer.len() <= self.max_request,
                "stream requested {} bytes, above the {}-byte test bound",
                buffer.len(),
                self.max_request
            );
            self.largest_request = self.largest_request.max(buffer.len());
            self.inner.read(buffer)
        }
    }

    fn open_store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn durable_directory_creation_is_recursive_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("new/store/blobs/aa/bb");

        create_dir_all_durable(&nested).unwrap();
        assert!(nested.is_dir());
        assert!(dir.path().join("new").is_dir());

        create_dir_all_durable(&nested).unwrap();
        assert!(nested.is_dir());
    }

    #[test]
    fn open_creates_nested_root_and_first_shard() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nested/store/root");
        let store = BlobStore::open(&root).unwrap();

        assert!(root.join("blobs").is_dir());
        assert!(root.join("tmp").is_dir());

        let (hash, _) = store.put(b"first blob in a new store").unwrap();
        let blob_path = store.path_for(&hash);
        assert!(blob_path.is_file());
        assert_eq!(store.get(hash).unwrap(), b"first blob in a new store");
    }

    #[test]
    fn durable_directory_creation_rejects_a_file_component() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-directory");
        fs::write(&file, b"file").unwrap();

        let err = create_dir_all_durable(&file.join("child")).unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
        ));
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
    fn verified_stream_is_chunk_bounded_and_round_trips_zstd() {
        let (_dir, store) = open_store();
        let payload = vec![b'S'; STREAM_BUF_BYTES * 3 + 17];
        let hash = BlobHash::from_bytes(*blake3::hash(&payload).as_bytes());
        let mut reader = ChunkBoundedReader::new(io::Cursor::new(&payload), STREAM_BUF_BYTES);

        let (actual, stat) = store
            .put_verified_exact(
                &mut reader,
                hash,
                payload.len() as u64,
                payload.len() as u64,
            )
            .unwrap();

        assert_eq!(actual, hash);
        assert!(stat.compressed);
        assert_eq!(reader.largest_request, STREAM_BUF_BYTES);
        assert_eq!(store.get(hash).unwrap(), payload);
    }

    #[test]
    fn verified_stream_round_trips_raw() {
        let (_dir, store) = open_store();
        let payload = b"small exact stream";
        let hash = BlobHash::from_bytes(*blake3::hash(payload).as_bytes());

        let (_, stat) = store
            .put_verified_exact(
                io::Cursor::new(payload),
                hash,
                payload.len() as u64,
                payload.len() as u64,
            )
            .unwrap();

        assert!(!stat.compressed);
        assert_eq!(store.get(hash).unwrap(), payload);
    }

    #[test]
    fn verified_stream_rejects_short_and_long_inputs_without_publication() {
        let (_dir, store) = open_store();
        let payload = b"exact-length-contract";
        let hash = BlobHash::from_bytes(*blake3::hash(payload).as_bytes());

        assert!(matches!(
            store.put_verified_exact(
                io::Cursor::new(payload),
                hash,
                payload.len() as u64 + 1,
                payload.len() as u64 + 1,
            ),
            Err(BlobError::LengthMismatch { expected, actual })
                if expected == payload.len() as u64 + 1 && actual == payload.len() as u64
        ));
        assert!(!store.path_for(&hash).exists());

        assert!(matches!(
            store.put_verified_exact(
                io::Cursor::new(payload),
                hash,
                payload.len() as u64 - 1,
                payload.len() as u64,
            ),
            Err(BlobError::LengthMismatch { expected, actual })
                if expected == payload.len() as u64 - 1 && actual == payload.len() as u64
        ));
        assert!(!store.path_for(&hash).exists());
        assert_eq!(fs::read_dir(store.root().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn verified_stream_rejects_wrong_hash_without_canonical_file() {
        let (_dir, store) = open_store();
        let payload = b"hash-contract";
        let claimed = BlobHash::from_bytes([0xA5; 32]);
        let actual = BlobHash::from_bytes(*blake3::hash(payload).as_bytes());

        assert!(matches!(
            store.put_verified_exact(
                io::Cursor::new(payload),
                claimed,
                payload.len() as u64,
                payload.len() as u64,
            ),
            Err(BlobError::HashMismatch { expected, actual: got })
                if expected == claimed && got == actual
        ));
        assert!(!store.path_for(&claimed).exists());
        assert!(!store.path_for(&actual).exists());
        assert_eq!(fs::read_dir(store.root().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn verified_stream_rejects_declared_size_above_cap_before_reading() {
        let (_dir, store) = open_store();
        let payload = b"over-cap";
        let hash = BlobHash::from_bytes(*blake3::hash(payload).as_bytes());
        let mut reader = ChunkBoundedReader::new(io::Cursor::new(payload), STREAM_BUF_BYTES);

        assert!(matches!(
            store.put_verified_exact(&mut reader, hash, 9, 8),
            Err(BlobError::SizeLimitExceeded { max: 8, actual: 9 })
        ));
        assert_eq!(reader.largest_request, 0);
        assert!(!store.path_for(&hash).exists());
        assert_eq!(fs::read_dir(store.root().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn get_rejects_raw_content_stored_under_the_wrong_hash() {
        let (_dir, store) = open_store();
        let (hash, _) = store.put(b"original raw bytes").unwrap();
        let path = store.path_for(&hash);
        let mut corrupt = vec![FLAG_RAW];
        corrupt.extend_from_slice(b"different raw bytes");
        fs::write(path, corrupt).unwrap();

        assert!(matches!(
            store.get(hash),
            Err(BlobError::HashMismatch { expected, .. }) if expected == hash
        ));
    }

    #[test]
    fn shared_guard_streaming_validation_rejects_present_corrupt_content() {
        let (_dir, store) = open_store();
        let payload = b"shared guard validation";
        let (hash, original_stat) = store.put(payload).unwrap();
        let path = store.path_for(&hash);
        let mut corrupt = vec![FLAG_RAW];
        corrupt.extend(std::iter::repeat_n(b'X', payload.len()));
        fs::write(path, corrupt).unwrap();

        let guard = store.shared_guard();
        assert_eq!(
            guard.stat(&hash).unwrap().unwrap().stored_bytes,
            original_stat.stored_bytes
        );
        assert!(matches!(
            guard.validate(hash),
            Err(BlobError::HashMismatch { expected, .. }) if expected == hash
        ));
    }

    #[test]
    fn put_repairs_raw_hash_mismatch() {
        let (_dir, store) = open_store();
        let payload = b"repair this raw blob";
        let (hash, _) = store.put(payload).unwrap();
        let path = store.path_for(&hash);
        let mut corrupt = vec![FLAG_RAW];
        corrupt.extend_from_slice(b"wrong bytes");
        fs::write(&path, corrupt).unwrap();

        let (repaired_hash, repaired_stat) = store.put(payload).unwrap();
        assert_eq!(repaired_hash, hash);
        assert!(!repaired_stat.compressed);
        assert_eq!(store.get(hash).unwrap(), payload);
        assert_eq!(fs::read_dir(store.root().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn put_repairs_valid_compressed_content_with_wrong_hash() {
        let (_dir, store) = open_store();
        let payload = vec![b'A'; 16_384];
        let wrong = vec![b'B'; 16_384];
        let (hash, stat) = store.put(&payload).unwrap();
        assert!(stat.compressed);
        let path = store.path_for(&hash);
        let mut corrupt = vec![FLAG_ZSTD];
        corrupt.extend_from_slice(&zstd::encode_all(wrong.as_slice(), ZSTD_LEVEL).unwrap());
        fs::write(&path, corrupt).unwrap();

        assert!(matches!(
            store.get(hash),
            Err(BlobError::HashMismatch { .. })
        ));
        let (_, repaired_stat) = store.put(&payload).unwrap();
        assert!(repaired_stat.compressed);
        assert_eq!(store.get(hash).unwrap(), payload);
    }

    #[test]
    fn put_repairs_compressed_decode_failure() {
        let (_dir, store) = open_store();
        let payload = vec![b'C'; 16_384];
        let (hash, _) = store.put(&payload).unwrap();
        let path = store.path_for(&hash);
        fs::write(&path, [FLAG_ZSTD, 0xFF, 0x00, 0x7F]).unwrap();

        assert!(matches!(store.get(hash), Err(BlobError::Decode { .. })));
        store.put(&payload).unwrap();
        assert_eq!(store.get(hash).unwrap(), payload);
    }

    #[test]
    fn verified_stream_repairs_corrupted_canonical_blob() {
        let (_dir, store) = open_store();
        let payload = vec![b'R'; 16_384];
        let hash = BlobHash::from_bytes(*blake3::hash(&payload).as_bytes());
        let path = store.path_for(&hash);
        if let Some(parent) = path.parent() {
            create_dir_all_durable(parent).unwrap();
        }
        fs::write(&path, [FLAG_ZSTD, 0xFF, 0x00]).unwrap();

        let (_, stat) = store
            .put_verified_exact(
                io::Cursor::new(&payload),
                hash,
                payload.len() as u64,
                payload.len() as u64,
            )
            .unwrap();

        assert!(stat.compressed);
        assert_eq!(store.get(hash).unwrap(), payload);
        assert_eq!(fs::read_dir(store.root().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn failed_atomic_install_removes_tempfile() {
        let (_dir, store) = open_store();
        let payload = b"destination-parent-failure";
        let hash = BlobHash::from_bytes(*blake3::hash(payload).as_bytes());
        let hash_hex = hash.to_hex();
        let shard = &hash_hex[..2];
        fs::write(store.root().join("blobs").join(shard), b"not a directory").unwrap();

        assert!(
            store
                .put_verified_exact(
                    io::Cursor::new(payload),
                    hash,
                    payload.len() as u64,
                    payload.len() as u64,
                )
                .is_err()
        );
        assert_eq!(fs::read_dir(store.root().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn put_repairs_empty_and_unknown_flag_files() {
        let (_dir, store) = open_store();
        let payload = b"canonical repair source";
        let (hash, _) = store.put(payload).unwrap();
        let path = store.path_for(&hash);

        fs::write(&path, []).unwrap();
        assert!(matches!(store.get(hash), Err(BlobError::Malformed(_))));
        store.put(payload).unwrap();
        assert_eq!(store.get(hash).unwrap(), payload);

        fs::write(&path, [0xFE, 1, 2, 3]).unwrap();
        assert!(matches!(
            store.get(hash),
            Err(BlobError::UnknownFlag { flag: 0xFE, .. })
        ));
        store.put(payload).unwrap();
        assert_eq!(store.get(hash).unwrap(), payload);
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
