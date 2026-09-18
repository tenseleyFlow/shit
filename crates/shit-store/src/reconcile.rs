// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conservative startup reconciliation for blob filesystem/index state.
//!
//! This pass is intended to run after process-lifetime blob leases have been
//! cleared and before any producer starts. It holds exclusive lifecycle
//! ownership for the complete filesystem/Index reconciliation.

use crate::blob::{BlobError, BlobExclusiveGuard, BlobStat, BlobStore};
use crate::index::{Index, validate_stored_events};
use rusqlite::{Connection, params};
use shit_planner::BlobHash;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupReconcileReport {
    pub tmp_files_removed: usize,
    pub refcount_rows_recomputed: usize,
    pub refcount_corrected_hashes: Vec<BlobHash>,
    pub metadata_corrected_hashes: Vec<BlobHash>,
    pub repaired_blob_rows: Vec<BlobHash>,
    pub removed_blob_rows: Vec<BlobHash>,
    pub removed_canonical_files: Vec<BlobHash>,
    pub missing_referenced_hashes: Vec<BlobHash>,
    pub corrupt_referenced_hashes: Vec<BlobHash>,
    /// Unexpected or ambiguously named paths that were deliberately retained.
    pub ignored_paths: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupReconcileError {
    #[error("blob store: {0}")]
    Blob(#[from] BlobError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("event journal integrity: {0}")]
    StoredEvent(String),
    #[error("startup reconciliation refused while {count} blob lease(s) are live")]
    LiveBlobLeases { count: usize },
    #[error("malformed {table} blob hash has {length} bytes (expected 32)")]
    MalformedDatabaseHash { table: &'static str, length: usize },
    #[error("owner count for blob {hash} exceeds sqlite INTEGER range")]
    OwnerCountOverflow { hash: BlobHash },
}

#[derive(Debug, Clone, Copy)]
struct DbBlob {
    size: u64,
    compressed: bool,
    refcount: i64,
}

#[derive(Debug, Clone)]
enum PhysicalBlob {
    Valid(BlobStat),
    Corrupt(BlobStat),
}

fn decode_hash(table: &'static str, bytes: Vec<u8>) -> Result<BlobHash, StartupReconcileError> {
    let length = bytes.len();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StartupReconcileError::MalformedDatabaseHash { table, length })?;
    Ok(BlobHash::from_bytes(raw))
}

fn parse_canonical_hash(name: &str) -> Option<BlobHash> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut raw = [0_u8; 32];
    for (index, pair) in name.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        raw[index] = (high << 4) | low;
    }
    Some(BlobHash::from_bytes(raw))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn live_lease_count(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM blob_leases", [], |row| row.get(0))?;
    Ok(count.max(0) as usize)
}

fn load_owner_counts(conn: &Connection) -> Result<BTreeMap<BlobHash, u64>, StartupReconcileError> {
    let mut owners = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT blob_hash, COUNT(*) FROM events
             WHERE blob_hash IS NOT NULL
               AND discriminant = 'FilePreImage'
             GROUP BY blob_hash",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (bytes, count) = row?;
            let hash = decode_hash("events", bytes)?;
            owners.insert(hash, count.max(0) as u64);
        }
    }
    {
        let mut stmt =
            conn.prepare("SELECT blob_hash, COUNT(*) FROM container_stashes GROUP BY blob_hash")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (bytes, count) = row?;
            let hash = decode_hash("container_stashes", bytes)?;
            *owners.entry(hash).or_default() += count.max(0) as u64;
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT hash, COUNT(*) FROM chunks
             WHERE materialized != 0 GROUP BY hash",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (bytes, count) = row?;
            let hash = decode_hash("chunks", bytes)?;
            *owners.entry(hash).or_default() += count.max(0) as u64;
        }
    }
    Ok(owners)
}

fn load_blob_rows(conn: &Connection) -> Result<BTreeMap<BlobHash, DbBlob>, StartupReconcileError> {
    let mut stmt = conn.prepare("SELECT hash, size, compressed, refcount FROM blobs")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut blobs = BTreeMap::new();
    for row in rows {
        let (bytes, size, compressed, refcount) = row?;
        blobs.insert(
            decode_hash("blobs", bytes)?,
            DbBlob {
                size: size.max(0) as u64,
                compressed: compressed != 0,
                refcount,
            },
        );
    }
    Ok(blobs)
}

fn is_lower_hex_component(name: &str) -> bool {
    name.len() == 2
        && name
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_managed_tmp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("blob-") else {
        return false;
    };
    let mut parts = rest.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(seq), None)
            if !pid.is_empty()
                && !seq.is_empty()
                && pid.bytes().all(|byte| byte.is_ascii_digit())
                && seq.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn clear_stale_tmp(
    root: &Path,
    report: &mut StartupReconcileReport,
) -> Result<(), StartupReconcileError> {
    let tmp = root.join("tmp");
    let mut removed_any = false;
    for entry in fs::read_dir(&tmp)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let managed = name.to_str().is_some_and(is_managed_tmp_name);
        let file_type = entry.file_type()?;
        if !managed || !(file_type.is_file() || file_type.is_symlink()) {
            report.ignored_paths.push(path);
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {
                report.tmp_files_removed += 1;
                removed_any = true;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if removed_any {
        fs::File::open(tmp)?.sync_all()?;
    }
    Ok(())
}

fn conservative_corrupt_stat(path: &Path) -> Result<BlobStat, io::Error> {
    let stored_bytes = fs::metadata(path)?.len();
    let mut file = fs::File::open(path)?;
    let mut flag = [0_u8; 1];
    let compressed = file.read(&mut flag)? == 1 && flag[0] == 0x01;
    Ok(BlobStat {
        stored_bytes,
        compressed,
    })
}

fn walk_canonical_blobs(
    root: &Path,
    blobs: &BlobExclusiveGuard<'_>,
    report: &mut StartupReconcileReport,
) -> Result<BTreeMap<BlobHash, PhysicalBlob>, StartupReconcileError> {
    let mut physical = BTreeMap::new();
    for first in fs::read_dir(root.join("blobs"))? {
        let first = first?;
        let first_path = first.path();
        let first_name = first.file_name();
        let Some(first_name) = first_name.to_str() else {
            report.ignored_paths.push(first_path);
            continue;
        };
        if !first.file_type()?.is_dir() || !is_lower_hex_component(first_name) {
            report.ignored_paths.push(first_path);
            continue;
        }
        for second in fs::read_dir(&first_path)? {
            let second = second?;
            let second_path = second.path();
            let second_name = second.file_name();
            let Some(second_name) = second_name.to_str() else {
                report.ignored_paths.push(second_path);
                continue;
            };
            if !second.file_type()?.is_dir() || !is_lower_hex_component(second_name) {
                report.ignored_paths.push(second_path);
                continue;
            }
            for leaf in fs::read_dir(&second_path)? {
                let leaf = leaf?;
                let path = leaf.path();
                if !leaf.file_type()?.is_file() {
                    report.ignored_paths.push(path);
                    continue;
                }
                let name = leaf.file_name();
                let Some(name) = name.to_str() else {
                    report.ignored_paths.push(path);
                    continue;
                };
                let Some(hash) = parse_canonical_hash(name) else {
                    report.ignored_paths.push(path);
                    continue;
                };
                if &name[..2] != first_name || &name[2..4] != second_name {
                    report.ignored_paths.push(path);
                    continue;
                }
                let state = match blobs.validate(hash) {
                    Ok(stat) => PhysicalBlob::Valid(stat),
                    Err(BlobError::HashMismatch { .. })
                    | Err(BlobError::Malformed(_))
                    | Err(BlobError::UnknownFlag { .. })
                    | Err(BlobError::Decode { .. }) => {
                        PhysicalBlob::Corrupt(conservative_corrupt_stat(&path)?)
                    }
                    Err(BlobError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                physical.insert(hash, state);
            }
        }
    }
    Ok(physical)
}

/// Reconcile the blob filesystem and Index before capture producers start.
///
/// Process-lifetime baseline leases must be cleared by the daemon first. This
/// function refuses to mutate anything while a lease remains. Physical
/// deletion is DB-first and all work runs under exclusive lifecycle ownership.
pub fn reconcile_startup(
    index: &Index,
    blob_store: &BlobStore,
) -> Result<StartupReconcileReport, StartupReconcileError> {
    let blobs = blob_store.exclusive_guard();
    let mut report = StartupReconcileReport::default();
    let mut physical_removals = BTreeSet::new();

    {
        // Global order: lifecycle first, Index second. Keeping the Index mutex
        // through scan + transaction makes the owner snapshot authoritative
        // for every in-process store caller.
        let conn = index.conn().lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let lease_count = live_lease_count(&tx)?;
        if lease_count != 0 {
            return Err(StartupReconcileError::LiveBlobLeases { count: lease_count });
        }

        validate_stored_events(&tx)
            .map_err(|error| StartupReconcileError::StoredEvent(error.to_string()))?;
        clear_stale_tmp(blob_store.root(), &mut report)?;
        let owners = load_owner_counts(&tx)?;
        let db_rows = load_blob_rows(&tx)?;
        let physical = walk_canonical_blobs(blob_store.root(), &blobs, &mut report)?;

        // Referenced evidence is never deleted. Record missing/corrupt files
        // and recreate every missing row. Conservative placeholders make
        // strict later event/stash release possible even without valid bytes.
        for (&hash, &owner_count) in &owners {
            let owner_count = i64::try_from(owner_count)
                .map_err(|_| StartupReconcileError::OwnerCountOverflow { hash })?;
            let placeholder = match physical.get(&hash) {
                None => {
                    report.missing_referenced_hashes.push(hash);
                    BlobStat {
                        stored_bytes: 0,
                        compressed: false,
                    }
                }
                Some(PhysicalBlob::Corrupt(stat)) => {
                    report.corrupt_referenced_hashes.push(hash);
                    stat.clone()
                }
                Some(PhysicalBlob::Valid(stat)) => stat.clone(),
            };
            if !db_rows.contains_key(&hash) {
                tx.execute(
                    "INSERT INTO blobs
                     (hash, size, compressed, refcount, created_logical)
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    params![
                        hash.as_bytes().as_slice(),
                        placeholder.stored_bytes as i64,
                        placeholder.compressed as i64,
                        owner_count,
                    ],
                )?;
                report.repaired_blob_rows.push(hash);
                report.refcount_rows_recomputed += 1;
            }
        }

        // Old refcounts are never trusted. Recompute all pre-existing rows
        // from event owners plus one owner per distinct stash row.
        for (&hash, row) in &db_rows {
            let expected_u64 = owners.get(&hash).copied().unwrap_or(0);
            let expected = i64::try_from(expected_u64)
                .map_err(|_| StartupReconcileError::OwnerCountOverflow { hash })?;
            report.refcount_rows_recomputed += 1;
            if row.refcount != expected {
                report.refcount_corrected_hashes.push(hash);
            }

            if expected != 0 {
                match physical.get(&hash) {
                    Some(PhysicalBlob::Valid(stat)) => {
                        if row.size != stat.stored_bytes || row.compressed != stat.compressed {
                            report.metadata_corrected_hashes.push(hash);
                        }
                        tx.execute(
                            "UPDATE blobs
                             SET size = ?2, compressed = ?3, refcount = ?4
                             WHERE hash = ?1",
                            params![
                                hash.as_bytes().as_slice(),
                                stat.stored_bytes as i64,
                                stat.compressed as i64,
                                expected,
                            ],
                        )?;
                    }
                    Some(PhysicalBlob::Corrupt(stat)) => {
                        // Corrupt bytes are deliberately retained for
                        // diagnosis, but stale row metadata must not inflate
                        // the size cap and trigger unrelated command eviction.
                        // The observed stored length and recognized envelope
                        // flag are conservative accounting facts even though
                        // the payload itself cannot be trusted for replay.
                        if row.size != stat.stored_bytes || row.compressed != stat.compressed {
                            report.metadata_corrected_hashes.push(hash);
                        }
                        tx.execute(
                            "UPDATE blobs
                             SET size = ?2, compressed = ?3, refcount = ?4
                             WHERE hash = ?1",
                            params![
                                hash.as_bytes().as_slice(),
                                stat.stored_bytes as i64,
                                stat.compressed as i64,
                                expected,
                            ],
                        )?;
                    }
                    None => {
                        // A referenced-but-missing file consumes no blob-store
                        // bytes. Keep the placeholder owner row so later
                        // command/stash release remains strict and atomic, but
                        // do not let historical size metadata distort GC.
                        if row.size != 0 || row.compressed {
                            report.metadata_corrected_hashes.push(hash);
                        }
                        tx.execute(
                            "UPDATE blobs
                             SET size = 0, compressed = 0, refcount = ?2
                             WHERE hash = ?1",
                            params![hash.as_bytes().as_slice(), expected],
                        )?;
                    }
                }
                continue;
            }

            // Authoritative in-transaction recheck. The old refcount is not a
            // condition because it is precisely the value being repaired.
            let removed = tx.execute(
                "DELETE FROM blobs
                 WHERE hash = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.blob_hash = blobs.hash
                         AND e.discriminant = 'FilePreImage'
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM container_stashes s
                       WHERE s.blob_hash = blobs.hash
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM chunks c
                       WHERE c.hash = blobs.hash AND c.materialized != 0
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM blob_leases l WHERE l.hash = blobs.hash
                   )",
                params![hash.as_bytes().as_slice()],
            )?;
            if removed == 1 {
                report.removed_blob_rows.push(hash);
                if physical.contains_key(&hash) {
                    physical_removals.insert(hash);
                }
            }
        }

        // A physical crash orphan has no DB row to remove; the authoritative
        // owner snapshot above is its DB-first proof of unowned status.
        for &hash in physical.keys() {
            if !db_rows.contains_key(&hash) && !owners.contains_key(&hash) {
                physical_removals.insert(hash);
            }
        }

        tx.commit()?;
    }

    // DB changes are durable before physical removal. Failure here is safe but
    // leaves an unindexed physical orphan for the next startup pass.
    for hash in physical_removals {
        blobs.delete(&hash)?;
        report.removed_canonical_files.push(hash);
    }
    report.ignored_paths.sort();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use shit_planner::{
        CaptureEvent, CaptureEventKind, CommandId, EventId, FileMetadata, FilePreImageSource,
        InodeRef, TimePoint,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn setup() -> (tempfile::TempDir, Index, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path().join("index.db")).unwrap();
        let blobs = BlobStore::open(dir.path().join("store")).unwrap();
        (dir, index, blobs)
    }

    fn canonical_path(blobs: &BlobStore, hash: BlobHash) -> PathBuf {
        let hex = hash.to_hex();
        blobs
            .root()
            .join("blobs")
            .join(&hex[..2])
            .join(&hex[2..4])
            .join(hex)
    }

    fn insert_open_command(index: &Index, command: CommandId) {
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos)
                 VALUES (?1, ?2, 'open', '/tmp', 1, 'bash', 1, 1)",
                params![command.session.as_bytes().as_slice(), command.seq as i64],
            )
            .unwrap();
    }

    fn insert_event_owner_conn(
        conn: &Connection,
        command: CommandId,
        hash: BlobHash,
        logical: u64,
    ) {
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: TimePoint::new(logical, logical),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, logical),
                path: PathBuf::from(format!("/reconcile-{logical}")),
                blob: hash,
                meta: FileMetadata {
                    mode: 0o100644,
                    uid: 1000,
                    gid: 1000,
                    size: 0,
                    mtime_unix_nanos: 0,
                    xattrs: BTreeMap::new(),
                    acl: None,
                    flags: 0,
                },
                post_content_hash: None,
                source: FilePreImageSource::Other,
            },
        };
        let denorm = crate::index::denormalize(&event.kind);
        let payload = postcard::to_allocvec(&event).unwrap();
        conn.execute(
            "INSERT INTO events
             (session, seq, ts_logical, ts_wall_nanos, partial,
              discriminant, dev, inode, path, blob_hash,
              post_content_hash, payload)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
            params![
                command.session.as_bytes().as_slice(),
                command.seq as i64,
                logical as i64,
                logical as i64,
                denorm.discriminant,
                denorm.dev,
                denorm.inode,
                denorm.path,
                hash.as_bytes().as_slice(),
                payload,
            ],
        )
        .unwrap();
    }

    fn insert_event_owner(index: &Index, command: CommandId, hash: BlobHash, logical: u64) {
        let conn = index.conn().lock().unwrap();
        insert_event_owner_conn(&conn, command, hash, logical);
    }

    fn blob_row(index: &Index, hash: BlobHash) -> Option<(u64, bool, i64)> {
        index
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT size, compressed, refcount FROM blobs WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                    ))
                },
            )
            .ok()
    }

    #[test]
    fn repairs_v4_style_referenced_file_without_blob_row() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path().join("store")).unwrap();
        let payload = b"legacy container and event bytes";
        let (hash, stat) = blobs.put(payload).unwrap();
        let db_path = dir.path().join("legacy-v4.db");
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 1,
        };

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
            conn.execute_batch(include_str!("../migrations/0001-init.sql"))
                .unwrap();
            conn.execute_batch(include_str!("../migrations/0002-importance.sql"))
                .unwrap();
            conn.execute_batch(include_str!(
                "../migrations/0003-large-objects-and-holds.sql"
            ))
            .unwrap();
            conn.execute_batch(include_str!("../migrations/0004-container-stash.sql"))
                .unwrap();
            conn.execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos)
                 VALUES (?1, ?2, 'legacy', '/tmp', 1, 'bash', 1, 1)",
                params![command.session.as_bytes().as_slice(), command.seq as i64],
            )
            .unwrap();
            for logical in [2_u64, 3] {
                insert_event_owner_conn(&conn, command, hash, logical);
            }
            conn.execute(
                "INSERT INTO container_stashes
                 (blob_hash, kind, runtime, name, size_bytes, created_unix_secs)
                 VALUES (?1, 0, 'docker', 'legacy-image', ?2, 1)",
                params![hash.as_bytes().as_slice(), stat.stored_bytes as i64],
            )
            .unwrap();
        }

        let index = Index::open(&db_path).unwrap();
        assert!(blob_row(&index, hash).is_none());
        let report = reconcile_startup(&index, &blobs).unwrap();

        assert_eq!(report.repaired_blob_rows, vec![hash]);
        assert_eq!(report.refcount_rows_recomputed, 1);
        assert!(report.missing_referenced_hashes.is_empty());
        assert!(report.corrupt_referenced_hashes.is_empty());
        assert_eq!(
            blob_row(&index, hash),
            Some((stat.stored_bytes, stat.compressed, 3))
        );
        assert_eq!(blobs.get(hash).unwrap(), payload);
    }

    #[test]
    fn removes_crash_orphans_but_never_ambiguous_paths() {
        let (_dir, index, blobs) = setup();
        let (file_only, _) = blobs.put(b"renamed before index commit").unwrap();
        let (corrupt, corrupt_stat) = blobs.put(b"db row then corrupt file").unwrap();
        index
            .put_blob_record(
                corrupt,
                corrupt_stat.stored_bytes,
                false,
                TimePoint::new(1, 1),
            )
            .unwrap();
        fs::write(canonical_path(&blobs, corrupt), [0xFE, 1, 2, 3]).unwrap();

        let missing = BlobHash::from_bytes([0x99; 32]);
        index
            .put_blob_record(missing, 123, false, TimePoint::new(1, 1))
            .unwrap();

        let stale_tmp = blobs.root().join("tmp/blob-4242-7");
        fs::write(&stale_tmp, b"partial").unwrap();
        let ambiguous = blobs.root().join("blobs/aa/bb/not-a-canonical-hash");
        fs::create_dir_all(ambiguous.parent().unwrap()).unwrap();
        fs::write(&ambiguous, b"do not delete me").unwrap();

        let report = reconcile_startup(&index, &blobs).unwrap();

        assert_eq!(report.tmp_files_removed, 1);
        assert!(!stale_tmp.exists());
        assert_eq!(
            report.removed_blob_rows,
            BTreeSet::from([corrupt, missing])
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.removed_canonical_files,
            BTreeSet::from([corrupt, file_only])
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert!(!blobs.contains(&file_only));
        assert!(!blobs.contains(&corrupt));
        assert!(blob_row(&index, corrupt).is_none());
        assert!(blob_row(&index, missing).is_none());
        assert!(ambiguous.exists());
        assert!(report.ignored_paths.contains(&ambiguous));
    }

    #[test]
    fn preserves_and_reports_referenced_missing_and_corrupt_evidence() {
        let (_dir, index, blobs) = setup();
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 3,
        };
        insert_open_command(&index, command);

        let missing = BlobHash::from_bytes([0xA1; 32]);
        index
            .put_blob_record(missing, 500, false, TimePoint::new(1, 1))
            .unwrap();
        let (corrupt, stat) = blobs.put(b"referenced bytes later corrupted").unwrap();
        index
            .put_blob_record(
                corrupt,
                stat.stored_bytes,
                stat.compressed,
                TimePoint::new(1, 1),
            )
            .unwrap();
        insert_event_owner(&index, command, missing, 2);
        insert_event_owner(&index, command, corrupt, 3);
        {
            let conn = index.conn().lock().unwrap();
            conn.execute(
                "UPDATE blobs SET refcount = 99 WHERE hash IN (?1, ?2)",
                params![missing.as_bytes().as_slice(), corrupt.as_bytes().as_slice()],
            )
            .unwrap();
        }
        fs::write(canonical_path(&blobs, corrupt), []).unwrap();

        let report = reconcile_startup(&index, &blobs).unwrap();

        assert_eq!(report.missing_referenced_hashes, vec![missing]);
        assert_eq!(report.corrupt_referenced_hashes, vec![corrupt]);
        assert_eq!(
            report.refcount_corrected_hashes,
            BTreeSet::from([missing, corrupt])
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(blob_row(&index, missing).unwrap().2, 1);
        assert_eq!(blob_row(&index, corrupt).unwrap().2, 1);
        assert_eq!(blob_row(&index, missing), Some((0, false, 1)));
        assert_eq!(blob_row(&index, corrupt), Some((0, false, 1)));
        assert_eq!(
            report.metadata_corrected_hashes,
            BTreeSet::from([missing, corrupt])
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(index.total_blob_size().unwrap(), 0);
        assert!(!blobs.contains(&missing));
        assert!(blobs.contains(&corrupt));
        assert!(report.removed_blob_rows.is_empty());
        assert!(report.removed_canonical_files.is_empty());
    }

    #[test]
    fn missing_rows_get_placeholders_that_later_owner_release_can_decrement() {
        let (_dir, index, blobs) = setup();
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 33,
        };
        insert_open_command(&index, command);

        let missing = BlobHash::from_bytes([0xB1; 32]);
        insert_event_owner(&index, command, missing, 2);

        let corrupt = BlobHash::from_bytes([0xB2; 32]);
        let corrupt_path = canonical_path(&blobs, corrupt);
        fs::create_dir_all(corrupt_path.parent().unwrap()).unwrap();
        fs::write(&corrupt_path, [0x01, 0xFF, 0x00, 0x7F]).unwrap();
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO container_stashes
                 (blob_hash, kind, runtime, name, size_bytes, created_unix_secs)
                 VALUES (?1, 0, 'docker', 'legacy-corrupt', 4, 0)",
                params![corrupt.as_bytes().as_slice()],
            )
            .unwrap();

        let report = reconcile_startup(&index, &blobs).unwrap();
        assert_eq!(
            report.repaired_blob_rows,
            BTreeSet::from([missing, corrupt])
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(report.missing_referenced_hashes, vec![missing]);
        assert_eq!(report.corrupt_referenced_hashes, vec![corrupt]);
        assert_eq!(blob_row(&index, missing), Some((0, false, 1)));
        assert_eq!(blob_row(&index, corrupt), Some((4, true, 1)));

        index.drop_command(command).unwrap();
        assert_eq!(blob_row(&index, missing).unwrap().2, 0);
        let pruned = crate::container_stash::prune_older_than(&index, 0, 1).unwrap();
        assert_eq!(pruned, vec![*corrupt.as_bytes()]);
        assert_eq!(blob_row(&index, corrupt).unwrap().2, 0);
        let unreferenced = index.unreferenced_blobs().unwrap();
        assert!(unreferenced.contains(&missing));
        assert!(unreferenced.contains(&corrupt));
    }

    #[test]
    fn refuses_corrupt_event_payload_before_reconciliation_mutates_state() {
        let (_dir, index, blobs) = setup();
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 41,
        };
        insert_open_command(&index, command);
        let hash = BlobHash::from_bytes([0xC1; 32]);
        insert_event_owner(&index, command, hash, 2);
        index
            .conn()
            .lock()
            .unwrap()
            .execute("UPDATE events SET payload = X'00'", [])
            .unwrap();
        let stale_tmp = blobs.root().join("tmp/blob-41-1");
        fs::write(&stale_tmp, b"must survive integrity refusal").unwrap();

        let error = reconcile_startup(&index, &blobs).unwrap_err();
        assert!(matches!(error, StartupReconcileError::StoredEvent(_)));
        assert!(stale_tmp.exists());
        assert!(blob_row(&index, hash).is_none());
    }

    #[test]
    fn refuses_event_payload_denormalization_mismatch() {
        let (_dir, index, blobs) = setup();
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 42,
        };
        insert_open_command(&index, command);
        let payload_hash = BlobHash::from_bytes([0xC2; 32]);
        insert_event_owner(&index, command, payload_hash, 2);
        let denormalized_hash = BlobHash::from_bytes([0xC3; 32]);
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE events SET blob_hash = ?1",
                [denormalized_hash.as_bytes().as_slice()],
            )
            .unwrap();

        let error = reconcile_startup(&index, &blobs).unwrap_err();
        assert!(matches!(error, StartupReconcileError::StoredEvent(_)));
        assert!(blob_row(&index, payload_hash).is_none());
        assert!(blob_row(&index, denormalized_hash).is_none());
    }

    #[test]
    fn materialized_chunks_are_rebuilt_as_authoritative_blob_owners() {
        let (_dir, index, blobs) = setup();
        let (chunk_hash, stat) = blobs.put(b"materialized large-object chunk").unwrap();
        let parent_hash = BlobHash::from_bytes([0xD1; 32]);
        {
            let conn = index.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO large_objects
                 (blob_hash, total_size, chunk_count, materialized, created_logical)
                 VALUES (?1, ?2, 1, 1, 1)",
                params![
                    parent_hash.as_bytes().as_slice(),
                    b"materialized large-object chunk".len() as i64
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chunks
                 (blob_hash, idx, offset, length, hash, materialized)
                 VALUES (?1, 0, 0, ?2, ?3, 1)",
                params![
                    parent_hash.as_bytes().as_slice(),
                    b"materialized large-object chunk".len() as i64,
                    chunk_hash.as_bytes().as_slice()
                ],
            )
            .unwrap();
        }

        let report = reconcile_startup(&index, &blobs).unwrap();
        assert_eq!(report.repaired_blob_rows, vec![chunk_hash]);
        assert_eq!(
            blob_row(&index, chunk_hash),
            Some((stat.stored_bytes, stat.compressed, 1))
        );
        assert!(blobs.contains(&chunk_hash));

        // The relationship itself is an authoritative defense even if the
        // denormalized refcount is later corrupted between restarts.
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE blobs SET refcount = 0 WHERE hash = ?1",
                [chunk_hash.as_bytes().as_slice()],
            )
            .unwrap();
        assert!(!index.unreferenced_blobs().unwrap().contains(&chunk_hash));
        assert!(!index.drop_blob_record(chunk_hash).unwrap());
        assert!(blobs.contains(&chunk_hash));
    }

    #[test]
    fn live_lease_refuses_before_tmp_or_blob_mutation() {
        let (_dir, index, blobs) = setup();
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 4,
        };
        insert_open_command(&index, command);
        let (hash, stat) = blobs.put(b"leased startup evidence").unwrap();
        index
            .put_blob_record(
                hash,
                stat.stored_bytes,
                stat.compressed,
                TimePoint::new(1, 1),
            )
            .unwrap();
        index
            .create_blob_lease(hash, command, TimePoint::new(2, 2))
            .unwrap();
        let stale_tmp = blobs.root().join("tmp/blob-99-1");
        fs::write(&stale_tmp, b"must remain on refusal").unwrap();

        assert!(matches!(
            reconcile_startup(&index, &blobs),
            Err(StartupReconcileError::LiveBlobLeases { count: 1 })
        ));
        assert!(stale_tmp.exists());
        assert!(blobs.contains(&hash));
        assert!(blob_row(&index, hash).is_some());
    }
}
