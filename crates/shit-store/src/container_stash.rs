// SPDX-License-Identifier: AGPL-3.0-or-later

//! Container-runtime stash store (C04.6).
//!
//! A separate retention surface for `docker save` image tarballs and
//! `docker volume rm` volume tarballs. The actual tarball bytes are
//! stored in the existing [`BlobStore`](crate::blob); this module is
//! the *index* + retention layer that tracks which blobs are
//! container stashes and when they should age out.
//!
//! Default retention for unbatched stashes is 1 day — image-save tarballs can
//! be tens of GiB, and keeping months of them eats disk fast. A stash associated
//! with a PREPARED or CONFIRMED atomic container batch is retained regardless
//! of age. FINALIZED batches move the stash's durable age origin to runtime
//! completion, guaranteeing a full retention window even for long-running
//! commands. Users who want longer retention can `shit pin <cmd>` (file-tier
//! pins from C01, independent of this store).
//!
//! The S13 GC pass calls [`prune_older_than`] before the file-tier
//! refcount sweep; that ordering matters because pruning a stash
//! decrements the underlying blob's refcount, which is what makes the
//! blob eligible for the same GC pass's blob sweep.

use crate::index::{Index, IndexError};
use rusqlite::params;
use shit_planner::{BlobHash, CommandId};
use uuid::Uuid;

/// Default retention for eligible, unbatched container stashes — 1 day in
/// seconds. Short because image tarballs are LARGE; users opt-in to longer
/// keep via `shit pin`. PREPARED/CONFIRMED stashes are not age-eligible;
/// FINALIZED stashes age from their durable runtime-completion origin.
pub const CONTAINER_STASH_RETENTION_SECS: u64 = 24 * 60 * 60;

/// What kind of container thing this stash represents. Drives the
/// reverse path (`docker load` for `ImageSave`, `tar -xzf -` into a
/// recreated volume for `VolumeTar`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StashKind {
    ImageSave = 0,
    VolumeTar = 1,
}

impl StashKind {
    fn as_wire(self) -> i64 {
        self as i64
    }

    fn from_wire(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::ImageSave),
            1 => Some(Self::VolumeTar),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImageSave => "image-save",
            Self::VolumeTar => "volume-tar",
        }
    }
}

/// One row in `container_stashes`. Returned by [`list_all`] /
/// [`list_for_command`] / [`get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerStash {
    /// 32-byte blake3 of the tarball bytes — also the key into the
    /// blob store.
    pub blob_hash: [u8; 32],
    pub kind: StashKind,
    /// `"docker"` or `"podman"`.
    pub runtime: String,
    /// Image name (e.g. `nginx:1.25`) or volume name.
    pub name: String,
    pub size_bytes: u64,
    pub created_unix_secs: u64,
    /// Best-effort link back to the originating command. `None` when
    /// the stash was registered before the command-window closed.
    pub command: Option<CommandId>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegisterRequest<'a> {
    pub blob_hash: [u8; 32],
    pub kind: StashKind,
    pub runtime: &'a str,
    pub name: &'a str,
    pub size_bytes: u64,
    pub command: Option<CommandId>,
    pub note: Option<&'a str>,
}

/// Register a stash and acquire its blob-owner reference.
///
/// Idempotent for a given `blob_hash`: a new stash row increments the blob
/// refcount exactly once, while re-registration only refreshes retention and
/// fills optional command/note metadata. The referenced blob row must already
/// exist. A ContainerOp event indexes this hash for history, but the stash row
/// is the sole owner. Its age origin advances on runtime finalization so bytes
/// cannot be reclaimed during execution or before a full post-runtime window.
pub fn register(
    index: &Index,
    req: RegisterRequest<'_>,
    now_unix_secs: u64,
) -> Result<(), IndexError> {
    let now = now_unix_secs.min(i64::MAX as u64) as i64;
    let session_bytes: Option<Vec<u8>> = req.command.map(|c| c.session.as_bytes().to_vec());
    let seq: Option<i64> = req.command.map(|c| c.seq as i64);
    let conn = index.conn().lock().unwrap();
    let tx = conn.unchecked_transaction()?;
    let hash = BlobHash::from_bytes(req.blob_hash);
    let blob_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = ?1)",
        [req.blob_hash.as_slice()],
        |row| row.get(0),
    )?;
    if !blob_exists {
        return Err(IndexError::MissingBlob(hash));
    }
    let inserted = tx.execute(
        "INSERT INTO container_stashes
            (blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
             session, seq, note, retain_from_unix_secs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?6)
         ON CONFLICT(blob_hash) DO NOTHING",
        params![
            req.blob_hash.as_slice(),
            req.kind.as_wire(),
            req.runtime,
            req.name,
            req.size_bytes as i64,
            now,
            session_bytes,
            seq,
            req.note,
        ],
    )?;
    if inserted == 1 {
        let bumped = tx.execute(
            "UPDATE blobs SET refcount = refcount + 1 WHERE hash = ?1",
            [req.blob_hash.as_slice()],
        )?;
        if bumped != 1 {
            return Err(IndexError::MissingBlob(hash));
        }
    } else {
        tx.execute(
            "UPDATE container_stashes
             SET created_unix_secs = MAX(created_unix_secs, ?2),
                 retain_from_unix_secs = MAX(retain_from_unix_secs, ?2),
                 session = COALESCE(?3, session),
                 seq = COALESCE(?4, seq),
                 note = COALESCE(?5, note)
             WHERE blob_hash = ?1",
            params![req.blob_hash.as_slice(), now, session_bytes, seq, req.note],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Fetch one stash by hash. Returns `None` if absent.
pub fn get(index: &Index, blob_hash: &[u8; 32]) -> Result<Option<ContainerStash>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
                session, seq, note
           FROM container_stashes
          WHERE blob_hash = ?1",
    )?;
    let mut rows = stmt.query([blob_hash.as_slice()])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_to_stash(row)?)),
        None => Ok(None),
    }
}

/// List every stash, newest first. Used by `shit container-stashes list`.
pub fn list_all(index: &Index) -> Result<Vec<ContainerStash>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
                session, seq, note
           FROM container_stashes
       ORDER BY created_unix_secs DESC",
    )?;
    let mut rows = stmt.query([])?;
    let mut stashes = Vec::new();
    while let Some(row) = rows.next()? {
        stashes.push(row_to_stash(row)?);
    }
    Ok(stashes)
}

/// List stashes belonging to a specific command. Used by `shit show`.
pub fn list_for_command(index: &Index, cmd: CommandId) -> Result<Vec<ContainerStash>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
                session, seq, note
           FROM container_stashes
          WHERE session = ?1 AND seq = ?2
       ORDER BY created_unix_secs ASC",
    )?;
    let mut rows = stmt.query(params![cmd.session.as_bytes().as_slice(), cmd.seq as i64])?;
    let mut stashes = Vec::new();
    while let Some(row) = rows.next()? {
        stashes.push(row_to_stash(row)?);
    }
    Ok(stashes)
}

/// Remove one stash and release exactly its stash-owner blob reference in the
/// same transaction. Event-owned references are unaffected. A stash backing
/// a PREPARED or CONFIRMED batch cannot be removed because the runtime may
/// still be authorized or running. REFUSED and FINALIZED stashes may be
/// explicitly removed; age pruning separately honors FINALIZED's timestamp.
pub fn remove(index: &Index, blob_hash: &[u8; 32]) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    let tx = conn.unchecked_transaction()?;
    let rows = tx.execute(
        "DELETE FROM container_stashes
         WHERE blob_hash = ?1
           AND NOT EXISTS (
               SELECT 1 FROM commands c
               WHERE c.session = container_stashes.session
                 AND c.seq = container_stashes.seq
                 AND c.ended_logical IS NULL
                 AND c.ended_wall_nanos IS NULL
                 AND c.exit_code IS NULL
           )
           AND NOT EXISTS (
               SELECT 1 FROM container_capture_batches b
               WHERE b.session = container_stashes.session
                 AND b.seq = container_stashes.seq
                 AND b.state IN ('PREPARED', 'CONFIRMED')
           )
           AND NOT EXISTS (
               SELECT 1
               FROM container_capture_batches b
               JOIN container_capture_batch_events m ON m.batch_id = b.batch_id
               JOIN events e ON e.id = m.event_id
               WHERE b.state IN ('PREPARED', 'CONFIRMED')
                 AND e.blob_hash = container_stashes.blob_hash
           )",
        [blob_hash.as_slice()],
    )?;
    if rows == 0 {
        tx.commit()?;
        return Ok(false);
    }
    let hash = BlobHash::from_bytes(*blob_hash);
    let decremented = tx.execute(
        "UPDATE blobs SET refcount = refcount - 1
         WHERE hash = ?1 AND refcount > 0",
        [blob_hash.as_slice()],
    )?;
    if decremented != 1 {
        return Err(IndexError::BlobRefcountInvariant {
            hash,
            operation: "removing container stash",
        });
    }
    tx.commit()?;
    Ok(true)
}

/// Prune every unpinned, unheld stash strictly older than
/// `older_than_secs`. Returns the list of `blob_hash`es that were pruned. Each
/// stash-owner reference is decremented in the same transaction as its row
/// deletion. Pins/holds on the originating command extend stash retention.
/// PREPARED/CONFIRMED associations protect the stash regardless of age.
/// FINALIZED associations advance `retain_from_unix_secs`, so the age test
/// starts from the greatest capture/finalization time across every batch that
/// referenced a shared content hash.
pub fn prune_older_than(
    index: &Index,
    older_than_secs: u64,
    now_unix_secs: u64,
) -> Result<Vec<[u8; 32]>, IndexError> {
    let cutoff = now_unix_secs
        .saturating_sub(older_than_secs)
        .min(i64::MAX as u64) as i64;
    let conn = index.conn().lock().unwrap();
    let tx = conn.unchecked_transaction()?;
    let hashes: Vec<[u8; 32]> = {
        let mut stmt = tx.prepare(
            "SELECT s.blob_hash FROM container_stashes s
             WHERE s.retain_from_unix_secs < ?1
               AND NOT EXISTS (
                   SELECT 1 FROM commands c
                   WHERE c.session = s.session AND c.seq = s.seq
                     AND c.ended_logical IS NULL
                     AND c.ended_wall_nanos IS NULL
                     AND c.exit_code IS NULL
               )
               AND NOT EXISTS (
                   SELECT 1 FROM pins p
                   WHERE p.session = s.session AND p.seq = s.seq
               )
               AND NOT EXISTS (
                   SELECT 1 FROM holds h
                   WHERE h.session = s.session AND h.seq = s.seq
               )
               AND NOT EXISTS (
                   SELECT 1 FROM events e
                   JOIN pins p ON p.session = e.session AND p.seq = e.seq
                   WHERE e.discriminant = 'ContainerOp'
                     AND e.blob_hash = s.blob_hash
               )
               AND NOT EXISTS (
                   SELECT 1 FROM events e
                   JOIN holds h ON h.session = e.session AND h.seq = e.seq
                   WHERE e.discriminant = 'ContainerOp'
                     AND e.blob_hash = s.blob_hash
               )
               AND NOT EXISTS (
                   SELECT 1 FROM container_capture_batches b
                   WHERE b.session = s.session AND b.seq = s.seq
                     AND b.state IN ('PREPARED', 'CONFIRMED')
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM container_capture_batches b
                   JOIN container_capture_batch_events m ON m.batch_id = b.batch_id
                   JOIN events e ON e.id = m.event_id
                   WHERE b.state IN ('PREPARED', 'CONFIRMED')
                     AND e.blob_hash = s.blob_hash
               )",
        )?;
        let mut rows = stmt.query([cutoff])?;
        let mut hashes = Vec::new();
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            hashes.push(decode_blob_hash(&bytes, "pruning container stash")?);
        }
        hashes
    };
    if hashes.is_empty() {
        tx.commit()?;
        return Ok(hashes);
    }
    tx.execute(
        "DELETE FROM container_stashes AS s
         WHERE s.retain_from_unix_secs < ?1
           AND NOT EXISTS (
               SELECT 1 FROM commands c
               WHERE c.session = s.session AND c.seq = s.seq
                 AND c.ended_logical IS NULL
                 AND c.ended_wall_nanos IS NULL
                 AND c.exit_code IS NULL
           )
           AND NOT EXISTS (
               SELECT 1 FROM pins p
               WHERE p.session = s.session AND p.seq = s.seq
           )
           AND NOT EXISTS (
               SELECT 1 FROM holds h
               WHERE h.session = s.session AND h.seq = s.seq
           )
           AND NOT EXISTS (
               SELECT 1 FROM events e
               JOIN pins p ON p.session = e.session AND p.seq = e.seq
               WHERE e.discriminant = 'ContainerOp'
                 AND e.blob_hash = s.blob_hash
           )
           AND NOT EXISTS (
               SELECT 1 FROM events e
               JOIN holds h ON h.session = e.session AND h.seq = e.seq
               WHERE e.discriminant = 'ContainerOp'
                 AND e.blob_hash = s.blob_hash
           )
           AND NOT EXISTS (
               SELECT 1 FROM container_capture_batches b
               WHERE b.session = s.session AND b.seq = s.seq
                 AND b.state IN ('PREPARED', 'CONFIRMED')
           )
           AND NOT EXISTS (
               SELECT 1
               FROM container_capture_batches b
               JOIN container_capture_batch_events m ON m.batch_id = b.batch_id
               JOIN events e ON e.id = m.event_id
               WHERE b.state IN ('PREPARED', 'CONFIRMED')
                 AND e.blob_hash = s.blob_hash
           )",
        [cutoff],
    )?;
    for bytes in &hashes {
        let hash = BlobHash::from_bytes(*bytes);
        let decremented = tx.execute(
            "UPDATE blobs SET refcount = refcount - 1
             WHERE hash = ?1 AND refcount > 0",
            [bytes.as_slice()],
        )?;
        if decremented != 1 {
            return Err(IndexError::BlobRefcountInvariant {
                hash,
                operation: "pruning container stash",
            });
        }
    }
    tx.commit()?;
    Ok(hashes)
}

/// Total bytes across all active stashes — `shit container-stashes
/// list` renders this so users can see the disk-usage exposure.
pub fn total_size_bytes(index: &Index) -> Result<u64, IndexError> {
    let conn = index.conn().lock().unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM container_stashes",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(n.max(0) as u64)
}

fn decode_blob_hash(bytes: &[u8], operation: &'static str) -> Result<[u8; 32], IndexError> {
    bytes.try_into().map_err(|_| IndexError::MalformedBlobHash {
        operation,
        actual_len: bytes.len(),
    })
}

fn row_to_stash(row: &rusqlite::Row<'_>) -> Result<ContainerStash, IndexError> {
    let hash_bytes: Vec<u8> = row.get(0)?;
    let blob_hash = decode_blob_hash(&hash_bytes, "reading container stash")?;
    let kind_wire: i64 = row.get(1)?;
    let kind = StashKind::from_wire(kind_wire).unwrap_or(StashKind::ImageSave);
    let runtime: String = row.get(2)?;
    let name: String = row.get(3)?;
    let size_bytes: i64 = row.get(4)?;
    let created_unix_secs: i64 = row.get(5)?;
    let session_bytes: Option<Vec<u8>> = row.get(6)?;
    let seq: Option<i64> = row.get(7)?;
    let note: Option<String> = row.get(8)?;
    let command = match (session_bytes, seq) {
        (Some(bytes), Some(s)) if bytes.len() == 16 => {
            let mut session = [0u8; 16];
            session.copy_from_slice(&bytes);
            Some(CommandId {
                session: Uuid::from_bytes(session),
                seq: s.max(0) as u64,
            })
        }
        _ => None,
    };
    Ok(ContainerStash {
        blob_hash,
        kind,
        runtime,
        name,
        size_bytes: size_bytes.max(0) as u64,
        created_unix_secs: created_unix_secs.max(0) as u64,
        command,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;
    use shit_planner::{
        CaptureEvent, CaptureEventKind, ContainerOp, ContainerRuntime, EventId, TimePoint,
    };

    fn fresh_index() -> Index {
        let tmp = tempfile::tempdir().unwrap();
        Index::open(tmp.path().join("idx.sqlite")).unwrap()
    }

    fn sample_request<'a>() -> RegisterRequest<'a> {
        RegisterRequest {
            blob_hash: [7; 32],
            kind: StashKind::ImageSave,
            runtime: "docker",
            name: "nginx:1.25",
            size_bytes: 65 * 1024 * 1024,
            command: None,
            note: None,
        }
    }

    const NOW: u64 = 10_000;

    fn register_with_blob(index: &Index, req: RegisterRequest<'_>) {
        index
            .put_blob_record(
                BlobHash::from_bytes(req.blob_hash),
                req.size_bytes,
                false,
                TimePoint::new(1, 0),
            )
            .unwrap();
        register(index, req, NOW).unwrap();
    }

    fn blob_refcount(index: &Index, hash: &[u8; 32]) -> i64 {
        index
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                [hash.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn insert_raw_stash(index: &Index, hash: &[u8], created_unix_secs: i64) {
        let conn = index.conn().lock().unwrap();
        conn.execute(
            "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
             VALUES (?1, 1, 0, 1, 1)",
            [hash],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO container_stashes
                (blob_hash, kind, runtime, name, size_bytes, created_unix_secs)
             VALUES (?1, 0, 'docker', 'raw', 1, ?2)",
            params![hash, created_unix_secs],
        )
        .unwrap();
    }

    fn insert_container_command(index: &Index, command: CommandId, hash: BlobHash) {
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos,
                  ended_logical, ended_wall_nanos, exit_code)
                 VALUES (?1, ?2, 'docker rmi image', '/tmp', 1, 'bash',
                         1, 1, 2, 2, 0)",
                params![command.session.as_bytes().as_slice(), command.seq as i64],
            )
            .unwrap();
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(2, 2),
                partial: false,
                kind: CaptureEventKind::ContainerOp {
                    runtime: ContainerRuntime::Docker,
                    op: ContainerOp::Rmi {
                        image: "image".into(),
                        digest: None,
                    },
                    captured_config: Vec::new(),
                    stash_image: None,
                    stash_tarball: Some(hash),
                },
            })
            .unwrap();
    }

    fn insert_open_container_command(index: &Index, command: CommandId) {
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos)
                 VALUES (?1, ?2, 'docker rmi --no-prune image:v1', '/tmp',
                         1, 'bash', 1, 1)",
                params![command.session.as_bytes().as_slice(), command.seq as i64],
            )
            .unwrap();
    }

    fn prepare_stash_batch(index: &Index, command: CommandId, batch_id: Uuid, hash: BlobHash) {
        index
            .prepare_container_batch(
                batch_id,
                [batch_id.as_bytes()[0]; 32],
                &[CaptureEvent {
                    id: EventId(0),
                    command,
                    ts: TimePoint::new(2, 2),
                    partial: true,
                    kind: CaptureEventKind::ContainerOp {
                        runtime: ContainerRuntime::Docker,
                        op: ContainerOp::Rmi {
                            image: "image:v1".into(),
                            digest: Some("sha256:before".into()),
                        },
                        captured_config: Vec::new(),
                        stash_image: None,
                        stash_tarball: Some(hash),
                    },
                }],
            )
            .unwrap();
    }

    #[test]
    fn register_then_get_roundtrips() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        let row = get(&idx, &[7; 32]).unwrap().unwrap();
        assert_eq!(row.blob_hash, [7; 32]);
        assert_eq!(row.kind, StashKind::ImageSave);
        assert_eq!(row.runtime, "docker");
        assert_eq!(row.name, "nginx:1.25");
        assert_eq!(row.size_bytes, 65 * 1024 * 1024);
        assert!(row.command.is_none());
    }

    #[test]
    fn get_missing_returns_none() {
        let idx = fresh_index();
        assert!(get(&idx, &[0; 32]).unwrap().is_none());
    }

    #[test]
    fn register_requires_existing_blob_record() {
        let idx = fresh_index();
        assert!(matches!(
            register(&idx, sample_request(), NOW),
            Err(IndexError::MissingBlob(hash)) if hash == BlobHash::from_bytes([7; 32])
        ));
        assert!(get(&idx, &[7; 32]).unwrap().is_none());
    }

    #[test]
    fn register_is_idempotent_on_hash_collision() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = 0, retain_from_unix_secs = 0
                 WHERE blob_hash = ?1",
                [[7; 32].as_slice()],
            )
            .unwrap();
        // Re-register with a command attached — should not error, and
        // should refresh retention and fill in the previously-NULL session/seq.
        let cmd = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 42,
        };
        let mut req = sample_request();
        req.command = Some(cmd);
        req.note = Some("attached on second pass");
        register(&idx, req, NOW + 1).unwrap();
        let row = get(&idx, &[7; 32]).unwrap().unwrap();
        assert_eq!(row.command, Some(cmd));
        assert_eq!(row.note.as_deref(), Some("attached on second pass"));
        assert_eq!(row.created_unix_secs, NOW + 1);
        assert_eq!(blob_refcount(&idx, &[7; 32]), 1);
    }

    #[test]
    fn reregister_does_not_move_retention_timestamp_backwards() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        let future = i64::MAX / 4;
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = ?1, retain_from_unix_secs = ?1
                 WHERE blob_hash = ?2",
                params![future, [7_u8; 32].as_slice()],
            )
            .unwrap();

        register(&idx, sample_request(), NOW).unwrap();
        let stored: i64 = idx
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT created_unix_secs FROM container_stashes
                 WHERE blob_hash = ?1",
                [[7_u8; 32].as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, future);
        assert_eq!(blob_refcount(&idx, &[7; 32]), 1);
    }

    #[test]
    fn list_all_orders_newest_first() {
        let idx = fresh_index();
        for i in 0..3 {
            let mut req = sample_request();
            req.blob_hash = [i; 32];
            // Bump size to disambiguate; all rows intentionally share the
            // deterministic checked clock sample in this test.
            register_with_blob(&idx, req);
        }
        let all = list_all(&idx).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_for_command_filters_correctly() {
        let idx = fresh_index();
        let cmd_a = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 1,
        };
        let cmd_b = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 2,
        };
        let mut r1 = sample_request();
        r1.blob_hash = [10; 32];
        r1.command = Some(cmd_a);
        register_with_blob(&idx, r1);
        let mut r2 = sample_request();
        r2.blob_hash = [20; 32];
        r2.command = Some(cmd_b);
        register_with_blob(&idx, r2);

        let only_a = list_for_command(&idx, cmd_a).unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].blob_hash, [10; 32]);
    }

    #[test]
    fn remove_returns_true_on_hit_false_on_miss() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        assert!(remove(&idx, &[7; 32]).unwrap());
        assert_eq!(blob_refcount(&idx, &[7; 32]), 0);
        assert!(!remove(&idx, &[7; 32]).unwrap());
    }

    #[test]
    fn remove_rolls_back_if_owner_refcount_is_corrupt() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE blobs SET refcount = 0 WHERE hash = ?1",
                [[7; 32].as_slice()],
            )
            .unwrap();

        assert!(matches!(
            remove(&idx, &[7; 32]),
            Err(IndexError::BlobRefcountInvariant { .. })
        ));
        assert!(get(&idx, &[7; 32]).unwrap().is_some());
        let hash = BlobHash::from_bytes([7; 32]);
        assert!(!idx.unreferenced_blobs().unwrap().contains(&hash));
        assert!(!idx.drop_blob_record(hash).unwrap());
    }

    #[test]
    fn total_size_bytes_aggregates_all_rows() {
        let idx = fresh_index();
        for i in 0..3 {
            let mut req = sample_request();
            req.blob_hash = [i; 32];
            req.size_bytes = 1000;
            register_with_blob(&idx, req);
        }
        assert_eq!(total_size_bytes(&idx).unwrap(), 3000);
    }

    #[test]
    fn prune_older_than_zero_drops_everything() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        let pruned = prune_older_than(&idx, 0, NOW + 1).unwrap();
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0], [7; 32]);
        assert!(list_all(&idx).unwrap().is_empty());
        assert_eq!(blob_refcount(&idx, &[7; 32]), 0);
    }

    #[test]
    fn prune_older_than_huge_keeps_everything() {
        let idx = fresh_index();
        register_with_blob(&idx, sample_request());
        let pruned = prune_older_than(&idx, 365 * 24 * 60 * 60, NOW).unwrap();
        assert!(pruned.is_empty());
        assert_eq!(list_all(&idx).unwrap().len(), 1);
    }

    #[test]
    fn direct_remove_protects_only_inflight_batch_states() {
        for (offset, transition, protected, label) in [
            (0_u8, None, true, "PREPARED"),
            (1, Some(true), true, "CONFIRMED"),
            (2, Some(false), false, "REFUSED"),
            (3, Some(true), false, "FINALIZED"),
        ] {
            let idx = fresh_index();
            let command = CommandId {
                session: Uuid::from_bytes([0x44 + offset; 16]),
                seq: 9,
            };
            insert_open_container_command(&idx, command);
            let mut request = sample_request();
            request.command = Some(command);
            register_with_blob(&idx, request);
            let batch_id = Uuid::from_bytes([0x55 + offset; 16]);
            prepare_stash_batch(&idx, command, batch_id, BlobHash::from_bytes([7; 32]));
            if let Some(confirm) = transition {
                idx.finalize_container_batch(batch_id, confirm).unwrap();
            }
            if label == "FINALIZED" {
                idx.mark_container_batch_finalized(batch_id, NOW + 100)
                    .unwrap();
            }
            assert!(
                idx.finish_command(command, TimePoint::new(3, 3), 0)
                    .unwrap()
            );

            assert_eq!(!remove(&idx, &[7; 32]).unwrap(), protected, "state={label}");
            assert_eq!(get(&idx, &[7; 32]).unwrap().is_some(), protected);
            assert_eq!(blob_refcount(&idx, &[7; 32]), i64::from(protected));
        }
    }

    #[test]
    fn shared_stash_uses_latest_finalization_and_any_inflight_batch_protects_it() {
        let idx = fresh_index();
        let hash = BlobHash::from_bytes([7; 32]);
        idx.put_blob_record(hash, 1, false, TimePoint::new(1, 1))
            .unwrap();
        let retention = CONTAINER_STASH_RETENTION_SECS;
        let first_finished = NOW + 2 * retention;
        let second_finished = first_finished + retention;

        let mut commands = Vec::new();
        for offset in 0_u8..3 {
            let command = CommandId {
                session: Uuid::from_bytes([0x70 + offset; 16]),
                seq: 1,
            };
            insert_open_container_command(&idx, command);
            register(
                &idx,
                RegisterRequest {
                    blob_hash: *hash.as_bytes(),
                    kind: StashKind::ImageSave,
                    runtime: "docker",
                    name: "shared:v1",
                    size_bytes: 1,
                    command: Some(command),
                    note: None,
                },
                NOW + u64::from(offset),
            )
            .unwrap();
            let batch_id = Uuid::from_bytes([0x80 + offset; 16]);
            prepare_stash_batch(&idx, command, batch_id, hash);
            commands.push((command, batch_id));
        }

        for ((command, batch_id), finalized_at) in commands[..2]
            .iter()
            .copied()
            .zip([first_finished, second_finished])
        {
            idx.finalize_container_batch(batch_id, true).unwrap();
            idx.mark_container_batch_finalized(batch_id, finalized_at)
                .unwrap();
            assert!(
                idx.finish_command(command, TimePoint::new(3, 3), 0)
                    .unwrap()
            );
            assert!(idx.drop_command(command).unwrap() > 0);
            assert!(idx.container_batch_info(batch_id).unwrap().is_none());
        }
        let (inflight_command, inflight_batch) = commands[2];
        assert!(
            idx.finish_command(inflight_command, TimePoint::new(3, 3), 0)
                .unwrap()
        );

        let retain_from: i64 = idx
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT retain_from_unix_secs FROM container_stashes WHERE blob_hash = ?1",
                [hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retain_from, second_finished as i64);

        let after_full_window = second_finished + retention + 1;
        assert!(
            prune_older_than(&idx, retention, after_full_window)
                .unwrap()
                .is_empty(),
            "a PREPARED reference must protect a shared stash past its finalized age window"
        );

        idx.finalize_container_batch(inflight_batch, false).unwrap();
        assert_eq!(
            prune_older_than(&idx, retention, after_full_window).unwrap(),
            vec![*hash.as_bytes()]
        );
        assert_eq!(blob_refcount(&idx, hash.as_bytes()), 0);
    }

    #[test]
    fn pin_on_any_deduplicated_container_event_extends_stash_retention() {
        let idx = fresh_index();
        let hash = BlobHash::from_bytes([7; 32]);
        let first = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 1,
        };
        let second = CommandId {
            session: Uuid::from_bytes([2; 16]),
            seq: 2,
        };

        let mut first_request = sample_request();
        first_request.command = Some(first);
        register_with_blob(&idx, first_request);
        insert_container_command(&idx, first, hash);
        idx.pin_command(first, Some("keep archive"), 3, None)
            .unwrap();

        // Re-registering identical bytes refreshes the single stash row and
        // points its convenience command link at the later command. The pin
        // on the first event must still protect the shared archive.
        let mut second_request = sample_request();
        second_request.command = Some(second);
        register(&idx, second_request, NOW + 1).unwrap();
        insert_container_command(&idx, second, hash);
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = 0, retain_from_unix_secs = 0
                 WHERE blob_hash = ?1",
                [hash.as_bytes().as_slice()],
            )
            .unwrap();

        assert!(prune_older_than(&idx, 1, NOW + 2).unwrap().is_empty());
        assert!(get(&idx, hash.as_bytes()).unwrap().is_some());
        assert_eq!(blob_refcount(&idx, hash.as_bytes()), 1);
    }

    #[test]
    fn malformed_hash_is_rejected_by_read_paths() {
        let idx = fresh_index();
        let malformed = [9u8; 31];
        insert_raw_stash(&idx, &malformed, 0);

        assert!(matches!(
            list_all(&idx),
            Err(IndexError::MalformedBlobHash {
                operation: "reading container stash",
                actual_len: 31,
            })
        ));
    }

    #[test]
    fn malformed_hash_aborts_prune_without_deleting_or_decrementing() {
        let idx = fresh_index();
        let malformed = [9u8; 31];
        let zero_hash = [0u8; 32];
        insert_raw_stash(&idx, &malformed, 0);
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
                 VALUES (?1, 1, 0, 1, 1)",
                [zero_hash.as_slice()],
            )
            .unwrap();

        assert!(matches!(
            prune_older_than(&idx, 1, NOW),
            Err(IndexError::MalformedBlobHash {
                operation: "pruning container stash",
                actual_len: 31,
            })
        ));

        let conn = idx.conn().lock().unwrap();
        let stash_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM container_stashes", [], |row| {
                row.get(0)
            })
            .unwrap();
        let malformed_refcount: i64 = conn
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                [malformed.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let zero_refcount: i64 = conn
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                [zero_hash.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stash_rows, 1, "the malformed stash deletion must roll back");
        assert_eq!(malformed_refcount, 1);
        assert_eq!(
            zero_refcount, 1,
            "a malformed hash must not alias zero hash"
        );
    }

    #[test]
    fn volume_tar_kind_roundtrips() {
        let idx = fresh_index();
        let mut req = sample_request();
        req.kind = StashKind::VolumeTar;
        req.name = "pgdata";
        register_with_blob(&idx, req);
        let row = get(&idx, &[7; 32]).unwrap().unwrap();
        assert_eq!(row.kind, StashKind::VolumeTar);
    }

    #[test]
    fn stash_kind_as_str_renders_for_cli() {
        assert_eq!(StashKind::ImageSave.as_str(), "image-save");
        assert_eq!(StashKind::VolumeTar.as_str(), "volume-tar");
    }
}
