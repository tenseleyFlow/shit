// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sqlite-backed implementation of [`PlannerStore`]. Holds the on-disk
//! journal, blob refcounts, and path history.
//!
//! Concurrency: single writer (the daemon), many readers. The connection
//! is wrapped in a `Mutex` for simple cross-thread access; the group-commit
//! writer (S04.4) batches inserts into a single transaction per tick.

use crate::schema::{self, SchemaError};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use shit_planner::{
    BlobHash, CaptureEvent, CaptureEventKind, CommandId, CommandRecord, EventId, InodeRef,
    PlannerStore, SeqRange, TimePoint,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),
    #[error("encode: {0}")]
    Encode(#[from] postcard::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The sqlite-backed index. One process opens the DB writeable; everything
/// goes through this struct.
pub struct Index {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl Index {
    /// Open (or create) the index at `path`. Runs migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IndexError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        schema::apply(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Idempotent: inserts the session row or replaces it (ON CONFLICT REPLACE).
    /// Sessions are write-once in practice but we don't enforce that here —
    /// the daemon can re-send open with no harm.
    pub fn put_session(
        &self,
        session: Uuid,
        shell_kind: &str,
        parent_pid: u32,
        tty: Option<&str>,
        opened: TimePoint,
    ) -> Result<(), IndexError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, shell_kind, parent_pid, tty, opened_logical, opened_wall_nanos)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET shell_kind=excluded.shell_kind",
            params![
                session.as_bytes().as_slice(),
                shell_kind,
                parent_pid as i64,
                tty,
                opened.logical as i64,
                opened.wallclock_unix_nanos as i64,
            ],
        )?;
        Ok(())
    }

    pub fn close_session(&self, session: Uuid, closed: TimePoint) -> Result<(), IndexError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions
             SET closed_logical = ?2, closed_wall_nanos = ?3
             WHERE id = ?1",
            params![
                session.as_bytes().as_slice(),
                closed.logical as i64,
                closed.wallclock_unix_nanos as i64,
            ],
        )?;
        Ok(())
    }

    pub fn put_command(&self, cmd: &CommandRecord) -> Result<(), IndexError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO commands (session, seq, cmd_string, cwd, pid, shell_kind,
                                   started_logical, started_wall_nanos,
                                   ended_logical, ended_wall_nanos, exit_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(session, seq) DO UPDATE SET
                cmd_string = excluded.cmd_string,
                ended_logical = excluded.ended_logical,
                ended_wall_nanos = excluded.ended_wall_nanos,
                exit_code = excluded.exit_code",
            params![
                cmd.command.session.as_bytes().as_slice(),
                cmd.command.seq as i64,
                cmd.cmd_string.as_deref(),
                cmd.cwd.to_string_lossy(),
                cmd.pid as i64,
                cmd.shell_kind.as_str(),
                cmd.started_at.logical as i64,
                cmd.started_at.wallclock_unix_nanos as i64,
                cmd.ended_at.map(|t| t.logical as i64),
                cmd.ended_at.map(|t| t.wallclock_unix_nanos as i64),
                cmd.exit_code,
            ],
        )?;
        Ok(())
    }

    /// Insert one event. Returns the assigned `EventId`. Increments any
    /// referenced blob's refcount.
    pub fn put_event(&self, event: &CaptureEvent) -> Result<EventId, IndexError> {
        let payload = postcard::to_allocvec(event)?;
        let denorm = denormalize(&event.kind);
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO events (session, seq, ts_logical, ts_wall_nanos, partial,
                                 discriminant, dev, inode, path, blob_hash,
                                 post_content_hash, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                event.command.session.as_bytes().as_slice(),
                event.command.seq as i64,
                event.ts.logical as i64,
                event.ts.wallclock_unix_nanos as i64,
                event.partial as i64,
                denorm.discriminant,
                denorm.dev,
                denorm.inode,
                denorm.path.as_deref(),
                denorm.blob_hash.as_ref().map(|h| h.as_bytes().as_slice()),
                denorm
                    .post_content_hash
                    .as_ref()
                    .map(|h| h.as_bytes().as_slice()),
                payload,
            ],
        )?;
        let id = tx.last_insert_rowid();
        if let Some(blob) = denorm.blob_hash.as_ref() {
            tx.execute(
                "UPDATE blobs SET refcount = refcount + 1 WHERE hash = ?1",
                params![blob.as_bytes().as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(EventId(id as u64))
    }

    /// Insert N events in a single transaction. Returns the assigned EventIds
    /// in input order. ~10× faster than calling [`Self::put_event`] in a loop
    /// for batches >100 — one fsync per batch instead of one per event.
    pub fn put_event_batch(
        &self,
        events: &[CaptureEvent],
    ) -> Result<Vec<EventId>, IndexError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let mut ids = Vec::with_capacity(events.len());
        {
            let mut insert = tx.prepare(
                "INSERT INTO events (session, seq, ts_logical, ts_wall_nanos, partial,
                                     discriminant, dev, inode, path, blob_hash,
                                     post_content_hash, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            let mut bump = tx.prepare(
                "UPDATE blobs SET refcount = refcount + 1 WHERE hash = ?1",
            )?;
            for ev in events {
                let payload = postcard::to_allocvec(ev)?;
                let denorm = denormalize(&ev.kind);
                insert.execute(params![
                    ev.command.session.as_bytes().as_slice(),
                    ev.command.seq as i64,
                    ev.ts.logical as i64,
                    ev.ts.wallclock_unix_nanos as i64,
                    ev.partial as i64,
                    denorm.discriminant,
                    denorm.dev,
                    denorm.inode,
                    denorm.path.as_deref(),
                    denorm.blob_hash.as_ref().map(|h| h.as_bytes().as_slice()),
                    denorm
                        .post_content_hash
                        .as_ref()
                        .map(|h| h.as_bytes().as_slice()),
                    payload,
                ])?;
                let id = tx.last_insert_rowid();
                ids.push(EventId(id as u64));
                if let Some(blob) = denorm.blob_hash.as_ref() {
                    bump.execute(params![blob.as_bytes().as_slice()])?;
                }
            }
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Record a blob's existence in the index. Idempotent; refcount is
    /// initialized to 0 and incremented by event inserts that reference it.
    pub fn put_blob_record(
        &self,
        hash: BlobHash,
        size: u64,
        compressed: bool,
        created: TimePoint,
    ) -> Result<(), IndexError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
             VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(hash) DO NOTHING",
            params![
                hash.as_bytes().as_slice(),
                size as i64,
                compressed as i64,
                created.logical as i64,
            ],
        )?;
        Ok(())
    }

    /// Total disk size of all stored blobs (compressed). Convenience for
    /// `shit status` and GC accounting.
    pub fn total_blob_size(&self) -> Result<u64, IndexError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM blobs", [], |row| {
            row.get(0)
        })?;
        Ok(n as u64)
    }
}

struct Denormalized<'a> {
    discriminant: &'static str,
    dev: Option<i64>,
    inode: Option<i64>,
    path: Option<String>,
    blob_hash: Option<&'a BlobHash>,
    post_content_hash: Option<&'a BlobHash>,
}

fn denormalize(kind: &CaptureEventKind) -> Denormalized<'_> {
    use CaptureEventKind as K;
    use shit_planner::TreeOp as T;
    match kind {
        K::FilePreImage {
            inode,
            path,
            blob,
            post_content_hash,
            ..
        } => Denormalized {
            discriminant: "FilePreImage",
            dev: Some(inode.dev as i64),
            inode: Some(inode.inode as i64),
            path: Some(path.to_string_lossy().into_owned()),
            blob_hash: Some(blob),
            post_content_hash: post_content_hash.as_ref(),
        },
        K::MetadataChange { inode, path, .. } => Denormalized {
            discriminant: "MetadataChange",
            dev: Some(inode.dev as i64),
            inode: Some(inode.inode as i64),
            path: Some(path.to_string_lossy().into_owned()),
            blob_hash: None,
            post_content_hash: None,
        },
        K::TreeOp(t) => {
            let (dev, inode, path, disc) = match t {
                T::Create { inode, path, .. } => (
                    Some(inode.dev as i64),
                    Some(inode.inode as i64),
                    Some(path.to_string_lossy().into_owned()),
                    "TreeOpCreate",
                ),
                T::Unlink { inode, path } => (
                    Some(inode.dev as i64),
                    Some(inode.inode as i64),
                    Some(path.to_string_lossy().into_owned()),
                    "TreeOpUnlink",
                ),
                T::Rename { inode, to, .. } => (
                    Some(inode.dev as i64),
                    Some(inode.inode as i64),
                    Some(to.to_string_lossy().into_owned()),
                    "TreeOpRename",
                ),
                T::Link { source, target } => (
                    Some(source.dev as i64),
                    Some(source.inode as i64),
                    Some(target.to_string_lossy().into_owned()),
                    "TreeOpLink",
                ),
                T::Symlink { path, .. } => (
                    None,
                    None,
                    Some(path.to_string_lossy().into_owned()),
                    "TreeOpSymlink",
                ),
            };
            Denormalized {
                discriminant: disc,
                dev,
                inode,
                path,
                blob_hash: None,
                post_content_hash: None,
            }
        }
        K::EnvDiff { .. } => Denormalized {
            discriminant: "EnvDiff",
            dev: None,
            inode: None,
            path: None,
            blob_hash: None,
            post_content_hash: None,
        },
        K::PackageOp { .. } => Denormalized {
            discriminant: "PackageOp",
            dev: None,
            inode: None,
            path: None,
            blob_hash: None,
            post_content_hash: None,
        },
        K::NetworkOp { .. } => Denormalized {
            discriminant: "NetworkOp",
            dev: None,
            inode: None,
            path: None,
            blob_hash: None,
            post_content_hash: None,
        },
        K::SystemdOp { .. } => Denormalized {
            discriminant: "SystemdOp",
            dev: None,
            inode: None,
            path: None,
            blob_hash: None,
            post_content_hash: None,
        },
        K::ProcessOp { .. } => Denormalized {
            discriminant: "ProcessOp",
            dev: None,
            inode: None,
            path: None,
            blob_hash: None,
            post_content_hash: None,
        },
    }
}

fn decode_event_row(row: &Row<'_>) -> rusqlite::Result<CaptureEvent> {
    let payload: Vec<u8> = row.get("payload")?;
    postcard::from_bytes(&payload).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e))
    })
}

impl PlannerStore for Index {
    fn events_for_command(&self, command: CommandId) -> Vec<CaptureEvent> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT payload FROM events
             WHERE session = ?1 AND seq = ?2
             ORDER BY ts_logical, id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(
            params![command.session.as_bytes().as_slice(), command.seq as i64],
            decode_event_row,
        );
        match rows {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn events_for_session(&self, session: Uuid, seq_range: SeqRange) -> Vec<CaptureEvent> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT payload FROM events
             WHERE session = ?1 AND seq >= ?2 AND seq < ?3
             ORDER BY seq, ts_logical, id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(
            params![
                session.as_bytes().as_slice(),
                seq_range.start as i64,
                seq_range.end as i64,
            ],
            decode_event_row,
        );
        match rows {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn events_touching_inode(&self, inode: InodeRef, since: TimePoint) -> Vec<CaptureEvent> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT payload FROM events
             WHERE dev = ?1 AND inode = ?2 AND ts_logical >= ?3
             ORDER BY ts_logical, id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(
            params![inode.dev as i64, inode.inode as i64, since.logical as i64],
            decode_event_row,
        );
        match rows {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn events_touching_path(&self, path: &Path, at: TimePoint) -> Vec<CaptureEvent> {
        let conn = self.conn.lock().unwrap();
        // v1: literal path match. Path-history resolution lands in S04.5.
        let mut stmt = match conn.prepare(
            "SELECT payload FROM events
             WHERE path = ?1 AND ts_logical <= ?2
             ORDER BY ts_logical, id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(
            params![path.to_string_lossy(), at.logical as i64],
            decode_event_row,
        );
        match rows {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn latest_command_for_session(&self, session: Uuid) -> Option<CommandRecord> {
        let conn = self.conn.lock().unwrap();
        let seq: i64 = conn
            .query_row(
                "SELECT MAX(seq) FROM commands WHERE session = ?1",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        drop(conn);
        self.command_by_id(CommandId {
            session,
            seq: seq as u64,
        })
    }

    fn command_by_id(&self, id: CommandId) -> Option<CommandRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cmd_string, cwd, pid, shell_kind,
                    started_logical, started_wall_nanos,
                    ended_logical, ended_wall_nanos, exit_code
             FROM commands WHERE session = ?1 AND seq = ?2",
            params![id.session.as_bytes().as_slice(), id.seq as i64],
            |row| {
                let cmd_string: Option<String> = row.get(0)?;
                let cwd: String = row.get(1)?;
                let pid: i64 = row.get(2)?;
                let shell_kind: String = row.get(3)?;
                let started_logical: i64 = row.get(4)?;
                let started_wall: i64 = row.get(5)?;
                let ended_logical: Option<i64> = row.get(6)?;
                let ended_wall: Option<i64> = row.get(7)?;
                let exit_code: Option<i32> = row.get(8)?;
                Ok(CommandRecord {
                    command: id,
                    cmd_string,
                    cwd: PathBuf::from(cwd),
                    pid: pid as u32,
                    shell_kind: shell_kind.parse().unwrap_or(shit_proto::ShellKind::Unknown),
                    started_at: TimePoint::new(started_logical as u64, started_wall as u64),
                    ended_at: match (ended_logical, ended_wall) {
                        (Some(l), Some(w)) => Some(TimePoint::new(l as u64, w as u64)),
                        _ => None,
                    },
                    exit_code,
                    event_ids: vec![], // populated lazily; not load-bearing here
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn event_by_id(&self, id: EventId) -> Option<CaptureEvent> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT payload FROM events WHERE id = ?1",
            params![id.0 as i64],
            decode_event_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    fn blob_size_hint(&self, hash: BlobHash) -> Option<u64> {
        let conn = self.conn.lock().unwrap();
        let size: Option<i64> = conn
            .query_row(
                "SELECT size FROM blobs WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten();
        size.map(|s| s as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::FileMetadata;
    use std::collections::BTreeMap;

    fn meta() -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
        }
    }

    fn open_index() -> (tempfile::TempDir, Index) {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path().join("db.sqlite")).unwrap();
        (dir, idx)
    }

    fn sample_command(session: Uuid, seq: u64) -> CommandRecord {
        CommandRecord {
            command: CommandId { session, seq },
            cmd_string: Some(format!("cmd-{seq}")),
            cwd: PathBuf::from("/tmp"),
            pid: 1234,
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(seq, seq * 1000),
            ended_at: Some(TimePoint::new(seq + 1, (seq + 1) * 1000)),
            exit_code: Some(0),
            event_ids: vec![],
        }
    }

    #[test]
    fn open_creates_db_with_schema() {
        let (_dir, idx) = open_index();
        let conn = idx.conn.lock().unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        for want in [
            "blobs",
            "commands",
            "events",
            "paths",
            "pins",
            "schema_version",
            "sessions",
        ] {
            assert!(tables.iter().any(|t| t == want), "missing table {want}");
        }
    }

    #[test]
    fn command_round_trip() {
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(
            session,
            "bash",
            999,
            Some("/dev/ttys0"),
            TimePoint::new(0, 0),
        )
        .unwrap();
        let cmd = sample_command(session, 1);
        idx.put_command(&cmd).unwrap();
        let got = idx.command_by_id(cmd.command).unwrap();
        assert_eq!(got.command, cmd.command);
        assert_eq!(got.cmd_string, cmd.cmd_string);
        assert_eq!(got.pid, cmd.pid);
        assert_eq!(got.exit_code, cmd.exit_code);
    }

    #[test]
    fn latest_command_picks_max_seq() {
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        for seq in [3u64, 1, 5, 2] {
            idx.put_command(&sample_command(session, seq)).unwrap();
        }
        let latest = idx.latest_command_for_session(session).unwrap();
        assert_eq!(latest.command.seq, 5);
    }

    #[test]
    fn event_round_trip() {
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();
        let blob = BlobHash::from_bytes([0xAB; 32]);
        idx.put_blob_record(blob, 64, false, TimePoint::new(0, 0))
            .unwrap();
        let ev = CaptureEvent {
            id: EventId(0), // ignored; sqlite assigns
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(1, 1000),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 42),
                path: PathBuf::from("/tmp/foo"),
                blob,
                meta: meta(),
                post_content_hash: Some(BlobHash::from_bytes([0xCD; 32])),
            },
        };
        let assigned = idx.put_event(&ev).unwrap();
        assert!(assigned.0 >= 1);
        let fetched = idx.events_for_command(CommandId { session, seq: 1 });
        assert_eq!(fetched.len(), 1);
        // payload round-trips structurally; only the id field differs.
        match (&fetched[0].kind, &ev.kind) {
            (
                CaptureEventKind::FilePreImage {
                    inode: a, blob: ba, ..
                },
                CaptureEventKind::FilePreImage {
                    inode: b, blob: bb, ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(ba, bb);
            }
            _ => panic!("kind mismatch"),
        }
    }

    #[test]
    fn blob_refcount_increments_on_event_insert() {
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();
        let blob = BlobHash::from_bytes([0x11; 32]);
        idx.put_blob_record(blob, 128, false, TimePoint::new(0, 0))
            .unwrap();
        for _ in 0..3 {
            idx.put_event(&CaptureEvent {
                id: EventId(0),
                command: CommandId { session, seq: 1 },
                ts: TimePoint::new(1, 0),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode: InodeRef::new(1, 1),
                    path: PathBuf::from("/x"),
                    blob,
                    meta: meta(),
                    post_content_hash: None,
                },
            })
            .unwrap();
        }
        let conn = idx.conn.lock().unwrap();
        let refcount: i64 = conn
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                params![blob.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount, 3);
    }

    #[test]
    fn put_event_batch_atomic_and_consistent_with_loop() {
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();
        let blob = BlobHash::from_bytes([0x33; 32]);
        idx.put_blob_record(blob, 1, false, TimePoint::new(0, 0))
            .unwrap();

        let events: Vec<CaptureEvent> = (0..50)
            .map(|i| CaptureEvent {
                id: EventId(0),
                command: CommandId { session, seq: 1 },
                ts: TimePoint::new(i + 1, (i + 1) * 1000),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode: InodeRef::new(1, i),
                    path: PathBuf::from(format!("/f{i}")),
                    blob,
                    meta: meta(),
                    post_content_hash: None,
                },
            })
            .collect();

        let ids = idx.put_event_batch(&events).unwrap();
        assert_eq!(ids.len(), 50);
        // IDs should be strictly increasing (one per insert).
        for w in ids.windows(2) {
            assert!(w[1].0 > w[0].0);
        }
        // Refcount should reflect the 50 inserts.
        let conn = idx.conn.lock().unwrap();
        let rc: i64 = conn
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                params![blob.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rc, 50);
    }

    #[test]
    fn put_event_batch_empty_is_noop() {
        let (_dir, idx) = open_index();
        let ids = idx.put_event_batch(&[]).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn blob_size_hint_works() {
        let (_dir, idx) = open_index();
        let blob = BlobHash::from_bytes([0x77; 32]);
        assert!(idx.blob_size_hint(blob).is_none());
        idx.put_blob_record(blob, 999, false, TimePoint::new(0, 0))
            .unwrap();
        assert_eq!(idx.blob_size_hint(blob), Some(999));
    }
}
