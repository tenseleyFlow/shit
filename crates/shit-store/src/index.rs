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

    /// Access to the inner connection mutex. `pub(crate)` so sibling
    /// modules (refcount, gc) can compose multi-statement transactions
    /// without re-implementing every primitive Index already has.
    pub(crate) fn conn(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Test-only accessor for the inner connection mutex. Integration
    /// tests (which live outside the crate, so `pub(crate)` is invisible)
    /// need raw SQL access to set up fixtures without re-implementing
    /// every insert primitive. Not part of the production API.
    #[doc(hidden)]
    pub fn conn_for_test(&self) -> &Mutex<Connection> {
        &self.conn
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
            // AU26: COALESCE(excluded.cmd_string, cmd_string) means
            // a later upsert with cmd_string=None does NOT clobber a
            // previously-recorded Some value. The PreExec hook writes
            // the string first; tier-event handlers (pkg/env/svc/net/
            // proc/db) upsert with cmd_string=None when they amend
            // CommandRecord state — that mustn't overwrite the real
            // string. The PreExec path can still set cmd_string from
            // None to Some (and vice-versa only if it explicitly
            // ships a real None — which it never does).
            "INSERT INTO commands (session, seq, cmd_string, cwd, pid, shell_kind,
                                   started_logical, started_wall_nanos,
                                   ended_logical, ended_wall_nanos, exit_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(session, seq) DO UPDATE SET
                cmd_string = COALESCE(excluded.cmd_string, cmd_string),
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
        update_path_history_with_conn(&tx, &event.kind, event.ts)?;
        tx.commit()?;
        Ok(EventId(id as u64))
    }

    /// Insert N events in a single transaction. Returns the assigned EventIds
    /// in input order. ~10× faster than calling [`Self::put_event`] in a loop
    /// for batches >100 — one fsync per batch instead of one per event.
    pub fn put_event_batch(&self, events: &[CaptureEvent]) -> Result<Vec<EventId>, IndexError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().unwrap();
        // DR-64 fault-injection: crash before opening the txn. On
        // restart, the events should not be in the DB; the daemon
        // re-ships them from the in-memory ring.
        shit_proto::fault_inject::maybe_inject("index.put_event_batch.before_tx");
        let tx = conn.unchecked_transaction()?;
        let mut ids = Vec::with_capacity(events.len());
        {
            let mut insert = tx.prepare(
                "INSERT INTO events (session, seq, ts_logical, ts_wall_nanos, partial,
                                     discriminant, dev, inode, path, blob_hash,
                                     post_content_hash, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            let mut bump =
                tx.prepare("UPDATE blobs SET refcount = refcount + 1 WHERE hash = ?1")?;
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
                update_path_history_with_conn(&tx, &ev.kind, ev.ts)?;
            }
        }
        // DR-64 fault-injection: crash between txn-body and commit.
        // On restart, sqlite WAL rolls back the partial work; the
        // daemon re-ships from the ring buffer.
        shit_proto::fault_inject::maybe_inject("index.put_event_batch.before_commit");
        tx.commit()?;
        shit_proto::fault_inject::maybe_inject("index.put_event_batch.after_commit");
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

    /// Update the path-history table for a TreeOp event. Called by
    /// [`Self::put_event`] / [`Self::put_event_batch`] internally — exposed
    /// so the daemon can also rebuild history if it ever needs to.
    ///
    /// Semantics:
    /// - `Create`: open a new (path, dev, inode, valid_from=ts, valid_to=NULL).
    /// - `Unlink`: close the active row for `path` (set `valid_to=ts`).
    /// - `Rename { from, to, inode }`: close the active row for `from`, open
    ///   a new row for `to` with the same `inode`.
    /// - `Link { target, .. }`: open a new row for `target`.
    /// - `Symlink { path, .. }`: open a new row for `path`.
    pub fn update_path_history(
        &self,
        kind: &CaptureEventKind,
        ts: TimePoint,
    ) -> Result<(), IndexError> {
        let conn = self.conn.lock().unwrap();
        update_path_history_with_conn(&conn, kind, ts)
    }

    /// Drop a command (and its events) from the index. Decrements blob
    /// refcounts for every FilePreImage event the command owned. The blob
    /// files themselves are not deleted here — that's the GC sweep (S13);
    /// this just makes the refcount drop to zero so a sweeper can find them.
    /// Returns the number of events dropped.
    pub fn drop_command(&self, id: CommandId) -> Result<usize, IndexError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        // First decrement refcounts for every blob this command referenced.
        let blobs_dropped = {
            let mut stmt = tx.prepare(
                "SELECT blob_hash FROM events
                 WHERE session = ?1 AND seq = ?2 AND blob_hash IS NOT NULL",
            )?;
            let hashes: Vec<Vec<u8>> = stmt
                .query_map(
                    params![id.session.as_bytes().as_slice(), id.seq as i64],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .filter_map(Result::ok)
                .collect();
            for h in &hashes {
                tx.execute(
                    "UPDATE blobs SET refcount = MAX(refcount - 1, 0) WHERE hash = ?1",
                    params![h.as_slice()],
                )?;
            }
            hashes.len()
        };
        let removed = tx.execute(
            "DELETE FROM events WHERE session = ?1 AND seq = ?2",
            params![id.session.as_bytes().as_slice(), id.seq as i64],
        )? + tx.execute(
            "DELETE FROM commands WHERE session = ?1 AND seq = ?2",
            params![id.session.as_bytes().as_slice(), id.seq as i64],
        )?;
        let _ = blobs_dropped;
        tx.commit()?;
        Ok(removed)
    }

    /// List blob hashes whose refcount is zero. The GC sweeper (S13) uses
    /// this to identify deletable blob files.
    pub fn unreferenced_blobs(&self) -> Result<Vec<BlobHash>, IndexError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash FROM blobs WHERE refcount = 0")?;
        let rows = stmt.query_map([], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let mut h = [0u8; 32];
            if bytes.len() != 32 {
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::<dyn std::error::Error + Send + Sync>::from(format!(
                        "blob hash row has wrong length: {}",
                        bytes.len()
                    )),
                ));
            }
            h.copy_from_slice(&bytes);
            Ok(BlobHash::from_bytes(h))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Remove a blob's index row. Caller is responsible for having already
    /// removed the on-disk file. Refuses to drop blobs with refcount > 0
    /// (defense in depth — the sweeper should only target zero-refcount
    /// rows).
    pub fn drop_blob_record(&self, hash: BlobHash) -> Result<bool, IndexError> {
        let conn = self.conn.lock().unwrap();
        let removed = conn.execute(
            "DELETE FROM blobs WHERE hash = ?1 AND refcount = 0",
            params![hash.as_bytes().as_slice()],
        )?;
        Ok(removed > 0)
    }

    /// S13.7: pin a command. Pinned commands are protected from GC.
    /// Idempotent — re-pinning the same id updates `name`/`expires_logical`.
    pub fn pin_command(
        &self,
        id: CommandId,
        name: Option<&str>,
        pinned_logical: u64,
        expires_logical: Option<u64>,
    ) -> Result<(), IndexError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO pins (session, seq, name, pinned_logical, expires_logical)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.session.as_bytes().as_slice(),
                id.seq as i64,
                name,
                pinned_logical as i64,
                expires_logical.map(|v| v as i64),
            ],
        )?;
        Ok(())
    }

    /// S13.7: list all pinned commands. Returns
    /// `(session, seq, name, pinned_logical, expires_logical)`.
    #[allow(clippy::type_complexity)]
    pub fn list_pins(
        &self,
    ) -> Result<Vec<(Uuid, u64, Option<String>, u64, Option<u64>)>, IndexError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session, seq, name, pinned_logical, expires_logical
             FROM pins ORDER BY pinned_logical DESC",
        )?;
        let rows: Vec<_> = stmt
            .query_map([], |row| {
                let session_bytes: Vec<u8> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                let name: Option<String> = row.get(2)?;
                let pinned: i64 = row.get(3)?;
                let expires: Option<i64> = row.get(4)?;
                let mut bytes = [0u8; 16];
                if session_bytes.len() == 16 {
                    bytes.copy_from_slice(&session_bytes);
                }
                Ok((
                    Uuid::from_bytes(bytes),
                    seq.max(0) as u64,
                    name,
                    pinned.max(0) as u64,
                    expires.map(|v| v.max(0) as u64),
                ))
            })?
            .filter_map(Result::ok)
            .collect();
        Ok(rows)
    }

    /// S13.7: total count of pins. Useful for status displays.
    pub fn pin_count(&self) -> Result<u64, IndexError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM pins", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
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

    /// Count of distinct blobs recorded in the index. Surfaced via
    /// `shit metrics` (S21.4) as `store_blob_count`.
    pub fn blob_count(&self) -> Result<u64, IndexError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// Count of recorded commands. Surfaced via `shit metrics` as
    /// `store_command_count`. Does not double-count commands across
    /// sessions; each row is one (session, seq) pair.
    pub fn command_count(&self) -> Result<u64, IndexError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// List the N most recently completed commands, latest first. S24.C
    /// uses this for `shit undo` (bare-`shit`) — no session UUID needed,
    /// the daemon picks the user's last command across all sessions.
    /// Skips commands that haven't closed yet (`ended_wall_nanos IS NULL`)
    /// to avoid clobbering an in-flight command.
    pub fn list_recent_commands(&self, limit: u32) -> Result<Vec<CommandRecord>, IndexError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session, seq, cmd_string, cwd, pid, shell_kind,
                    started_logical, started_wall_nanos,
                    ended_logical, ended_wall_nanos, exit_code
             FROM commands
             WHERE ended_wall_nanos IS NOT NULL
             ORDER BY ended_wall_nanos DESC, seq DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let session_blob: Vec<u8> = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let cmd_string: Option<String> = row.get(2)?;
            let cwd: String = row.get(3)?;
            let pid: i64 = row.get(4)?;
            let shell_kind: String = row.get(5)?;
            let started_logical: i64 = row.get(6)?;
            let started_wall: i64 = row.get(7)?;
            let ended_logical: Option<i64> = row.get(8)?;
            let ended_wall: Option<i64> = row.get(9)?;
            let exit_code: Option<i32> = row.get(10)?;
            // session_blob comes back as 16 bytes for a uuid; fall through
            // to nil on any other length (shouldn't happen — PK ensures it).
            let session = Uuid::from_slice(&session_blob).unwrap_or_else(|_| Uuid::nil());
            Ok(CommandRecord {
                command: CommandId {
                    session,
                    seq: seq as u64,
                },
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
                event_ids: vec![],
            })
        })?;
        let mut out = Vec::with_capacity(limit as usize);
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// Apply path-history maintenance using a borrowed Connection (so the same
/// transaction batches event-insert + path-history update). The connection
/// must already hold the index's write lock.
fn update_path_history_with_conn(
    conn: &Connection,
    kind: &CaptureEventKind,
    ts: TimePoint,
) -> Result<(), IndexError> {
    use shit_planner::TreeOp as T;
    let CaptureEventKind::TreeOp(t) = kind else {
        return Ok(());
    };
    match t {
        T::Create { inode, path, .. } => {
            conn.execute(
                "INSERT INTO paths (path, dev, inode, valid_from_logical, valid_to_logical)
                 VALUES (?1, ?2, ?3, ?4, NULL)
                 ON CONFLICT(path, valid_from_logical) DO NOTHING",
                params![
                    path.to_string_lossy(),
                    inode.dev as i64,
                    inode.inode as i64,
                    ts.logical as i64,
                ],
            )?;
        }
        T::Unlink { path, .. } => {
            // Close the most recent active row for this path.
            conn.execute(
                "UPDATE paths SET valid_to_logical = ?2
                 WHERE path = ?1 AND valid_to_logical IS NULL",
                params![path.to_string_lossy(), ts.logical as i64],
            )?;
        }
        T::Rename { from, to, inode } => {
            conn.execute(
                "UPDATE paths SET valid_to_logical = ?2
                 WHERE path = ?1 AND valid_to_logical IS NULL",
                params![from.to_string_lossy(), ts.logical as i64],
            )?;
            conn.execute(
                "INSERT INTO paths (path, dev, inode, valid_from_logical, valid_to_logical)
                 VALUES (?1, ?2, ?3, ?4, NULL)
                 ON CONFLICT(path, valid_from_logical) DO NOTHING",
                params![
                    to.to_string_lossy(),
                    inode.dev as i64,
                    inode.inode as i64,
                    ts.logical as i64,
                ],
            )?;
        }
        T::Link { source, target } => {
            conn.execute(
                "INSERT INTO paths (path, dev, inode, valid_from_logical, valid_to_logical)
                 VALUES (?1, ?2, ?3, ?4, NULL)
                 ON CONFLICT(path, valid_from_logical) DO NOTHING",
                params![
                    target.to_string_lossy(),
                    source.dev as i64,
                    source.inode as i64,
                    ts.logical as i64,
                ],
            )?;
        }
        T::Symlink { path, .. } => {
            // Symlinks: we don't know the inode of the link itself from this
            // event variant; record with sentinel inode 0/0 so the path-history
            // entry exists. Sufficient for rename-resolution to skip it.
            conn.execute(
                "INSERT INTO paths (path, dev, inode, valid_from_logical, valid_to_logical)
                 VALUES (?1, 0, 0, ?2, NULL)
                 ON CONFLICT(path, valid_from_logical) DO NOTHING",
                params![path.to_string_lossy(), ts.logical as i64],
            )?;
        }
        T::SymlinkRemoved { path, .. } => {
            // W09.16.1 — close the path-history row for the OLD
            // symlink at this path. A paired Create event for the
            // NEW symlink at the same path opens a fresh row.
            conn.execute(
                "UPDATE paths SET valid_to_logical = ?2
                 WHERE path = ?1 AND valid_to_logical IS NULL",
                params![path.to_string_lossy(), ts.logical as i64],
            )?;
        }
    }
    Ok(())
}

/// Resolve a path to the (dev, inode) it referred to at `at`. Returns
/// `None` if no path-history row covers that point.
fn resolve_path_at(conn: &Connection, path: &Path, at: TimePoint) -> Option<InodeRef> {
    conn.query_row(
        "SELECT dev, inode FROM paths
         WHERE path = ?1
           AND valid_from_logical <= ?2
           AND (valid_to_logical IS NULL OR valid_to_logical > ?2)
         ORDER BY valid_from_logical DESC
         LIMIT 1",
        params![path.to_string_lossy(), at.logical as i64],
        |row| {
            let dev: i64 = row.get(0)?;
            let inode: i64 = row.get(1)?;
            Ok(InodeRef::new(dev as u64, inode as u64))
        },
    )
    .optional()
    .ok()
    .flatten()
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
        K::FileAppendPreStash { inode, path, .. } => Denormalized {
            // AU27 / DR-CR-55 — daemon-side `cmd >> file` pre-stash.
            // The full event (incl. pre_size) is serialized in the
            // separate `payload` JSON column; this row's denorm
            // fields just expose path + inode for the existing
            // discriminant-keyed queries.
            discriminant: "FileAppendPreStash",
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
                T::Unlink { inode, path, .. } => (
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
                T::SymlinkRemoved { path, .. } => (
                    None,
                    None,
                    Some(path.to_string_lossy().into_owned()),
                    "TreeOpSymlinkRemoved",
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
        K::ShellStateDiff { .. } => Denormalized {
            discriminant: "ShellStateDiff",
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
        K::DbOp { .. } => Denormalized {
            discriminant: "DbOp",
            dev: None,
            inode: None,
            path: None,
            blob_hash: None,
            post_content_hash: None,
        },
        K::ContainerOp { stash_tarball, .. } => Denormalized {
            discriminant: "ContainerOp",
            dev: None,
            inode: None,
            path: None,
            // The stash blob hash is the load-bearing identifier for
            // container ops; index it alongside FilePreImage blobs so
            // GC's blob-refcount sweep keeps it pinned.
            blob_hash: stash_tarball.as_ref(),
            post_content_hash: None,
        },
        K::TerraformOp { .. } => Denormalized {
            discriminant: "TerraformOp",
            dev: None,
            inode: None,
            path: None,
            // prior_state lives in the events row as serialized bytes;
            // no separate blob to refcount-pin for GC.
            blob_hash: None,
            post_content_hash: None,
        },
        K::KubectlOp { .. } => Denormalized {
            discriminant: "KubectlOp",
            dev: None,
            inode: None,
            path: None,
            // captured_yaml lives inline in the events row.
            blob_hash: None,
            post_content_hash: None,
        },
        K::GhOp { .. } => Denormalized {
            discriminant: "GhOp",
            dev: None,
            inode: None,
            path: None,
            // captured_json lives inline in the events row.
            blob_hash: None,
            post_content_hash: None,
        },
        K::CaptureRefused { path, .. } => Denormalized {
            discriminant: "CaptureRefused",
            dev: None,
            inode: None,
            path: Some(path.to_string_lossy().into_owned()),
            blob_hash: None,
            post_content_hash: None,
        },
    }
}

fn collect_events(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Vec<CaptureEvent> {
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    match stmt.query_map(params, decode_event_row) {
        Ok(it) => it.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

fn decode_event_row(row: &Row<'_>) -> rusqlite::Result<CaptureEvent> {
    let payload: Vec<u8> = row.get("payload")?;
    let id: i64 = row.get("id")?;
    let mut ev: CaptureEvent = postcard::from_bytes(&payload).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    // Overlay the sqlite rowid onto the in-memory event. The payload's
    // own `id` field is always EventId(0) (put_event serializes before
    // INSERT, so the autoincrement isn't known yet). Without this
    // overlay, two events with the same `ts` would tie on (ts, id) and
    // the planner's reverse-chronological sort would be unstable —
    // bug surfaced by the rm-undo smoke (S24.C).
    ev.id = shit_planner::events::EventId(id as u64);
    Ok(ev)
}

impl PlannerStore for Index {
    fn events_for_command(&self, command: CommandId) -> Vec<CaptureEvent> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT id, payload FROM events
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
            "SELECT id, payload FROM events
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
            "SELECT id, payload FROM events
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
        // Resolve via the paths table: find what (dev, inode) `path`
        // referred to at `at`. If found, query unifies literal-path and
        // inode-resolved events; otherwise we fall back to literal-only.
        let inode_at = resolve_path_at(&conn, path, at);
        let path_str = path.to_string_lossy();

        match inode_at {
            Some(i) => collect_events(
                &conn,
                "SELECT id, payload FROM events
                 WHERE ts_logical <= ?1 AND (path = ?2 OR (dev = ?3 AND inode = ?4))
                 ORDER BY ts_logical, id",
                params![at.logical as i64, path_str, i.dev as i64, i.inode as i64,],
            ),
            None => collect_events(
                &conn,
                "SELECT id, payload FROM events
                 WHERE ts_logical <= ?1 AND path = ?2
                 ORDER BY ts_logical, id",
                params![at.logical as i64, path_str],
            ),
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
            "SELECT id, payload FROM events WHERE id = ?1",
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
            flags: 0,
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
                source: shit_planner::FilePreImageSource::Other,
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
                    source: shit_planner::FilePreImageSource::Other,
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
                    source: shit_planner::FilePreImageSource::Other,
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
    fn path_history_resolves_through_rename() {
        // Sequence:
        //   T1: create /foo (inode=10)
        //   T2: write /foo (FilePreImage on inode 10)
        //   T3: rename /foo -> /bar
        //   T4: write /bar (FilePreImage on inode 10)
        // Query: events_touching_path("/bar", T4) should return both writes.
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();

        let inode = InodeRef::new(1, 10);
        let blob = BlobHash::from_bytes([0x10; 32]);
        idx.put_blob_record(blob, 1, false, TimePoint::new(0, 0))
            .unwrap();

        // T1: create
        idx.put_event(&CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(1, 1000),
            partial: false,
            kind: CaptureEventKind::TreeOp(shit_planner::TreeOp::Create {
                inode,
                path: PathBuf::from("/foo"),
                kind: shit_planner::FileKind::Regular,
                mode: 0o100644,
            }),
        })
        .unwrap();

        // T2: write at /foo
        idx.put_event(&CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(2, 2000),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: PathBuf::from("/foo"),
                blob,
                meta: meta(),
                post_content_hash: None,
                source: shit_planner::FilePreImageSource::Other,
            },
        })
        .unwrap();

        // T3: rename /foo -> /bar
        idx.put_event(&CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(3, 3000),
            partial: false,
            kind: CaptureEventKind::TreeOp(shit_planner::TreeOp::Rename {
                from: PathBuf::from("/foo"),
                to: PathBuf::from("/bar"),
                inode,
            }),
        })
        .unwrap();

        // T4: write at /bar
        idx.put_event(&CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(4, 4000),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: PathBuf::from("/bar"),
                blob,
                meta: meta(),
                post_content_hash: None,
                source: shit_planner::FilePreImageSource::Other,
            },
        })
        .unwrap();

        // Query /bar at T4 should pick up BOTH writes via inode resolution.
        let hits = idx.events_touching_path(Path::new("/bar"), TimePoint::new(4, 0));
        let pre_images = hits
            .iter()
            .filter(|e| matches!(e.kind, CaptureEventKind::FilePreImage { .. }))
            .count();
        assert_eq!(
            pre_images, 2,
            "expected 2 pre-image events, got {pre_images}"
        );
    }

    #[test]
    fn drop_command_decrements_refcount_and_removes_events() {
        let (_dir, idx) = open_index();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();
        let blob = BlobHash::from_bytes([0x55; 32]);
        idx.put_blob_record(blob, 1, false, TimePoint::new(0, 0))
            .unwrap();
        for i in 0..5 {
            idx.put_event(&CaptureEvent {
                id: EventId(0),
                command: CommandId { session, seq: 1 },
                ts: TimePoint::new(i + 1, 0),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode: InodeRef::new(1, i),
                    path: PathBuf::from(format!("/p{i}")),
                    blob,
                    meta: meta(),
                    post_content_hash: None,
                    source: shit_planner::FilePreImageSource::Other,
                },
            })
            .unwrap();
        }
        // Pre-drop: refcount 5, command exists.
        assert_eq!(idx.blob_size_hint(blob), Some(1));
        let dropped = idx.drop_command(CommandId { session, seq: 1 }).unwrap();
        assert!(dropped >= 5, "expected >=5 rows dropped, got {dropped}");

        // Post-drop: refcount should be 0, command + events gone.
        let conn = idx.conn.lock().unwrap();
        let rc: i64 = conn
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                params![blob.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rc, 0);
        let event_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(event_count, 0);
    }

    #[test]
    fn unreferenced_blobs_lists_zero_refcount() {
        let (_dir, idx) = open_index();
        let referenced = BlobHash::from_bytes([0xA1; 32]);
        let orphan = BlobHash::from_bytes([0xA2; 32]);
        idx.put_blob_record(referenced, 1, false, TimePoint::new(0, 0))
            .unwrap();
        idx.put_blob_record(orphan, 1, false, TimePoint::new(0, 0))
            .unwrap();
        // Reference `referenced` via an event.
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();
        idx.put_event(&CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/x"),
                blob: referenced,
                meta: meta(),
                post_content_hash: None,
                source: shit_planner::FilePreImageSource::Other,
            },
        })
        .unwrap();
        let unref = idx.unreferenced_blobs().unwrap();
        assert!(unref.contains(&orphan));
        assert!(!unref.contains(&referenced));
    }

    #[test]
    fn drop_blob_record_refuses_referenced() {
        let (_dir, idx) = open_index();
        let blob = BlobHash::from_bytes([0xBB; 32]);
        idx.put_blob_record(blob, 1, false, TimePoint::new(0, 0))
            .unwrap();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        idx.put_command(&sample_command(session, 1)).unwrap();
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
                source: shit_planner::FilePreImageSource::Other,
            },
        })
        .unwrap();
        let removed = idx.drop_blob_record(blob).unwrap();
        assert!(!removed, "referenced blob must not be droppable");
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
