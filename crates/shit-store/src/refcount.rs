// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blob refcount + reap primitives for the GC pass (S13.2).
//!
//! Most of the refcount machinery already exists in [`Index`]:
//! - inserts auto-increment `blobs.refcount`,
//! - `Index::drop_command` decrements per-command refs in one tx,
//! - `Index::unreferenced_blobs` lists `refcount = 0` rows.
//!
//! This module adds **batched** drop + sweep helpers — one sqlite
//! transaction per N commands, instead of N transactions for N
//! commands. That matters for the GC pass: a 10 GiB store reduction
//! to 1 GiB might mean thousands of expired commands. One transaction
//! per command would mean thousands of fsync stalls; batching keeps
//! the pass under the sprint plan's 60s target.
//!
//! Atomicity: within a batch, the transaction is all-or-nothing. If
//! the commit fails, no refcounts change. Inter-batch the GC pass is
//! resumable — the next pass picks up whatever wasn't dropped.

use rusqlite::{OptionalExtension, params};

use crate::index::{Index, IndexError, decrement_event_blob_ref};
use shit_planner::CommandId;

/// Summary of a batch reap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReapBatch {
    /// Number of commands removed from `commands`.
    pub commands_dropped: usize,
    /// Number of events removed from `events`.
    pub events_dropped: usize,
    /// Number of event-owned blob references decremented. Repeated hashes
    /// count once per owning event. (NOT necessarily the number that hit zero — call
    /// [`Index::unreferenced_blobs`] for that.)
    pub refs_decremented: usize,
}

impl ReapBatch {
    pub fn merge(&mut self, other: &ReapBatch) {
        self.commands_dropped += other.commands_dropped;
        self.events_dropped += other.events_dropped;
        self.refs_decremented += other.refs_decremented;
    }
}

/// Drop a batch of commands in a single transaction.
///
/// Pinned commands are **silently skipped** — caller is expected to
/// have filtered them out via the GC's mark-expired phase. Defense
/// in depth: this helper also checks the `pins` table inside the
/// transaction so a TOCTOU race can't drop a pin that landed mid-pass.
/// Commands associated with PREPARED or CONFIRMED container batches are also
/// retained because authorization may still be pending or the runtime may
/// still be running. REFUSED and FINALIZED batches return to normal retention.
pub fn reap_commands(index: &Index, ids: &[CommandId]) -> Result<ReapBatch, IndexError> {
    if ids.is_empty() {
        return Ok(ReapBatch::default());
    }
    let conn = index.conn().lock().unwrap();
    let tx = conn.unchecked_transaction()?;

    let mut summary = ReapBatch::default();

    for id in ids {
        // A command can be marked for GC and then race a delayed PostExec (or
        // be supplied directly by another caller). Recheck completion inside
        // this transaction before touching its events/refcounts. Open commands
        // are capture state, not reclaimable history.
        let completed: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM commands
                 WHERE session = ?1 AND seq = ?2
                   AND ended_logical IS NOT NULL
                   AND ended_wall_nanos IS NOT NULL",
                params![id.session.as_bytes().as_slice(), id.seq as i64],
                |row| row.get(0),
            )
            .optional()?;
        if completed.is_none() {
            continue;
        }

        // TOCTOU guard: if this command became pinned (via `pins`, the
        // user-facing savepoint table) or held (via `holds`, the C01
        // programmatic per-pid pin) since the mark-expired pass enumerated
        // it, skip.
        let pinned = tx
            .query_row(
                "SELECT 1 FROM pins WHERE session = ?1 AND seq = ?2",
                params![id.session.as_bytes().as_slice(), id.seq as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if pinned {
            continue;
        }
        let held = tx
            .query_row(
                "SELECT 1 FROM holds WHERE session = ?1 AND seq = ?2 LIMIT 1",
                params![id.session.as_bytes().as_slice(), id.seq as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if held {
            continue;
        }
        let has_container_batch: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM container_capture_batches
                 WHERE session = ?1 AND seq = ?2
                   AND state IN ('PREPARED', 'CONFIRMED')
             )",
            params![id.session.as_bytes().as_slice(), id.seq as i64],
            |row| row.get(0),
        )?;
        if has_container_batch {
            continue;
        }

        // Decrement refcounts for every blob this command owned. ContainerOp
        // tarballs are owned by their stash rows; confirmed in-flight batches
        // remain protected until durable runtime finalization.
        let hashes: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare(
                "SELECT blob_hash FROM events
                 WHERE session = ?1 AND seq = ?2
                   AND discriminant = 'FilePreImage'
                   AND blob_hash IS NOT NULL
                 ORDER BY id",
            )?;
            stmt.query_map(
                params![id.session.as_bytes().as_slice(), id.seq as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<Result<_, _>>()?
        };
        for h in &hashes {
            decrement_event_blob_ref(&tx, h, "reaping command batch")?;
        }
        summary.refs_decremented += hashes.len();

        let events = tx.execute(
            "DELETE FROM events WHERE session = ?1 AND seq = ?2",
            params![id.session.as_bytes().as_slice(), id.seq as i64],
        )?;
        summary.events_dropped += events;
        let cmds = tx.execute(
            "DELETE FROM commands WHERE session = ?1 AND seq = ?2",
            params![id.session.as_bytes().as_slice(), id.seq as i64],
        )?;
        summary.commands_dropped += cmds;
    }

    tx.commit()?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use shit_planner::BlobHash;
    use uuid::Uuid;

    fn make_index() -> Index {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("test.db");
        // Leak the tempdir so it outlives the index — fine for tests.
        std::mem::forget(dir);
        Index::open(p).unwrap()
    }

    fn insert_command(index: &Index, session: Uuid, seq: u64) {
        let conn = index.conn().lock().unwrap();
        conn.execute(
            "INSERT INTO commands
             (session, seq, cmd_string, cwd, pid, shell_kind, started_logical,
              started_wall_nanos, ended_logical, ended_wall_nanos, exit_code)
             VALUES (?1, ?2, ?3, '/tmp', 1, 'bash', ?2, 0, ?2 + 1, 1, 0)",
            params![session.as_bytes().as_slice(), seq as i64, "test"],
        )
        .unwrap();
    }

    #[test]
    fn reap_empty_returns_zero_summary() {
        let idx = make_index();
        let s = reap_commands(&idx, &[]).unwrap();
        assert_eq!(s, ReapBatch::default());
    }

    #[test]
    fn reap_skips_open_command_even_when_requested_directly() {
        let idx = make_index();
        let session = Uuid::now_v7();
        let id = CommandId { session, seq: 7 };
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos)
                 VALUES (?1, ?2, 'open', '/tmp', 1, 'bash', 1, 0)",
                params![session.as_bytes().as_slice(), id.seq as i64],
            )
            .unwrap();
        }

        assert_eq!(reap_commands(&idx, &[id]).unwrap(), ReapBatch::default());
        let remains: i64 = idx
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM commands WHERE session = ?1 AND seq = ?2",
                params![session.as_bytes().as_slice(), id.seq as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remains, 1);
    }

    #[test]
    fn reap_drops_commands_in_one_transaction() {
        let idx = make_index();
        let session = Uuid::now_v7();
        for seq in 0..5u64 {
            insert_command(&idx, session, seq);
        }
        let ids: Vec<CommandId> = (0..5u64).map(|seq| CommandId { session, seq }).collect();
        let summary = reap_commands(&idx, &ids).unwrap();
        assert_eq!(summary.commands_dropped, 5);
        // Verify gone.
        let conn = idx.conn().lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM commands WHERE session = ?1",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn reap_retains_only_inflight_container_batch_states() {
        let idx = make_index();
        let session = Uuid::from_bytes([0x52; 16]);
        let mut ids = Vec::new();
        for (offset, state, finalized_at) in [
            (0_u8, "PREPARED", None),
            (1, "CONFIRMED", None),
            (2, "REFUSED", None),
            (3, "FINALIZED", Some(100_i64)),
        ] {
            let id = CommandId {
                session,
                seq: offset as u64 + 1,
            };
            insert_command(&idx, session, id.seq);
            idx.conn()
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO container_capture_batches
                     (batch_id, session, seq, request_hash, event_count, state,
                      finalized_unix_secs)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
                    params![
                        [offset + 11; 16].as_slice(),
                        session.as_bytes().as_slice(),
                        id.seq as i64,
                        [offset + 11; 32].as_slice(),
                        state,
                        finalized_at,
                    ],
                )
                .unwrap();
            ids.push(id);
        }

        let summary = reap_commands(&idx, &ids).unwrap();
        assert_eq!(summary.commands_dropped, 2);
        let conn = idx.conn().lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT seq FROM commands WHERE session = ?1 ORDER BY seq")
            .unwrap();
        let remaining = stmt
            .query_map(params![session.as_bytes().as_slice()], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<i64>, _>>()
            .unwrap();
        assert_eq!(remaining, vec![1, 2]);
    }

    #[test]
    fn reap_batch_missing_blob_rolls_back_prior_command() {
        let idx = make_index();
        let session = Uuid::now_v7();
        let first = CommandId { session, seq: 1 };
        let corrupt = CommandId { session, seq: 2 };
        insert_command(&idx, session, first.seq);
        insert_command(&idx, session, corrupt.seq);
        let present = BlobHash::from_bytes([0x71; 32]);
        let missing = BlobHash::from_bytes([0x72; 32]);
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
                 VALUES (?1, 1, 0, 1, 0)",
                params![present.as_bytes().as_slice()],
            )
            .unwrap();
            for (id, hash) in [(first, present), (corrupt, missing)] {
                conn.execute(
                    "INSERT INTO events
                     (session, seq, ts_logical, ts_wall_nanos, partial,
                      discriminant, blob_hash, payload)
                     VALUES (?1, ?2, 1, 0, 0, 'FilePreImage', ?3, X'')",
                    params![
                        id.session.as_bytes().as_slice(),
                        id.seq as i64,
                        hash.as_bytes().as_slice(),
                    ],
                )
                .unwrap();
            }
        }

        assert!(matches!(
            reap_commands(&idx, &[first, corrupt]),
            Err(IndexError::MissingBlob(hash)) if hash == missing
        ));

        let conn = idx.conn().lock().unwrap();
        let refcount: i64 = conn
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                params![present.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let commands: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM commands WHERE session = ?1",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let events: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE session = ?1",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount, 1);
        assert_eq!(commands, 2);
        assert_eq!(events, 2);
    }

    #[test]
    fn reap_skips_pinned_command() {
        let idx = make_index();
        let session = Uuid::now_v7();
        insert_command(&idx, session, 0);
        insert_command(&idx, session, 1);

        // Pin seq=1 directly.
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO pins (session, seq, name, pinned_logical) VALUES (?1, ?2, ?3, 0)",
                params![session.as_bytes().as_slice(), 1i64, "test-pin"],
            )
            .unwrap();
        }

        let ids = vec![CommandId { session, seq: 0 }, CommandId { session, seq: 1 }];
        let summary = reap_commands(&idx, &ids).unwrap();
        // Only seq=0 was reaped.
        assert_eq!(summary.commands_dropped, 1);
        let conn = idx.conn().lock().unwrap();
        let remaining: Vec<i64> = {
            let mut s = conn
                .prepare("SELECT seq FROM commands WHERE session = ?1 ORDER BY seq")
                .unwrap();
            s.query_map(params![session.as_bytes().as_slice()], |row| row.get(0))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        assert_eq!(remaining, vec![1]);
    }

    #[test]
    fn reap_skips_held_command() {
        // C01: a programmatic hold also protects from GC, distinct from
        // the user-facing `pins` table.
        let idx = make_index();
        let session = Uuid::now_v7();
        insert_command(&idx, session, 0);
        insert_command(&idx, session, 1);

        // Hold seq=1 directly.
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO holds (session, seq, owner_pid, owner_user, taken_logical)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![session.as_bytes().as_slice(), 1i64, 4242i64, "alice", 0i64],
            )
            .unwrap();
        }

        let ids = vec![CommandId { session, seq: 0 }, CommandId { session, seq: 1 }];
        let summary = reap_commands(&idx, &ids).unwrap();
        assert_eq!(summary.commands_dropped, 1);
        let conn = idx.conn().lock().unwrap();
        let remaining: Vec<i64> = {
            let mut s = conn
                .prepare("SELECT seq FROM commands WHERE session = ?1 ORDER BY seq")
                .unwrap();
            s.query_map(params![session.as_bytes().as_slice()], |row| row.get(0))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        assert_eq!(remaining, vec![1]);
    }
}
