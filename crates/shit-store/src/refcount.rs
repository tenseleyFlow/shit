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

use rusqlite::params;

use crate::index::{Index, IndexError};
use shit_planner::CommandId;

/// Summary of a batch reap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReapBatch {
    /// Number of commands removed from `commands`.
    pub commands_dropped: usize,
    /// Number of events removed from `events`.
    pub events_dropped: usize,
    /// Number of distinct blob hashes whose refcount was decremented.
    /// (NOT necessarily the number that hit zero — call
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
pub fn reap_commands(index: &Index, ids: &[CommandId]) -> Result<ReapBatch, IndexError> {
    if ids.is_empty() {
        return Ok(ReapBatch::default());
    }
    let conn = index.conn().lock().unwrap();
    let tx = conn.unchecked_transaction()?;

    let mut summary = ReapBatch::default();

    for id in ids {
        // TOCTOU guard: if this command became pinned since the
        // mark-expired pass enumerated it, skip.
        let pinned: bool = tx
            .query_row(
                "SELECT 1 FROM pins WHERE session = ?1 AND seq = ?2",
                params![id.session.as_bytes().as_slice(), id.seq as i64],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if pinned {
            continue;
        }

        // Decrement refcounts for every blob this command referenced.
        let hashes: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare(
                "SELECT blob_hash FROM events
                 WHERE session = ?1 AND seq = ?2 AND blob_hash IS NOT NULL",
            )?;
            stmt.query_map(
                params![id.session.as_bytes().as_slice(), id.seq as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .filter_map(Result::ok)
            .collect()
        };
        for h in &hashes {
            tx.execute(
                "UPDATE blobs SET refcount = MAX(refcount - 1, 0) WHERE hash = ?1",
                params![h.as_slice()],
            )?;
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
             (session, seq, cmd_string, cwd, pid, shell_kind, started_logical, started_wall_nanos)
             VALUES (?1, ?2, ?3, '/tmp', 1, 'bash', ?2, 0)",
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
}
