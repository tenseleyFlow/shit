// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metadata-only durable references to commands.
//!
//! A bookmark survives blob-tier GC AND the eventual reaping of the
//! corresponding `commands` row (`bookmarks` deliberately has no FK to
//! `commands`). The intent: a user can still `shit log` and see "this
//! command happened at time T," even when the data needed to undo it has
//! been compacted away.
//!
//! Spec: `.docs/sprints/C01-foundational-refit.md` (C01.7).

use crate::index::{Index, IndexError};
use rusqlite::params;
use shit_planner::CommandId;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    pub command: CommandId,
    pub created_logical: u64,
    pub note: Option<String>,
}

/// Create or update (UPSERT) a bookmark on `command`.
pub fn create(
    index: &Index,
    command: CommandId,
    created_logical: u64,
    note: Option<&str>,
) -> Result<(), IndexError> {
    let conn = index.conn().lock().unwrap();
    conn.execute(
        "INSERT INTO bookmarks (session, seq, created_logical, note)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(session, seq) DO UPDATE SET
            created_logical = excluded.created_logical,
            note            = excluded.note",
        params![
            command.session.as_bytes().as_slice(),
            command.seq as i64,
            created_logical as i64,
            note,
        ],
    )?;
    Ok(())
}

/// Remove a bookmark. Returns `false` if no row matched.
pub fn remove(index: &Index, command: CommandId) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    let rows = conn.execute(
        "DELETE FROM bookmarks WHERE session = ?1 AND seq = ?2",
        params![
            command.session.as_bytes().as_slice(),
            command.seq as i64,
        ],
    )?;
    Ok(rows > 0)
}

/// List all bookmarks, most-recent first.
pub fn list_all(index: &Index) -> Result<Vec<Bookmark>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT session, seq, created_logical, note
           FROM bookmarks
       ORDER BY created_logical DESC",
    )?;
    let rows: Vec<Bookmark> = stmt
        .query_map([], |row| {
            let session_bytes: Vec<u8> = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let created: i64 = row.get(2)?;
            let note: Option<String> = row.get(3)?;
            let mut bytes = [0u8; 16];
            if session_bytes.len() == 16 {
                bytes.copy_from_slice(&session_bytes);
            }
            Ok(Bookmark {
                command: CommandId {
                    session: Uuid::from_bytes(bytes),
                    seq: seq.max(0) as u64,
                },
                created_logical: created.max(0) as u64,
                note,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;

    fn fresh_index() -> Index {
        let tmp = tempfile::tempdir().unwrap();
        Index::open(tmp.path().join("idx.sqlite")).unwrap()
    }

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    #[test]
    fn create_then_list_returns_bookmark() {
        let idx = fresh_index();
        create(&idx, cmd(1), 100, Some("important")).unwrap();
        let all = list_all(&idx).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].command.seq, 1);
        assert_eq!(all[0].created_logical, 100);
        assert_eq!(all[0].note.as_deref(), Some("important"));
    }

    #[test]
    fn create_without_referent_command_row_succeeds() {
        // Deliberate: bookmarks have no FK to commands. They survive
        // the command being reaped.
        let idx = fresh_index();
        // Note: no INSERT into `commands` here.
        create(&idx, cmd(999), 42, None).unwrap();
        let all = list_all(&idx).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn create_is_upsert() {
        let idx = fresh_index();
        create(&idx, cmd(1), 100, Some("first")).unwrap();
        create(&idx, cmd(1), 200, Some("second")).unwrap();
        let all = list_all(&idx).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].created_logical, 200);
        assert_eq!(all[0].note.as_deref(), Some("second"));
    }

    #[test]
    fn remove_drops_row() {
        let idx = fresh_index();
        create(&idx, cmd(1), 100, None).unwrap();
        assert!(remove(&idx, cmd(1)).unwrap());
        assert_eq!(list_all(&idx).unwrap().len(), 0);
    }

    #[test]
    fn remove_returns_false_when_no_match() {
        let idx = fresh_index();
        assert!(!remove(&idx, cmd(1)).unwrap());
    }

    #[test]
    fn list_all_orders_by_created_desc() {
        let idx = fresh_index();
        create(&idx, cmd(1), 100, None).unwrap();
        create(&idx, cmd(2), 300, None).unwrap();
        create(&idx, cmd(3), 200, None).unwrap();
        let all = list_all(&idx).unwrap();
        let seqs: Vec<u64> = all.iter().map(|b| b.command.seq).collect();
        assert_eq!(seqs, vec![2, 3, 1]);
    }
}
