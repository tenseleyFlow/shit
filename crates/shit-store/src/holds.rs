// SPDX-License-Identifier: AGPL-3.0-or-later

//! Programmatic per-pid pins on commands.
//!
//! Distinct from the existing `pins` table (which is the user-facing named
//! savepoint added in 0001-init): a hold is a short-lived, pid-scoped pin
//! intended for agents that want to keep an event alive while they process
//! it. Both `pins` and `holds` protect a command from GC.
//!
//! Lifecycle:
//! - [`create`] / [`renew`] insert or update the row.
//! - [`release`] removes a specific (command, pid) hold.
//! - [`sweep_expired`] drops rows whose `expires_logical < now_logical`.
//! - [`list_active_for_user`] enumerates a user's holds, used by `shit pins`.
//!
//! Spec: `.docs/sprints/C01-foundational-refit.md` (C01.7).

use crate::index::{Index, IndexError};
use rusqlite::{Connection, params};
use shit_planner::CommandId;
use uuid::Uuid;

/// A hold row, as returned by enumeration APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    pub command: CommandId,
    pub owner_pid: u32,
    pub owner_user: String,
    pub taken_logical: u64,
    pub expires_logical: Option<u64>,
    pub note: Option<String>,
}

/// Create or update (UPSERT) a hold on `command` owned by `(owner_pid, owner_user)`.
/// Idempotent on the `(session, seq, owner_pid)` primary key.
pub fn create(
    index: &Index,
    command: CommandId,
    owner_pid: u32,
    owner_user: &str,
    taken_logical: u64,
    expires_logical: Option<u64>,
    note: Option<&str>,
) -> Result<(), IndexError> {
    let conn = index.conn().lock().unwrap();
    create_with_conn(
        &conn,
        command,
        owner_pid,
        owner_user,
        taken_logical,
        expires_logical,
        note,
    )
}

pub(crate) fn create_with_conn(
    conn: &Connection,
    command: CommandId,
    owner_pid: u32,
    owner_user: &str,
    taken_logical: u64,
    expires_logical: Option<u64>,
    note: Option<&str>,
) -> Result<(), IndexError> {
    conn.execute(
        "INSERT INTO holds
            (session, seq, owner_pid, owner_user, taken_logical, expires_logical, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(session, seq, owner_pid) DO UPDATE SET
            owner_user      = excluded.owner_user,
            taken_logical   = excluded.taken_logical,
            expires_logical = excluded.expires_logical,
            note            = excluded.note",
        params![
            command.session.as_bytes().as_slice(),
            command.seq as i64,
            owner_pid as i64,
            owner_user,
            taken_logical as i64,
            expires_logical.map(|v| v as i64),
            note,
        ],
    )?;
    Ok(())
}

/// Refresh `taken_logical` and `expires_logical` for an existing hold. Returns
/// `false` if no row exists.
pub fn renew(
    index: &Index,
    command: CommandId,
    owner_pid: u32,
    taken_logical: u64,
    expires_logical: Option<u64>,
) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    let rows = conn.execute(
        "UPDATE holds
            SET taken_logical = ?1,
                expires_logical = ?2
          WHERE session = ?3 AND seq = ?4 AND owner_pid = ?5",
        params![
            taken_logical as i64,
            expires_logical.map(|v| v as i64),
            command.session.as_bytes().as_slice(),
            command.seq as i64,
            owner_pid as i64,
        ],
    )?;
    Ok(rows > 0)
}

/// Release a specific (command, pid) hold. Returns `false` if no row matched.
pub fn release(index: &Index, command: CommandId, owner_pid: u32) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    let rows = conn.execute(
        "DELETE FROM holds
          WHERE session = ?1 AND seq = ?2 AND owner_pid = ?3",
        params![
            command.session.as_bytes().as_slice(),
            command.seq as i64,
            owner_pid as i64,
        ],
    )?;
    Ok(rows > 0)
}

/// Drop holds whose `expires_logical < now_logical`. Returns the count
/// reaped. Invoked from the existing S13 GC pass.
pub fn sweep_expired(index: &Index, now_logical: u64) -> Result<usize, IndexError> {
    let conn = index.conn().lock().unwrap();
    let rows = conn.execute(
        "DELETE FROM holds
          WHERE expires_logical IS NOT NULL AND expires_logical < ?1",
        params![now_logical as i64],
    )?;
    Ok(rows)
}

/// List holds owned by `owner_user`, most-recent first. Used by `shit pins`.
pub fn list_active_for_user(index: &Index, owner_user: &str) -> Result<Vec<Hold>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT session, seq, owner_pid, owner_user, taken_logical, expires_logical, note
           FROM holds
          WHERE owner_user = ?1
       ORDER BY taken_logical DESC",
    )?;
    let rows: Vec<Hold> = stmt
        .query_map(params![owner_user], |row| {
            let session_bytes: Vec<u8> = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let owner_pid: i64 = row.get(2)?;
            let owner_user: String = row.get(3)?;
            let taken: i64 = row.get(4)?;
            let expires: Option<i64> = row.get(5)?;
            let note: Option<String> = row.get(6)?;
            let mut bytes = [0u8; 16];
            if session_bytes.len() == 16 {
                bytes.copy_from_slice(&session_bytes);
            }
            Ok(Hold {
                command: CommandId {
                    session: Uuid::from_bytes(bytes),
                    seq: seq.max(0) as u64,
                },
                owner_pid: owner_pid.max(0) as u32,
                owner_user,
                taken_logical: taken.max(0) as u64,
                expires_logical: expires.map(|v| v.max(0) as u64),
                note,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

/// True iff at least one hold exists for `command`. Used by GC as a
/// supplemental protection check alongside the existing `pins` test.
pub fn is_held(index: &Index, command: CommandId) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    is_held_with_conn(&conn, command)
}

pub(crate) fn is_held_with_conn(conn: &Connection, command: CommandId) -> Result<bool, IndexError> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM holds WHERE session = ?1 AND seq = ?2 LIMIT 1",
            params![command.session.as_bytes().as_slice(), command.seq as i64],
            |_| Ok(true),
        )
        .unwrap_or(false);
    Ok(exists)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;
    use rusqlite::params;

    fn fresh_index() -> Index {
        let tmp = tempfile::tempdir().unwrap();
        let idx = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        // Holds FK to commands(session, seq). Insert a seed command.
        let conn = idx.conn_for_test().lock().unwrap();
        let session_blob = [0u8; 16];
        conn.execute(
            "INSERT INTO sessions
             (id, shell_kind, parent_pid, tty, opened_logical, opened_wall_nanos)
             VALUES (?1, 'bash', 1, NULL, 0, 0)",
            params![&session_blob[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO commands
             (session, seq, cmd_string, cwd, pid, shell_kind,
              started_logical, started_wall_nanos)
             VALUES (?1, 1, 'true', '/', 1, 'bash', 0, 0)",
            params![&session_blob[..]],
        )
        .unwrap();
        drop(conn);
        idx
    }

    fn cmd() -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq: 1,
        }
    }

    #[test]
    fn create_then_is_held() {
        let idx = fresh_index();
        assert!(!is_held(&idx, cmd()).unwrap());
        create(&idx, cmd(), 42, "alice", 100, Some(200), Some("agent A")).unwrap();
        assert!(is_held(&idx, cmd()).unwrap());
    }

    #[test]
    fn create_is_upsert_per_pid() {
        let idx = fresh_index();
        create(&idx, cmd(), 42, "alice", 100, None, None).unwrap();
        // Same (cmd, pid) re-create updates rather than inserts.
        create(&idx, cmd(), 42, "alice", 200, Some(300), Some("note")).unwrap();
        let holds = list_active_for_user(&idx, "alice").unwrap();
        assert_eq!(holds.len(), 1);
        assert_eq!(holds[0].taken_logical, 200);
        assert_eq!(holds[0].expires_logical, Some(300));
        assert_eq!(holds[0].note.as_deref(), Some("note"));
    }

    #[test]
    fn different_pids_create_distinct_rows() {
        let idx = fresh_index();
        create(&idx, cmd(), 42, "alice", 100, None, None).unwrap();
        create(&idx, cmd(), 99, "alice", 100, None, None).unwrap();
        let holds = list_active_for_user(&idx, "alice").unwrap();
        assert_eq!(holds.len(), 2);
    }

    #[test]
    fn release_drops_only_matching_row() {
        let idx = fresh_index();
        create(&idx, cmd(), 42, "alice", 100, None, None).unwrap();
        create(&idx, cmd(), 99, "alice", 100, None, None).unwrap();
        assert!(release(&idx, cmd(), 42).unwrap());
        let holds = list_active_for_user(&idx, "alice").unwrap();
        assert_eq!(holds.len(), 1);
        assert_eq!(holds[0].owner_pid, 99);
    }

    #[test]
    fn release_returns_false_when_no_match() {
        let idx = fresh_index();
        assert!(!release(&idx, cmd(), 42).unwrap());
    }

    #[test]
    fn sweep_expired_drops_only_expired() {
        let idx = fresh_index();
        create(&idx, cmd(), 1, "alice", 100, Some(200), None).unwrap();
        create(&idx, cmd(), 2, "alice", 100, Some(500), None).unwrap();
        create(&idx, cmd(), 3, "alice", 100, None, None).unwrap();
        let reaped = sweep_expired(&idx, 300).unwrap();
        assert_eq!(reaped, 1);
        let holds = list_active_for_user(&idx, "alice").unwrap();
        assert_eq!(holds.len(), 2);
        let pids: Vec<u32> = holds.iter().map(|h| h.owner_pid).collect();
        assert!(pids.contains(&2));
        assert!(pids.contains(&3));
    }

    #[test]
    fn sweep_expired_ignores_null_expiry() {
        let idx = fresh_index();
        create(&idx, cmd(), 1, "alice", 100, None, None).unwrap();
        let reaped = sweep_expired(&idx, u64::MAX).unwrap();
        assert_eq!(reaped, 0);
    }

    #[test]
    fn renew_updates_existing_hold() {
        let idx = fresh_index();
        create(&idx, cmd(), 42, "alice", 100, Some(200), None).unwrap();
        assert!(renew(&idx, cmd(), 42, 500, Some(900)).unwrap());
        let holds = list_active_for_user(&idx, "alice").unwrap();
        assert_eq!(holds[0].taken_logical, 500);
        assert_eq!(holds[0].expires_logical, Some(900));
    }

    #[test]
    fn renew_returns_false_for_missing_hold() {
        let idx = fresh_index();
        assert!(!renew(&idx, cmd(), 42, 0, None).unwrap());
    }

    #[test]
    fn list_active_for_user_isolates_users() {
        let idx = fresh_index();
        create(&idx, cmd(), 1, "alice", 100, None, None).unwrap();
        create(&idx, cmd(), 2, "bob", 100, None, None).unwrap();
        assert_eq!(list_active_for_user(&idx, "alice").unwrap().len(), 1);
        assert_eq!(list_active_for_user(&idx, "bob").unwrap().len(), 1);
        assert_eq!(list_active_for_user(&idx, "carol").unwrap().len(), 0);
    }
}
