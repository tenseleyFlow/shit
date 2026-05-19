// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embedded sqlite migrations. Each migration is a `.sql` file under
//! `migrations/` named `NNNN-description.sql`. The migration runner records
//! the highest-applied version in the `schema_version` table.

use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("on-disk schema is newer than this build expects (disk={disk}, build={build})")]
    AhheadOfBuild { disk: u32, build: u32 },
}

const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001-init.sql")),
    (2, include_str!("../migrations/0002-importance.sql")),
    (
        3,
        include_str!("../migrations/0003-large-objects-and-holds.sql"),
    ),
];

const TARGET_VERSION: u32 = 3;

pub fn apply(conn: &Connection) -> Result<(), SchemaError> {
    // Pragmas first: durable but not paranoid.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;
         PRAGMA wal_autocheckpoint=10000;",
    )?;

    let current = current_version(conn)?;
    if current > TARGET_VERSION {
        return Err(SchemaError::AhheadOfBuild {
            disk: current,
            build: TARGET_VERSION,
        });
    }
    for (ver, sql) in MIGRATIONS {
        if *ver > current {
            conn.execute_batch(sql)?;
        }
    }
    Ok(())
}

pub fn current_version(conn: &Connection) -> Result<u32, SchemaError> {
    // The schema_version table doesn't exist before the first migration.
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !exists {
        return Ok(0);
    }
    let v: i64 = conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
        row.get(0)
    })?;
    Ok(v.max(0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_to_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), TARGET_VERSION);
    }

    #[test]
    fn migrations_are_idempotent_at_target() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        // Running again should not re-execute any migration.
        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), TARGET_VERSION);
    }

    #[test]
    fn all_tables_present() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        let want = [
            "sessions",
            "commands",
            "events",
            "blobs",
            "paths",
            "pins",
            "large_objects",
            "chunks",
            "holds",
            "bookmarks",
        ];
        for table in want {
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    [table],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            assert!(exists, "table {table} missing after migrations");
        }
    }

    #[test]
    fn migration_v3_creates_large_object_indexes() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        for idx in [
            "idx_large_objects_unmaterialized",
            "idx_chunks_hash",
            "idx_holds_expires",
            "idx_holds_owner_user",
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
                    [idx],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            assert!(exists, "index {idx} missing after migration v3");
        }
    }

    #[test]
    fn migration_v3_forward_migrates_from_v2() {
        // Apply migrations 1+2 only by faking schema_version = 2 mid-flight.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/0001-init.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0002-importance.sql"))
            .unwrap();
        assert_eq!(current_version(&conn).unwrap(), 2);

        // Seed a row in the v2 store; v3 must not disturb it.
        conn.execute(
            "INSERT INTO sessions
             (id, shell_kind, parent_pid, tty, opened_logical, opened_wall_nanos)
             VALUES (X'00000000000000000000000000000000', 'bash', 1, NULL, 0, 0)",
            [],
        )
        .unwrap();

        // Run apply(); only v3 should execute.
        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 3);

        // The seeded session row survived.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn bookmarks_have_no_fk_to_commands() {
        // Sanity: a bookmark row can be inserted with no matching commands
        // entry, since bookmarks are meant to survive command reaping.
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        let session_blob: [u8; 16] = [0u8; 16];
        conn.execute(
            "INSERT INTO bookmarks (session, seq, created_logical, note)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&session_blob[..], 42_i64, 100_i64, "test"],
        )
        .unwrap();
        // No error → no FK to commands exists, as designed.
    }

    #[test]
    fn migration_v2_adds_importance_column() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        // pragma_table_info returns one row per column; assert importance present.
        let mut stmt = conn
            .prepare("SELECT name FROM pragma_table_info('commands')")
            .unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            cols.iter().any(|c| c == "importance"),
            "missing `importance` column: {cols:?}"
        );
    }

    #[test]
    fn migration_v2_adds_age_importance_index() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_commands_age_importance'",
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        assert!(exists);
    }

    #[test]
    fn refuses_to_open_newer_schema() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", [999])
            .unwrap();
        let err = apply(&conn).expect_err("should refuse");
        assert!(matches!(err, SchemaError::AhheadOfBuild { .. }));
    }
}
