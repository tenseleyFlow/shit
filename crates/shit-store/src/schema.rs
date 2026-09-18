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
    (4, include_str!("../migrations/0004-container-stash.sql")),
    (5, include_str!("../migrations/0005-blob-leases.sql")),
    (
        6,
        include_str!("../migrations/0006-container-capture-batches.sql"),
    ),
];

const TARGET_VERSION: u32 = 6;

pub fn apply(conn: &Connection) -> Result<(), SchemaError> {
    // Pragmas first. FULL is required for the cross-domain GC invariant:
    // sqlite ownership removal must survive power loss before the blob file
    // is unlinked and its directory fsynced. On Apple platforms `fullfsync`
    // asks SQLite to use the stronger F_FULLFSYNC barrier where available;
    // other SQLite builds accept it as a no-op.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA fullfsync=ON;
         PRAGMA checkpoint_fullfsync=ON;
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
            apply_migration(conn, sql)?;
        }
    }
    Ok(())
}

/// Apply one migration atomically.
///
/// A migration contains both its schema changes and its `schema_version` row.
/// Keeping those statements in one transaction prevents a crash or statement
/// failure from leaving objects behind without the matching version marker.
fn apply_migration(conn: &Connection, sql: &str) -> Result<(), SchemaError> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(sql)?;
    tx.commit()?;
    Ok(())
}

pub fn current_version(conn: &Connection) -> Result<u32, SchemaError> {
    // The schema_version table doesn't exist before the first migration.
    // `EXISTS` always returns exactly one row, so every sqlite failure here is
    // a real error. In particular, corruption/I/O errors must not be mistaken
    // for a fresh database and followed by migration attempts.
    let exists: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type='table' AND name='schema_version'
         )",
        [],
        |row| row.get(0),
    )?;
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
    fn failed_migration_rolls_back_schema_and_version_together() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration(&conn, MIGRATIONS[0].1).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 1);

        let err = apply_migration(
            &conn,
            "CREATE TABLE migration_should_rollback (id INTEGER PRIMARY KEY);\n\
             INSERT INTO schema_version (version) VALUES (99);\n\
             INSERT INTO table_that_does_not_exist DEFAULT VALUES;",
        )
        .expect_err("the final statement must fail");
        assert!(matches!(err, SchemaError::Sql(_)));

        let partial_table_exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master\n\
                 WHERE type='table' AND name='migration_should_rollback'",
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        assert!(!partial_table_exists);
        assert_eq!(current_version(&conn).unwrap(), 1);
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
            "container_stashes",
            "blob_leases",
            "container_capture_batches",
            "container_capture_batch_events",
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
    fn migration_forward_from_v2_reaches_target() {
        // Apply migrations 1+2 only by faking schema_version = 2 mid-flight.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/0001-init.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0002-importance.sql"))
            .unwrap();
        assert_eq!(current_version(&conn).unwrap(), 2);

        // Seed a row in the v2 store; later migrations must not disturb it.
        conn.execute(
            "INSERT INTO sessions
             (id, shell_kind, parent_pid, tty, opened_logical, opened_wall_nanos)
             VALUES (X'00000000000000000000000000000000', 'bash', 1, NULL, 0, 0)",
            [],
        )
        .unwrap();

        // Run apply(); v3 through v5 should execute.
        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), TARGET_VERSION);

        // The seeded session row survived.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn migration_v4_forward_migrates_from_v3() {
        // Apply migrations 1+2+3 only by stopping mid-chain. v4 must
        // be additive — pre-existing rows in v3-era tables survive.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/0001-init.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0002-importance.sql"))
            .unwrap();
        conn.execute_batch(include_str!(
            "../migrations/0003-large-objects-and-holds.sql"
        ))
        .unwrap();
        assert_eq!(current_version(&conn).unwrap(), 3);

        // Seed a v3-era bookmark row.
        conn.execute(
            "INSERT INTO bookmarks (session, seq, created_logical, note)
             VALUES (X'00000000000000000000000000000000', 1, 0, 'pre-v4')",
            [],
        )
        .unwrap();

        // Run apply(); v4 and the later additive v5 should execute.
        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), TARGET_VERSION);

        // The container_stashes table exists.
        let has_table: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='container_stashes'",
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        assert!(has_table);

        // Pre-v4 bookmark row survived.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM bookmarks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn migration_v5_forward_migrates_from_v4() {
        let conn = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..4] {
            conn.execute_batch(migration.1).unwrap();
        }
        assert_eq!(current_version(&conn).unwrap(), 4);

        conn.execute(
            "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
             VALUES (?1, 1, 0, 0, 1)",
            [&[0xA5_u8; 32][..]],
        )
        .unwrap();

        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), TARGET_VERSION);
        let blob_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(blob_count, 1);
        let has_index: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type='index' AND name='idx_blob_leases_command'",
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        assert!(has_index);
    }

    #[test]
    fn migration_v6_forward_migrates_from_v5_with_integrity_objects() {
        let conn = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..5] {
            conn.execute_batch(migration.1).unwrap();
        }
        assert_eq!(current_version(&conn).unwrap(), 5);

        conn.execute(
            "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
             VALUES (?1, 1, 0, 1, 1)",
            [&[0xB6_u8; 32][..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO container_stashes
             (blob_hash, kind, runtime, name, size_bytes, created_unix_secs)
             VALUES (?1, 0, 'docker', 'legacy:v5', 1, 123)",
            [&[0xB6_u8; 32][..]],
        )
        .unwrap();

        apply(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), TARGET_VERSION);
        let retain_from: i64 = conn
            .query_row(
                "SELECT retain_from_unix_secs FROM container_stashes
                 WHERE blob_hash = ?1",
                [&[0xB6_u8; 32][..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retain_from, 123);

        for object in [
            ("table", "container_capture_batches"),
            ("table", "container_capture_batch_events"),
            ("index", "idx_container_capture_batches_command_state"),
            ("index", "idx_container_capture_batch_events_event"),
            ("index", "idx_container_stashes_retain_from"),
            ("view", "confirmed_container_capture_events"),
            ("trigger", "container_capture_batch_event_validate_insert"),
            ("trigger", "container_capture_batch_event_immutable"),
            ("trigger", "container_capture_batch_state_transition"),
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2
                     )",
                    [object.0, object.1],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing schema object {}/{}", object.0, object.1);
        }
    }

    #[test]
    fn container_batch_lifecycle_requires_confirmed_then_timestamped_finalized() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        let session = [0xC6_u8; 16];
        let batch = [0xD6_u8; 16];
        conn.execute(
            "INSERT INTO commands
             (session, seq, cwd, pid, shell_kind, started_logical,
              started_wall_nanos)
             VALUES (?1, 1, '/tmp', 1, 'bash', 1, 1)",
            [&session[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO container_capture_batches
             (batch_id, session, seq, request_hash, event_count)
             VALUES (?1, ?2, 1, ?3, 1)",
            rusqlite::params![&batch[..], &session[..], &[0xE6_u8; 32][..]],
        )
        .unwrap();

        assert!(
            conn.execute(
                "UPDATE container_capture_batches
                 SET state = 'FINALIZED', finalized_unix_secs = 10
                 WHERE batch_id = ?1",
                [&batch[..]],
            )
            .is_err(),
            "PREPARED must not skip directly to FINALIZED"
        );
        conn.execute(
            "UPDATE container_capture_batches SET state = 'CONFIRMED'
             WHERE batch_id = ?1",
            [&batch[..]],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE container_capture_batches SET state = 'FINALIZED'
                 WHERE batch_id = ?1",
                [&batch[..]],
            )
            .is_err(),
            "FINALIZED requires its durable runtime-finished timestamp"
        );
        conn.execute(
            "UPDATE container_capture_batches
             SET state = 'FINALIZED', finalized_unix_secs = 10
             WHERE batch_id = ?1",
            [&batch[..]],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE container_capture_batches SET finalized_unix_secs = 11
                 WHERE batch_id = ?1",
                [&batch[..]],
            )
            .is_err(),
            "first finalization timestamp must be immutable"
        );
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
