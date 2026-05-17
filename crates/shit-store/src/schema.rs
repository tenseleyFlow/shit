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
];

const TARGET_VERSION: u32 = 2;

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
        let want = ["sessions", "commands", "events", "blobs", "paths", "pins"];
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
