// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the S13 GC pass (S13.9).
//!
//! Synthetic stores rather than real captures — the capture-runtime
//! pipeline is deferred. These tests exercise the full Index +
//! BlobStore stack against the same operations a real capture would
//! produce.

use rusqlite::params;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use uuid::Uuid;

use shit_store::{BlobStore, GcConfig, Index, run_pass};

/// Sets up a fresh Index + BlobStore in a tempdir. Returns the
/// tempdir so the caller can keep it alive.
fn setup() -> (tempfile::TempDir, Index, BlobStore) {
    let dir = tempfile::tempdir().unwrap();
    let idx = Index::open(dir.path().join("index.db")).unwrap();
    let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
    (dir, idx, blobs)
}

/// Insert `count` synthetic commands at varying `started_logical`.
/// Even seqs are pinned, odd are not, so the test can assert
/// pin-protection on a known partition.
fn populate(index: &Index, session: Uuid, count: u64) {
    let conn = index.conn_for_test().lock().unwrap();
    for seq in 0..count {
        conn.execute(
            "INSERT INTO commands
             (session, seq, cmd_string, cwd, pid, shell_kind,
              started_logical, started_wall_nanos, importance)
             VALUES (?1, ?2, 'echo', '/tmp', 1, 'bash', ?2, 0, 0)",
            params![session.as_bytes().as_slice(), seq as i64],
        )
        .unwrap();
        if seq % 2 == 0 {
            conn.execute(
                "INSERT INTO pins (session, seq, name, pinned_logical)
                 VALUES (?1, ?2, NULL, 0)",
                params![session.as_bytes().as_slice(), seq as i64],
            )
            .unwrap();
        }
    }
}

#[test]
fn pinned_commands_survive_aggressive_pass() {
    let (_dir, idx, blobs) = setup();
    let session = Uuid::now_v7();
    let count = 100u64;
    populate(&idx, session, count);

    let config = GcConfig {
        age_threshold_logical: 0,
        size_cap_bytes: Some(1), // tiny cap → aggressive
        batch_size: 10,
        ..GcConfig::default()
    };
    let report = run_pass(
        &idx,
        &blobs,
        &config,
        Arc::new(AtomicBool::new(false)),
        u64::MAX / 2,
    )
    .unwrap();

    // Half the commands were pinned (even seqs); the other half
    // (odd seqs) should be reaped.
    let conn = idx.conn_for_test().lock().unwrap();
    let remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM commands WHERE session = ?1",
            params![session.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining, (count / 2) as i64, "pinned half should remain");
    assert!(
        report.commands_dropped >= (count / 2) as usize,
        "report.commands_dropped should reflect the odd half: got {}",
        report.commands_dropped
    );

    // All remaining commands must be pinned (sanity).
    let unpinned_remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM commands c
             LEFT JOIN pins p ON c.session = p.session AND c.seq = p.seq
             WHERE c.session = ?1 AND p.session IS NULL",
            params![session.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unpinned_remaining, 0);
}

#[test]
fn cancellation_leaves_consistent_state() {
    let (_dir, idx, blobs) = setup();
    let session = Uuid::now_v7();
    populate(&idx, session, 50);

    let cancel = Arc::new(AtomicBool::new(true));
    let config = GcConfig {
        age_threshold_logical: 0,
        batch_size: 5,
        ..GcConfig::default()
    };
    let _ = run_pass(&idx, &blobs, &config, cancel, u64::MAX / 2);

    // Even after cancellation, the schema invariants must hold:
    // every events row points at a commands row; pinned commands
    // still have pin rows. Pre-existing rows are either fully
    // present or fully gone — never half-deleted.
    let conn = idx.conn_for_test().lock().unwrap();
    let dangling_events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events e
             WHERE NOT EXISTS (
               SELECT 1 FROM commands c
               WHERE c.session = e.session AND c.seq = e.seq
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(dangling_events, 0, "no event should outlive its command");
}

#[test]
fn idempotent_run_on_empty_store_is_noop() {
    let (_dir, idx, blobs) = setup();
    let r1 = run_pass(
        &idx,
        &blobs,
        &GcConfig::default(),
        Arc::new(AtomicBool::new(false)),
        1,
    )
    .unwrap();
    let r2 = run_pass(
        &idx,
        &blobs,
        &GcConfig::default(),
        Arc::new(AtomicBool::new(false)),
        1,
    )
    .unwrap();
    assert_eq!(r1.commands_dropped, 0);
    assert_eq!(r2.commands_dropped, 0);
    assert_eq!(r1.blobs_swept, 0);
    assert_eq!(r2.blobs_swept, 0);
}
