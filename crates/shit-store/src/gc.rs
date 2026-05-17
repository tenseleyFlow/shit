// SPDX-License-Identifier: AGPL-3.0-or-later

//! GC algorithm — pure-Rust passes over the [`Index`] + [`BlobStore`]
//! pair. Owned here, called from the daemon's background task (S13.6).
//!
//! ## Algorithm (per the S13 sprint plan)
//!
//! 1. **Mark-expired:** find commands older than `age_cap`, not
//!    pinned, ordered by `(importance ASC, started_logical ASC)` so
//!    low-importance + old-first.
//! 2. **Reap:** for each batch of expired commands, drop them via
//!    [`refcount::reap_commands`] which decrements blob refcounts in
//!    one transaction. Pinned commands are silently filtered (TOCTOU
//!    guard) by the reaper.
//! 3. **Sweep-blobs:** list `refcount = 0` blobs; delete file +
//!    blob row. Logged size totals.
//! 4. **Compact-paths:** prune `paths` rows whose `valid_to_logical`
//!    is older than `age_cap`.
//! 5. **Vacuum-if-needed:** check sqlite's freelist; if >20% of the
//!    file size is freelist pages, run `VACUUM`.
//!
//! Each phase respects the `cancel` flag — checked between batches,
//! never mid-transaction. Cancellation leaves the store consistent
//! (the current transaction either commits or rolls back).
//!
//! ## Why we don't `VACUUM INCREMENTAL` per phase
//!
//! The sprint plan suggested `VACUUM INCREMENTAL`. That requires
//! `auto_vacuum = INCREMENTAL`, which the v1 schema didn't set. Stage
//! 1 here does a full `VACUUM` when fragmentation exceeds the
//! threshold; switching to incremental is a follow-up schema bump.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rusqlite::params;
use shit_planner::{BlobHash, CommandId};
use uuid::Uuid;

use crate::blob::BlobStore;
use crate::index::{Index, IndexError};
use crate::refcount::{ReapBatch, reap_commands};

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("index: {0}")]
    Index(#[from] IndexError),
    #[error("blob store: {0}")]
    Blob(#[from] crate::blob::BlobError),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("cancelled")]
    Cancelled,
}

/// Knobs for a GC pass. The daemon reads these from `config.toml`
/// (see `shitd::config`) and passes them in.
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// Commands older than this in *logical* time are eligible for
    /// expiry. Logical units are sprint-plan-agnostic — the daemon
    /// converts wall-clock durations to logical-time threshold at
    /// pass start.
    pub age_threshold_logical: u64,
    /// Soft cap on total blob size. When exceeded, the pass enters
    /// aggressive mode and bypasses `age_threshold_logical`.
    pub size_cap_bytes: Option<u64>,
    /// How many commands to drop per transaction. Keeps each tx
    /// short so capture inserts don't stall.
    pub batch_size: usize,
    /// Sqlite freelist fraction at which to run VACUUM. 0.0..=1.0.
    pub vacuum_freelist_threshold: f32,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            // 7 days at 1000 logical units/second = ~604_800_000.
            age_threshold_logical: 604_800_000,
            size_cap_bytes: Some(5 * 1024 * 1024 * 1024), // 5 GiB
            batch_size: 100,
            vacuum_freelist_threshold: 0.20,
        }
    }
}

/// Summary of one full GC pass.
#[derive(Debug, Clone, Default)]
pub struct GcReport {
    pub commands_dropped: usize,
    pub events_dropped: usize,
    pub blobs_swept: usize,
    pub bytes_reclaimed: u64,
    pub paths_compacted: usize,
    pub vacuumed: bool,
    pub aggressive_mode_used: bool,
    pub duration: std::time::Duration,
}

/// Run one full GC pass. Idempotent: re-running on a clean store is
/// a near no-op (still walks the indexes once).
pub fn run_pass(
    index: &Index,
    blob_store: &BlobStore,
    config: &GcConfig,
    cancel: Arc<AtomicBool>,
    now_logical: u64,
) -> Result<GcReport, GcError> {
    let started = Instant::now();
    let mut report = GcReport::default();

    // 0. Decide whether we're already over size cap → aggressive mode.
    let size_now = index.total_blob_size()?;
    let aggressive = size_threshold_breached(size_now, config.size_cap_bytes);
    report.aggressive_mode_used = aggressive;
    let mut effective_age_cutoff = if aggressive {
        // Aggressive: drop anything not pinned, regardless of age.
        u64::MAX
    } else {
        now_logical.saturating_sub(config.age_threshold_logical)
    };

    // Pre-emptive trigger: 90% of cap also pulls aggressive mode in
    // even though we haven't hit the wall yet.
    if let Some(cap) = config.size_cap_bytes {
        if !aggressive && size_now * 10 >= cap * 9 {
            effective_age_cutoff = u64::MAX;
            report.aggressive_mode_used = true;
        }
    }

    // 1+2. Mark-expired loop. We process in `batch_size` chunks so the
    // sqlite write transactions stay short.
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(GcError::Cancelled);
        }
        let batch = mark_expired_batch(index, effective_age_cutoff, config.batch_size)?;
        if batch.is_empty() {
            break;
        }
        let summary = reap_commands(index, &batch)?;
        report.commands_dropped += summary.commands_dropped;
        report.events_dropped += summary.events_dropped;
        if summary.commands_dropped == 0 {
            // Every command in the batch was pinned (rare). Without
            // this break we'd loop forever on the same batch.
            break;
        }
    }

    // 3. Sweep-blobs.
    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    let to_sweep = index.unreferenced_blobs()?;
    for hash in &to_sweep {
        if cancel.load(Ordering::Acquire) {
            return Err(GcError::Cancelled);
        }
        let size = blob_size_for(index, hash).unwrap_or(0);
        // Best-effort file removal; even if the file is already gone
        // (manual cleanup, fs corruption), the index row should still
        // come out so refcount accounting stays correct.
        let _ = blob_store.delete(hash);
        if index.drop_blob_record(*hash)? {
            report.blobs_swept += 1;
            report.bytes_reclaimed += size;
        }
    }

    // 4. Compact-paths.
    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    report.paths_compacted = compact_paths(index, effective_age_cutoff)?;

    // 5. Vacuum if freelist is too fragmented.
    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    if should_vacuum(index, config.vacuum_freelist_threshold)? {
        let conn = index.conn().lock().unwrap();
        conn.execute_batch("VACUUM")?;
        report.vacuumed = true;
    }

    report.duration = started.elapsed();
    Ok(report)
}

fn size_threshold_breached(size_now: u64, cap: Option<u64>) -> bool {
    cap.is_some_and(|c| size_now > c)
}

/// Capture-path status check. The daemon calls this before accepting
/// a new capture event so we can refuse-closed when the store is
/// full and even aggressive GC can't reclaim more space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeCapStatus {
    /// Under cap (or no cap configured). Accept captures normally.
    Ok,
    /// Above the 90% pre-emptive trigger but below the hard wall.
    /// Capture accepted; GC should run aggressively soon. The daemon
    /// surfaces this in `shit status`.
    Approaching,
    /// At or above the cap, and aggressive GC most recently ran
    /// without freeing enough. The capture path must hard-fail this
    /// command (exit code 5, `CAPTURE_DENIED`).
    HardFail,
}

/// Check the current store size against the configured cap. Pass
/// `last_aggressive_freed_to` as the size value observed right after
/// the most recent aggressive pass; if we're back above cap, that's
/// the trigger for `HardFail`.
pub fn check_size_cap(
    current_size: u64,
    cap_bytes: Option<u64>,
    last_aggressive_freed_to: Option<u64>,
) -> SizeCapStatus {
    let Some(cap) = cap_bytes else {
        return SizeCapStatus::Ok;
    };
    if current_size <= cap * 9 / 10 {
        return SizeCapStatus::Ok;
    }
    if current_size > cap {
        // If aggressive GC ran recently and couldn't bring us below
        // cap, hard-fail. Otherwise just signal "approaching" and let
        // the next scheduled aggressive pass try.
        if matches!(last_aggressive_freed_to, Some(after) if after > cap) {
            return SizeCapStatus::HardFail;
        }
    }
    SizeCapStatus::Approaching
}

/// Query the next batch of expired commands. Pinned commands are
/// filtered out at the SQL level (LEFT JOIN pins ... IS NULL).
/// Ordering: `(importance ASC, started_logical ASC)` so low-importance
/// + old-first.
fn mark_expired_batch(
    index: &Index,
    age_cutoff_logical: u64,
    limit: usize,
) -> Result<Vec<CommandId>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT c.session, c.seq
         FROM commands c
         LEFT JOIN pins p ON c.session = p.session AND c.seq = p.seq
         WHERE p.session IS NULL
           AND c.started_logical < ?1
         ORDER BY c.importance ASC, c.started_logical ASC
         LIMIT ?2",
    )?;
    // `u64::MAX as i64` wraps to -1; saturate so "aggressive mode"
    // (cutoff = u64::MAX) still passes SQL's signed comparison.
    let cutoff_signed: i64 = age_cutoff_logical.min(i64::MAX as u64) as i64;
    let rows: Vec<CommandId> = stmt
        .query_map(params![cutoff_signed, limit as i64], |row| {
            let session_bytes: Vec<u8> = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let mut bytes = [0u8; 16];
            if session_bytes.len() == 16 {
                bytes.copy_from_slice(&session_bytes);
            }
            Ok(CommandId {
                session: Uuid::from_bytes(bytes),
                seq: seq as u64,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

fn blob_size_for(index: &Index, hash: &BlobHash) -> Option<u64> {
    let conn = index.conn().lock().unwrap();
    conn.query_row(
        "SELECT size FROM blobs WHERE hash = ?1",
        params![hash.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )
    .ok()
    .map(|s| s.max(0) as u64)
}

fn compact_paths(index: &Index, age_cutoff_logical: u64) -> Result<usize, IndexError> {
    let conn = index.conn().lock().unwrap();
    let cutoff_signed: i64 = age_cutoff_logical.min(i64::MAX as u64) as i64;
    let removed = conn.execute(
        "DELETE FROM paths
         WHERE valid_to_logical IS NOT NULL
           AND valid_to_logical < ?1",
        params![cutoff_signed],
    )?;
    Ok(removed)
}

fn should_vacuum(index: &Index, threshold: f32) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    let freelist: i64 = conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    if page_count == 0 {
        return Ok(false);
    }
    let frac = (freelist as f32) / (page_count as f32);
    Ok(frac >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn tempstore() -> (tempfile::TempDir, Index, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path().join("index.db")).unwrap();
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, idx, blobs)
    }

    fn insert_command_at(
        index: &Index,
        session: Uuid,
        seq: u64,
        started_logical: u64,
        importance: u8,
    ) {
        let conn = index.conn().lock().unwrap();
        conn.execute(
            "INSERT INTO commands
             (session, seq, cmd_string, cwd, pid, shell_kind, started_logical,
              started_wall_nanos, importance)
             VALUES (?1, ?2, 'test', '/tmp', 1, 'bash', ?3, 0, ?4)",
            params![
                session.as_bytes().as_slice(),
                seq as i64,
                started_logical as i64,
                importance as i64
            ],
        )
        .unwrap();
    }

    #[test]
    fn empty_store_runs_clean() {
        let (_dir, idx, blobs) = tempstore();
        let report = run_pass(
            &idx,
            &blobs,
            &GcConfig::default(),
            Arc::new(AtomicBool::new(false)),
            1_000_000,
        )
        .unwrap();
        assert_eq!(report.commands_dropped, 0);
        assert_eq!(report.blobs_swept, 0);
    }

    #[test]
    fn expires_old_commands_keeps_recent() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        // Old command (started at logical=10), recent (started at 1000).
        insert_command_at(&idx, session, 0, 10, 0);
        insert_command_at(&idx, session, 1, 1000, 0);
        let config = GcConfig {
            age_threshold_logical: 100,
            ..GcConfig::default()
        };
        // now_logical = 500. Cutoff = 500 - 100 = 400. seq=0 (start=10)
        // is expired; seq=1 (start=1000) is recent → stays.
        let report =
            run_pass(&idx, &blobs, &config, Arc::new(AtomicBool::new(false)), 500).unwrap();
        assert_eq!(report.commands_dropped, 1);
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
    fn pinned_commands_survive_expiry() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        insert_command_at(&idx, session, 0, 10, 0);
        // Pin seq=0.
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO pins (session, seq, pinned_logical) VALUES (?1, 0, 0)",
                params![session.as_bytes().as_slice()],
            )
            .unwrap();
        }
        let config = GcConfig {
            age_threshold_logical: 100,
            ..GcConfig::default()
        };
        let report =
            run_pass(&idx, &blobs, &config, Arc::new(AtomicBool::new(false)), 500).unwrap();
        assert_eq!(report.commands_dropped, 0, "pinned should survive");
    }

    #[test]
    fn mark_expired_orders_by_importance_then_age() {
        let (_dir, idx, _blobs) = tempstore();
        let session = Uuid::now_v7();
        // Same age; lower importance should sort first.
        insert_command_at(&idx, session, 0, 10, 5);
        insert_command_at(&idx, session, 1, 10, 1);
        insert_command_at(&idx, session, 2, 10, 9);
        let batch = mark_expired_batch(&idx, u64::MAX, 10).unwrap();
        assert_eq!(
            batch.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![1, 0, 2]
        );
    }

    #[test]
    fn cancellation_returns_early() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        // Many commands so we'd loop several batches.
        for seq in 0..50u64 {
            insert_command_at(&idx, session, seq, 10, 0);
        }
        let cancel = Arc::new(AtomicBool::new(true));
        let config = GcConfig {
            age_threshold_logical: 100,
            batch_size: 5,
            ..GcConfig::default()
        };
        match run_pass(&idx, &blobs, &config, cancel, 500) {
            Err(GcError::Cancelled) => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    #[test]
    fn check_size_cap_ok_below_threshold() {
        assert_eq!(check_size_cap(50, Some(100), None), SizeCapStatus::Ok);
    }

    #[test]
    fn check_size_cap_approaching_at_90pct() {
        assert_eq!(
            check_size_cap(91, Some(100), None),
            SizeCapStatus::Approaching
        );
        assert_eq!(
            check_size_cap(101, Some(100), None),
            SizeCapStatus::Approaching
        );
    }

    #[test]
    fn check_size_cap_hard_fail_only_after_aggressive_couldnt_help() {
        // We're over cap AND aggressive ran and ended up still over cap.
        assert_eq!(
            check_size_cap(150, Some(100), Some(120)),
            SizeCapStatus::HardFail
        );
        // Over cap but aggressive freed below cap (so we accept; the
        // current overage is from new captures we want to keep).
        assert_eq!(
            check_size_cap(150, Some(100), Some(80)),
            SizeCapStatus::Approaching
        );
    }

    #[test]
    fn check_size_cap_no_cap_always_ok() {
        assert_eq!(check_size_cap(u64::MAX, None, None), SizeCapStatus::Ok);
    }

    #[test]
    fn aggressive_mode_triggers_above_size_cap() {
        let (_dir, idx, _blobs) = tempstore();
        // Insert a fake blob to push size over cap.
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
                 VALUES (?1, ?2, 0, 1, 0)",
                params![&[1u8; 32][..], 1024i64],
            )
            .unwrap();
        }
        let config = GcConfig {
            size_cap_bytes: Some(100),
            ..GcConfig::default()
        };
        // We have 1024 bytes; cap is 100 → aggressive.
        let (_dir, idx2, blobs2) = tempstore();
        // Repeat the setup against the fresh store for isolation.
        {
            let conn = idx2.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
                 VALUES (?1, ?2, 0, 1, 0)",
                params![&[1u8; 32][..], 1024i64],
            )
            .unwrap();
        }
        let report = run_pass(
            &idx2,
            &blobs2,
            &config,
            Arc::new(AtomicBool::new(false)),
            1000,
        )
        .unwrap();
        assert!(report.aggressive_mode_used);
    }
}
