// SPDX-License-Identifier: AGPL-3.0-or-later

//! GC algorithm — pure-Rust passes over the [`Index`] + [`BlobStore`]
//! pair. Owned here, called from the daemon's background task (S13.6).
//!
//! ## Algorithm (per the S13 sprint plan)
//!
//! 1. **Prune-container-stashes:** release expired unbatched stash-owner
//!    references, then sweep blobs that no longer have any durable owner.
//!    Stashes associated with PREPARED/CONFIRMED container batches remain
//!    protected; FINALIZED stashes age from durable runtime completion. This
//!    runs before size-cap evaluation so expired archives cannot trigger
//!    command eviction.
//! 2. **Mark-expired:** find commands completed before the wall-clock
//!    retention cutoff, not pinned, ordered by
//!    `(importance ASC, started_logical ASC)` so
//!    low-importance + old-first.
//! 3. **Reap:** for each batch of expired commands, drop them via
//!    [`refcount::reap_commands`] which decrements blob refcounts in
//!    one transaction. Pinned commands are silently filtered (TOCTOU
//!    guard) by the reaper.
//! 4. **Sweep-blobs:** sweep again for blobs released by command reaping. Under
//!    exclusive blob
//!    lifecycle ownership, atomically recheck/delete the index row and then
//!    unlink the file. Logged size totals.
//! 5. **Compact-paths:** prune closed `paths` rows older than the earliest
//!    command still retained.
//! 6. **Vacuum-if-needed:** check sqlite's freelist; if >20% of the
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
//!
//! Blob sweep is deliberately DB-first. A crash or unlink/fsync error after
//! the index commit can leave an unindexed physical orphan; it cannot leave a
//! live index reference pointing at a file GC already removed. Orphan-file
//! reconciliation is a separate recovery pass.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rusqlite::params;
use shit_planner::{BlobHash, CommandId};
use uuid::Uuid;

use crate::blob::BlobStore;
use crate::container_stash::{CONTAINER_STASH_RETENTION_SECS, prune_older_than};
use crate::index::{Index, IndexError};
use crate::refcount::reap_commands;

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
    /// Completed commands older than this many wall-clock seconds are
    /// eligible for expiry.
    pub age_threshold_secs: u64,
    /// Soft cap on total blob size. When exceeded, the pass enters
    /// aggressive mode and bypasses `age_threshold_secs`.
    pub size_cap_bytes: Option<u64>,
    /// How many commands to drop per transaction. Keeps each tx
    /// short so capture inserts don't stall.
    pub batch_size: usize,
    /// Sqlite freelist fraction at which to run VACUUM. 0.0..=1.0.
    pub vacuum_freelist_threshold: f32,
    /// Wall-clock age after which eligible container stash rows release their
    /// independent blob-owner reference. PREPARED/CONFIRMED rows are not
    /// eligible; FINALIZED rows receive a fresh full retention window. This is
    /// intentionally separate from command retention because container
    /// archives are typically much larger.
    pub container_stash_retention_secs: u64,
    /// Force command collection regardless of age. This remains effective
    /// while age-based expiry is quarantined after a clock sanity failure.
    pub force_aggressive: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            age_threshold_secs: 7 * 24 * 60 * 60,
            size_cap_bytes: Some(5 * 1024 * 1024 * 1024), // 5 GiB
            batch_size: 100,
            vacuum_freelist_threshold: 0.20,
            container_stash_retention_secs: CONTAINER_STASH_RETENTION_SECS,
            force_aggressive: false,
        }
    }
}

/// One checked daemon-clock sample shared by every age decision in a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionNow {
    pub unix_secs: u64,
    /// False after a suspicious wall-clock jump. Age-based command and stash
    /// expiry must then retain data; explicit and size-driven GC still run.
    pub age_expiry_safe: bool,
}

impl RetentionNow {
    pub const fn trusted(unix_secs: u64) -> Self {
        Self {
            unix_secs,
            age_expiry_safe: true,
        }
    }

    pub const fn quarantined(unix_secs: u64) -> Self {
        Self {
            unix_secs,
            age_expiry_safe: false,
        }
    }
}

/// Summary of one full GC pass.
#[derive(Debug, Clone, Default)]
pub struct GcReport {
    pub commands_dropped: usize,
    pub events_dropped: usize,
    /// Stash-owner rows removed. This does not itself imply physical bytes
    /// were reclaimed: an event or another durable owner can retain the blob.
    pub container_stashes_pruned: usize,
    pub blobs_swept: usize,
    /// Physical blob bytes deleted by the sweep, never merely references
    /// released by command or container-stash pruning.
    pub bytes_reclaimed: u64,
    pub paths_compacted: usize,
    pub vacuumed: bool,
    pub aggressive_mode_used: bool,
    /// True when normal command/stash age expiry was deliberately skipped
    /// because the daemon wall clock failed its sanity bound.
    pub age_expiry_suppressed: bool,
    pub duration: std::time::Duration,
}

/// Run one full GC pass. Idempotent: re-running on a clean store is
/// a near no-op (still walks the indexes once).
pub fn run_pass(
    index: &Index,
    blob_store: &BlobStore,
    config: &GcConfig,
    cancel: Arc<AtomicBool>,
    now: RetentionNow,
) -> Result<GcReport, GcError> {
    let started = Instant::now();
    let mut report = GcReport {
        age_expiry_suppressed: !now.age_expiry_safe,
        ..GcReport::default()
    };

    // 1. Expire container stashes and immediately sweep anything whose last
    // durable owner was that stash. Size-cap mode must be selected from the
    // post-retention footprint; otherwise an already-expired large archive can
    // cause unrelated, recent commands to be evicted unnecessarily.
    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    if now.age_expiry_safe {
        report.container_stashes_pruned =
            prune_older_than(index, config.container_stash_retention_secs, now.unix_secs)?.len();
    }

    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    sweep_unreferenced_blobs(index, blob_store, &cancel, &mut report)?;

    // Decide whether the retained footprint requires aggressive mode.
    let size_now = index.total_blob_size()?;
    let aggressive =
        config.force_aggressive || size_threshold_breached(size_now, config.size_cap_bytes);
    report.aggressive_mode_used = aggressive;
    let mut effective_age_cutoff_wall_nanos = if aggressive {
        // Aggressive: drop anything not pinned, regardless of age.
        u64::MAX
    } else {
        now.unix_secs
            .saturating_sub(config.age_threshold_secs)
            .saturating_mul(1_000_000_000)
    };

    // Pre-emptive trigger: 90% of cap also pulls aggressive mode in
    // even though we haven't hit the wall yet.
    if let Some(cap) = config.size_cap_bytes
        && !aggressive
        && size_now >= cap.saturating_sub(cap / 10)
    {
        effective_age_cutoff_wall_nanos = u64::MAX;
        report.aggressive_mode_used = true;
    }

    // 2+3. Mark-expired loop. We process in `batch_size` chunks so the
    // sqlite write transactions stay short.
    while report.aggressive_mode_used || now.age_expiry_safe {
        if cancel.load(Ordering::Acquire) {
            return Err(GcError::Cancelled);
        }
        let batch = mark_expired_batch(index, effective_age_cutoff_wall_nanos, config.batch_size)?;
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

    // 4. Sweep again for blobs whose last event-owner reference was released
    // by command reaping above.
    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    sweep_unreferenced_blobs(index, blob_store, &cancel, &mut report)?;

    // 5. Compact-paths.
    if cancel.load(Ordering::Acquire) {
        return Err(GcError::Cancelled);
    }
    report.paths_compacted = compact_paths(index)?;

    // 6. Vacuum if freelist is too fragmented.
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
    if current_size <= cap.saturating_sub(cap / 10) {
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

/// Query the next batch of expired commands. Pinned commands (`pins` —
/// user-facing named savepoints) and held commands (`holds` — C01
/// programmatic per-pid pins) are filtered out at the SQL level via
/// LEFT JOINs whose right side must be NULL.
/// Ordering: `(importance ASC, started_logical ASC)` so low-importance
/// + old-first.
fn mark_expired_batch(
    index: &Index,
    age_cutoff_wall_nanos: u64,
    limit: usize,
) -> Result<Vec<CommandId>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT c.session, c.seq
         FROM commands c
         LEFT JOIN pins  p ON c.session = p.session AND c.seq = p.seq
         LEFT JOIN holds h ON c.session = h.session AND c.seq = h.seq
         WHERE p.session IS NULL
           AND h.session IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM container_capture_batches b
               WHERE b.session = c.session AND b.seq = c.seq
                 AND b.state IN ('PREPARED', 'CONFIRMED')
           )
           AND c.ended_logical IS NOT NULL
           AND c.ended_wall_nanos IS NOT NULL
           AND c.ended_wall_nanos < ?1
         ORDER BY c.importance ASC, c.started_logical ASC
         LIMIT ?2",
    )?;
    // `u64::MAX as i64` wraps to -1; saturate so "aggressive mode"
    // (cutoff = u64::MAX) still passes SQL's signed comparison.
    let cutoff_signed: i64 = age_cutoff_wall_nanos.min(i64::MAX as u64) as i64;
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

/// Sweep one previously enumerated candidate. The exclusive lifecycle guard
/// is acquired before either Index access, preserving the global
/// lifecycle -> Index lock order. `drop_blob_record` is the authoritative
/// atomic recheck: a ref, lease, or stash acquired since enumeration makes it
/// return `false`, and the physical file is left untouched.
fn sweep_blob_candidate(
    index: &Index,
    blob_store: &BlobStore,
    hash: BlobHash,
) -> Result<Option<u64>, GcError> {
    let blobs = blob_store.exclusive_guard();
    let size = blob_size_for(index, &hash).unwrap_or(0);
    if !index.drop_blob_record(hash)? {
        return Ok(None);
    }
    blobs.delete(&hash)?;
    Ok(Some(size))
}

fn sweep_unreferenced_blobs(
    index: &Index,
    blob_store: &BlobStore,
    cancel: &AtomicBool,
    report: &mut GcReport,
) -> Result<(), GcError> {
    let to_sweep = index.unreferenced_blobs()?;
    for hash in to_sweep {
        if cancel.load(Ordering::Acquire) {
            return Err(GcError::Cancelled);
        }
        if let Some(size) = sweep_blob_candidate(index, blob_store, hash)? {
            report.blobs_swept += 1;
            report.bytes_reclaimed += size;
        }
    }
    Ok(())
}

fn compact_paths(index: &Index) -> Result<usize, IndexError> {
    let conn = index.conn().lock().unwrap();
    // DR-64 fault-injection: crash before the DELETE issues. The
    // compaction is idempotent (next sweep restarts from the same
    // age cutoff); the test asserts no rows were dropped.
    shit_proto::fault_inject::maybe_inject("gc.compact_paths.before_delete");
    let removed = conn.execute(
        "DELETE FROM paths
         WHERE valid_to_logical IS NOT NULL
           AND valid_to_logical < COALESCE(
               (SELECT MIN(started_logical) FROM commands),
               9223372036854775807
           )",
        [],
    )?;
    // DR-64 fault-injection: crash after the DELETE issues but
    // before the function returns. The compaction must remain
    // idempotent — re-running it on the same cutoff is a no-op.
    shit_proto::fault_inject::maybe_inject("gc.compact_paths.after_delete");
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
    use crate::container_stash::{RegisterRequest, StashKind, get, register};
    use rusqlite::params;
    use shit_planner::{
        CaptureEvent, CaptureEventKind, ContainerOp, ContainerRuntime, EventId, PlannerStore,
        TimePoint,
    };
    use std::sync::mpsc;
    use std::time::Duration;

    const TEST_NOW: u64 = 10_000;

    fn tempstore() -> (tempfile::TempDir, Index, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path().join("index.db")).unwrap();
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, idx, blobs)
    }

    fn insert_blob_candidate(index: &Index, blobs: &BlobStore, bytes: &[u8]) -> BlobHash {
        let (hash, stat) = blobs.put(bytes).unwrap();
        index
            .put_blob_record(
                hash,
                stat.stored_bytes,
                stat.compressed,
                shit_planner::TimePoint::new(1, 1),
            )
            .unwrap();
        assert!(index.unreferenced_blobs().unwrap().contains(&hash));
        hash
    }

    fn insert_container_stash(
        index: &Index,
        blobs: &BlobStore,
        bytes: &[u8],
        name: &str,
    ) -> (BlobHash, u64) {
        let (hash, stat) = blobs.put(bytes).unwrap();
        index
            .put_blob_record(
                hash,
                stat.stored_bytes,
                stat.compressed,
                shit_planner::TimePoint::new(1, 1),
            )
            .unwrap();
        register(
            index,
            RegisterRequest {
                blob_hash: *hash.as_bytes(),
                kind: StashKind::ImageSave,
                runtime: "docker",
                name,
                size_bytes: bytes.len() as u64,
                command: None,
                note: None,
            },
            TEST_NOW,
        )
        .unwrap();
        (hash, stat.stored_bytes)
    }

    fn insert_open_command(index: &Index, session: Uuid, seq: u64) {
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos)
                 VALUES (?1, ?2, 'open', '/tmp', 1, 'bash', 1, 1)",
                params![session.as_bytes().as_slice(), seq as i64],
            )
            .unwrap();
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
              started_wall_nanos, ended_logical, ended_wall_nanos, exit_code, importance)
             VALUES (?1, ?2, 'test', '/tmp', 1, 'bash', ?3, ?5,
                     ?3 + 1, ?6, 0, ?4)",
            params![
                session.as_bytes().as_slice(),
                seq as i64,
                started_logical as i64,
                importance as i64,
                started_logical.saturating_mul(1_000_000_000) as i64,
                started_logical
                    .saturating_add(1)
                    .saturating_mul(1_000_000_000) as i64,
            ],
        )
        .unwrap();
    }

    fn insert_container_event_stash(
        index: &Index,
        blobs: &BlobStore,
        command: CommandId,
        bytes: &[u8],
    ) -> (BlobHash, u64) {
        let (hash, stat) = blobs.put(bytes).unwrap();
        index
            .put_blob_record(
                hash,
                stat.stored_bytes,
                stat.compressed,
                TimePoint::new(1, 1),
            )
            .unwrap();
        register(
            index,
            RegisterRequest {
                blob_hash: *hash.as_bytes(),
                kind: StashKind::ImageSave,
                runtime: "docker",
                name: "expired:image",
                size_bytes: bytes.len() as u64,
                command: Some(command),
                note: None,
            },
            TEST_NOW,
        )
        .unwrap();
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(951, 951),
                partial: false,
                kind: CaptureEventKind::ContainerOp {
                    runtime: ContainerRuntime::Docker,
                    op: ContainerOp::Rmi {
                        image: "expired:image".into(),
                        digest: None,
                    },
                    captured_config: Vec::new(),
                    stash_image: None,
                    stash_tarball: Some(hash),
                },
            })
            .unwrap();
        let refcount: i64 = index
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount, 1, "only the stash row owns container bytes");
        (hash, stat.stored_bytes)
    }

    #[test]
    fn empty_store_runs_clean() {
        let (_dir, idx, blobs) = tempstore();
        let report = run_pass(
            &idx,
            &blobs,
            &GcConfig::default(),
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(1_000_000),
        )
        .unwrap();
        assert_eq!(report.commands_dropped, 0);
        assert_eq!(report.container_stashes_pruned, 0);
        assert_eq!(report.blobs_swept, 0);
    }

    #[test]
    fn default_container_stash_retention_is_24_hours() {
        assert_eq!(
            GcConfig::default().container_stash_retention_secs,
            24 * 60 * 60
        );
    }

    #[test]
    fn one_pass_prunes_aged_stash_and_sweeps_only_its_unowned_blob() {
        let (_dir, index, blobs) = tempstore();
        let (aged, aged_stored_bytes) =
            insert_container_stash(&index, &blobs, b"aged container archive", "aged:image");
        let (fresh, _) =
            insert_container_stash(&index, &blobs, b"fresh container archive", "fresh:image");

        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = 0, retain_from_unix_secs = 0
                 WHERE blob_hash = ?1",
                params![aged.as_bytes().as_slice()],
            )
            .unwrap();

        let config = GcConfig {
            container_stash_retention_secs: 60 * 60,
            ..GcConfig::default()
        };
        let report = run_pass(
            &index,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(TEST_NOW),
        )
        .unwrap();

        assert_eq!(report.container_stashes_pruned, 1);
        assert_eq!(report.blobs_swept, 1);
        assert_eq!(report.bytes_reclaimed, aged_stored_bytes);
        assert!(get(&index, aged.as_bytes()).unwrap().is_none());
        assert!(get(&index, fresh.as_bytes()).unwrap().is_some());
        assert!(!blobs.contains(&aged));
        assert!(blobs.contains(&fresh));

        let fresh_refcount: i64 = index
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                params![fresh.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fresh_refcount, 1, "fresh stash must retain its owner ref");
    }

    #[test]
    fn expired_stash_bytes_do_not_trigger_aggressive_command_eviction() {
        let (_dir, index, blobs) = tempstore();
        let container_command = CommandId {
            session: Uuid::now_v7(),
            seq: 1,
        };
        insert_command_at(
            &index,
            container_command.session,
            container_command.seq,
            TEST_NOW - 50,
            0,
        );
        let (expired, stored_bytes) = insert_container_event_stash(
            &index,
            &blobs,
            container_command,
            b"expired archive that alone exceeds the configured cap",
        );
        assert!(stored_bytes > 1);
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = 0, retain_from_unix_secs = 0
                 WHERE blob_hash = ?1",
                params![expired.as_bytes().as_slice()],
            )
            .unwrap();

        let session = Uuid::now_v7();
        insert_command_at(&index, session, 1, TEST_NOW - 50, 0);
        let config = GcConfig {
            age_threshold_secs: 100,
            size_cap_bytes: Some(1),
            container_stash_retention_secs: 60 * 60,
            ..GcConfig::default()
        };
        let report = run_pass(
            &index,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(TEST_NOW),
        )
        .unwrap();

        assert_eq!(report.container_stashes_pruned, 1);
        assert_eq!(report.blobs_swept, 1);
        assert!(!report.aggressive_mode_used);
        assert_eq!(report.commands_dropped, 0);
        let command_rows: i64 = index
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM commands WHERE session = ?1 AND seq = 1",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(command_rows, 1, "recent command must not be evicted");
        assert_eq!(index.events_for_command(container_command).len(), 1);
        assert!(!blobs.contains(&expired));
    }

    #[test]
    fn shared_publication_guard_blocks_gc_until_index_ownership_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.db")).unwrap());
        let blobs = Arc::new(BlobStore::open(dir.path().join("blobs")).unwrap());
        let gc_index = Arc::clone(&index);
        let gc_blobs = Arc::clone(&blobs);
        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 1,
        };
        insert_open_command(&index, command.session, command.seq);

        let publication = blobs.shared_guard();
        let (hash, stat) = publication.put(b"publication in progress").unwrap();
        index
            .put_blob_record(
                hash,
                stat.stored_bytes,
                stat.compressed,
                shit_planner::TimePoint::new(1, 1),
            )
            .unwrap();
        assert!(index.unreferenced_blobs().unwrap().contains(&hash));

        let (attempt_tx, attempt_rx) = mpsc::sync_channel(0);
        let (done_tx, done_rx) = mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            done_tx
                .send(sweep_blob_candidate(&gc_index, &gc_blobs, hash))
                .unwrap();
        });
        attempt_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert!(publication.contains(&hash));

        // Publish the durable owner while retaining the shared guard, then
        // release it. GC wakes, performs its final DB recheck, and declines.
        index
            .create_blob_lease(hash, command, shit_planner::TimePoint::new(2, 2))
            .unwrap();
        drop(publication);
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            None
        );
        worker.join().unwrap();
        assert!(blobs.contains(&hash));
    }

    #[test]
    fn stale_candidates_that_gain_ref_lease_or_stash_are_not_unlinked() {
        let (_dir, index, blobs) = tempstore();
        let referenced = insert_blob_candidate(&index, &blobs, b"new event reference");
        let leased = insert_blob_candidate(&index, &blobs, b"new baseline lease");
        let stashed = insert_blob_candidate(&index, &blobs, b"new container stash");
        let stale_candidates = index.unreferenced_blobs().unwrap();
        assert!(stale_candidates.contains(&referenced));
        assert!(stale_candidates.contains(&leased));
        assert!(stale_candidates.contains(&stashed));

        let command = CommandId {
            session: Uuid::now_v7(),
            seq: 2,
        };
        insert_open_command(&index, command.session, command.seq);
        {
            let conn = index.conn().lock().unwrap();
            conn.execute(
                "UPDATE blobs SET refcount = 1 WHERE hash = ?1",
                params![referenced.as_bytes().as_slice()],
            )
            .unwrap();
        }
        index
            .create_blob_lease(leased, command, shit_planner::TimePoint::new(2, 2))
            .unwrap();
        // Keep refcount at zero here to exercise the independent stash
        // predicate in the authoritative delete, not just refcount defense.
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO container_stashes
                 (blob_hash, kind, runtime, name, size_bytes, created_unix_secs)
                 VALUES (?1, 0, 'docker', 'stale-candidate', 1, 1)",
                params![stashed.as_bytes().as_slice()],
            )
            .unwrap();

        for hash in stale_candidates {
            assert_eq!(sweep_blob_candidate(&index, &blobs, hash).unwrap(), None);
            assert!(blobs.contains(&hash), "stale candidate {hash} was unlinked");
        }
    }

    #[test]
    fn sweep_deletes_index_row_before_unlinking_unowned_blob() {
        let (_dir, index, blobs) = tempstore();
        let hash = insert_blob_candidate(&index, &blobs, b"unowned candidate");
        let expected_size = blob_size_for(&index, &hash).unwrap();

        assert_eq!(
            sweep_blob_candidate(&index, &blobs, hash).unwrap(),
            Some(expected_size)
        );
        assert!(!blobs.contains(&hash));
        let rows: i64 = index
            .conn()
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM blobs WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn mark_expired_never_selects_open_commands() {
        let (_dir, idx, _blobs) = tempstore();
        let session = Uuid::now_v7();
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos, importance)
                 VALUES (?1, 1, 'long-running', '/tmp', 1, 'bash', 1, 0, 0)",
                params![session.as_bytes().as_slice()],
            )
            .unwrap();
        }

        assert!(mark_expired_batch(&idx, u64::MAX, 10).unwrap().is_empty());
    }

    #[test]
    fn mark_expired_retains_only_inflight_container_batch_states() {
        let (_dir, idx, _blobs) = tempstore();
        let session = Uuid::from_bytes([0x53; 16]);
        for (offset, state, finalized_at) in [
            (0_u8, "PREPARED", None),
            (1, "CONFIRMED", None),
            (2, "REFUSED", None),
            (3, "FINALIZED", Some(100_i64)),
        ] {
            let seq = offset as u64 + 1;
            insert_command_at(&idx, session, seq, 1, 0);
            idx.conn()
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO container_capture_batches
                     (batch_id, session, seq, request_hash, event_count, state,
                      finalized_unix_secs)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
                    params![
                        [offset + 21; 16].as_slice(),
                        session.as_bytes().as_slice(),
                        seq as i64,
                        [offset + 21; 32].as_slice(),
                        state,
                        finalized_at,
                    ],
                )
                .unwrap();
        }

        assert_eq!(
            mark_expired_batch(&idx, u64::MAX, 10)
                .unwrap()
                .iter()
                .map(|command| command.seq)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn expires_old_commands_keeps_recent() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        // Old command (started at logical=10), recent (started at 1000).
        insert_command_at(&idx, session, 0, 10, 0);
        insert_command_at(&idx, session, 1, 1000, 0);
        let config = GcConfig {
            age_threshold_secs: 100,
            ..GcConfig::default()
        };
        // now = 500s. Cutoff = 400s. seq=0 ended at 11s and expires;
        // seq=1 ends at 1001s and stays.
        let report = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(500),
        )
        .unwrap();
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
    fn quarantined_clock_suppresses_command_and_stash_age_expiry() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        insert_command_at(&idx, session, 1, 10, 0);
        let (stash, _) = insert_container_stash(&idx, &blobs, b"old stash", "old:image");
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = 0, retain_from_unix_secs = 0
                 WHERE blob_hash = ?1",
                params![stash.as_bytes().as_slice()],
            )
            .unwrap();
        let config = GcConfig {
            age_threshold_secs: 1,
            size_cap_bytes: None,
            container_stash_retention_secs: 1,
            ..GcConfig::default()
        };

        let report = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::quarantined(TEST_NOW),
        )
        .unwrap();

        assert!(report.age_expiry_suppressed);
        assert!(!report.aggressive_mode_used);
        assert_eq!(report.commands_dropped, 0);
        assert_eq!(report.container_stashes_pruned, 0);
        assert_eq!(idx.command_count().unwrap(), 1);
        assert!(get(&idx, stash.as_bytes()).unwrap().is_some());
    }

    #[test]
    fn one_checked_now_drives_command_and_stash_cutoffs() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        // insert_command_at records the terminal wall second as start + 1.
        insert_command_at(&idx, session, 1, 900, 0);
        let (stash, _) = insert_container_stash(&idx, &blobs, b"boundary stash", "boundary");
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "UPDATE container_stashes
                 SET created_unix_secs = 901, retain_from_unix_secs = 901
                 WHERE blob_hash = ?1",
                params![stash.as_bytes().as_slice()],
            )
            .unwrap();
        let config = GcConfig {
            age_threshold_secs: 100,
            size_cap_bytes: None,
            container_stash_retention_secs: 100,
            ..GcConfig::default()
        };

        let boundary = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(1_001),
        )
        .unwrap();
        assert_eq!(boundary.commands_dropped, 0);
        assert_eq!(boundary.container_stashes_pruned, 0);

        let expired = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(1_002),
        )
        .unwrap();
        assert_eq!(expired.commands_dropped, 1);
        assert_eq!(expired.container_stashes_pruned, 1);
    }

    #[test]
    fn explicit_aggressive_gc_still_runs_while_age_is_quarantined() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        insert_command_at(&idx, session, 1, TEST_NOW, 0);
        let config = GcConfig {
            force_aggressive: true,
            size_cap_bytes: None,
            ..GcConfig::default()
        };

        let report = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::quarantined(TEST_NOW),
        )
        .unwrap();

        assert!(report.age_expiry_suppressed);
        assert!(report.aggressive_mode_used);
        assert_eq!(report.commands_dropped, 1);
        assert_eq!(idx.command_count().unwrap(), 0);
    }

    #[test]
    fn size_driven_aggressive_gc_still_runs_while_age_is_quarantined() {
        let (_dir, idx, blobs) = tempstore();
        let session = Uuid::now_v7();
        insert_command_at(&idx, session, 1, TEST_NOW, 0);
        idx.conn()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO blobs (hash, size, compressed, refcount, created_logical)
                 VALUES (?1, 1024, 0, 1, 1)",
                [[0x55_u8; 32].as_slice()],
            )
            .unwrap();
        let config = GcConfig {
            size_cap_bytes: Some(100),
            ..GcConfig::default()
        };

        let report = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::quarantined(TEST_NOW),
        )
        .unwrap();

        assert!(report.age_expiry_suppressed);
        assert!(report.aggressive_mode_used);
        assert_eq!(report.commands_dropped, 1);
        assert_eq!(idx.command_count().unwrap(), 0);
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
            age_threshold_secs: 100,
            ..GcConfig::default()
        };
        let report = run_pass(
            &idx,
            &blobs,
            &config,
            Arc::new(AtomicBool::new(false)),
            RetentionNow::trusted(500),
        )
        .unwrap();
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
            age_threshold_secs: 100,
            batch_size: 5,
            ..GcConfig::default()
        };
        match run_pass(&idx, &blobs, &config, cancel, RetentionNow::trusted(500)) {
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
            RetentionNow::trusted(1000),
        )
        .unwrap();
        assert!(report.aggressive_mode_used);
    }
}
