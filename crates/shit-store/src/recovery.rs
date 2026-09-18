// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash-recovery for command windows left open by a previous daemon.
//!
//! An open command normally cannot safely be resumed after process restart:
//! the in-memory capture fences and baseline state that proved completeness
//! died with the old daemon. Startup therefore converts interrupted commands
//! into completed, command-atomic refusals before any new producer starts.
//! The narrow exception is a command whose entire persisted journal consists
//! of already-CONFIRMED or FINALIZED container-batch members. Those inverses
//! were made actionable before the runtime received authorization, so adding a
//! generic restart refusal would destroy a stronger durable guarantee. Startup
//! never promotes CONFIRMED to FINALIZED: absence of a finalize request is not
//! proof that the runtime returned.

use crate::index::Index;
use rusqlite::params;
use shit_planner::{CaptureEvent, CaptureEventKind, CommandId, EventId, TimePoint};
use std::path::PathBuf;
use uuid::Uuid;

/// Exit status reserved for a command closed by daemon startup recovery.
///
/// POSIX shell exit statuses are non-negative, so `-1` cannot be confused
/// with the status observed by a normal PostExec hook.
pub const STARTUP_RECOVERY_EXIT_CODE: i32 = -1;

/// Sentinel path carried by the command-scoped startup refusal.
#[cfg(not(windows))]
pub const STARTUP_RECOVERY_PATH: &str = "/.shit-daemon-startup-recovery";
/// Sentinel path carried by the command-scoped startup refusal.
#[cfg(windows)]
pub const STARTUP_RECOVERY_PATH: &str = r"C:\.shit-daemon-startup-recovery";

/// Stable explanation persisted in recovered command journals.
pub const STARTUP_RECOVERY_DETAIL: &str = "daemon startup recovery: the previous daemon lifetime ended before this command was fully finalized; capture completeness cannot be proven";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupRecoveryReport {
    /// Commands closed by this invocation, including the narrowly preserved
    /// confirmed-container subset.
    pub recovered_commands: Vec<CommandId>,
    /// Interrupted commands closed without a refusal because every persisted
    /// event belonged to one or more complete CONFIRMED/FINALIZED batches.
    pub preserved_confirmed_container_commands: Vec<CommandId>,
    /// Crash-left batches that never reached pre-authorization confirmation.
    pub prepared_batches_refused: usize,
    /// Command-scoped blob leases removed in the same transaction.
    pub blob_leases_cleared: usize,
    /// First logical timestamp the new daemon lifetime may allocate.
    pub next_logical: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupRecoveryError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("could not encode startup recovery refusal: {0}")]
    Encode(#[from] postcard::Error),
    #[error("open command has malformed {length}-byte session id")]
    MalformedSession { length: usize },
    #[error("open command has invalid negative sequence number {seq}")]
    InvalidSequence { seq: i64 },
    #[error("journal has invalid negative global logical timestamp {logical}")]
    InvalidLogicalTime { logical: i64 },
    #[error("logical timestamp exhausted while recovering open command {command}")]
    LogicalTimeExhausted { command: CommandId },
    #[error("global logical timestamp exhausted; no new journal event can be allocated")]
    GlobalLogicalTimeExhausted,
    #[error("startup recovery wallclock {wallclock_unix_nanos} exceeds sqlite INTEGER range")]
    WallclockOutOfRange { wallclock_unix_nanos: u64 },
    #[error("open command {command} disappeared while startup recovery held its transaction")]
    CommandNoLongerOpen { command: CommandId },
}

struct PendingRecovery {
    command: CommandId,
    refusal_logical: Option<i64>,
    ended_logical: i64,
    payload: Option<Vec<u8>>,
}

fn has_only_confirmed_container_events(
    tx: &rusqlite::Transaction<'_>,
    command: CommandId,
) -> Result<bool, rusqlite::Error> {
    tx.query_row(
        "SELECT
             EXISTS(
                 SELECT 1 FROM container_capture_batches b
                 WHERE b.session = ?1 AND b.seq = ?2
                   AND b.state IN ('CONFIRMED', 'FINALIZED')
             )
             AND NOT EXISTS(
                 SELECT 1
                 FROM events e
                 LEFT JOIN confirmed_container_capture_events confirmed
                   ON confirmed.event_id = e.id
                 WHERE e.session = ?1 AND e.seq = ?2
                   AND confirmed.event_id IS NULL
             )",
        params![command.session.as_bytes().as_slice(), command.seq as i64],
        |row| row.get(0),
    )
}

/// Refuse and close every command whose terminal timestamp is incomplete.
///
/// The refusal event, synthetic terminal status, and removal of that
/// command's blob leases are one transaction. A crash before commit leaves
/// the old open row intact for a retry; a crash after commit observes a fully
/// refused and closed row, so rerunning this function is idempotent.
///
/// `wallclock_unix_nanos` is only a display hint. Recovery starts after the
/// global maximum journal/session/command logical time, then allocates a
/// refusal tick and a later terminal tick for each command in stable order.
/// This avoids relying on the daemon's process-local logical clock, which
/// resets on restart, and preserves global path-history ordering.
pub fn recover_interrupted_commands(
    index: &Index,
    wallclock_unix_nanos: u64,
) -> Result<StartupRecoveryReport, StartupRecoveryError> {
    let wallclock = i64::try_from(wallclock_unix_nanos).map_err(|_| {
        StartupRecoveryError::WallclockOutOfRange {
            wallclock_unix_nanos,
        }
    })?;
    let conn = index.conn().lock().unwrap();
    let tx = conn.unchecked_transaction()?;

    // Startup runs before any request listener, so no legitimate prepare can
    // be in flight. Sweep PREPARED globally rather than only through open
    // commands: PostExec may have closed the owner just before the old daemon
    // crashed between insertion and pre-authorization confirmation.
    let prepared_batches_refused = tx.execute(
        "UPDATE container_capture_batches
         SET state = 'REFUSED'
         WHERE state = 'PREPARED'",
        [],
    )?;

    let rows = {
        let mut stmt = tx.prepare(
            "SELECT c.session, c.seq
             FROM commands c
             WHERE c.ended_logical IS NULL
                OR c.ended_wall_nanos IS NULL
                OR c.exit_code IS NULL
             ORDER BY c.session, c.seq",
        )?;
        stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };

    let global_latest_logical: Option<i64> = tx.query_row(
        "SELECT MAX(logical) FROM (
             SELECT MAX(ts_logical) AS logical FROM events
             UNION ALL SELECT MAX(started_logical) FROM commands
             UNION ALL SELECT MAX(ended_logical) FROM commands
             UNION ALL SELECT MAX(opened_logical) FROM sessions
             UNION ALL SELECT MAX(closed_logical) FROM sessions
             UNION ALL SELECT MAX(valid_from_logical) FROM paths
             UNION ALL SELECT MAX(valid_to_logical) FROM paths
             UNION ALL SELECT MAX(created_logical) FROM blobs
             UNION ALL SELECT MAX(pinned_logical) FROM pins
             UNION ALL SELECT MAX(created_logical) FROM large_objects
             UNION ALL SELECT MAX(taken_logical) FROM holds
             UNION ALL SELECT MAX(created_logical) FROM bookmarks
             UNION ALL SELECT MAX(created_logical) FROM blob_leases
         )",
        [],
        |row| row.get(0),
    )?;
    let mut logical_cursor = global_latest_logical.unwrap_or(0);
    if logical_cursor < 0 {
        return Err(StartupRecoveryError::InvalidLogicalTime {
            logical: logical_cursor,
        });
    }

    // Validate and serialize every recovery event before mutating the
    // transaction. Transaction rollback is still the final safety net, but
    // front-loading fallible work keeps the write phase simple and auditable.
    let mut pending = Vec::with_capacity(rows.len());
    for (session_bytes, seq) in rows {
        let session = Uuid::from_slice(&session_bytes).map_err(|_| {
            StartupRecoveryError::MalformedSession {
                length: session_bytes.len(),
            }
        })?;
        let seq = u64::try_from(seq).map_err(|_| StartupRecoveryError::InvalidSequence { seq })?;
        let command = CommandId { session, seq };
        let preserve_confirmed = has_only_confirmed_container_events(&tx, command)?;
        let refusal_logical = if preserve_confirmed {
            None
        } else {
            Some(
                logical_cursor
                    .checked_add(1)
                    .ok_or(StartupRecoveryError::LogicalTimeExhausted { command })?,
            )
        };
        let ended_logical = refusal_logical
            .unwrap_or(logical_cursor)
            .checked_add(1)
            .ok_or(StartupRecoveryError::LogicalTimeExhausted { command })?;
        logical_cursor = ended_logical;
        let payload = refusal_logical
            .map(|logical| CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(logical as u64, wallclock_unix_nanos),
                partial: false,
                kind: CaptureEventKind::CaptureRefused {
                    class: "capture-incomplete".to_string(),
                    path: PathBuf::from(STARTUP_RECOVERY_PATH),
                    detail: STARTUP_RECOVERY_DETAIL.to_string(),
                },
            })
            .map(|refusal| postcard::to_allocvec(&refusal))
            .transpose()?;
        pending.push(PendingRecovery {
            command,
            refusal_logical,
            ended_logical,
            payload,
        });
    }

    let next_logical = logical_cursor
        .checked_add(1)
        .ok_or(StartupRecoveryError::GlobalLogicalTimeExhausted)?;
    let mut report = StartupRecoveryReport {
        next_logical: next_logical as u64,
        prepared_batches_refused,
        ..StartupRecoveryReport::default()
    };
    for recovery in pending {
        if let (Some(refusal_logical), Some(payload)) =
            (recovery.refusal_logical, recovery.payload.as_ref())
        {
            tx.execute(
                "INSERT INTO events
                 (session, seq, ts_logical, ts_wall_nanos, partial,
                  discriminant, dev, inode, path, blob_hash,
                  post_content_hash, payload)
                 VALUES (?1, ?2, ?3, ?4, 0,
                         'CaptureRefused', NULL, NULL, ?5, NULL, NULL, ?6)",
                params![
                    recovery.command.session.as_bytes().as_slice(),
                    recovery.command.seq as i64,
                    refusal_logical,
                    wallclock,
                    STARTUP_RECOVERY_PATH,
                    payload,
                ],
            )?;
        } else {
            report
                .preserved_confirmed_container_commands
                .push(recovery.command);
        }

        let updated = tx.execute(
            "UPDATE commands
             SET ended_logical = ?3, ended_wall_nanos = ?4, exit_code = ?5
             WHERE session = ?1 AND seq = ?2
               AND (ended_logical IS NULL
                    OR ended_wall_nanos IS NULL
                    OR exit_code IS NULL)",
            params![
                recovery.command.session.as_bytes().as_slice(),
                recovery.command.seq as i64,
                recovery.ended_logical,
                wallclock,
                STARTUP_RECOVERY_EXIT_CODE,
            ],
        )?;
        if updated != 1 {
            return Err(StartupRecoveryError::CommandNoLongerOpen {
                command: recovery.command,
            });
        }

        report.blob_leases_cleared += tx.execute(
            "DELETE FROM blob_leases WHERE session = ?1 AND seq = ?2",
            params![
                recovery.command.session.as_bytes().as_slice(),
                recovery.command.seq as i64,
            ],
        )?;
        report.recovered_commands.push(recovery.command);
    }

    tx.commit()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContainerBatchState;
    use shit_planner::{
        CommandRecord, ContainerOp, ContainerRuntime, InverseOp, PlannerStore,
        probe::mock::InMemoryProbe,
    };

    fn setup() -> (tempfile::TempDir, Index, Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path().join("index.sqlite")).unwrap();
        let session = Uuid::from_bytes([0x51; 16]);
        index
            .put_session(session, "bash", 1, None, TimePoint::new(1, 1))
            .unwrap();
        (dir, index, session)
    }

    fn begin(index: &Index, session: Uuid, seq: u64, logical: u64) -> CommandId {
        let command = CommandId { session, seq };
        assert!(
            index
                .begin_command(&CommandRecord {
                    command,
                    cmd_string: Some(format!("command-{seq}")),
                    cwd: PathBuf::from("/tmp"),
                    pid: 123,
                    shell_kind: shit_proto::ShellKind::Bash,
                    started_at: TimePoint::new(logical, logical * 10),
                    ended_at: None,
                    exit_code: None,
                    event_ids: Vec::new(),
                })
                .unwrap()
        );
        command
    }

    fn ordinary_refusal(command: CommandId, logical: u64) -> CaptureEvent {
        CaptureEvent {
            id: EventId(0),
            command,
            ts: TimePoint::new(logical, logical * 10),
            partial: false,
            kind: CaptureEventKind::CaptureRefused {
                class: "capture-incomplete".into(),
                path: PathBuf::from("/tmp/original"),
                detail: "earlier refusal".into(),
            },
        }
    }

    #[test]
    fn interrupted_commands_are_atomically_refused_closed_and_unleased() {
        let (_dir, index, session) = setup();
        let interrupted = begin(&index, session, 1, 10);
        index.put_event(&ordinary_refusal(interrupted, 40)).unwrap();
        let prepared_batch = Uuid::from_bytes([0xBA; 16]);
        index
            .prepare_container_batch(
                prepared_batch,
                [0xBA; 32],
                &[CaptureEvent {
                    id: EventId(0),
                    command: interrupted,
                    ts: TimePoint::new(41, 410),
                    partial: true,
                    kind: CaptureEventKind::ContainerOp {
                        runtime: ContainerRuntime::Docker,
                        op: ContainerOp::NetworkRm {
                            name: "recovery-test".into(),
                        },
                        captured_config: br#"{"Name":"recovery-test"}"#.to_vec(),
                        stash_image: None,
                        stash_tarball: None,
                    },
                }],
            )
            .unwrap();

        let leased = shit_planner::BlobHash::from_bytes([0x42; 32]);
        index
            .put_blob_record(leased, 12, false, TimePoint::new(2, 2))
            .unwrap();
        index
            .create_blob_lease(leased, interrupted, TimePoint::new(3, 3))
            .unwrap();

        // This completed command is unrelated to either interrupted command,
        // but its high timestamp still establishes the global journal floor.
        let completed = begin(&index, session, 2, 20);
        index.put_event(&ordinary_refusal(completed, 80)).unwrap();
        assert!(
            index
                .finish_command(completed, TimePoint::new(81, 810), 7)
                .unwrap()
        );
        // Expiry columns are future deadlines, not observations of the
        // logical clock. They must not jump startup time forward.
        index
            .pin_command(completed, Some("future"), 75, Some(1_000_000))
            .unwrap();
        crate::holds::create(&index, completed, 99, "test", 76, Some(2_000_000), None).unwrap();

        // A row with terminal timestamps but no exit code is only partially
        // terminal and must be recovered conservatively too.
        let partial_terminal = begin(&index, session, 3, 30);
        assert!(
            index
                .finish_command(partial_terminal, TimePoint::new(31, 310), 0)
                .unwrap()
        );
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute(
                "UPDATE commands SET exit_code = NULL WHERE session = ?1 AND seq = ?2",
                params![
                    partial_terminal.session.as_bytes().as_slice(),
                    partial_terminal.seq as i64
                ],
            )
            .unwrap();

        let report = recover_interrupted_commands(&index, 900).unwrap();
        assert_eq!(
            report.recovered_commands,
            vec![interrupted, partial_terminal]
        );
        assert_eq!(report.blob_leases_cleared, 1);
        assert_eq!(report.prepared_batches_refused, 1);
        assert_eq!(report.next_logical, 86);
        assert!(!index.has_blob_lease(leased, interrupted).unwrap());
        assert_eq!(
            index.container_batch_state(prepared_batch).unwrap(),
            Some(ContainerBatchState::Refused)
        );

        let events = index.events_for_command(interrupted);
        assert_eq!(events.len(), 3);
        assert!(events[1].partial);
        assert_eq!(events[2].ts, TimePoint::new(82, 900));
        assert!(matches!(
            &events[2].kind,
            CaptureEventKind::CaptureRefused { class, path, detail }
                if class == "capture-incomplete"
                    && path == std::path::Path::new(STARTUP_RECOVERY_PATH)
                    && detail == STARTUP_RECOVERY_DETAIL
        ));
        let recovered = index.command_by_id(interrupted).unwrap();
        assert_eq!(recovered.ended_at, Some(TimePoint::new(83, 900)));
        assert_eq!(recovered.exit_code, Some(STARTUP_RECOVERY_EXIT_CODE));

        let partial_events = index.events_for_command(partial_terminal);
        assert_eq!(partial_events.len(), 1);
        assert_eq!(partial_events[0].ts, TimePoint::new(84, 900));
        let partial_recovered = index.command_by_id(partial_terminal).unwrap();
        assert_eq!(partial_recovered.ended_at, Some(TimePoint::new(85, 900)));
        assert_eq!(
            partial_recovered.exit_code,
            Some(STARTUP_RECOVERY_EXIT_CODE)
        );

        let untouched = index.command_by_id(completed).unwrap();
        assert_eq!(untouched.ended_at, Some(TimePoint::new(81, 810)));
        assert_eq!(untouched.exit_code, Some(7));
        assert_eq!(index.events_for_command(completed).len(), 1);

        // A committed recovery is terminal and therefore replay-safe.
        let replay = recover_interrupted_commands(&index, 901).unwrap();
        assert!(replay.recovered_commands.is_empty());
        assert_eq!(replay.blob_leases_cleared, 0);
        assert_eq!(replay.next_logical, 86);
        assert_eq!(index.events_for_command(interrupted).len(), 3);
    }

    #[test]
    fn restart_preserves_a_fully_confirmed_container_only_command() {
        let (_dir, index, session) = setup();
        let command = begin(&index, session, 9, 10);
        let batch_id = Uuid::from_bytes([0xC9; 16]);
        let stash = shit_planner::BlobHash::from_bytes([0x39; 32]);
        index
            .prepare_container_batch(
                batch_id,
                [0xC9; 32],
                &[CaptureEvent {
                    id: EventId(0),
                    command,
                    ts: TimePoint::new(11, 110),
                    partial: true,
                    kind: CaptureEventKind::ContainerOp {
                        runtime: ContainerRuntime::Docker,
                        op: ContainerOp::Rmi {
                            image: "example:old".into(),
                            digest: Some(format!("sha256:{}", "a".repeat(64))),
                        },
                        captured_config: Vec::new(),
                        stash_image: None,
                        stash_tarball: Some(stash),
                    },
                }],
            )
            .unwrap();
        assert_eq!(
            index.finalize_container_batch(batch_id, true).unwrap(),
            ContainerBatchState::Confirmed
        );

        let report = recover_interrupted_commands(&index, 900).unwrap();
        assert_eq!(report.recovered_commands, vec![command]);
        assert_eq!(report.preserved_confirmed_container_commands, vec![command]);
        assert_eq!(report.next_logical, 13);
        assert_eq!(report.prepared_batches_refused, 0);
        assert_eq!(
            index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Confirmed)
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "restart must not append CaptureRefused");
        assert!(!events[0].partial);
        let record = index.command_by_id(command).unwrap();
        assert_eq!(record.ended_at, Some(TimePoint::new(12, 900)));
        assert_eq!(record.exit_code, Some(STARTUP_RECOVERY_EXIT_CODE));
        let plan = shit_planner::plan(record, &events, &InMemoryProbe::new(), &index);
        assert!(matches!(
            plan.nodes.as_slice(),
            [shit_planner::PlanNode {
                op: InverseOp::ContainerRestore {
                    op: ContainerOp::Rmi { image, .. },
                    ..
                },
                ..
            }] if image == "example:old"
        ));
    }

    #[test]
    fn restart_preserves_finalized_container_events_without_reopening_lifecycle() {
        let (_dir, index, session) = setup();
        let command = begin(&index, session, 19, 10);
        let batch_id = Uuid::from_bytes([0xD9; 16]);
        index
            .prepare_container_batch(
                batch_id,
                [0xD9; 32],
                &[CaptureEvent {
                    id: EventId(0),
                    command,
                    ts: TimePoint::new(11, 110),
                    partial: true,
                    kind: CaptureEventKind::ContainerOp {
                        runtime: ContainerRuntime::Docker,
                        op: ContainerOp::Rmi {
                            image: "example:finalized".into(),
                            digest: Some(format!("sha256:{}", "f".repeat(64))),
                        },
                        captured_config: Vec::new(),
                        stash_image: None,
                        stash_tarball: None,
                    },
                }],
            )
            .unwrap();
        index.finalize_container_batch(batch_id, true).unwrap();
        index.mark_container_batch_finalized(batch_id, 777).unwrap();

        let report = recover_interrupted_commands(&index, 900).unwrap();
        assert_eq!(report.recovered_commands, vec![command]);
        assert_eq!(report.preserved_confirmed_container_commands, vec![command]);
        assert_eq!(report.prepared_batches_refused, 0);
        let info = index.container_batch_info(batch_id).unwrap().unwrap();
        assert_eq!(info.state, ContainerBatchState::Finalized);
        assert_eq!(info.finalized_unix_secs, Some(777));
        assert_eq!(index.events_for_command(command).len(), 1);
        assert!(!index.events_for_command(command)[0].partial);
    }

    #[test]
    fn startup_refuses_prepared_batches_even_when_their_command_already_closed() {
        let (_dir, index, session) = setup();
        let command = begin(&index, session, 10, 10);
        let batch_id = Uuid::from_bytes([0xDA; 16]);
        index
            .prepare_container_batch(
                batch_id,
                [0xDA; 32],
                &[CaptureEvent {
                    id: EventId(0),
                    command,
                    ts: TimePoint::new(11, 110),
                    partial: true,
                    kind: CaptureEventKind::ContainerOp {
                        runtime: ContainerRuntime::Docker,
                        op: ContainerOp::Rmi {
                            image: "example:old".into(),
                            digest: Some(format!("sha256:{}", "d".repeat(64))),
                        },
                        captured_config: Vec::new(),
                        stash_image: None,
                        stash_tarball: Some(shit_planner::BlobHash::from_bytes([0xDA; 32])),
                    },
                }],
            )
            .unwrap();
        assert!(
            index
                .finish_command(command, TimePoint::new(12, 120), 125)
                .unwrap()
        );

        let report = recover_interrupted_commands(&index, 900).unwrap();
        assert!(report.recovered_commands.is_empty());
        assert_eq!(report.prepared_batches_refused, 1);
        assert_eq!(
            index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Refused)
        );
        assert!(index.events_for_command(command)[0].partial);
    }

    #[test]
    fn validation_failure_rolls_back_the_whole_recovery_batch() {
        let (_dir, index, session) = setup();
        let first = begin(&index, session, 1, 10);
        let exhausted = begin(&index, session, 2, 20);
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute(
                "UPDATE commands SET started_logical = ?3
                 WHERE session = ?1 AND seq = ?2",
                params![
                    session.as_bytes().as_slice(),
                    exhausted.seq as i64,
                    i64::MAX
                ],
            )
            .unwrap();

        let leased = shit_planner::BlobHash::from_bytes([0x24; 32]);
        index
            .put_blob_record(leased, 12, false, TimePoint::new(2, 2))
            .unwrap();
        index
            .create_blob_lease(leased, first, TimePoint::new(3, 3))
            .unwrap();

        assert!(matches!(
            recover_interrupted_commands(&index, 900),
            Err(StartupRecoveryError::LogicalTimeExhausted { command })
                if command == first
        ));
        for command in [first, exhausted] {
            assert!(index.command_by_id(command).unwrap().ended_at.is_none());
            assert!(index.events_for_command(command).is_empty());
        }
        assert!(index.has_blob_lease(leased, first).unwrap());
    }

    #[test]
    fn sql_failure_after_first_mutation_rolls_back_events_closes_and_leases() {
        let (_dir, index, session) = setup();
        let first = begin(&index, session, 1, 10);
        let second = begin(&index, session, 2, 20);
        let leased = shit_planner::BlobHash::from_bytes([0x66; 32]);
        index
            .put_blob_record(leased, 12, false, TimePoint::new(2, 2))
            .unwrap();
        index
            .create_blob_lease(leased, first, TimePoint::new(3, 3))
            .unwrap();

        // The first command is inserted/closed/unleased before this trigger
        // aborts insertion of the second command's refusal. All of those
        // earlier writes must roll back with the transaction.
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_second_startup_recovery
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'CaptureRefused' AND NEW.seq = 2
                 BEGIN
                     SELECT RAISE(ABORT, 'injected second recovery failure');
                 END;",
            )
            .unwrap();

        assert!(matches!(
            recover_interrupted_commands(&index, 900),
            Err(StartupRecoveryError::Sql(_))
        ));
        for command in [first, second] {
            let record = index.command_by_id(command).unwrap();
            assert!(record.ended_at.is_none());
            assert!(record.exit_code.is_none());
            assert!(index.events_for_command(command).is_empty());
        }
        assert!(index.has_blob_lease(leased, first).unwrap());
    }
}
