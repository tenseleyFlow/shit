// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable pre-authorization publication for destructive container operations.
//!
//! Preparing a batch inserts every capture event as partial in one SQLite
//! transaction. The daemon validates every external blob and immediately
//! confirms the complete batch before acknowledging the wrapper, updating
//! both the denormalized `events.partial` column and postcard payload. A
//! pre-authorization failure refuses the batch and leaves every member
//! partial. Post-runtime observations are telemetry and cannot revoke an
//! already-actionable inverse. CONFIRMED and REFUSED are pre-runtime protocol
//! decisions; only FINALIZED durably proves that the wrapper observed a
//! runtime outcome. Retention protects PREPARED and CONFIRMED, then ages
//! finalized evidence from the durable runtime-finished timestamp.

use crate::index::{Index, IndexError, denormalize};
use rusqlite::{OptionalExtension, params};
use shit_planner::{CaptureEvent, CaptureEventKind, CommandId, ContainerOp, EventId};
use uuid::Uuid;

/// Protocol/store hard bound for one destructive runtime invocation.
pub const MAX_CONTAINER_BATCH_EVENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerBatchState {
    Prepared,
    Confirmed,
    Refused,
    Finalized,
}

impl ContainerBatchState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Confirmed => "CONFIRMED",
            Self::Refused => "REFUSED",
            Self::Finalized => "FINALIZED",
        }
    }

    fn from_sql(batch_id: Uuid, value: &str) -> Result<Self, IndexError> {
        match value {
            "PREPARED" => Ok(Self::Prepared),
            "CONFIRMED" => Ok(Self::Confirmed),
            "REFUSED" => Ok(Self::Refused),
            "FINALIZED" => Ok(Self::Finalized),
            other => Err(IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("unknown state {other:?}"),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerBatchPrepareResult {
    pub state: ContainerBatchState,
    pub event_ids: Vec<EventId>,
    /// `true` only when this call inserted the batch. A same-hash retry
    /// returns the original ids with `inserted=false`.
    pub inserted: bool,
}

/// Immutable batch identity plus its current durable lifecycle state. Daemon
/// finalize handling uses this to bind ownership, validate observations, and
/// expose the first persisted runtime-finished timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerBatchInfo {
    pub batch_id: Uuid,
    pub command: CommandId,
    pub request_hash: [u8; 32],
    pub event_count: usize,
    pub state: ContainerBatchState,
    /// First durable observation that the authorized runtime invocation
    /// returned. Present only for [`ContainerBatchState::Finalized`].
    pub finalized_unix_secs: Option<u64>,
    pub event_ids: Vec<EventId>,
}

struct StoredBatch {
    command_session: Vec<u8>,
    command_seq: i64,
    request_hash: Vec<u8>,
    event_count: i64,
    state: ContainerBatchState,
    finalized_unix_secs: Option<u64>,
}

type StoredEventRow = (Vec<u8>, i64, i64, String, Option<Vec<u8>>, Vec<u8>);

fn is_destructive_container_event(event: &CaptureEvent) -> bool {
    matches!(
        &event.kind,
        CaptureEventKind::ContainerOp { op, .. } if !matches!(op, ContainerOp::Pull { .. })
    )
}

fn validate_new_events(batch_id: Uuid, events: &[CaptureEvent]) -> Result<(), IndexError> {
    if events.is_empty() {
        return Err(IndexError::InvalidContainerBatch {
            batch_id,
            reason: "batch must contain at least one event".into(),
        });
    }
    if events.len() > MAX_CONTAINER_BATCH_EVENTS {
        return Err(IndexError::InvalidContainerBatch {
            batch_id,
            reason: format!(
                "batch has {} events; maximum is {MAX_CONTAINER_BATCH_EVENTS}",
                events.len()
            ),
        });
    }

    let command = events[0].command;
    for (ordinal, event) in events.iter().enumerate() {
        if event.command != command {
            return Err(IndexError::InvalidContainerBatch {
                batch_id,
                reason: format!("event ordinal {ordinal} belongs to a different command"),
            });
        }
        if !event.partial {
            return Err(IndexError::InvalidContainerBatch {
                batch_id,
                reason: format!("event ordinal {ordinal} is not partial"),
            });
        }
        if !is_destructive_container_event(event) {
            return Err(IndexError::InvalidContainerBatch {
                batch_id,
                reason: format!("event ordinal {ordinal} is not a destructive ContainerOp"),
            });
        }
    }
    Ok(())
}

fn stored_batch(
    tx: &rusqlite::Transaction<'_>,
    batch_id: Uuid,
) -> Result<Option<StoredBatch>, IndexError> {
    let row = tx
        .query_row(
            "SELECT session, seq, request_hash, event_count, state,
                    finalized_unix_secs
             FROM container_capture_batches WHERE batch_id = ?1",
            params![batch_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(command_session, command_seq, request_hash, event_count, state, finalized_unix_secs)| {
            let state = ContainerBatchState::from_sql(batch_id, &state)?;
            let finalized_unix_secs = finalized_unix_secs
                .map(|value| {
                    u64::try_from(value).map_err(|_| IndexError::ContainerBatchIntegrity {
                        batch_id,
                        reason: format!("negative finalization timestamp {value}"),
                    })
                })
                .transpose()?;
            if (state == ContainerBatchState::Finalized) != finalized_unix_secs.is_some() {
                return Err(IndexError::ContainerBatchIntegrity {
                    batch_id,
                    reason: format!(
                        "state {state:?} disagrees with finalization timestamp presence"
                    ),
                });
            }
            Ok(StoredBatch {
                command_session,
                command_seq,
                request_hash,
                event_count,
                state,
                finalized_unix_secs,
            })
        },
    )
    .transpose()
}

fn mapped_event_ids(
    tx: &rusqlite::Transaction<'_>,
    batch_id: Uuid,
    expected_count: usize,
) -> Result<Vec<EventId>, IndexError> {
    let mut stmt = tx.prepare(
        "SELECT ordinal, event_id
         FROM container_capture_batch_events
         WHERE batch_id = ?1
         ORDER BY ordinal",
    )?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map(params![batch_id.as_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<_, _>>()?;
    if rows.len() != expected_count {
        return Err(IndexError::ContainerBatchIntegrity {
            batch_id,
            reason: format!("expected {expected_count} mappings, found {}", rows.len()),
        });
    }
    rows.into_iter()
        .enumerate()
        .map(|(expected, (ordinal, event_id))| {
            if ordinal != expected as i64 || event_id <= 0 {
                return Err(IndexError::ContainerBatchIntegrity {
                    batch_id,
                    reason: format!(
                        "invalid mapping at position {expected}: ordinal={ordinal}, event_id={event_id}"
                    ),
                });
            }
            Ok(EventId(event_id as u64))
        })
        .collect()
}

fn validated_stored_events(
    tx: &rusqlite::Transaction<'_>,
    batch_id: Uuid,
    stored: &StoredBatch,
    event_ids: &[EventId],
    expected_partial: bool,
) -> Result<Vec<(EventId, CaptureEvent)>, IndexError> {
    let mut events = Vec::with_capacity(event_ids.len());
    for (ordinal, event_id) in event_ids.iter().copied().enumerate() {
        let (session, seq, partial, discriminant, blob_hash, payload): StoredEventRow = tx
            .query_row(
                "SELECT session, seq, partial, discriminant, blob_hash, payload
             FROM events WHERE id = ?1",
                params![event_id.0 as i64],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )?;
        let event: CaptureEvent = postcard::from_bytes(&payload).map_err(|error| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("event ordinal {ordinal} payload does not decode: {error}"),
            }
        })?;
        if session.as_slice() != stored.command_session.as_slice()
            || seq != stored.command_seq
            || event.command.session.as_bytes() != stored.command_session.as_slice()
            || event.command.seq as i64 != stored.command_seq
            || !is_destructive_container_event(&event)
        {
            return Err(IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("event ordinal {ordinal} is not a valid batch member"),
            });
        }
        let denormalized = denormalize(&event.kind);
        let expected_blob = denormalized
            .blob_hash
            .as_ref()
            .map(|hash| hash.as_bytes().as_slice());
        if discriminant != denormalized.discriminant || blob_hash.as_deref() != expected_blob {
            return Err(IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!(
                    "event ordinal {ordinal} denormalized evidence disagrees with its payload"
                ),
            });
        }
        if (partial != 0) != expected_partial || event.partial != expected_partial {
            return Err(IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("event ordinal {ordinal} partial state disagrees with batch state"),
            });
        }
        events.push((event_id, event));
    }
    Ok(events)
}

impl Index {
    /// Atomically insert a nonempty, bounded batch of already-validated
    /// destructive container captures.
    ///
    /// Every event must belong to the same open command and must arrive with
    /// `partial=true`. Reusing `batch_id` with the same request hash is an
    /// idempotent lookup of the original result; reusing it with any other
    /// hash is rejected without mutation.
    pub fn prepare_container_batch(
        &self,
        batch_id: Uuid,
        request_hash: [u8; 32],
        events: &[CaptureEvent],
    ) -> Result<ContainerBatchPrepareResult, IndexError> {
        validate_new_events(batch_id, events)?;
        let payloads = events
            .iter()
            .map(postcard::to_allocvec)
            .collect::<Result<Vec<_>, _>>()?;
        let command = events[0].command;

        let conn = self.conn().lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        if let Some(stored) = stored_batch(&tx, batch_id)? {
            if stored.request_hash.as_slice() != request_hash
                || stored.command_session.as_slice() != command.session.as_bytes()
                || stored.command_seq != command.seq as i64
                || stored.event_count != events.len() as i64
            {
                return Err(IndexError::ContainerBatchConflict { batch_id });
            }
            let event_ids = mapped_event_ids(&tx, batch_id, events.len())?;
            tx.commit()?;
            return Ok(ContainerBatchPrepareResult {
                state: stored.state,
                event_ids,
                inserted: false,
            });
        }

        let command_is_open: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM commands
                 WHERE session = ?1 AND seq = ?2
                   AND ended_logical IS NULL
                   AND ended_wall_nanos IS NULL
                   AND exit_code IS NULL
             )",
            params![command.session.as_bytes().as_slice(), command.seq as i64],
            |row| row.get(0),
        )?;
        if !command_is_open {
            return Err(IndexError::CommandNotOpen {
                session: command.session,
                seq: command.seq,
            });
        }

        tx.execute(
            "INSERT INTO container_capture_batches
             (batch_id, session, seq, request_hash, event_count, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'PREPARED')",
            params![
                batch_id.as_bytes().as_slice(),
                command.session.as_bytes().as_slice(),
                command.seq as i64,
                request_hash.as_slice(),
                events.len() as i64,
            ],
        )?;

        let mut event_ids = Vec::with_capacity(events.len());
        for (ordinal, (event, payload)) in events.iter().zip(payloads).enumerate() {
            let denorm = denormalize(&event.kind);
            tx.execute(
                "INSERT INTO events
                 (session, seq, ts_logical, ts_wall_nanos, partial,
                  discriminant, dev, inode, path, blob_hash,
                  post_content_hash, payload)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    event.command.session.as_bytes().as_slice(),
                    event.command.seq as i64,
                    event.ts.logical as i64,
                    event.ts.wallclock_unix_nanos as i64,
                    denorm.discriminant,
                    denorm.dev,
                    denorm.inode,
                    denorm.path.as_deref(),
                    denorm.blob_hash.as_ref().map(|h| h.as_bytes().as_slice()),
                    denorm
                        .post_content_hash
                        .as_ref()
                        .map(|h| h.as_bytes().as_slice()),
                    payload,
                ],
            )?;
            let event_id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO container_capture_batch_events
                 (batch_id, session, seq, ordinal, event_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    batch_id.as_bytes().as_slice(),
                    command.session.as_bytes().as_slice(),
                    command.seq as i64,
                    ordinal as i64,
                    event_id,
                ],
            )?;
            event_ids.push(EventId(event_id as u64));
        }
        tx.commit()?;
        Ok(ContainerBatchPrepareResult {
            state: ContainerBatchState::Prepared,
            event_ids,
            inserted: true,
        })
    }

    /// Atomically move a prepared batch to its pre-runtime protocol decision.
    /// This does not record durable runtime completion.
    ///
    /// `validated_success=true` means the daemon has validated the complete
    /// capture set and its physical evidence before authorizing the runtime.
    /// It is the sole route to CONFIRMED. `false` records a pre-authorization
    /// refusal and deliberately leaves all event rows partial.
    pub fn finalize_container_batch(
        &self,
        batch_id: Uuid,
        validated_success: bool,
    ) -> Result<ContainerBatchState, IndexError> {
        let conn = self.conn().lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let stored =
            stored_batch(&tx, batch_id)?.ok_or(IndexError::ContainerBatchNotFound { batch_id })?;
        let expected_count = usize::try_from(stored.event_count).map_err(|_| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("invalid event count {}", stored.event_count),
            }
        })?;
        let event_ids = mapped_event_ids(&tx, batch_id, expected_count)?;

        let desired = if validated_success {
            ContainerBatchState::Confirmed
        } else {
            ContainerBatchState::Refused
        };
        if stored.state != ContainerBatchState::Prepared && stored.state != desired {
            return Err(IndexError::ContainerBatchConflict { batch_id });
        }

        let expected_partial = !matches!(
            stored.state,
            ContainerBatchState::Confirmed | ContainerBatchState::Finalized
        );
        let stored_events =
            validated_stored_events(&tx, batch_id, &stored, &event_ids, expected_partial)?;
        let mut confirmed_payloads = Vec::with_capacity(event_ids.len());
        if desired == ContainerBatchState::Confirmed
            && stored.state == ContainerBatchState::Prepared
        {
            for (event_id, mut event) in stored_events {
                event.partial = false;
                confirmed_payloads.push((event_id.0 as i64, postcard::to_allocvec(&event)?));
            }
        }

        if stored.state == ContainerBatchState::Prepared {
            if desired == ContainerBatchState::Confirmed {
                for (event_id, payload) in confirmed_payloads {
                    let updated = tx.execute(
                        "UPDATE events SET partial = 0, payload = ?2
                         WHERE id = ?1 AND partial = 1",
                        params![event_id, payload],
                    )?;
                    if updated != 1 {
                        return Err(IndexError::ContainerBatchIntegrity {
                            batch_id,
                            reason: format!("event {event_id} changed during confirmation"),
                        });
                    }
                }
            }
            let updated = tx.execute(
                "UPDATE container_capture_batches SET state = ?2
                 WHERE batch_id = ?1 AND state = 'PREPARED'",
                params![batch_id.as_bytes().as_slice(), desired.as_sql()],
            )?;
            if updated != 1 {
                return Err(IndexError::ContainerBatchIntegrity {
                    batch_id,
                    reason: "batch state changed during finalization".into(),
                });
            }
        }
        tx.commit()?;
        Ok(desired)
    }

    /// Atomically record durable runtime completion for a confirmed batch.
    ///
    /// The first successful call preserves `finalized_unix_secs`, validates
    /// that every confirmed member is still intact, and advances every
    /// associated stash's retention origin. A repeated call on an already
    /// FINALIZED batch performs the same integrity validation but leaves the
    /// original timestamp unchanged.
    pub fn mark_container_batch_finalized(
        &self,
        batch_id: Uuid,
        finalized_unix_secs: u64,
    ) -> Result<ContainerBatchState, IndexError> {
        let finalized = i64::try_from(finalized_unix_secs).map_err(|_| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!(
                    "finalization timestamp {finalized_unix_secs} exceeds sqlite INTEGER range"
                ),
            }
        })?;
        let conn = self.conn().lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let stored =
            stored_batch(&tx, batch_id)?.ok_or(IndexError::ContainerBatchNotFound { batch_id })?;
        if !matches!(
            stored.state,
            ContainerBatchState::Confirmed | ContainerBatchState::Finalized
        ) {
            return Err(IndexError::ContainerBatchConflict { batch_id });
        }
        let expected_count = usize::try_from(stored.event_count).map_err(|_| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("invalid event count {}", stored.event_count),
            }
        })?;
        let event_ids = mapped_event_ids(&tx, batch_id, expected_count)?;
        let stored_events = validated_stored_events(&tx, batch_id, &stored, &event_ids, false)?;

        if stored.state == ContainerBatchState::Finalized {
            tx.commit()?;
            return Ok(ContainerBatchState::Finalized);
        }

        // CONFIRMED protects these owners from removal. Revalidate their
        // indexed ownership in the same transaction that releases that
        // protection; a missing owner must leave the batch in-flight.
        for (ordinal, (_, event)) in stored_events.iter().enumerate() {
            let CaptureEventKind::ContainerOp {
                stash_tarball: Some(hash),
                ..
            } = &event.kind
            else {
                continue;
            };
            let evidence_exists: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1
                     FROM container_stashes s
                     JOIN blobs b ON b.hash = s.blob_hash
                     WHERE s.blob_hash = ?1 AND b.refcount > 0
                 )",
                params![hash.as_bytes().as_slice()],
                |row| row.get(0),
            )?;
            if !evidence_exists {
                return Err(IndexError::ContainerBatchIntegrity {
                    batch_id,
                    reason: format!(
                        "event ordinal {ordinal} lost its indexed stash evidence before finalization"
                    ),
                });
            }
        }

        let updated = tx.execute(
            "UPDATE container_capture_batches
             SET state = 'FINALIZED', finalized_unix_secs = ?2
             WHERE batch_id = ?1 AND state = 'CONFIRMED'
               AND finalized_unix_secs IS NULL",
            params![batch_id.as_bytes().as_slice(), finalized],
        )?;
        if updated != 1 {
            return Err(IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: "batch state changed during runtime finalization".into(),
            });
        }

        // Persist the maximum age origin on the stash itself. Commands may be
        // collected after FINALIZED, cascading their batch rows; retaining the
        // timestamp here preserves the full post-runtime retention window.
        tx.execute(
            "UPDATE container_stashes AS s
             SET retain_from_unix_secs = MAX(
                 s.retain_from_unix_secs,
                 s.created_unix_secs,
                 ?2
             )
             WHERE (s.session = ?3 AND s.seq = ?4)
                OR EXISTS (
                    SELECT 1
                    FROM container_capture_batch_events m
                    JOIN events e ON e.id = m.event_id
                    WHERE m.batch_id = ?1 AND e.blob_hash = s.blob_hash
                )",
            params![
                batch_id.as_bytes().as_slice(),
                finalized,
                stored.command_session.as_slice(),
                stored.command_seq,
            ],
        )?;
        tx.commit()?;
        Ok(ContainerBatchState::Finalized)
    }

    pub fn container_batch_state(
        &self,
        batch_id: Uuid,
    ) -> Result<Option<ContainerBatchState>, IndexError> {
        Ok(self.container_batch_info(batch_id)?.map(|info| info.state))
    }

    /// Read immutable batch identity, target cardinality, ordered event ids,
    /// lifecycle state, and runtime-finished timestamp for daemon validation.
    pub fn container_batch_info(
        &self,
        batch_id: Uuid,
    ) -> Result<Option<ContainerBatchInfo>, IndexError> {
        let conn = self.conn().lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let Some(stored) = stored_batch(&tx, batch_id)? else {
            tx.commit()?;
            return Ok(None);
        };
        let session = Uuid::from_slice(&stored.command_session).map_err(|_| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!(
                    "command session has {} bytes instead of 16",
                    stored.command_session.len()
                ),
            }
        })?;
        let seq =
            u64::try_from(stored.command_seq).map_err(|_| IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("negative command sequence {}", stored.command_seq),
            })?;
        let event_count = usize::try_from(stored.event_count).map_err(|_| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!("invalid event count {}", stored.event_count),
            }
        })?;
        let request_hash: [u8; 32] = stored.request_hash.as_slice().try_into().map_err(|_| {
            IndexError::ContainerBatchIntegrity {
                batch_id,
                reason: format!(
                    "request hash has {} bytes instead of 32",
                    stored.request_hash.len()
                ),
            }
        })?;
        let event_ids = mapped_event_ids(&tx, batch_id, event_count)?;
        let info = ContainerBatchInfo {
            batch_id,
            command: CommandId { session, seq },
            request_hash,
            event_count,
            state: stored.state,
            finalized_unix_secs: stored.finalized_unix_secs,
            event_ids,
        };
        tx.commit()?;
        Ok(Some(info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{CommandId, CommandRecord, ContainerRuntime, PlannerStore, TimePoint};
    use std::path::PathBuf;

    fn setup() -> (tempfile::TempDir, Index, CommandId) {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path().join("index.sqlite")).unwrap();
        let session = Uuid::from_bytes([0x66; 16]);
        index
            .put_session(session, "bash", 1, None, TimePoint::new(1, 1))
            .unwrap();
        let command = CommandId { session, seq: 7 };
        assert!(
            index
                .begin_command(&CommandRecord {
                    command,
                    cmd_string: Some("docker network rm one two".into()),
                    cwd: PathBuf::from("/tmp"),
                    pid: 4242,
                    shell_kind: shit_proto::ShellKind::Bash,
                    started_at: TimePoint::new(2, 2),
                    ended_at: None,
                    exit_code: None,
                    event_ids: Vec::new(),
                })
                .unwrap()
        );
        (dir, index, command)
    }

    fn destructive_event(command: CommandId, ordinal: u64) -> CaptureEvent {
        CaptureEvent {
            id: EventId(0),
            command,
            ts: TimePoint::new(10 + ordinal, 100 + ordinal),
            partial: true,
            kind: CaptureEventKind::ContainerOp {
                runtime: ContainerRuntime::Docker,
                op: ContainerOp::NetworkRm {
                    name: format!("network-{ordinal}"),
                },
                captured_config: format!(r#"{{"Name":"network-{ordinal}"}}"#).into_bytes(),
                stash_image: None,
                stash_tarball: None,
            },
        }
    }

    fn pull_event(command: CommandId) -> CaptureEvent {
        CaptureEvent {
            id: EventId(0),
            command,
            ts: TimePoint::new(20, 200),
            partial: false,
            kind: CaptureEventKind::ContainerOp {
                runtime: ContainerRuntime::Docker,
                op: ContainerOp::Pull {
                    image: "alpine:latest".into(),
                    resolved_id: Some("sha256:abc".into()),
                },
                captured_config: Vec::new(),
                stash_image: None,
                stash_tarball: None,
            },
        }
    }

    #[test]
    fn prepare_is_atomic_and_same_hash_retry_is_idempotent() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x10; 16]);
        let events = [destructive_event(command, 0), destructive_event(command, 1)];

        let first = index
            .prepare_container_batch(batch_id, [0xA1; 32], &events)
            .unwrap();
        assert!(first.inserted);
        assert_eq!(first.state, ContainerBatchState::Prepared);
        assert_eq!(first.event_ids.len(), 2);

        let retry = index
            .prepare_container_batch(batch_id, [0xA1; 32], &events)
            .unwrap();
        assert!(!retry.inserted);
        assert_eq!(retry.event_ids, first.event_ids);
        assert_eq!(index.events_for_command(command).len(), 2);

        assert!(matches!(
            index.prepare_container_batch(batch_id, [0xB2; 32], &events),
            Err(IndexError::ContainerBatchConflict { .. })
        ));
        assert_eq!(index.events_for_command(command).len(), 2);
    }

    #[test]
    fn invalid_member_rolls_back_the_whole_prepare() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x20; 16]);
        let events = [destructive_event(command, 0), pull_event(command)];
        assert!(matches!(
            index.prepare_container_batch(batch_id, [0x20; 32], &events),
            Err(IndexError::InvalidContainerBatch { .. })
        ));

        let conn = index.conn().lock().unwrap();
        let batches: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM container_capture_batches",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let events: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!((batches, events), (0, 0));
    }

    #[test]
    fn confirmation_updates_column_and_payload_together() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x30; 16]);
        let events = [destructive_event(command, 0), destructive_event(command, 1)];
        let prepared = index
            .prepare_container_batch(batch_id, [0x30; 32], &events)
            .unwrap();

        assert_eq!(
            index.finalize_container_batch(batch_id, true).unwrap(),
            ContainerBatchState::Confirmed
        );
        assert_eq!(
            index.finalize_container_batch(batch_id, true).unwrap(),
            ContainerBatchState::Confirmed
        );

        let conn = index.conn().lock().unwrap();
        for id in prepared.event_ids {
            let (partial, payload): (i64, Vec<u8>) = conn
                .query_row(
                    "SELECT partial, payload FROM events WHERE id = ?1",
                    params![id.0 as i64],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let event: CaptureEvent = postcard::from_bytes(&payload).unwrap();
            assert_eq!(partial, 0);
            assert!(!event.partial);
        }
        drop(conn);
        assert!(
            index
                .events_for_command(command)
                .iter()
                .all(|event| !event.partial)
        );
    }

    #[test]
    fn runtime_finalization_is_durable_actionable_and_idempotent() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x35; 16]);
        let events = [destructive_event(command, 0)];
        index
            .prepare_container_batch(batch_id, [0x35; 32], &events)
            .unwrap();
        index.finalize_container_batch(batch_id, true).unwrap();

        assert_eq!(
            index
                .mark_container_batch_finalized(batch_id, 12_345)
                .unwrap(),
            ContainerBatchState::Finalized
        );
        let first = index.container_batch_info(batch_id).unwrap().unwrap();
        assert_eq!(first.state, ContainerBatchState::Finalized);
        assert_eq!(first.finalized_unix_secs, Some(12_345));
        assert!(
            index
                .events_for_command(command)
                .iter()
                .all(|event| !event.partial)
        );

        assert_eq!(
            index
                .mark_container_batch_finalized(batch_id, 99_999)
                .unwrap(),
            ContainerBatchState::Finalized
        );
        assert_eq!(
            index
                .container_batch_info(batch_id)
                .unwrap()
                .unwrap()
                .finalized_unix_secs,
            Some(12_345),
            "an idempotent retry must preserve the first durable finish time"
        );
        assert!(matches!(
            index.finalize_container_batch(batch_id, true),
            Err(IndexError::ContainerBatchConflict { .. })
        ));
        assert_eq!(
            index
                .prepare_container_batch(batch_id, [0x35; 32], &events)
                .unwrap()
                .state,
            ContainerBatchState::Finalized
        );
    }

    #[test]
    fn runtime_finalization_keeps_confirmed_when_stash_owner_disappeared() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x36; 16]);
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: TimePoint::new(10, 100),
            partial: true,
            kind: CaptureEventKind::ContainerOp {
                runtime: ContainerRuntime::Docker,
                op: ContainerOp::Rmi {
                    image: "missing:v1".into(),
                    digest: Some(format!("sha256:{}", "a".repeat(64))),
                },
                captured_config: Vec::new(),
                stash_image: None,
                stash_tarball: Some(shit_planner::BlobHash::from_bytes([0x36; 32])),
            },
        };
        index
            .prepare_container_batch(batch_id, [0x36; 32], &[event])
            .unwrap();
        index.finalize_container_batch(batch_id, true).unwrap();

        assert!(matches!(
            index.mark_container_batch_finalized(batch_id, 12_345),
            Err(IndexError::ContainerBatchIntegrity { .. })
        ));
        let info = index.container_batch_info(batch_id).unwrap().unwrap();
        assert_eq!(info.state, ContainerBatchState::Confirmed);
        assert_eq!(info.finalized_unix_secs, None);
    }

    #[test]
    fn refusal_is_terminal_and_leaves_members_partial() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x40; 16]);
        index
            .prepare_container_batch(batch_id, [0x40; 32], &[destructive_event(command, 0)])
            .unwrap();
        assert_eq!(
            index.finalize_container_batch(batch_id, false).unwrap(),
            ContainerBatchState::Refused
        );
        assert_eq!(
            index.finalize_container_batch(batch_id, false).unwrap(),
            ContainerBatchState::Refused
        );
        assert!(matches!(
            index.finalize_container_batch(batch_id, true),
            Err(IndexError::ContainerBatchConflict { .. })
        ));
        assert!(matches!(
            index.mark_container_batch_finalized(batch_id, 12_345),
            Err(IndexError::ContainerBatchConflict { .. })
        ));
        assert!(index.events_for_command(command)[0].partial);
    }

    #[test]
    fn prepared_batch_cannot_be_marked_runtime_finalized() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x45; 16]);
        index
            .prepare_container_batch(batch_id, [0x45; 32], &[destructive_event(command, 0)])
            .unwrap();
        assert!(matches!(
            index.mark_container_batch_finalized(batch_id, 12_345),
            Err(IndexError::ContainerBatchConflict { .. })
        ));
        assert_eq!(
            index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Prepared)
        );
    }

    #[test]
    fn command_close_preserves_inflight_prepared_batch_until_confirmation() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x50; 16]);
        index
            .prepare_container_batch(batch_id, [0x50; 32], &[destructive_event(command, 0)])
            .unwrap();

        assert!(
            index
                .finish_command(command, TimePoint::new(30, 300), 0)
                .unwrap()
        );
        assert_eq!(
            index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Prepared)
        );
        assert!(index.events_for_command(command)[0].partial);
        assert_eq!(index.drop_command(command).unwrap(), 0);
        assert_eq!(
            crate::refcount::reap_commands(&index, &[command])
                .unwrap()
                .commands_dropped,
            0
        );

        // A background wrapper's prepare request can finish after the shell
        // has emitted PostExec. The helper has not been authorized while this
        // batch is PREPARED; confirmation makes every member visible together
        // and only then permits the daemon to acknowledge the request.
        assert_eq!(
            index.finalize_container_batch(batch_id, true).unwrap(),
            ContainerBatchState::Confirmed
        );
        assert!(!index.events_for_command(command)[0].partial);
    }

    #[test]
    fn closed_command_rejects_new_prepare_without_writes() {
        let (_dir, index, command) = setup();
        assert!(
            index
                .finish_command(command, TimePoint::new(30, 300), 0)
                .unwrap()
        );
        let batch_id = Uuid::from_bytes([0x60; 16]);
        assert!(matches!(
            index.prepare_container_batch(batch_id, [0x60; 32], &[destructive_event(command, 0)]),
            Err(IndexError::CommandNotOpen { .. })
        ));
        assert_eq!(index.container_batch_state(batch_id).unwrap(), None);
    }

    #[test]
    fn legacy_destructive_event_without_confirmed_mapping_is_effectively_partial() {
        let (_dir, index, command) = setup();
        let mut destructive = destructive_event(command, 0);
        destructive.partial = false;
        index.put_event(&destructive).unwrap();
        index.put_event(&pull_event(command)).unwrap();

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 2);
        assert!(
            events[0].partial,
            "legacy destructive event must fail closed"
        );
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::ContainerOp {
                op: ContainerOp::NetworkRm { .. },
                ..
            }
        ));
        assert!(!events[1].partial, "non-destructive Pull remains exempt");
        assert!(matches!(
            events[1].kind,
            CaptureEventKind::ContainerOp {
                op: ContainerOp::Pull { .. },
                ..
            }
        ));
    }

    #[test]
    fn incomplete_confirmed_mapping_invalidates_the_whole_batch_on_read() {
        let (_dir, index, command) = setup();
        let batch_id = Uuid::from_bytes([0x70; 16]);
        let events = [destructive_event(command, 0), destructive_event(command, 1)];
        let prepared = index
            .prepare_container_batch(batch_id, [0x70; 32], &events)
            .unwrap();
        index.finalize_container_batch(batch_id, true).unwrap();
        assert!(
            index
                .events_for_command(command)
                .iter()
                .all(|event| !event.partial)
        );

        // Simulate index damage or a pre-v6 partial migration by dropping one
        // ordinal. The validity view must withdraw confirmation from every
        // remaining batch member, not just the missing row.
        index
            .conn()
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM container_capture_batch_events
                 WHERE batch_id = ?1 AND ordinal = 1",
                params![batch_id.as_bytes().as_slice()],
            )
            .unwrap();
        let read = index.events_for_command(command);
        assert_eq!(read.len(), 2);
        assert!(read.iter().all(|event| event.partial));
        assert!(matches!(
            index.container_batch_info(batch_id),
            Err(IndexError::ContainerBatchIntegrity { .. })
        ));
        assert_eq!(prepared.event_ids.len(), 2);
    }
}
