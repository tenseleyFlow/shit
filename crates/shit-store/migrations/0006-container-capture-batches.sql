-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Durable container capture lifecycle:
-- PREPARED -> CONFIRMED -> FINALIZED, or PREPARED -> REFUSED.
--
-- A destructive runtime invocation is journaled as one atomic batch. The
-- schema can hold multiple members even when an initial policy admits only a
-- single target, avoiding a future on-disk migration to strengthen coverage.
-- Every member event is inserted partial. The daemon validates the complete
-- capture set and all physical blob evidence, then confirms the batch before
-- acknowledging the wrapper and authorizing the real runtime. Post-operation
-- observations are telemetry and never revoke a confirmed inverse.
-- CONFIRMED/REFUSED are pre-runtime protocol decisions. Only FINALIZED proves
-- that the wrapper observed a runtime outcome and durably closed the lifecycle.

-- v4/v5 databases need a durable per-stash age origin that survives command
-- collection (and the resulting batch-row cascade). Runtime finalization moves
-- this origin forward transactionally. Reused content hashes retain the
-- greatest capture/finalization time across every owner.
ALTER TABLE container_stashes
    ADD COLUMN retain_from_unix_secs INTEGER NOT NULL DEFAULT 0
        CHECK (retain_from_unix_secs >= 0);

UPDATE container_stashes
SET retain_from_unix_secs = MAX(created_unix_secs, 0);

CREATE INDEX idx_container_stashes_retain_from
    ON container_stashes(retain_from_unix_secs);

CREATE TABLE container_capture_batches (
    batch_id            BLOB PRIMARY KEY CHECK (length(batch_id) = 16),
    session             BLOB NOT NULL CHECK (length(session) = 16),
    seq                 INTEGER NOT NULL CHECK (seq >= 0),
    request_hash        BLOB NOT NULL CHECK (length(request_hash) = 32),
    event_count         INTEGER NOT NULL CHECK (event_count BETWEEN 1 AND 256),
    state               TEXT NOT NULL DEFAULT 'PREPARED'
                            CHECK (state IN ('PREPARED', 'CONFIRMED', 'REFUSED', 'FINALIZED')),
    finalized_unix_secs INTEGER CHECK (finalized_unix_secs >= 0),
    UNIQUE (batch_id, session, seq),
    FOREIGN KEY (session, seq) REFERENCES commands(session, seq) ON DELETE CASCADE,
    CHECK (
        (state = 'FINALIZED' AND finalized_unix_secs IS NOT NULL)
        OR (state != 'FINALIZED' AND finalized_unix_secs IS NULL)
    )
);

CREATE INDEX idx_container_capture_batches_command_state
    ON container_capture_batches(session, seq, state);

CREATE TABLE container_capture_batch_events (
    batch_id            BLOB NOT NULL,
    session             BLOB NOT NULL CHECK (length(session) = 16),
    seq                 INTEGER NOT NULL CHECK (seq >= 0),
    ordinal             INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 255),
    event_id            INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (batch_id, ordinal),
    FOREIGN KEY (batch_id, session, seq)
        REFERENCES container_capture_batches(batch_id, session, seq) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE INDEX idx_container_capture_batch_events_event
    ON container_capture_batch_events(event_id);

-- Mapping rows are only valid when the ordinal is within this batch and the
-- event is a ContainerOp owned by the same command. Keeping these checks in
-- SQLite protects future call sites as well as the current Rust transaction.
CREATE TRIGGER container_capture_batch_event_validate_insert
BEFORE INSERT ON container_capture_batch_events
BEGIN
    SELECT CASE WHEN (
        SELECT state FROM container_capture_batches WHERE batch_id = NEW.batch_id
    ) != 'PREPARED' THEN RAISE(ABORT, 'container batch membership is terminal') END;

    SELECT CASE WHEN NEW.ordinal >= (
        SELECT event_count FROM container_capture_batches WHERE batch_id = NEW.batch_id
    ) THEN RAISE(ABORT, 'container batch ordinal out of range') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM events e
        WHERE e.id = NEW.event_id
          AND e.session = NEW.session
          AND e.seq = NEW.seq
          AND e.discriminant = 'ContainerOp'
    ) THEN RAISE(ABORT, 'container batch event does not match command') END;
END;

CREATE TRIGGER container_capture_batch_event_immutable
BEFORE UPDATE ON container_capture_batch_events
BEGIN
    SELECT RAISE(ABORT, 'container batch membership is immutable');
END;

-- Batch membership and identity are immutable. Lifecycle state and the
-- finalization timestamp move only through the transitions below.
CREATE TRIGGER container_capture_batch_identity_immutable
BEFORE UPDATE OF batch_id, session, seq, request_hash, event_count
ON container_capture_batches
BEGIN
    SELECT RAISE(ABORT, 'container batch identity is immutable');
END;

CREATE TRIGGER container_capture_batch_state_transition
BEFORE UPDATE OF state, finalized_unix_secs ON container_capture_batches
WHEN NOT (
    (NEW.state = OLD.state
        AND NEW.finalized_unix_secs IS OLD.finalized_unix_secs)
    OR (OLD.state = 'PREPARED'
        AND NEW.state IN ('CONFIRMED', 'REFUSED')
        AND NEW.finalized_unix_secs IS NULL)
    OR (OLD.state = 'CONFIRMED'
        AND NEW.state = 'FINALIZED'
        AND OLD.finalized_unix_secs IS NULL
        AND NEW.finalized_unix_secs IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid container batch state transition');
END;

-- Read paths join this view rather than trusting `state = CONFIRMED` alone.
-- A missing mapping, a gap in ordinals, a cross-command event, or a still-
-- partial SQL row invalidates the entire batch and makes every destructive
-- event in it effectively partial.
CREATE VIEW confirmed_container_capture_events AS
SELECT m.event_id
FROM container_capture_batches b
JOIN container_capture_batch_events m ON m.batch_id = b.batch_id
WHERE b.state IN ('CONFIRMED', 'FINALIZED')
  AND b.event_count = (
      SELECT COUNT(*)
      FROM container_capture_batch_events count_m
      WHERE count_m.batch_id = b.batch_id
  )
  AND 0 = (
      SELECT MIN(min_m.ordinal)
      FROM container_capture_batch_events min_m
      WHERE min_m.batch_id = b.batch_id
  )
  AND b.event_count - 1 = (
      SELECT MAX(max_m.ordinal)
      FROM container_capture_batch_events max_m
      WHERE max_m.batch_id = b.batch_id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM container_capture_batch_events check_m
      LEFT JOIN events e ON e.id = check_m.event_id
      WHERE check_m.batch_id = b.batch_id
        AND (
            e.id IS NULL
            OR e.session != b.session
            OR e.seq != b.seq
            OR e.discriminant != 'ContainerOp'
            OR e.partial != 0
        )
  );

INSERT INTO schema_version (version) VALUES (6);
