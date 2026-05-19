-- SPDX-License-Identifier: AGPL-3.0-or-later
-- C01.4 — large-object chunk index + holds + bookmarks.
--
-- Three additions:
--
--   1. `large_objects` + `chunks` carry the .caibx-style chunk index for
--      pre-images over the large-object threshold (default 64 MiB).
--      Materialization is deferred: a row in `large_objects` with
--      materialized=0 means the chunk *index* is durable but the chunk
--      *bytes* may not yet be in the blob store. `BlobStore::open()`
--      lazily fetches missing chunks on read, or eagerly on GC pressure.
--
--   2. `holds` are programmatic short-lived per-pid pins on commands.
--      Distinct from `pins` (added in 0001-init), which is the user-facing
--      named-savepoint table: pins persist across daemon restarts and are
--      named; holds are pid-scoped and intended for agents that want to
--      keep an event alive while they process it. Both protect from GC.
--
--   3. `bookmarks` are metadata-only durable references that survive
--      blob-tier GC AND the eventual reaping of the corresponding
--      `commands` row. Deliberately *no* foreign key to `commands` so
--      the row outlives its referent.

CREATE TABLE large_objects (
    blob_hash           BLOB PRIMARY KEY,
    total_size          INTEGER NOT NULL,
    chunk_count         INTEGER NOT NULL,
    materialized        INTEGER NOT NULL DEFAULT 0,        -- 0 = chunk bytes deferred; 1 = all chunks present
    created_logical     INTEGER NOT NULL,
    FOREIGN KEY (blob_hash) REFERENCES blobs(hash)
);

CREATE INDEX idx_large_objects_unmaterialized
    ON large_objects(blob_hash) WHERE materialized = 0;

CREATE TABLE chunks (
    blob_hash           BLOB NOT NULL,
    idx                 INTEGER NOT NULL,                  -- 0-based chunk index within the parent blob
    offset              INTEGER NOT NULL,                  -- byte offset within the parent blob
    length              INTEGER NOT NULL,
    hash                BLOB NOT NULL,                     -- 32-byte blake3 of the chunk's content
    materialized        INTEGER NOT NULL DEFAULT 0,        -- 0 = bytes not yet in store; 1 = in store
    PRIMARY KEY (blob_hash, idx),
    FOREIGN KEY (blob_hash) REFERENCES large_objects(blob_hash)
);

-- Lookups: "find the chunk by content hash" for dedup-on-materialize.
CREATE INDEX idx_chunks_hash ON chunks(hash);

CREATE TABLE holds (
    session             BLOB NOT NULL,
    seq                 INTEGER NOT NULL,
    owner_pid           INTEGER NOT NULL,
    owner_user          TEXT NOT NULL,
    taken_logical       INTEGER NOT NULL,
    expires_logical     INTEGER,                           -- NULL = no expiry; otherwise reaped when current_logical >= this
    note                TEXT,
    PRIMARY KEY (session, seq, owner_pid),
    FOREIGN KEY (session, seq) REFERENCES commands(session, seq)
);

-- Sweep-expired: WHERE expires_logical IS NOT NULL AND expires_logical < ?
CREATE INDEX idx_holds_expires
    ON holds(expires_logical) WHERE expires_logical IS NOT NULL;

-- List-active-by-user: shit pins.
CREATE INDEX idx_holds_owner_user ON holds(owner_user);

-- Bookmarks deliberately have no FK to commands; the row survives reaping.
CREATE TABLE bookmarks (
    session             BLOB NOT NULL,
    seq                 INTEGER NOT NULL,
    created_logical     INTEGER NOT NULL,
    note                TEXT,
    PRIMARY KEY (session, seq)
);

INSERT INTO schema_version (version) VALUES (3);
