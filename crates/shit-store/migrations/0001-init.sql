-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Initial schema for `shit-store`.

CREATE TABLE schema_version (
    version INTEGER NOT NULL PRIMARY KEY
);

INSERT INTO schema_version (version) VALUES (1);

-- One row per shell session.
CREATE TABLE sessions (
    id                  BLOB PRIMARY KEY,     -- 16-byte UUID
    shell_kind          TEXT NOT NULL,
    parent_pid          INTEGER NOT NULL,
    tty                 TEXT,
    opened_logical      INTEGER NOT NULL,
    opened_wall_nanos   INTEGER NOT NULL,
    closed_logical      INTEGER,
    closed_wall_nanos   INTEGER
);

-- One row per command. Compound primary key matches CommandId.
CREATE TABLE commands (
    session             BLOB NOT NULL,
    seq                 INTEGER NOT NULL,
    cmd_string          TEXT,
    cwd                 TEXT NOT NULL,
    pid                 INTEGER NOT NULL,
    shell_kind          TEXT NOT NULL,
    started_logical     INTEGER NOT NULL,
    started_wall_nanos  INTEGER NOT NULL,
    ended_logical       INTEGER,
    ended_wall_nanos    INTEGER,
    exit_code           INTEGER,
    PRIMARY KEY (session, seq)
);

-- One row per CaptureEvent. `payload` holds the postcard-encoded
-- CaptureEvent in full; denormalized columns (dev/inode/path/blob_hash/
-- post_content_hash) accelerate the common index lookups without forcing
-- the planner to scan-and-decode every event.
CREATE TABLE events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session             BLOB NOT NULL,
    seq                 INTEGER NOT NULL,
    ts_logical          INTEGER NOT NULL,
    ts_wall_nanos       INTEGER NOT NULL,
    partial             INTEGER NOT NULL,         -- 0 / 1
    discriminant        TEXT NOT NULL,            -- 'FilePreImage', 'TreeOp', 'EnvDiff', etc.
    dev                 INTEGER,
    inode               INTEGER,
    path                TEXT,
    blob_hash           BLOB,                     -- 32-byte blake3
    post_content_hash   BLOB,                     -- 32-byte blake3, nullable
    payload             BLOB NOT NULL,
    FOREIGN KEY (session, seq) REFERENCES commands(session, seq)
);

CREATE INDEX idx_events_command         ON events(session, seq, ts_logical);
CREATE INDEX idx_events_inode_time      ON events(dev, inode, ts_logical) WHERE dev IS NOT NULL;
CREATE INDEX idx_events_path_time       ON events(path, ts_logical) WHERE path IS NOT NULL;
CREATE INDEX idx_events_blob            ON events(blob_hash) WHERE blob_hash IS NOT NULL;

-- One row per distinct blob. `refcount` mirrors the number of `events`
-- rows that reference this blob (via FilePreImage `blob_hash`). GC
-- (S13) sweeps when refcount reaches zero.
CREATE TABLE blobs (
    hash                BLOB PRIMARY KEY,         -- 32-byte blake3
    size                INTEGER NOT NULL,
    compressed          INTEGER NOT NULL,         -- 0 / 1
    refcount            INTEGER NOT NULL DEFAULT 0,
    created_logical     INTEGER NOT NULL
);

CREATE INDEX idx_blobs_refcount         ON blobs(refcount) WHERE refcount = 0;

-- Path-history: ranges of logical time during which a (path) referred
-- to a (dev, inode). Updated by tree-op events. `valid_to_logical = NULL`
-- means "still valid". Used by `events_touching_path` to resolve backward
-- through renames.
CREATE TABLE paths (
    path                TEXT NOT NULL,
    dev                 INTEGER NOT NULL,
    inode               INTEGER NOT NULL,
    valid_from_logical  INTEGER NOT NULL,
    valid_to_logical    INTEGER,
    PRIMARY KEY (path, valid_from_logical)
);

CREATE INDEX idx_paths_inode            ON paths(dev, inode);
CREATE INDEX idx_paths_active           ON paths(path) WHERE valid_to_logical IS NULL;

-- Named savepoints. Pinned commands and (transitively) their blobs are
-- protected from GC.
CREATE TABLE pins (
    session             BLOB NOT NULL,
    seq                 INTEGER NOT NULL,
    name                TEXT,
    pinned_logical      INTEGER NOT NULL,
    expires_logical     INTEGER,
    PRIMARY KEY (session, seq)
);
