-- SPDX-License-Identifier: AGPL-3.0-or-later
-- C04.6 — container-runtime stash store.
--
-- A separate retention store for `docker save` image tarballs,
-- `docker volume rm` volume tarballs, and (informational) the
-- captured-rootfs `shit-stash:<id>:<ts>` image tags from the
-- `docker rm -f` capture path. Container stashes are LARGE
-- (image tarballs run 100 MiB to several GiB) and short-lived; we
-- intentionally do NOT mix them into the long-retention blob store.
--
-- Default retention: 1 day (configurable; see
-- `daemon::container_stash::CONTAINER_STASH_RETENTION_SECS`). The S13
-- GC pass walks `container_stashes` independently from the file-tier
-- refcount-driven reap.
--
-- Each row is content-addressed by blake3 of the tarball bytes. The
-- bytes themselves live OUTSIDE this index: they're shipped through
-- the existing BlobStore (with their own short-retention policy
-- applied at the GC layer). The `blob_hash` column is the lookup key
-- back into BlobStore; the rest of this row is the metadata needed to
-- enumerate, surface, and prune.

CREATE TABLE container_stashes (
    blob_hash           BLOB PRIMARY KEY,                  -- 32-byte blake3 of the tarball
    kind                INTEGER NOT NULL,                  -- 0 = image-save, 1 = volume-tar
    runtime             TEXT NOT NULL,                     -- "docker" | "podman"
    name                TEXT NOT NULL,                     -- image name (e.g. "nginx:1.25") or volume name
    size_bytes          INTEGER NOT NULL,
    created_unix_secs   INTEGER NOT NULL,                  -- wall-clock; the prune is time-based, not logical-clock
    -- Linking back to a command is best-effort. NULLable because the
    -- daemon may register a stash before the command-window closes
    -- (e.g. capture-time inserts during the rm flow itself).
    session             BLOB,
    seq                 INTEGER,
    note                TEXT
);

-- Prune-by-age: WHERE created_unix_secs < (now - retention).
CREATE INDEX idx_container_stashes_created_unix
    ON container_stashes(created_unix_secs);

-- List by command for `shit show <cmd>`: WHERE session = ? AND seq = ?.
CREATE INDEX idx_container_stashes_command
    ON container_stashes(session, seq) WHERE session IS NOT NULL;

INSERT INTO schema_version (version) VALUES (4);
