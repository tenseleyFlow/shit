-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Blob leases protect command baselines between durable capture and event
-- publication.  A lease is deliberately not part of blobs.refcount: it is a
-- short-lived GC exclusion owned by one open command.  Publishing an event
-- for the same (blob, command) consumes it; successfully finishing the
-- command clears any remainder.

CREATE TABLE blob_leases (
    hash                BLOB NOT NULL,
    session             BLOB NOT NULL,
    seq                 INTEGER NOT NULL,
    created_logical     INTEGER NOT NULL,
    PRIMARY KEY (hash, session, seq),
    FOREIGN KEY (hash) REFERENCES blobs(hash),
    FOREIGN KEY (session, seq) REFERENCES commands(session, seq) ON DELETE CASCADE
);

CREATE INDEX idx_blob_leases_command
    ON blob_leases(session, seq);

INSERT INTO schema_version (version) VALUES (5);
