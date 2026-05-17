-- SPDX-License-Identifier: AGPL-3.0-or-later
-- S13.1 — Importance scoring + GC-friendly indexes.
--
-- `commands.importance` is a u8 (0..=255) computed by the daemon when
-- a command finishes. GC's mark-expired phase uses it as a tiebreak
-- when otherwise eligible commands compete for retention slots: lower
-- importance is dropped first. Default 0 means "no special status."

ALTER TABLE commands ADD COLUMN importance INTEGER NOT NULL DEFAULT 0;

-- Index supports two scan patterns:
--   1. "Find expired commands oldest first, then by-importance asc"
--      — the mark-expired pass. The covering order matches the WHERE
--      / ORDER BY of `gc::mark_expired`.
--   2. "Find low-importance commands first" during aggressive mode,
--      where age_cap is bypassed.
CREATE INDEX idx_commands_age_importance
    ON commands (started_logical, importance);

INSERT INTO schema_version (version) VALUES (2);
