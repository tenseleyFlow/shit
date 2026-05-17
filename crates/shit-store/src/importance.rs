// SPDX-License-Identifier: AGPL-3.0-or-later

//! Baseline importance scoring for captured commands (S13.4).
//!
//! Importance is a `u8` (0..=255) the daemon writes to
//! `commands.importance` when a command finishes. GC's mark-expired
//! pass orders by `(importance ASC, started_logical ASC)`, so
//! lower-importance commands are evicted first.
//!
//! ## Scoring inputs
//!
//! The sprint plan calls for three baseline signals:
//!
//! 1. **File count.** Commands that touched > `threshold` files get
//!    bumped — they likely represent meaningful work (a build, a
//!    refactor) the user may want to undo.
//! 2. **Sensitive paths.** Commands touching `/etc/`, `~/.ssh/`,
//!    `~/.gnupg/`, `~/Library/Keychains/` get bumped. Mis-applied
//!    changes to those paths are the highest-stakes things to be
//!    able to undo.
//! 3. **Was-undone bump.** Commands the user successfully ran
//!    `shit undo` on get bumped — they were useful once, the user
//!    may want them around. The daemon detects this by the presence
//!    of an exec-log entry referencing the command.
//!
//! ## Where this runs
//!
//! The daemon calls `score_command` once at command finalization
//! (postexec) and writes the result into `commands.importance`.
//! Re-scoring happens implicitly via `bump_for_undo` when an undo
//! is applied.

use std::path::Path;

use rusqlite::params;
use shit_planner::CommandId;

use crate::index::{Index, IndexError};

/// Tuning knobs. Defaults track the sprint plan's defaults.
#[derive(Debug, Clone)]
pub struct ImportanceConfig {
    /// Threshold above which the file-count bump applies.
    pub file_count_threshold: usize,
    /// Score bump per signal — additive, saturating at u8::MAX.
    pub bump_per_signal: u8,
    /// Paths that trigger the sensitive-path bump. Match by prefix.
    pub sensitive_path_prefixes: Vec<String>,
}

impl Default for ImportanceConfig {
    fn default() -> Self {
        Self {
            file_count_threshold: 10,
            bump_per_signal: 20,
            sensitive_path_prefixes: vec![
                "/etc/".to_string(),
                "~/.ssh/".to_string(),
                "~/.gnupg/".to_string(),
                "~/Library/Keychains/".to_string(),
            ],
        }
    }
}

/// Input view of a command for scoring. The daemon constructs this
/// from its in-memory command-window state at postexec time.
#[derive(Debug, Clone)]
pub struct ScoreInputs<'a> {
    pub file_count: usize,
    pub touched_paths: &'a [&'a Path],
}

/// Compute the baseline importance for a freshly-finalized command.
/// Returns a `u8` clamped to `[0, 255]`.
pub fn score_command(inputs: &ScoreInputs<'_>, config: &ImportanceConfig) -> u8 {
    let mut score: u32 = 0;
    if inputs.file_count >= config.file_count_threshold {
        score = score.saturating_add(config.bump_per_signal as u32);
    }
    if inputs
        .touched_paths
        .iter()
        .any(|p| path_is_sensitive(p, &config.sensitive_path_prefixes))
    {
        score = score.saturating_add(config.bump_per_signal as u32);
    }
    score.min(u8::MAX as u32) as u8
}

/// True when `path` starts with any of the configured prefixes.
fn path_is_sensitive(path: &Path, prefixes: &[String]) -> bool {
    let s = path.to_string_lossy();
    prefixes.iter().any(|prefix| s.starts_with(prefix.as_str()))
}

/// Bump a command's importance after a successful `shit undo`. Uses
/// saturating arithmetic — repeated undos can't overflow u8.
pub fn bump_for_undo(index: &Index, id: CommandId, bump: u8) -> Result<(), IndexError> {
    let conn = index.conn().lock().unwrap();
    conn.execute(
        "UPDATE commands
         SET importance = MIN(importance + ?1, 255)
         WHERE session = ?2 AND seq = ?3",
        params![bump as i64, id.session.as_bytes().as_slice(), id.seq as i64],
    )?;
    Ok(())
}

/// Write the computed importance into a row that already exists.
/// Caller has typically just inserted the command and now scored it.
pub fn set_importance(index: &Index, id: CommandId, importance: u8) -> Result<(), IndexError> {
    let conn = index.conn().lock().unwrap();
    conn.execute(
        "UPDATE commands SET importance = ?1
         WHERE session = ?2 AND seq = ?3",
        params![
            importance as i64,
            id.session.as_bytes().as_slice(),
            id.seq as i64
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn no_signals_score_zero() {
        let cfg = ImportanceConfig::default();
        let inputs = ScoreInputs {
            file_count: 1,
            touched_paths: &[],
        };
        assert_eq!(score_command(&inputs, &cfg), 0);
    }

    #[test]
    fn many_files_bumps_score() {
        let cfg = ImportanceConfig::default();
        let inputs = ScoreInputs {
            file_count: 50,
            touched_paths: &[],
        };
        assert_eq!(score_command(&inputs, &cfg), cfg.bump_per_signal);
    }

    #[test]
    fn sensitive_path_bumps_score() {
        let cfg = ImportanceConfig::default();
        let p = PathBuf::from("/etc/passwd");
        let touched = [p.as_path()];
        let inputs = ScoreInputs {
            file_count: 1,
            touched_paths: &touched,
        };
        assert_eq!(score_command(&inputs, &cfg), cfg.bump_per_signal);
    }

    #[test]
    fn both_signals_stack() {
        let cfg = ImportanceConfig::default();
        let p = PathBuf::from("/etc/x");
        let touched = [p.as_path()];
        let inputs = ScoreInputs {
            file_count: 50,
            touched_paths: &touched,
        };
        assert_eq!(score_command(&inputs, &cfg), cfg.bump_per_signal * 2);
    }

    #[test]
    fn score_caps_at_u8_max() {
        let cfg = ImportanceConfig {
            bump_per_signal: 200,
            ..ImportanceConfig::default()
        };
        let p = PathBuf::from("/etc/x");
        let touched = [p.as_path()];
        let inputs = ScoreInputs {
            file_count: 50,
            touched_paths: &touched,
        };
        // Two signals × 200 = 400, capped at 255.
        assert_eq!(score_command(&inputs, &cfg), 255);
    }

    #[test]
    fn bump_for_undo_is_saturating() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path().join("test.db")).unwrap();
        let session = Uuid::now_v7();
        let id = CommandId { session, seq: 0 };
        {
            let conn = idx.conn().lock().unwrap();
            conn.execute(
                "INSERT INTO commands
                 (session, seq, cmd_string, cwd, pid, shell_kind,
                  started_logical, started_wall_nanos, importance)
                 VALUES (?1, 0, 'x', '/tmp', 1, 'bash', 0, 0, 250)",
                params![session.as_bytes().as_slice()],
            )
            .unwrap();
        }
        bump_for_undo(&idx, id, 50).unwrap();
        let conn = idx.conn().lock().unwrap();
        let v: i64 = conn
            .query_row(
                "SELECT importance FROM commands WHERE session = ?1 AND seq = 0",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, 255, "saturating add should cap at 255");
    }
}
