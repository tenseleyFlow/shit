// SPDX-License-Identifier: AGPL-3.0-or-later

//! Render the "Statements affected" section for `shit show` / `shit
//! undo` (S19.8).
//!
//! Pure stringifier — no terminal probing, no I/O. Takes a slice of
//! [`DbSuggestion`](shit_planner::executors::db::DbSuggestion) and
//! emits text the CLI prints alongside the rest of the change
//! summary.
//!
//! ## Redaction
//!
//! Statement text may carry secrets verbatim (e.g.
//! `INSERT INTO secrets VALUES ('hunter2')`). The renderer applies
//! the same env-style redaction marker. With
//! [`RedactionDisplay::HideEntirely`] redacted statements are
//! dropped from the listing; the default `NamesVisible` shows the
//! statement with the secret span replaced by `<redacted>`.
//!
//! ## Pagination cap
//!
//! `psql -f migrations.sql` may ship hundreds of statements. We
//! truncate at [`MAX_STATEMENTS_PRINTED`] and append a "+N more"
//! line so the section stays readable in a non-paged terminal.
//! `shit show --all-stmts` lifts the cap (CLI flag — wired with
//! the rest of the show subcommand polish later).

use std::fmt::Write;

use shit_planner::executors::db::DbSuggestion;
use shit_planner::inverse::{DbEngine, RollbackHint};

use crate::render::env_diff::RedactionDisplay;

const REDACTED_PREFIX: &str = "<redacted:";
const REDACTED_LABEL: &str = "<redacted>";

pub const MAX_STATEMENTS_PRINTED: usize = 20;

/// Render `Statements affected:` for a list of DB suggestions.
/// Returns an empty string when `suggestions` is empty.
pub fn render(suggestions: &[DbSuggestion], display: RedactionDisplay) -> String {
    if suggestions.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("Statements affected:\n");
    for s in suggestions {
        render_one(&mut out, s, display);
    }
    out
}

fn render_one(out: &mut String, s: &DbSuggestion, display: RedactionDisplay) {
    let _ = writeln!(out, "  engine: {} target: {}", s.engine.as_str(), s.target);
    let filtered = filter_statements(&s.statements, display);
    if filtered.is_empty() {
        let _ = writeln!(out, "    (no statements; engine redaction may have dropped them)");
    } else {
        let truncated = filtered.len() > MAX_STATEMENTS_PRINTED;
        let n = filtered.len().min(MAX_STATEMENTS_PRINTED);
        for stmt in filtered.iter().take(n) {
            let _ = writeln!(out, "    - {}", oneline(stmt));
        }
        if truncated {
            let _ = writeln!(
                out,
                "    + {} more (re-run with --all-stmts to see)",
                filtered.len() - n
            );
        }
    }
    render_hint(out, &s.engine, &s.hint);
}

fn render_hint(out: &mut String, engine: &DbEngine, hint: &RollbackHint) {
    match hint {
        RollbackHint::Sqlite { path, file_blob } => {
            let _ = writeln!(out, "    rollback: restore {}", path.display());
            if file_blob.is_none() {
                let _ = writeln!(
                    out,
                    "      (no file-tier blob captured; manual restore from your own backup)"
                );
            }
        }
        RollbackHint::Postgres {
            pitr_recommended,
            wal_position,
            ..
        } => {
            let _ = writeln!(out, "    rollback: review statements; no auto-apply");
            if *pitr_recommended {
                if let Some(pos) = wal_position {
                    let _ = writeln!(
                        out,
                        "      PITR target: WAL position {pos} (use pg_basebackup + WAL replay)"
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "      PITR recommended; WAL position not captured (DR-56)"
                    );
                }
            }
        }
        RollbackHint::Mysql {
            binlog_position, ..
        } => {
            let _ = writeln!(out, "    rollback: review statements; no auto-apply");
            if let Some(pos) = binlog_position {
                let _ = writeln!(
                    out,
                    "      binlog rewind: mysqlbinlog --stop-position={pos} ... (manual)"
                );
            } else {
                let _ = writeln!(
                    out,
                    "      no binlog position captured ({}); manual review only",
                    engine.as_str()
                );
            }
        }
        RollbackHint::None => {
            let _ = writeln!(
                out,
                "    rollback: no actionable hint; review statements manually"
            );
        }
    }
}

/// Apply redaction to a statement list. The marker shape is
/// `<redacted:HHHHHHHH>` like other tiers. We don't try to parse
/// SQL — the capture pipeline should have inserted markers in
/// place of secret values before journaling. If a statement
/// contains the marker, the whole statement renders with `<redacted>`
/// substituted for the marker.
fn filter_statements(statements: &[String], display: RedactionDisplay) -> Vec<String> {
    let mut out = Vec::with_capacity(statements.len());
    for s in statements {
        if has_redacted_marker(s) {
            match display {
                RedactionDisplay::HideEntirely => continue,
                RedactionDisplay::NamesVisible => out.push(mask_redacted_markers(s)),
            }
        } else {
            out.push(s.clone());
        }
    }
    out
}

fn has_redacted_marker(s: &str) -> bool {
    s.contains(REDACTED_PREFIX)
}

/// Replace `<redacted:HHHHHHHH>` spans with the bare `<redacted>`
/// label so the capture-time hash never reaches the terminal.
fn mask_redacted_markers(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(REDACTED_PREFIX) {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        if let Some(end) = after.find('>') {
            out.push_str(REDACTED_LABEL);
            rest = &after[end + 1..];
        } else {
            // Malformed marker (no closing `>`): emit label and stop.
            out.push_str(REDACTED_LABEL);
            return out;
        }
    }
    out.push_str(rest);
    out
}

/// Collapse a multi-line statement onto one line for the bullet
/// listing. Useful for `psql -c "INSERT INTO t \n VALUES (1)"`.
fn oneline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sug(engine: DbEngine, target: &str, statements: &[&str], hint: RollbackHint) -> DbSuggestion {
        DbSuggestion {
            engine,
            target: target.into(),
            statements: statements.iter().map(|s| (*s).to_string()).collect(),
            hint,
        }
    }

    #[test]
    fn empty_input_yields_empty_string() {
        assert!(render(&[], RedactionDisplay::default()).is_empty());
    }

    #[test]
    fn postgres_suggestion_lists_engine_target_and_stmts() {
        let s = sug(
            DbEngine::Postgres,
            "prod",
            &["INSERT INTO t VALUES (1)", "UPDATE t SET x = 2"],
            RollbackHint::Postgres {
                pitr_recommended: true,
                wal_position: Some("0/1A2B3C".into()),
                statements_for_review: vec![],
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.starts_with("Statements affected:\n"));
        assert!(out.contains("engine: psql"));
        assert!(out.contains("target: prod"));
        assert!(out.contains("- INSERT INTO t VALUES (1)"));
        assert!(out.contains("- UPDATE t SET x = 2"));
        assert!(out.contains("WAL position 0/1A2B3C"));
    }

    #[test]
    fn mysql_renders_binlog_rewind_or_no_position() {
        let s = sug(
            DbEngine::Mysql,
            "prod",
            &["DELETE FROM t"],
            RollbackHint::Mysql {
                binlog_position: Some("mysql-bin.000001:12345".into()),
                statements_for_review: vec![],
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("mysqlbinlog --stop-position=mysql-bin.000001:12345"));

        let s = sug(
            DbEngine::Mysql,
            "prod",
            &["DELETE FROM t"],
            RollbackHint::Mysql {
                binlog_position: None,
                statements_for_review: vec![],
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("no binlog position captured"));
    }

    #[test]
    fn sqlite_renders_restore_with_path() {
        let s = sug(
            DbEngine::Sqlite3,
            "/tmp/test.db",
            &["CREATE TABLE t (id INT)"],
            RollbackHint::Sqlite {
                path: PathBuf::from("/tmp/test.db"),
                file_blob: Some(shit_planner::inode::BlobHash::from_bytes([7; 32])),
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("rollback: restore /tmp/test.db"));
        assert!(!out.contains("no file-tier blob captured"));
    }

    #[test]
    fn sqlite_without_blob_calls_out_manual_restore() {
        let s = sug(
            DbEngine::Sqlite3,
            "/tmp/test.db",
            &["UPDATE t SET x = 1"],
            RollbackHint::Sqlite {
                path: PathBuf::from("/tmp/test.db"),
                file_blob: None,
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("no file-tier blob captured"));
    }

    #[test]
    fn redaction_marker_masked_by_default() {
        let s = sug(
            DbEngine::Postgres,
            "prod",
            &["INSERT INTO secrets VALUES ('<redacted:deadbeef>')"],
            RollbackHint::None,
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("<redacted>"));
        assert!(!out.contains("deadbeef"));
    }

    #[test]
    fn redaction_marker_dropped_with_hide_entirely() {
        let s = sug(
            DbEngine::Postgres,
            "prod",
            &[
                "INSERT INTO secrets VALUES ('<redacted:cafe>')",
                "UPDATE t SET x = 2",
            ],
            RollbackHint::None,
        );
        let out = render(&[s], RedactionDisplay::HideEntirely);
        assert!(!out.contains("secrets"));
        assert!(!out.contains("cafe"));
        assert!(out.contains("UPDATE t SET x = 2"));
    }

    #[test]
    fn empty_statements_after_redaction_calls_out() {
        // Single statement, fully redacted, with HideEntirely.
        let s = sug(
            DbEngine::Postgres,
            "prod",
            &["INSERT INTO secrets VALUES ('<redacted:cafe>')"],
            RollbackHint::None,
        );
        let out = render(&[s], RedactionDisplay::HideEntirely);
        assert!(out.contains("(no statements"));
    }

    #[test]
    fn truncates_long_statement_lists() {
        let stmts: Vec<String> = (0..MAX_STATEMENTS_PRINTED + 5)
            .map(|i| format!("UPDATE t SET x = {i}"))
            .collect();
        let stmts_ref: Vec<&str> = stmts.iter().map(String::as_str).collect();
        let s = sug(DbEngine::Postgres, "prod", &stmts_ref, RollbackHint::None);
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("+ 5 more"));
        // Verify it stopped at the cap.
        let bullet_count = out.lines().filter(|l| l.trim_start().starts_with("- ")).count();
        assert_eq!(bullet_count, MAX_STATEMENTS_PRINTED);
    }

    #[test]
    fn multiline_statement_oneliner_normalizes_whitespace() {
        let s = sug(
            DbEngine::Postgres,
            "prod",
            &["INSERT INTO t\n  VALUES\n  (1)"],
            RollbackHint::None,
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("- INSERT INTO t VALUES (1)"));
    }

    #[test]
    fn rollback_hint_none_says_no_actionable() {
        let s = sug(DbEngine::Postgres, "prod", &["INSERT INTO t VALUES (1)"], RollbackHint::None);
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("no actionable hint"));
    }

    #[test]
    fn multiple_suggestions_each_get_a_block() {
        let a = sug(DbEngine::Postgres, "prod", &["INSERT INTO t VALUES (1)"], RollbackHint::None);
        let b = sug(DbEngine::Mysql, "stage", &["UPDATE t SET x = 1"], RollbackHint::None);
        let out = render(&[a, b], RedactionDisplay::default());
        let engine_lines = out.lines().filter(|l| l.contains("engine:")).count();
        assert_eq!(engine_lines, 2);
    }

    #[test]
    fn malformed_redaction_marker_is_safely_masked() {
        let s = sug(
            DbEngine::Postgres,
            "prod",
            &["INSERT INTO t VALUES ('<redacted:no-close"],
            RollbackHint::None,
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("<redacted>"));
        assert!(!out.contains("no-close"));
    }
}
