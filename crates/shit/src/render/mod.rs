// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]

//! Output formatting infrastructure (S12.2).
//!
//! Subcommands write their human-readable output through this module
//! so behavior is consistent: TTY detection, color resolution,
//! JSON-vs-text dispatch, optional paging.
//!
//! ## Why no top-level `--json` / `--color`
//!
//! The bare-`shit`-is-`shit undo` rule (see memory
//! `shit-cli-undo-default`) means the top-level `Cli` accepts no
//! flags. Each subcommand that needs formatting flags carries its
//! own `--json` / `--color` — same code path, just no risk of
//! `shit --json` parsing as a top-level arg that disturbs the
//! bare-`shit` semantics.

pub mod color;
pub mod db;
pub mod env_diff;
pub mod git;
pub mod json;
pub mod pager;
pub mod process;

#[allow(unused_imports)]
pub use color::{ColorPref, resolve_color};
#[allow(unused_imports)]
pub use db::render as render_db;
#[allow(unused_imports)]
pub use env_diff::{RedactionDisplay, render as render_env_diff};
#[allow(unused_imports)]
pub use git::{BlobByPath, GitRestoreGroup, detect_git_restores, detect_git_restores_enriched};
#[allow(unused_imports)]
pub use json::{JsonError, write_json};
#[allow(unused_imports)]
pub use pager::page_if_tty;
#[allow(unused_imports)]
pub use process::render as render_process;

#[cfg(test)]
mod redaction_uniformity_tests {
    //! S20.6 — cross-tier redaction-uniformity audit tests.
    //!
    //! Every renderer that takes a `<redacted:HASH>` marker MUST mask
    //! the marker before display. The threat model (TC-7) treats this
    //! as a release-blocker property. If a future change introduces a
    //! path that doesn't redact, these tests catch it.
    //!
    //! The tracer pattern: plant a unique sentinel
    //! `<redacted:S20-TRACER-DEADBEEF>` into every renderer's input
    //! and grep the output. The sentinel hash MUST NOT appear.

    use super::env_diff::{RedactionDisplay, render as env_render};
    use super::{db::render as db_render, process::render as proc_render};
    use shit_planner::EnvDiff;
    use shit_planner::executors::db::DbSuggestion;
    use shit_planner::executors::process::{RestartHint, RestartSuggestion};
    use shit_planner::inverse::{DbEngine, RollbackHint};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const TRACER_MARKER: &str = "<redacted:S20-TRACER-DEADBEEF>";
    const TRACER_HASH: &str = "S20-TRACER-DEADBEEF";

    fn env_diff_with(added: &[(&str, &str)]) -> EnvDiff {
        let mut a = BTreeMap::new();
        for (k, v) in added {
            a.insert((*k).to_string(), (*v).to_string());
        }
        EnvDiff {
            added: a,
            removed: BTreeMap::new(),
            modified: BTreeMap::new(),
        }
    }

    #[test]
    fn env_diff_renderer_masks_tracer_in_added() {
        let diff = env_diff_with(&[("GITHUB_TOKEN", TRACER_MARKER)]);
        let out = env_render(&diff, RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked in 'added': {out}");
    }

    #[test]
    fn env_diff_renderer_masks_tracer_in_removed() {
        let mut removed = BTreeMap::new();
        removed.insert("OLD_TOKEN".into(), TRACER_MARKER.to_string());
        let diff = EnvDiff {
            added: BTreeMap::new(),
            removed,
            modified: BTreeMap::new(),
        };
        let out = env_render(&diff, RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked in 'removed': {out}");
    }

    #[test]
    fn env_diff_renderer_masks_tracer_in_modified_pre_and_post() {
        let mut modified = BTreeMap::new();
        modified.insert(
            "TOKEN".into(),
            (TRACER_MARKER.to_string(), TRACER_MARKER.to_string()),
        );
        let diff = EnvDiff {
            added: BTreeMap::new(),
            removed: BTreeMap::new(),
            modified,
        };
        let out = env_render(&diff, RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked in 'modified': {out}");
    }

    #[test]
    fn env_diff_renderer_hide_entirely_drops_tracer_row() {
        let diff = env_diff_with(&[("GITHUB_TOKEN", TRACER_MARKER)]);
        let out = env_render(&diff, RedactionDisplay::HideEntirely);
        assert!(
            !out.contains(TRACER_HASH) && !out.contains("GITHUB_TOKEN"),
            "HideEntirely should drop redacted rows: {out}"
        );
    }

    #[test]
    fn process_renderer_masks_tracer_in_env_summary() {
        let mut env = BTreeMap::new();
        env.insert("API_KEY".into(), TRACER_MARKER.to_string());
        let s = RestartSuggestion {
            original_argv: vec!["app".into()],
            cwd: PathBuf::from("/srv"),
            env_summary: env,
            message: String::new(),
            hint: RestartHint::RawArgv,
        };
        let out = proc_render(&[s], RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked: {out}");
    }

    #[test]
    fn process_renderer_does_not_export_redacted_in_raw_argv_snippet() {
        let mut env = BTreeMap::new();
        env.insert("API_KEY".into(), TRACER_MARKER.to_string());
        let s = RestartSuggestion {
            original_argv: vec!["app".into()],
            cwd: PathBuf::from("/srv"),
            env_summary: env,
            message: String::new(),
            hint: RestartHint::RawArgv,
        };
        let out = proc_render(&[s], RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked hash: {out}");
        assert!(
            !out.contains("export API_KEY='<redacted:"),
            "raw-argv snippet should drop redacted exports entirely: {out}"
        );
    }

    #[test]
    fn db_renderer_masks_tracer_in_statement_body() {
        let s = DbSuggestion {
            engine: DbEngine::Postgres,
            target: "prod".into(),
            statements: vec![format!("INSERT INTO secrets VALUES ('{TRACER_MARKER}')")],
            hint: RollbackHint::None,
        };
        let out = db_render(&[s], RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked: {out}");
    }

    #[test]
    fn db_renderer_hide_entirely_drops_tracer_statement() {
        let s = DbSuggestion {
            engine: DbEngine::Postgres,
            target: "prod".into(),
            statements: vec![format!("INSERT INTO secrets VALUES ('{TRACER_MARKER}')")],
            hint: RollbackHint::None,
        };
        let out = db_render(&[s], RedactionDisplay::HideEntirely);
        assert!(
            !out.contains(TRACER_HASH) && !out.contains("INSERT INTO secrets"),
            "HideEntirely should drop redacted statements: {out}"
        );
    }

    #[test]
    fn redaction_label_is_uniform_across_tiers() {
        let env_out = env_render(
            &env_diff_with(&[("X", TRACER_MARKER)]),
            RedactionDisplay::NamesVisible,
        );
        let mut env = BTreeMap::new();
        env.insert("X".into(), TRACER_MARKER.to_string());
        let proc_out = proc_render(
            &[RestartSuggestion {
                original_argv: vec!["app".into()],
                cwd: PathBuf::from("/"),
                env_summary: env,
                message: String::new(),
                hint: RestartHint::RawArgv,
            }],
            RedactionDisplay::NamesVisible,
        );
        let db_out = db_render(
            &[DbSuggestion {
                engine: DbEngine::Postgres,
                target: "x".into(),
                statements: vec![format!("INSERT INTO t VALUES ('{TRACER_MARKER}')")],
                hint: RollbackHint::None,
            }],
            RedactionDisplay::NamesVisible,
        );
        assert!(
            env_out.contains("<redacted>"),
            "env: missing label: {env_out}"
        );
        assert!(
            proc_out.contains("<redacted>"),
            "proc: missing label: {proc_out}"
        );
        assert!(db_out.contains("<redacted>"), "db: missing label: {db_out}");
    }

    #[test]
    fn multiple_tracers_in_one_string_all_get_masked() {
        let s = DbSuggestion {
            engine: DbEngine::Postgres,
            target: "x".into(),
            statements: vec![format!(
                "INSERT INTO t VALUES ('{TRACER_MARKER}', '{TRACER_MARKER}')"
            )],
            hint: RollbackHint::None,
        };
        let out = db_render(&[s], RedactionDisplay::NamesVisible);
        assert!(!out.contains(TRACER_HASH), "leaked: {out}");
        let label_count = out.matches("<redacted>").count();
        assert_eq!(label_count, 2, "expected two masked labels: {out}");
    }
}
