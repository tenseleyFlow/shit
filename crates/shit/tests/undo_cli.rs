// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration test for the bare-`shit`-as-`shit undo` rule
//! (memory: `shit-cli-undo-default`).
//!
//! Rule:
//! - `shit` (no args) runs `shit undo` with default args.
//! - `shit undo ...` accepts undo's flags / positional.
//! - **Top-level `shit` does NOT accept undo's flags.** `shit --dry-run`,
//!   `shit 3`, `shit --on-conflict=skip` must be rejected by clap.

use std::process::Command;

/// Resolve the path to the built `shit` binary in this workspace.
/// `env!("CARGO_BIN_EXE_shit")` is set by cargo when running integration
/// tests for the same binary crate.
fn shit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shit")
}

#[test]
fn bare_shit_runs_undo_with_defaults() {
    let out = Command::new(shit_bin()).output().expect("spawn shit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("shit undo"), "stdout was: {stdout}");
    assert!(stdout.contains("steps:       1"), "stdout was: {stdout}");
    assert!(
        stdout.contains("dry-run:     false"),
        "stdout was: {stdout}"
    );
}

#[test]
fn shit_undo_explicit_matches_bare() {
    let bare = Command::new(shit_bin()).output().unwrap();
    let explicit = Command::new(shit_bin()).arg("undo").output().unwrap();
    assert_eq!(bare.stdout, explicit.stdout);
}

#[test]
fn shit_undo_accepts_dry_run_flag() {
    let out = Command::new(shit_bin())
        .args(["undo", "--dry-run"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dry-run:     true"), "stdout: {stdout}");
}

#[test]
fn shit_undo_accepts_steps_positional() {
    let out = Command::new(shit_bin())
        .args(["undo", "5"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("steps:       5"), "stdout: {stdout}");
}

#[test]
fn top_level_dry_run_is_rejected() {
    let out = Command::new(shit_bin()).arg("--dry-run").output().unwrap();
    assert!(!out.status.success(), "bare `shit --dry-run` must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("--dry-run"),
        "stderr: {stderr}"
    );
}

#[test]
fn top_level_positional_is_rejected() {
    let out = Command::new(shit_bin()).arg("3").output().unwrap();
    assert!(
        !out.status.success(),
        "bare `shit 3` must fail (3 is not a subcommand)"
    );
}

#[test]
fn top_level_on_conflict_flag_is_rejected() {
    let out = Command::new(shit_bin())
        .arg("--on-conflict=skip")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "bare `shit --on-conflict=skip` must fail"
    );
}

#[test]
fn force_requires_yes() {
    let out = Command::new(shit_bin())
        .args(["undo", "--on-conflict=force"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "force without --yes must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--yes"), "stderr: {stderr}");
}

#[test]
fn force_with_yes_passes() {
    let out = Command::new(shit_bin())
        .args(["undo", "--on-conflict=force", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
