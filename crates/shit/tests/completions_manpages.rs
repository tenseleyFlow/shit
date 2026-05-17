// SPDX-License-Identifier: AGPL-3.0-or-later

//! Smoke tests for `shit completions` and `shit manpages` (S12.9).

use std::process::Command;

fn shit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shit")
}

#[test]
fn completions_bash_renders() {
    let out = Command::new(shit_bin())
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("_shit()"),
        "no bash completion header: {stdout}"
    );
}

#[test]
fn completions_zsh_renders() {
    let out = Command::new(shit_bin())
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("#compdef shit") || stdout.contains("_shit"));
}

#[test]
fn completions_fish_renders() {
    let out = Command::new(shit_bin())
        .args(["completions", "fish"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("complete -c shit"));
}

#[test]
fn manpages_writes_files_for_each_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shit_bin())
        .args(["manpages", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Must include the top-level page + the headline subcommands.
    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.contains(&"shit.1".to_string()),
        "missing shit.1: {entries:?}"
    );
    assert!(
        entries.iter().any(|n| n == "shit-undo.1"),
        "missing shit-undo.1: {entries:?}"
    );
    assert!(
        entries.iter().any(|n| n == "shit-list.1"),
        "missing shit-list.1: {entries:?}"
    );
    // Generated man files contain `.TH` (title header).
    let undo = std::fs::read_to_string(dir.path().join("shit-undo.1")).unwrap();
    assert!(undo.contains(".TH"), "shit-undo.1 missing .TH: {undo}");
}

#[test]
fn manpages_does_not_emit_help_entry() {
    // The clap-generated `help` subcommand shouldn't get its own man
    // page — it'd shadow `man help` on the system.
    let dir = tempfile::tempdir().unwrap();
    let _ = Command::new(shit_bin())
        .args(["manpages", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !entries.iter().any(|n| n == "shit-help.1"),
        "shouldn't emit shit-help.1: {entries:?}"
    );
}
