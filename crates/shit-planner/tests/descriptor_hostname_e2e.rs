// SPDX-License-Identifier: AGPL-3.0-or-later

//! C02.10: end-to-end integration test for the hostname descriptor.
//!
//! Stitches the full descriptor pipeline together:
//!
//!     fake hostname binary on PATH
//!         │
//!         ▼
//!     Loader::from_roots  →  Descriptor (parsed + linted)
//!         │
//!         ▼
//!     match_descriptor(argv)  →  MatchOutcome (MATCH)
//!         │
//!         ▼
//!     run pre.command (stub prints "oldhost\n")
//!         │
//!         ▼
//!     extract_all(parse=raw)  →  state = { old_hostname: "oldhost" }
//!         │
//!         ▼
//!     interpolate reverse.command  →  ["hostname", "oldhost"]
//!         │
//!         ▼
//!     DescriptorExecutor (with SystemDescRunner against the stub)
//!         │
//!         ▼
//!     stub records its argv  →  test asserts ["hostname", "oldhost"]
//!
//! The test is hermetic: every external dependency (the hostname
//! binary) is provided as a shell script in a tempdir; no real
//! `hostname(1)` is invoked. Hard-coded for Unix.

#![cfg(unix)]

use shit_desc::{
    DescriptorAuthority, Loader, MatchOutcome, ParseKind, extract_all, interpolate_argv,
    match_descriptor,
};
use shit_planner::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use shit_planner::executors::descriptor::{DescRunner, DescriptorExecutor};
use shit_planner::inverse::InverseOp;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

/// Write a POSIX shell script that:
/// - With no args, prints `$preset_hostname` to stdout (the "old" value).
/// - With one arg, records its argv to `$record_file` and exits 0.
fn write_fake_hostname(
    dir: &std::path::Path,
    preset: &str,
    record_file: &std::path::Path,
) -> PathBuf {
    let path = dir.join("hostname");
    let body = format!(
        "#!/bin/sh\n\
         if [ $# -eq 0 ]; then\n\
           printf '%s\\n' '{preset}'\n\
         else\n\
           printf '%s\\n' \"$@\" > '{}'\n\
         fi\n",
        record_file.display()
    );
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    let mut perms = f.metadata().unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

/// Stage a copy of the hostname.toml pack from the workspace's
/// packaging/descriptors/builtin/ dir into `dir` so the Loader picks
/// it up. We deliberately don't `cp -r` the whole builtin dir — this
/// test wants exactly one descriptor in scope.
fn stage_hostname_pack(dir: &std::path::Path) {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .unwrap()
        .to_path_buf();
    let src = workspace_root.join("packaging/descriptors/builtin/hostname.toml");
    let dst = dir.join("hostname.toml");
    fs::copy(&src, &dst)
        .unwrap_or_else(|e| panic!("copy {} → {}: {e}", src.display(), dst.display()));
}

/// A DescRunner that shells out via `std::process::Command` with the
/// custom PATH that contains our stub. The planner's `SystemDescRunner`
/// uses the default PATH; we override here for hermeticity.
struct PathInjectingRunner {
    path: String,
}

impl PathInjectingRunner {
    fn new(path: &std::path::Path) -> Self {
        Self {
            path: path.display().to_string(),
        }
    }
}

impl DescRunner for PathInjectingRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = Command::new(cmd)
            .args(args)
            .env("PATH", &self.path)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn run_privileged(&self, argv: &[String]) -> Result<(), String> {
        // The test runner doesn't enforce a privilege boundary; the
        // privileged path is identical to the non-privileged one. The
        // production helper-IPC wiring is gated on a separate DR.
        self.run(argv)
    }
    fn capture_guard(&self, argv: &[String]) -> Result<Vec<u8>, String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let out = Command::new(cmd)
            .args(args)
            .env("PATH", &self.path)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("guard {cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }
}

/// Run the descriptor's pre-snapshot command (with the same PATH
/// injection) and return its stdout. This is the "snapshot driver"
/// the daemon would normally run; the test inlines it for clarity.
fn run_snapshot(argv: &[String], path: &std::path::Path) -> Vec<u8> {
    let (cmd, args) = argv.split_first().unwrap();
    Command::new(cmd)
        .args(args)
        .env("PATH", path)
        .output()
        .unwrap_or_else(|e| panic!("snapshot {cmd}: {e}"))
        .stdout
}

#[test]
fn hostname_descriptor_full_pipeline() {
    // 1. Tempdir scaffolding: PATH dir (stub binary), descriptor dir
    //    (pack), and record-file path.
    let bin_dir = tempdir().unwrap();
    let pack_dir = tempdir().unwrap();
    // Bind the record dir to a named variable so it lives for the test;
    // `tempdir().path().join(..)` lets the TempDir drop immediately.
    let record_dir = tempdir().unwrap();
    let record_path = record_dir.path().join("recorded-argv");
    write_fake_hostname(bin_dir.path(), "oldhost", &record_path);
    stage_hostname_pack(pack_dir.path());

    // 2. Loader picks up the pack and dispatches against argv.
    let loader =
        Loader::from_roots(&[(DescriptorAuthority::Builtin, pack_dir.path())]).expect("loader");
    let argv = vec!["hostname".to_string(), "newhost".to_string()];
    let resolved = loader.dispatch(&argv).expect("dispatch should match");
    assert_eq!(resolved.descriptor.descriptor.name, "hostname-set");

    // Cross-check the matcher's own surface: same answer, score >0.
    let outcome: MatchOutcome = match_descriptor(&resolved.descriptor.match_, &argv);
    assert!(outcome.matched);
    assert!(outcome.score > 0.0);

    // 3. Run the pre-snapshot command against the stub binary.
    let stdout = run_snapshot(&resolved.descriptor.snapshot.pre.command, bin_dir.path());
    assert_eq!(std::str::from_utf8(&stdout).unwrap().trim(), "oldhost");

    // 4. Extract state.
    assert_eq!(resolved.descriptor.snapshot.pre.parse, ParseKind::Raw);
    let state: BTreeMap<String, String> = extract_all(
        resolved.descriptor.snapshot.pre.parse,
        &stdout,
        &resolved.descriptor.snapshot.pre.extract,
    )
    .expect("extract");
    assert_eq!(state.get("old_hostname"), Some(&"oldhost".to_string()));

    // 5. Interpolate reverse argv from state.
    let reverse_argv =
        interpolate_argv(&resolved.descriptor.reverse.command, &state).expect("interpolate");
    assert_eq!(
        reverse_argv,
        vec!["hostname".to_string(), "oldhost".to_string()]
    );

    // 6. Build an InverseOp and run it through the executor against
    //    the stub binary. Asserts the executor returns Applied.
    let op = InverseOp::DescriptorReverse {
        descriptor_name: resolved.descriptor.descriptor.name.clone(),
        descriptor_version: resolved.descriptor.descriptor.version,
        captured_state: state.clone(),
        reverse_argv: reverse_argv.clone(),
        privileged: resolved.descriptor.reverse.privileged,
        requires_confirmation: resolved.descriptor.reverse.requires_confirmation,
        guard: None,
    };
    let runner = PathInjectingRunner::new(bin_dir.path());
    let executor = DescriptorExecutor::new(runner);
    let outcome = executor.execute(&op, /*dry_run=*/ false, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::Applied);

    // 7. Verify the stub recorded the exact reverse argv.
    let recorded = fs::read_to_string(&record_path)
        .expect("stub should have recorded argv at {record_path:?}");
    // The stub prints one token per line.
    let tokens: Vec<&str> = recorded.lines().collect();
    assert_eq!(tokens, vec!["oldhost"]);
}

#[test]
fn hostname_descriptor_dry_run_does_not_invoke_stub() {
    let bin_dir = tempdir().unwrap();
    let pack_dir = tempdir().unwrap();
    // Bind the record dir to a named variable so it lives for the test;
    // `tempdir().path().join(..)` lets the TempDir drop immediately.
    let record_dir = tempdir().unwrap();
    let record_path = record_dir.path().join("recorded-argv");
    write_fake_hostname(bin_dir.path(), "oldhost", &record_path);
    stage_hostname_pack(pack_dir.path());

    let loader = Loader::from_roots(&[(DescriptorAuthority::Builtin, pack_dir.path())]).unwrap();
    let argv = vec!["hostname".to_string(), "newhost".to_string()];
    let resolved = loader.dispatch(&argv).unwrap();
    let stdout = run_snapshot(&resolved.descriptor.snapshot.pre.command, bin_dir.path());
    let state = extract_all(
        resolved.descriptor.snapshot.pre.parse,
        &stdout,
        &resolved.descriptor.snapshot.pre.extract,
    )
    .unwrap();
    let reverse_argv = interpolate_argv(&resolved.descriptor.reverse.command, &state).unwrap();

    let op = InverseOp::DescriptorReverse {
        descriptor_name: resolved.descriptor.descriptor.name.clone(),
        descriptor_version: resolved.descriptor.descriptor.version,
        captured_state: state,
        reverse_argv,
        privileged: resolved.descriptor.reverse.privileged,
        requires_confirmation: resolved.descriptor.reverse.requires_confirmation,
        guard: None,
    };
    let executor = DescriptorExecutor::new(PathInjectingRunner::new(bin_dir.path()));
    let outcome = executor.execute(&op, /*dry_run=*/ true, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::WouldApply);
    // Crucially: the stub did NOT run, so the record file does not exist.
    assert!(!record_path.exists());
}
