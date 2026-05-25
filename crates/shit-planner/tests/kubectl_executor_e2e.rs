// SPDX-License-Identifier: AGPL-3.0-or-later

//! C03.8: end-to-end integration test for the kubectl executor.
//!
//! Stitches the kubectl reverse path against a real subprocess:
//!
//!     fake kubectl shell script on PATH
//!         │
//!         ▼
//!     KubectlExecutor (production code, with context guard ENABLED)
//!         │
//!         ├── runner.capture(["kubectl","config","current-context"])
//!         │      ── stub prints captured context to stdout ──┐
//!         │                                                   ▼
//!         │      guard compares to op.context — must match
//!         │
//!         └── runner.run_with_stdin(["kubectl","apply","-f","-"], yaml)
//!                ── stub records the piped YAML to a file ──
//!
//! The test is hermetic — no real kubectl binary is invoked; no
//! cluster is contacted. The stub binary is a POSIX shell script
//! emitted into a tempdir and exec'd via a PATH-injecting runner.

#![cfg(unix)]

use shit_planner::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use shit_planner::executors::kubectl::{KubectlExecutor, KubectlRunner};
use shit_planner::inverse::{InverseOp, KubectlOp};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

/// Write a POSIX shell stub for `kubectl` that handles the two argv
/// shapes the executor exercises:
///
/// - `kubectl config current-context`  → print `$preset_context\n`.
/// - `kubectl apply -f -`              → cat stdin into `$record_file`.
///
/// Any other argv exits 2 so a regression that synthesizes the wrong
/// reverse argv fails loudly.
fn write_fake_kubectl(
    dir: &std::path::Path,
    preset_context: &str,
    record_file: &std::path::Path,
) -> PathBuf {
    let path = dir.join("kubectl");
    let body = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = config ] && [ \"$2\" = current-context ]; then\n\
           printf '%s\\n' '{preset_context}'\n\
           exit 0\n\
         fi\n\
         if [ \"$1\" = apply ] && [ \"$2\" = -f ] && [ \"$3\" = - ]; then\n\
           cat > '{record}'\n\
           exit 0\n\
         fi\n\
         echo \"fake kubectl: unexpected argv: $*\" >&2\n\
         exit 2\n",
        record = record_file.display(),
    );
    // Write-then-rename-then-fsync-dir: matches the fix in
    // container_executor_e2e.rs. Rename alone isn't enough on some
    // filesystems (notably the ARM CI runner's overlayfs) where the
    // directory entry update can lag behind the rename return; fsync
    // the parent dir to force the dentry write durable before exec.
    let staging = dir.join(".kubectl.staging");
    fs::write(&staging, body.as_bytes()).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(&staging, &path).unwrap();
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    path
}

/// KubectlRunner that shells out via `std::process::Command` with the
/// PATH overridden to point at the stub directory. The production
/// `SystemKubectlRunner` inherits the ambient PATH; we override here
/// for hermeticity.
struct PathInjectingKubectlRunner {
    path: String,
}

impl PathInjectingKubectlRunner {
    fn new(path: &std::path::Path) -> Self {
        // The stub uses `cat` to slurp stdin, so the system bin dirs
        // need to be reachable for the spawned shell process.
        Self {
            path: format!("{}:/usr/bin:/bin", path.display()),
        }
    }
}

impl KubectlRunner for PathInjectingKubectlRunner {
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

    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let mut child = Command::new(cmd)
            .args(args)
            .env("PATH", &self.path)
            .env("SHIT_DURING_UNDO", "1")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_bytes)
                .map_err(|e| format!("write stdin: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("wait {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }

    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let out = Command::new(cmd)
            .args(args)
            .env("PATH", &self.path)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }
}

const SAMPLE_YAML: &[u8] = b"apiVersion: apps/v1\n\
kind: Deployment\n\
metadata:\n\
  name: api\n\
  namespace: default\n\
spec:\n\
  replicas: 3\n";

fn delete_op(ctx: &str) -> InverseOp {
    InverseOp::KubectlReverse {
        context: ctx.into(),
        namespace: Some("default".into()),
        op: KubectlOp::Delete {
            kind: "Deployment".into(),
            name: "api".into(),
        },
        captured_yaml: SAMPLE_YAML.to_vec(),
        requires_confirmation: true,
    }
}

#[test]
fn kubectl_reverse_full_pipeline() {
    // 1. Tempdir scaffolding: bin dir holds the stub kubectl; record
    //    dir holds the file the stub will pipe stdin into. Bind the
    //    record dir to a named var so the TempDir doesn't drop early.
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    let record_path = record_dir.path().join("applied-yaml");
    write_fake_kubectl(bin_dir.path(), "kind-c1", &record_path);

    // 2. Build the executor with context-guard ENABLED — we want the
    //    guard to run end-to-end against the stub's
    //    `config current-context` output.
    let runner = PathInjectingKubectlRunner::new(bin_dir.path());
    let executor = KubectlExecutor::new(runner);
    let op = delete_op("kind-c1");

    // 3. Run it. Asserts the executor returns Applied.
    let outcome = executor.execute(&op, /*dry_run=*/ false, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::Applied, "got {outcome:?}");

    // 4. Verify the stub received the exact captured YAML on stdin.
    let recorded = fs::read(&record_path).expect("stub recorded stdin");
    assert_eq!(recorded, SAMPLE_YAML);
}

#[test]
fn kubectl_context_drift_refuses() {
    // The stub will report a different context than the captured one,
    // so the guard must refuse and never run apply.
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    let record_path = record_dir.path().join("applied-yaml");
    write_fake_kubectl(bin_dir.path(), "different-cluster", &record_path);

    let runner = PathInjectingKubectlRunner::new(bin_dir.path());
    let executor = KubectlExecutor::new(runner);
    let op = delete_op("kind-c1");

    let outcome = executor.execute(&op, /*dry_run=*/ false, ConflictPolicy::Abort);
    match outcome {
        ExecutionOutcome::Failed { err } => {
            assert!(
                err.contains("kube-context drift") || err.contains("context drift"),
                "expected context-drift error, got: {err}"
            );
        }
        other => panic!("expected Failed (context drift), got {other:?}"),
    }

    // Crucially: apply did NOT run, so the record file does not exist.
    assert!(
        !record_path.exists(),
        "context drift must short-circuit before apply"
    );
}

#[test]
fn kubectl_dry_run_skips_apply_but_runs_guard() {
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    let record_path = record_dir.path().join("applied-yaml");
    write_fake_kubectl(bin_dir.path(), "kind-c1", &record_path);

    let runner = PathInjectingKubectlRunner::new(bin_dir.path());
    let executor = KubectlExecutor::new(runner);
    let op = delete_op("kind-c1");

    let outcome = executor.execute(&op, /*dry_run=*/ true, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::WouldApply);
    // Guard is read-only and still runs; the apply does not, so the
    // record file is never written.
    assert!(
        !record_path.exists(),
        "dry-run must not invoke `kubectl apply`"
    );
}
