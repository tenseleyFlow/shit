// SPDX-License-Identifier: AGPL-3.0-or-later

//! C04.9: end-to-end integration tests for the container executor.
//!
//! Each test stitches the executor against a real subprocess via a
//! PATH-injecting runner. Per-variant coverage:
//!
//! - `Rmi`: `docker load < tarball` — stub cats stdin to a record file;
//!   test asserts the recorded bytes equal the captured tarball.
//! - `VolumeRm`: two-step `docker volume create` + `docker run --rm
//!   -i -v vol:/data busybox tar -xzf -` — stub records both argvs +
//!   the stdin of the second; test asserts both invocations and the
//!   tarball bytes.
//! - `NetworkRm`: `docker network create --driver ... --subnet ...
//!   --gateway ... <name>` synthesized from the captured inspect
//!   JSON; test asserts the argv contains all three pieces.
//! - `ComposeDown`: `docker compose -f <file> -p <project> up -d` —
//!   stub records argv; test asserts the project + file made it onto
//!   the line.
//!
//! All stubs are POSIX shell scripts emitted into a tempdir; no real
//! docker daemon is contacted.

#![cfg(unix)]

use shit_planner::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use shit_planner::executors::container::{ContainerExecutor, ContainerRunner};
use shit_planner::inode::BlobHash;
use shit_planner::inverse::{ContainerOp, ContainerRuntime, InverseOp};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use tempfile::tempdir;

/// Write a POSIX shell stub for `docker` that dispatches on the first
/// few argv tokens to record argv (and optionally stdin) for each
/// expected reverse-path subcommand. Anything unrecognized exits 2.
fn write_fake_docker(dir: &std::path::Path, record_dir: &std::path::Path) -> PathBuf {
    let path = dir.join("docker");
    // Each invocation appends a line to `record_dir/argv-<verb>` with
    // its argv; when stdin is consumed, it goes into
    // `record_dir/stdin-<verb>`. We need /bin/sh-portable tar/cat
    // since the runner restricts PATH but adds /usr/bin:/bin.
    let body = format!(
        r#"#!/bin/sh
set -e
case "$1 $2 $3" in
  "image inspect "*)
    printf '[{{"Id":"sha256:abc","RepoTags":["%s"]}}]\n' "$3"
    exit 0
    ;;
  "load  ")
    cat > '{rec}/stdin-load'
    printf '%s\n' "$*" > '{rec}/argv-load'
    exit 0
    ;;
  "load -i ")
    cat > '{rec}/stdin-load'
    printf '%s\n' "$*" > '{rec}/argv-load'
    exit 0
    ;;
esac
case "$1 $2" in
  "volume create")
    printf '%s\n' "$*" > '{rec}/argv-volcreate'
    exit 0
    ;;
  "network create")
    printf '%s\n' "$*" > '{rec}/argv-netcreate'
    exit 0
    ;;
  "compose -f")
    printf '%s\n' "$*" > '{rec}/argv-compose'
    exit 0
    ;;
esac
case "$1" in
  "run")
    # docker run --rm -i -v X:/data busybox tar -C /data -xzf -
    cat > '{rec}/stdin-run'
    printf '%s\n' "$*" > '{rec}/argv-run'
    exit 0
    ;;
  "load")
    cat > '{rec}/stdin-load'
    printf '%s\n' "$*" > '{rec}/argv-load'
    exit 0
    ;;
esac
echo "fake docker: unexpected argv: $*" >&2
exit 2
"#,
        rec = record_dir.display()
    );
    // Write-then-rename pattern: even with fs::write closing the fd
    // synchronously, Linux occasionally flakes with ETXTBSY ("Text file
    // busy", os error 26) when exec(2) lands on `path` immediately
    // after the close. Writing to a sibling tempname and atomically
    // renaming guarantees the final inode has never been open for
    // writing (i_writecount==0) by the time the executor spawns it.
    let staging = dir.join(".docker.staging");
    fs::write(&staging, body.as_bytes()).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(&staging, &path).unwrap();
    path
}

/// ContainerRunner that shells out via real `std::process::Command`
/// with PATH overridden to point at the stub directory (+ /usr/bin:/bin
/// for `cat` / `tar` builtins the stub uses).
struct PathInjectingRunner {
    path: String,
    blobs: Mutex<HashMap<BlobHash, Vec<u8>>>,
}

impl PathInjectingRunner {
    fn new(path: &std::path::Path) -> Self {
        Self {
            path: format!("{}:/usr/bin:/bin", path.display()),
            blobs: Mutex::new(HashMap::new()),
        }
    }
    fn add_blob(&self, hash: BlobHash, bytes: Vec<u8>) {
        self.blobs.lock().unwrap().insert(hash, bytes);
    }
}

impl ContainerRunner for PathInjectingRunner {
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

    fn load_stash_tarball(&self, hash: &BlobHash) -> Option<Vec<u8>> {
        self.blobs.lock().unwrap().get(hash).cloned()
    }
}

const SAMPLE_TAR: &[u8] = b"this is a fake tarball with enough bytes to round-trip";

#[test]
fn rmi_reverse_runs_docker_load_with_captured_tarball() {
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    write_fake_docker(bin_dir.path(), record_dir.path());

    let runner = PathInjectingRunner::new(bin_dir.path());
    let h = BlobHash::from_bytes([42; 32]);
    runner.add_blob(h, SAMPLE_TAR.to_vec());
    let executor = ContainerExecutor::new(runner);

    let op = InverseOp::ContainerRestore {
        runtime: ContainerRuntime::Docker,
        op: ContainerOp::Rmi {
            image: "nginx:1.25".into(),
            digest: Some("sha256:abc".into()),
        },
        captured_config: b"{}".to_vec(),
        stash_image: None,
        stash_tarball: Some(h),
        requires_confirmation: true,
    };

    let outcome = executor.execute(&op, false, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::Applied, "got {outcome:?}");

    let recorded = fs::read(record_dir.path().join("stdin-load")).expect("stub recorded stdin");
    assert_eq!(recorded, SAMPLE_TAR);
}

#[test]
fn volume_rm_reverse_creates_then_extracts() {
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    write_fake_docker(bin_dir.path(), record_dir.path());

    let runner = PathInjectingRunner::new(bin_dir.path());
    let h = BlobHash::from_bytes([43; 32]);
    runner.add_blob(h, SAMPLE_TAR.to_vec());
    let executor = ContainerExecutor::new(runner);

    let op = InverseOp::ContainerRestore {
        runtime: ContainerRuntime::Docker,
        op: ContainerOp::VolumeRm {
            name: "pgdata".into(),
            driver: Some("local".into()),
        },
        captured_config: b"{}".to_vec(),
        stash_image: None,
        stash_tarball: Some(h),
        requires_confirmation: true,
    };

    let outcome = executor.execute(&op, false, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::Applied, "got {outcome:?}");

    // Step 1: volume create.
    let create_argv = fs::read_to_string(record_dir.path().join("argv-volcreate"))
        .expect("stub recorded volume create");
    assert!(create_argv.contains("volume create"));
    assert!(create_argv.contains("--driver local"));
    assert!(create_argv.contains("pgdata"));

    // Step 2: docker run --rm -i -v pgdata:/data busybox tar ...
    let run_argv =
        fs::read_to_string(record_dir.path().join("argv-run")).expect("stub recorded run-extract");
    assert!(run_argv.contains("pgdata:/data"));
    assert!(run_argv.contains("busybox"));
    assert!(run_argv.contains("tar"));

    // The tarball bytes went into the extract's stdin.
    let stdin = fs::read(record_dir.path().join("stdin-run")).expect("stub recorded run stdin");
    assert_eq!(stdin, SAMPLE_TAR);
}

#[test]
fn network_rm_reverse_synthesizes_create_with_inspect_fields() {
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    write_fake_docker(bin_dir.path(), record_dir.path());

    let runner = PathInjectingRunner::new(bin_dir.path());
    let executor = ContainerExecutor::new(runner);

    let inspect_json = br#"[{
        "Driver": "bridge",
        "IPAM": {
            "Config": [{
                "Subnet": "172.20.0.0/16",
                "Gateway": "172.20.0.1"
            }]
        }
    }]"#;

    let op = InverseOp::ContainerRestore {
        runtime: ContainerRuntime::Docker,
        op: ContainerOp::NetworkRm {
            name: "frontend".into(),
        },
        captured_config: inspect_json.to_vec(),
        stash_image: None,
        stash_tarball: None,
        requires_confirmation: false,
    };

    let outcome = executor.execute(&op, false, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::Applied, "got {outcome:?}");

    let argv = fs::read_to_string(record_dir.path().join("argv-netcreate"))
        .expect("stub recorded network create");
    assert!(argv.contains("network create"));
    assert!(argv.contains("--driver bridge"));
    assert!(argv.contains("--subnet 172.20.0.0/16"));
    assert!(argv.contains("--gateway 172.20.0.1"));
    assert!(argv.contains("frontend"));
}

#[test]
fn compose_down_reverse_invokes_docker_compose_up() {
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    write_fake_docker(bin_dir.path(), record_dir.path());

    let runner = PathInjectingRunner::new(bin_dir.path());
    let executor = ContainerExecutor::new(runner);

    let op = InverseOp::ContainerRestore {
        runtime: ContainerRuntime::Docker,
        op: ContainerOp::ComposeDown {
            project: "myapp".into(),
            services: vec!["web".into(), "db".into()],
            compose_file: PathBuf::from("/srv/myapp/docker-compose.yml"),
            with_volumes: false,
        },
        captured_config: b"{}".to_vec(),
        stash_image: None,
        stash_tarball: None,
        requires_confirmation: true,
    };

    let outcome = executor.execute(&op, false, ConflictPolicy::Abort);
    assert_eq!(outcome, ExecutionOutcome::Applied, "got {outcome:?}");

    let argv = fs::read_to_string(record_dir.path().join("argv-compose"))
        .expect("stub recorded compose up");
    assert!(argv.contains("compose"));
    assert!(argv.contains("-f /srv/myapp/docker-compose.yml"));
    assert!(argv.contains("-p myapp"));
    assert!(argv.contains("up"));
    assert!(argv.contains("-d"));
}

#[test]
fn rm_reverse_inspects_stash_then_runs_synthesized_argv() {
    // AR10.9 (DR-CR-22): the full `docker run` synthesis path.
    // Executor verifies the stash image exists via `docker image
    // inspect`, then walks the captured inspect JSON through
    // `synthesize_container_run` and execs the produced argv. This
    // e2e test confirms both calls land on the stub docker and
    // asserts the executor reports Applied.
    let bin_dir = tempdir().unwrap();
    let record_dir = tempdir().unwrap();
    write_fake_docker(bin_dir.path(), record_dir.path());

    let runner = PathInjectingRunner::new(bin_dir.path());
    let executor = ContainerExecutor::new(runner);

    // Minimal-but-valid captured inspect: image + name + env so the
    // synthesizer emits a real argv (not just `docker run -d --name X`).
    let inspect = br#"[{
        "Id": "abc123",
        "Name": "/web",
        "Config": {"Image": "nginx:alpine", "Env": ["FOO=bar"]},
        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
        "Mounts": []
    }]"#;

    let op = InverseOp::ContainerRestore {
        runtime: ContainerRuntime::Docker,
        op: ContainerOp::Rm {
            id: "abc123".into(),
            name: Some("web".into()),
            was_running: true,
        },
        captured_config: inspect.to_vec(),
        stash_image: Some("shit-stash:abc123:1700000000".into()),
        stash_tarball: None,
        requires_confirmation: true,
    };

    match executor.execute(&op, false, ConflictPolicy::Abort) {
        ExecutionOutcome::Applied => {}
        other => panic!("expected Applied, got {other:?}"),
    }

    // Stub recorded the synthesized `docker run` invocation.
    let argv_run = fs::read_to_string(record_dir.path().join("argv-run")).unwrap();
    assert!(argv_run.contains("--name"), "argv-run missing --name: {argv_run}");
    assert!(argv_run.contains("web"), "argv-run missing container name: {argv_run}");
    // Image should be the stash, not the original.
    assert!(
        argv_run.contains("shit-stash:abc123:1700000000"),
        "argv-run should use stash image: {argv_run}"
    );
    assert!(!argv_run.contains("nginx:alpine"), "argv-run leaked original image: {argv_run}");
    assert!(
        argv_run.contains("--restart=unless-stopped"),
        "argv-run missing restart policy: {argv_run}"
    );
}
