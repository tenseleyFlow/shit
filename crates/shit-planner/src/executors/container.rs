// SPDX-License-Identifier: AGPL-3.0-or-later

//! Container-runtime tier executor (C04.5).
//!
//! Applies [`InverseOp::ContainerRestore`]. Stash existence checks
//! gate the reverse — if the user manually removed
//! `shit-stash:<id>:<ts>` between capture and undo, or the image /
//! volume tarball was GC'd from the container-stash store, the
//! executor refuses cleanly rather than producing a partial reverse.
//!
//! Per-`ContainerOp` reverse strategy:
//!
//! - `Rm` (running container, force-removed) — re-launch a container
//!   from the captured `docker inspect` JSON, using `stash_image` as
//!   the rootfs. v1 is informational: the full `docker run` synthesis
//!   from inspect is non-trivial (network bindings, port maps, mount
//!   replays, GPU runtime detection); we surface the inspect JSON in
//!   `shit show` and emit a `docker run` skeleton. Fully automated
//!   synthesis is DR-CR-22.
//! - `Rmi` — `docker load < <stash_tarball>`. The tarball is keyed by
//!   blake3 in the container-stash store (C04.6).
//! - `VolumeRm` — two steps: `docker volume create [-d <driver>]
//!   <name>` then extract the tarball into the recreated volume via
//!   a transient `tar -xzf -` container.
//! - `NetworkRm` — parse the captured inspect JSON's Driver / Subnet
//!   / Gateway / Options / Labels and synthesize `docker network
//!   create`.
//! - `ComposeDown` — `docker compose -f <file> -p <project> up -d`.
//!   Volume restoration (when `with_volumes` was true) routes through
//!   the per-service Rm captures stashed alongside the compose down.

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{ContainerOp, InverseOp};

/// Subprocess + stdin-piping abstraction. Tests inject a spy.
pub trait ContainerRunner {
    /// Run an argv (no stdin). Returns `Ok` on exit 0.
    fn run(&self, argv: &[String]) -> Result<(), String>;
    /// Run an argv with `stdin_bytes` piped to stdin. Used for
    /// `docker load < tarball` and the volume `tar -xzf -` extract.
    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String>;
    /// Capture stdout of a command (used for stash-existence check
    /// via `docker image inspect ...`).
    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String>;
    /// Test-only: load tarball bytes for a stash blob hash. The
    /// production runner wraps the daemon-side container-stash store
    /// (C04.6). Returning `None` means the stash is missing.
    fn load_stash_tarball(&self, hash: &crate::inode::BlobHash) -> Option<Vec<u8>>;
}

/// Production runner: real `std::process::Command`. The
/// `SHIT_DURING_UNDO=1` env-var prevents the container wrapper from
/// re-capturing our own reverse invocation.
#[derive(Debug, Default)]
pub struct SystemContainerRunner;

impl ContainerRunner for SystemContainerRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
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
        let mut child = std::process::Command::new(cmd)
            .args(args)
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
        let out = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }

    fn load_stash_tarball(&self, _hash: &crate::inode::BlobHash) -> Option<Vec<u8>> {
        // Production wiring to the daemon-side container-stash store
        // is DR-CR-26; v1 production code paths run through
        // `daemon::container_stash::fetch_tarball`. Returning None
        // here means the executor reports "stash missing" — which is
        // correct fail-closed behavior if a caller forgets to wire
        // the store.
        None
    }
}

pub struct ContainerExecutor<R: ContainerRunner> {
    runner: R,
}

impl<R: ContainerRunner> ContainerExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: ContainerRunner> InverseOpExecutor for ContainerExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::ContainerRestore { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::ContainerRestore {
            runtime,
            op: container_op,
            captured_config,
            stash_image,
            stash_tarball,
            requires_confirmation: _,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "container executor reached non-container op".into(),
            };
        };

        let bin = runtime.as_str();
        match container_op {
            ContainerOp::Rm {
                id,
                name,
                was_running,
            } => self.apply_rm(bin, id, name.as_deref(), *was_running, stash_image, dry_run),
            ContainerOp::Rmi { image, digest } => {
                self.apply_rmi(bin, image, digest.as_deref(), stash_tarball, dry_run)
            }
            ContainerOp::VolumeRm { name, driver } => {
                self.apply_volume_rm(bin, name, driver.as_deref(), stash_tarball, dry_run)
            }
            ContainerOp::NetworkRm { name } => {
                self.apply_network_rm(bin, name, captured_config, dry_run)
            }
            ContainerOp::ComposeDown {
                project,
                services: _,
                compose_file,
                with_volumes: _,
            } => self.apply_compose_down(bin, project, compose_file, dry_run),
        }
    }
}

impl<R: ContainerRunner> ContainerExecutor<R> {
    fn apply_rm(
        &self,
        bin: &str,
        id: &str,
        name: Option<&str>,
        was_running: bool,
        stash_image: &Option<String>,
        dry_run: bool,
    ) -> ExecutionOutcome {
        // v1: informational. Container rootfs replay from a captured
        // inspect blob is non-trivial (port maps, network refs, mount
        // replays, GPU runtime detection). DR-CR-22 covers full
        // synthesis; for now we verify the stash image exists (so
        // `shit show` can offer it as the rootfs source) and emit a
        // skeleton `docker run` skipped-Note.
        if was_running {
            let stash = match stash_image {
                Some(s) => s,
                None => {
                    return ExecutionOutcome::Failed {
                        err: format!(
                            "{bin} rm reverse: container `{}` was running at capture but no \
                             stash image was recorded (capture path missed `{bin} commit`)",
                            name.unwrap_or(id),
                        ),
                    };
                }
            };
            // Verify the stash image still exists.
            let guard_argv = vec![
                bin.to_string(),
                "image".to_string(),
                "inspect".to_string(),
                stash.clone(),
            ];
            if let Err(e) = self.runner.capture(&guard_argv) {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rm reverse: stash image `{stash}` missing ({e}); cannot replay \
                         running container `{}`",
                        name.unwrap_or(id),
                    ),
                };
            }
        }
        // Reverse is informational in stage 1 — no live exec.
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        ExecutionOutcome::Skipped {
            reason: format!(
                "{bin} rm reverse synthesis is deferred (DR-CR-22). \
                 Captured inspect JSON is available via `shit show` for `{}` (id `{id}`).",
                name.unwrap_or(id),
            ),
        }
    }

    fn apply_rmi(
        &self,
        bin: &str,
        image: &str,
        _digest: Option<&str>,
        stash_tarball: &Option<crate::inode::BlobHash>,
        dry_run: bool,
    ) -> ExecutionOutcome {
        let hash = match stash_tarball {
            Some(h) => h,
            None => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rmi reverse: no stash tarball recorded for image `{image}` \
                         (capture path missed `{bin} save`)"
                    ),
                };
            }
        };
        let tarball = match self.runner.load_stash_tarball(hash) {
            Some(b) => b,
            None => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rmi reverse: stash tarball for `{image}` missing from store \
                         (GC'd past retention or manually removed)"
                    ),
                };
            }
        };
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        let argv = vec![bin.to_string(), "load".to_string()];
        match self.runner.run_with_stdin(&argv, &tarball) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("{bin} load: {e}"),
            },
        }
    }

    fn apply_volume_rm(
        &self,
        bin: &str,
        name: &str,
        driver: Option<&str>,
        stash_tarball: &Option<crate::inode::BlobHash>,
        dry_run: bool,
    ) -> ExecutionOutcome {
        let hash = match stash_tarball {
            Some(h) => h,
            None => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} volume rm reverse: no stash tarball recorded for volume \
                         `{name}` (capture path missed the tar step)"
                    ),
                };
            }
        };
        let tarball = match self.runner.load_stash_tarball(hash) {
            Some(b) => b,
            None => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} volume rm reverse: stash tarball for `{name}` missing from \
                         store (GC'd past retention or manually removed)"
                    ),
                };
            }
        };
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        // Step 1: recreate the volume.
        let mut create_argv = vec![bin.to_string(), "volume".to_string(), "create".to_string()];
        if let Some(d) = driver {
            create_argv.push("--driver".to_string());
            create_argv.push(d.to_string());
        }
        create_argv.push(name.to_string());
        if let Err(e) = self.runner.run(&create_argv) {
            return ExecutionOutcome::Failed {
                err: format!("{bin} volume create: {e}"),
            };
        }
        // Step 2: extract the tarball into the recreated volume via a
        // transient `busybox` mount. `docker run --rm -v
        // <name>:/data -i busybox tar -C /data -xzf -`.
        let extract_argv = vec![
            bin.to_string(),
            "run".to_string(),
            "--rm".to_string(),
            "-i".to_string(),
            "-v".to_string(),
            format!("{name}:/data"),
            "busybox".to_string(),
            "tar".to_string(),
            "-C".to_string(),
            "/data".to_string(),
            "-xzf".to_string(),
            "-".to_string(),
        ];
        match self.runner.run_with_stdin(&extract_argv, &tarball) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("{bin} volume extract: {e}"),
            },
        }
    }

    fn apply_network_rm(
        &self,
        bin: &str,
        name: &str,
        captured_config: &[u8],
        dry_run: bool,
    ) -> ExecutionOutcome {
        let inspect: serde_json::Value = match serde_json::from_slice(captured_config) {
            Ok(v) => v,
            Err(e) => {
                return ExecutionOutcome::Failed {
                    err: format!("{bin} network create: captured inspect JSON is invalid: {e}"),
                };
            }
        };
        // `docker network inspect` returns an array of one element;
        // unwrap that if necessary.
        let obj = match &inspect {
            serde_json::Value::Array(arr) => {
                arr.first().cloned().unwrap_or(serde_json::Value::Null)
            }
            v => v.clone(),
        };
        let argv = synthesize_network_create(bin, name, &obj);
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        match self.runner.run(&argv) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("{bin} network create: {e}"),
            },
        }
    }

    fn apply_compose_down(
        &self,
        bin: &str,
        project: &str,
        compose_file: &std::path::Path,
        dry_run: bool,
    ) -> ExecutionOutcome {
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        // `docker` plugin form: `docker compose -f <file> -p <project> up -d`.
        // For podman, podman-compose has the same flag shape.
        let argv = vec![
            bin.to_string(),
            "compose".to_string(),
            "-f".to_string(),
            compose_file.display().to_string(),
            "-p".to_string(),
            project.to_string(),
            "up".to_string(),
            "-d".to_string(),
        ];
        match self.runner.run(&argv) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("{bin} compose up: {e}"),
            },
        }
    }
}

/// Pure: from a `docker network inspect`-style JSON object, synthesize
/// the `docker network create` argv that reproduces it. Best-effort —
/// the fields we extract are the ones `docker network create` accepts
/// on the CLI. Anything unrecognized is ignored (the user can re-edit
/// from the captured JSON in `shit show`).
pub fn synthesize_network_create(
    bin: &str,
    name: &str,
    inspect: &serde_json::Value,
) -> Vec<String> {
    let mut argv = vec![bin.to_string(), "network".to_string(), "create".to_string()];
    if let Some(driver) = inspect.get("Driver").and_then(|v| v.as_str())
        && !driver.is_empty()
    {
        argv.push("--driver".to_string());
        argv.push(driver.to_string());
    }
    if let Some(internal) = inspect.get("Internal").and_then(|v| v.as_bool())
        && internal
    {
        argv.push("--internal".to_string());
    }
    if let Some(ipam) = inspect.get("IPAM")
        && let Some(configs) = ipam.get("Config").and_then(|v| v.as_array())
    {
        for c in configs {
            if let Some(subnet) = c.get("Subnet").and_then(|v| v.as_str()) {
                argv.push("--subnet".to_string());
                argv.push(subnet.to_string());
            }
            if let Some(gw) = c.get("Gateway").and_then(|v| v.as_str()) {
                argv.push("--gateway".to_string());
                argv.push(gw.to_string());
            }
            if let Some(range) = c.get("IPRange").and_then(|v| v.as_str()) {
                argv.push("--ip-range".to_string());
                argv.push(range.to_string());
            }
        }
    }
    if let Some(labels) = inspect.get("Labels").and_then(|v| v.as_object()) {
        for (k, val) in labels {
            if let Some(s) = val.as_str() {
                argv.push("--label".to_string());
                argv.push(format!("{k}={s}"));
            }
        }
    }
    if let Some(options) = inspect.get("Options").and_then(|v| v.as_object()) {
        for (k, val) in options {
            if let Some(s) = val.as_str() {
                argv.push("--opt".to_string());
                argv.push(format!("{k}={s}"));
            }
        }
    }
    argv.push(name.to_string());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::BlobHash;
    use crate::inverse::ContainerRuntime;
    use std::cell::RefCell;
    use std::path::PathBuf;

    type CallRecord = (String, Vec<String>, Vec<u8>);

    #[derive(Default)]
    struct SpyRunner {
        calls: RefCell<Vec<CallRecord>>,
        canned_inspect: RefCell<Vec<u8>>,
        inspect_should_fail: RefCell<bool>,
        run_should_fail: RefCell<bool>,
        stash_blobs: RefCell<std::collections::HashMap<BlobHash, Vec<u8>>>,
    }

    impl ContainerRunner for SpyRunner {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(("run".into(), argv.to_vec(), Vec::new()));
            if *self.run_should_fail.borrow() {
                Err("simulated run failure".into())
            } else {
                Ok(())
            }
        }
        fn run_with_stdin(&self, argv: &[String], stdin: &[u8]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(("run_stdin".into(), argv.to_vec(), stdin.to_vec()));
            Ok(())
        }
        fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
            self.calls
                .borrow_mut()
                .push(("capture".into(), argv.to_vec(), Vec::new()));
            if *self.inspect_should_fail.borrow() {
                Err("not found".into())
            } else {
                Ok(self.canned_inspect.borrow().clone())
            }
        }
        fn load_stash_tarball(&self, hash: &BlobHash) -> Option<Vec<u8>> {
            self.stash_blobs.borrow().get(hash).cloned()
        }
    }

    // ----- Rmi -----

    fn rmi_op(stash: Option<BlobHash>) -> InverseOp {
        InverseOp::ContainerRestore {
            runtime: ContainerRuntime::Docker,
            op: ContainerOp::Rmi {
                image: "nginx:1.25".into(),
                digest: Some("sha256:deadbeef".into()),
            },
            captured_config: b"{}".to_vec(),
            stash_image: None,
            stash_tarball: stash,
            requires_confirmation: true,
        }
    }

    #[test]
    fn rmi_reverse_runs_docker_load_with_tarball_on_stdin() {
        let runner = SpyRunner::default();
        let h = BlobHash::from_bytes([9; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(h, b"<tarball bytes>".to_vec());
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(&rmi_op(Some(h)), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "run_stdin");
        assert_eq!(calls[0].1, vec!["docker".to_string(), "load".to_string()]);
        assert_eq!(calls[0].2, b"<tarball bytes>");
    }

    #[test]
    fn rmi_without_stash_fails_cleanly() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        match exe.execute(&rmi_op(None), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("no stash tarball"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rmi_with_missing_tarball_blob_fails_cleanly() {
        let runner = SpyRunner::default();
        // hash NOT in stash_blobs → load returns None.
        let h = BlobHash::from_bytes([9; 32]);
        let exe = ContainerExecutor::new(runner);
        match exe.execute(&rmi_op(Some(h)), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("missing from store"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rmi_dry_run_loads_blob_but_does_not_exec() {
        let runner = SpyRunner::default();
        let h = BlobHash::from_bytes([9; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(h, b"<bytes>".to_vec());
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(&rmi_op(Some(h)), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        // No run/run_stdin invocation in dry-run.
        assert!(exe.runner.calls.borrow().is_empty());
    }

    // ----- VolumeRm -----

    fn volume_rm_op(stash: Option<BlobHash>, driver: Option<&str>) -> InverseOp {
        InverseOp::ContainerRestore {
            runtime: ContainerRuntime::Docker,
            op: ContainerOp::VolumeRm {
                name: "pgdata".into(),
                driver: driver.map(String::from),
            },
            captured_config: b"{}".to_vec(),
            stash_image: None,
            stash_tarball: stash,
            requires_confirmation: true,
        }
    }

    #[test]
    fn volume_rm_reverse_creates_then_extracts() {
        let runner = SpyRunner::default();
        let h = BlobHash::from_bytes([1; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(h, b"<tar.gz>".to_vec());
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(
            &volume_rm_op(Some(h), Some("local")),
            false,
            ConflictPolicy::Abort,
        );
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        // Step 1: docker volume create --driver local pgdata
        assert_eq!(calls[0].0, "run");
        assert_eq!(
            calls[0].1,
            vec!["docker", "volume", "create", "--driver", "local", "pgdata"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        // Step 2: docker run --rm -i -v pgdata:/data busybox tar -C /data -xzf -
        assert_eq!(calls[1].0, "run_stdin");
        assert!(calls[1].1.contains(&"busybox".to_string()));
        assert!(calls[1].1.contains(&"pgdata:/data".to_string()));
        assert_eq!(calls[1].2, b"<tar.gz>");
    }

    #[test]
    fn volume_rm_without_driver_omits_flag() {
        let runner = SpyRunner::default();
        let h = BlobHash::from_bytes([2; 32]);
        runner.stash_blobs.borrow_mut().insert(h, b"x".to_vec());
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(&volume_rm_op(Some(h), None), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        // Create argv must NOT contain --driver.
        assert!(!calls[0].1.iter().any(|s| s == "--driver"));
    }

    // ----- NetworkRm -----

    fn network_rm_op(inspect_json: &[u8]) -> InverseOp {
        InverseOp::ContainerRestore {
            runtime: ContainerRuntime::Docker,
            op: ContainerOp::NetworkRm {
                name: "frontend".into(),
            },
            captured_config: inspect_json.to_vec(),
            stash_image: None,
            stash_tarball: None,
            requires_confirmation: false,
        }
    }

    #[test]
    fn network_rm_synthesizes_create_with_driver_subnet_gateway() {
        let inspect = br#"[{
            "Driver": "bridge",
            "Internal": false,
            "IPAM": {
                "Config": [{
                    "Subnet": "172.20.0.0/16",
                    "Gateway": "172.20.0.1"
                }]
            },
            "Labels": {"com.example.env": "prod"},
            "Options": {"com.docker.network.bridge.name": "br-x"}
        }]"#;
        let exe = ContainerExecutor::new(SpyRunner::default());
        let outcome = exe.execute(&network_rm_op(inspect), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        let argv = &calls[0].1;
        assert!(argv.windows(2).any(|w| w == ["--driver", "bridge"]));
        assert!(argv.windows(2).any(|w| w == ["--subnet", "172.20.0.0/16"]));
        assert!(argv.windows(2).any(|w| w == ["--gateway", "172.20.0.1"]));
        assert!(
            argv.windows(2)
                .any(|w| w == ["--label", "com.example.env=prod"])
        );
        // Name is the last positional.
        assert_eq!(argv.last().unwrap(), "frontend");
    }

    #[test]
    fn network_rm_minimal_inspect_still_emits_create() {
        let inspect = br#"[{"Driver": "bridge"}]"#;
        let exe = ContainerExecutor::new(SpyRunner::default());
        let outcome = exe.execute(&network_rm_op(inspect), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls[0].1.last().unwrap(), "frontend");
    }

    #[test]
    fn network_rm_invalid_json_fails_cleanly() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        match exe.execute(&network_rm_op(b"{not json"), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => assert!(err.contains("invalid")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ----- Rm (informational) -----

    fn rm_op(was_running: bool, stash: Option<&str>) -> InverseOp {
        InverseOp::ContainerRestore {
            runtime: ContainerRuntime::Docker,
            op: ContainerOp::Rm {
                id: "abc123".into(),
                name: Some("web".into()),
                was_running,
            },
            captured_config: b"{}".to_vec(),
            stash_image: stash.map(String::from),
            stash_tarball: None,
            requires_confirmation: true,
        }
    }

    #[test]
    fn rm_running_with_existing_stash_returns_skipped_pending_dr() {
        let runner = SpyRunner::default();
        *runner.canned_inspect.borrow_mut() = b"{\"Id\":\"...\"}".to_vec();
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(
            &rm_op(true, Some("shit-stash:abc123:1700000000")),
            false,
            ConflictPolicy::Abort,
        );
        match outcome {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("DR-CR-22"), "got: {reason}");
            }
            other => panic!("expected Skipped (DR deferral), got {other:?}"),
        }
        // The stash-existence inspect ran.
        assert_eq!(exe.runner.calls.borrow()[0].0, "capture");
    }

    #[test]
    fn rm_running_missing_stash_image_fails() {
        let runner = SpyRunner::default();
        *runner.inspect_should_fail.borrow_mut() = true;
        let exe = ContainerExecutor::new(runner);
        match exe.execute(
            &rm_op(true, Some("shit-stash:gone:1700000000")),
            false,
            ConflictPolicy::Abort,
        ) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("stash image") && err.contains("missing"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rm_running_without_recorded_stash_fails() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        match exe.execute(&rm_op(true, None), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => assert!(err.contains("no stash image")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ----- ComposeDown -----

    fn compose_down_op() -> InverseOp {
        InverseOp::ContainerRestore {
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
        }
    }

    #[test]
    fn compose_down_reverse_is_compose_up_with_project_and_file() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        let outcome = exe.execute(&compose_down_op(), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        let argv = &calls[0].1;
        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "compose");
        assert!(
            argv.windows(2)
                .any(|w| w == ["-f", "/srv/myapp/docker-compose.yml"])
        );
        assert!(argv.windows(2).any(|w| w == ["-p", "myapp"]));
        assert!(argv.iter().any(|s| s == "up"));
        assert!(argv.iter().any(|s| s == "-d"));
    }

    #[test]
    fn supports_only_container_variant() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        assert!(exe.supports(&compose_down_op()));
        assert!(!exe.supports(&InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        }));
    }
}
