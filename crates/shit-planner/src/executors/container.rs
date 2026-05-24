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
            } => self.apply_rm(
                bin,
                id,
                name.as_deref(),
                *was_running,
                captured_config,
                stash_image,
                dry_run,
            ),
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
    #[allow(clippy::too_many_arguments)]
    fn apply_rm(
        &self,
        bin: &str,
        id: &str,
        name: Option<&str>,
        was_running: bool,
        captured_config: &[u8],
        stash_image: &Option<String>,
        dry_run: bool,
    ) -> ExecutionOutcome {
        // AR10.9 (DR-CR-22): full reverse synthesis. Parse the
        // captured `docker inspect` JSON, optionally substitute the
        // stash-commit image for a running-at-capture container, and
        // synthesize a `docker run -d` invocation that round-trips
        // the common ~15 options.
        let inspect: serde_json::Value = match serde_json::from_slice(captured_config) {
            Ok(v) => v,
            Err(e) => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rm reverse: captured inspect JSON is invalid: {e} \
                         (container `{}`, id `{id}`)",
                        name.unwrap_or(id),
                    ),
                };
            }
        };
        // `docker inspect <id>` returns an array-of-one; unwrap if so.
        let obj = match &inspect {
            serde_json::Value::Array(arr) => {
                arr.first().cloned().unwrap_or(serde_json::Value::Null)
            }
            v => v.clone(),
        };

        // The user-facing name. If the wire-level name was None
        // (auto-generated container), recover it from the inspect
        // blob's `.Name` field (docker reports a leading slash; strip).
        let restored_name = match name {
            Some(n) => n.to_string(),
            None => obj
                .get("Name")
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches('/').to_string())
                .unwrap_or_else(|| format!("shit-restored-{id}")),
        };

        // When the container was running at capture, the user's
        // rootfs may have diverged from the original image (in-place
        // edits, written files, etc.). The capture path commits the
        // running container to `shit-stash:<id>:<ts>` and ships that
        // tag as `stash_image`. The synthesized `docker run` uses
        // that image instead of the original `.Config.Image` so the
        // restored container has the same in-place state.
        //
        // Guard: if `was_running` but no stash, refuse cleanly —
        // running from `.Config.Image` would silently lose any
        // rootfs writes the user accumulated.
        if was_running && stash_image.is_none() {
            return ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rm reverse: container `{restored_name}` was running at \
                     capture but no stash image was recorded (capture path missed \
                     `{bin} commit`). Restoring from the original image would lose \
                     any rootfs writes."
                ),
            };
        }
        if let Some(stash) = stash_image {
            // Verify the stash image still exists before issuing the run.
            // A run-against-a-missing-image fails with an opaque
            // "Unable to find image" — we want to surface the actual
            // problem (stash GC'd / manually removed) earlier.
            let guard_argv = vec![
                bin.to_string(),
                "image".to_string(),
                "inspect".to_string(),
                stash.clone(),
            ];
            if let Err(e) = self.runner.capture(&guard_argv) {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rm reverse: stash image `{stash}` missing ({e}); \
                         cannot replay container `{restored_name}`"
                    ),
                };
            }
        }

        // Resolve the image source up-front so we can fail cleanly
        // before invoking the synthesizer if neither stash nor
        // captured .Config.Image is populated. Running with an empty
        // image would produce an opaque docker CLI error.
        let resolved_image = stash_image
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                obj.get("Config")
                    .and_then(|c| c.get("Image"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            });
        if resolved_image.is_none() {
            return ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rm reverse: captured inspect JSON has no resolvable image \
                     for container `{restored_name}` (neither stash_image nor \
                     .Config.Image populated)"
                ),
            };
        }

        let argv = synthesize_container_run(bin, &restored_name, &obj, stash_image.as_deref());

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        match self.runner.run(&argv) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("{bin} run (rm reverse): {e}"),
            },
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

/// Pure: from a `docker inspect <container>`-style JSON object,
/// synthesize the `docker run -d` argv that reproduces it. Returns
/// the full argv ready for `Command::new(bin).args(&argv[1..])`.
/// `image_override` lets the caller substitute the original
/// `.Config.Image` with the stash-commit image when the container
/// was running at capture time (the commit preserves rootfs changes
/// the original image doesn't have).
///
/// Best-effort — covers the common ~15 options that round-trip the
/// vast majority of user workloads (name, image, env, ports,
/// mounts, restart policy, network, working dir, user, hostname,
/// labels, privileged, read-only, cap-add/drop, entrypoint, cmd).
/// GPU runtime detection (DR-CR-30), IPC / PID / UTS namespace
/// modes, and resource limits (--memory / --cpus / --shm-size)
/// land in v1.x; the captured JSON is always available via `shit
/// show` for the user to fill in manually.
///
/// `name` is the container's user-visible name (the `--name` arg).
/// Docker assigns auto-names like `friendly_chandrasekhar` if the
/// user didn't provide one; we honor whatever the inspect blob
/// reports.
pub fn synthesize_container_run(
    bin: &str,
    name: &str,
    inspect: &serde_json::Value,
    image_override: Option<&str>,
) -> Vec<String> {
    let mut argv = vec![bin.to_string(), "run".to_string(), "-d".to_string()];

    argv.push("--name".to_string());
    argv.push(name.to_string());

    let config = inspect
        .get("Config")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let host_config = inspect
        .get("HostConfig")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // --hostname (best-effort; docker auto-generates from container
    // id if not set, so we only emit when the captured value is
    // distinguishable from the auto-generated form).
    if let Some(hostname) = config.get("Hostname").and_then(|v| v.as_str())
        && !hostname.is_empty()
        && !looks_like_auto_hostname(hostname, inspect)
    {
        argv.push("--hostname".to_string());
        argv.push(hostname.to_string());
    }

    // -u / --user
    if let Some(user) = config.get("User").and_then(|v| v.as_str())
        && !user.is_empty()
    {
        argv.push("-u".to_string());
        argv.push(user.to_string());
    }

    // -w / --workdir
    if let Some(wd) = config.get("WorkingDir").and_then(|v| v.as_str())
        && !wd.is_empty()
    {
        argv.push("-w".to_string());
        argv.push(wd.to_string());
    }

    // -e / --env from .Config.Env (array of "KEY=VALUE" strings).
    // Docker images bake env vars into their config; the captured
    // env may include image-default ones. Round-tripping them all is
    // safe (docker treats explicit -e identical to image-default for
    // the same key), and filtering against an image's baseline env
    // would require an extra `docker image inspect` call we'd rather
    // avoid in the executor.
    if let Some(envs) = config.get("Env").and_then(|v| v.as_array()) {
        for e in envs {
            if let Some(s) = e.as_str() {
                argv.push("-e".to_string());
                argv.push(s.to_string());
            }
        }
    }

    // --label from .Config.Labels (object of key→value strings).
    if let Some(labels) = config.get("Labels").and_then(|v| v.as_object()) {
        for (k, val) in labels {
            if let Some(s) = val.as_str() {
                argv.push("--label".to_string());
                argv.push(format!("{k}={s}"));
            }
        }
    }

    // -p / --publish from .HostConfig.PortBindings (object of
    // "<port>/<proto>" → array of { HostIp, HostPort }).
    if let Some(pbs) = host_config.get("PortBindings").and_then(|v| v.as_object()) {
        for (container_port_proto, bindings) in pbs {
            // container_port_proto is "80/tcp" etc. Split off the proto.
            let (cport, proto) = match container_port_proto.split_once('/') {
                Some((p, pr)) => (p, pr),
                None => (container_port_proto.as_str(), "tcp"),
            };
            if let Some(arr) = bindings.as_array() {
                for binding in arr {
                    let host_ip = binding.get("HostIp").and_then(|v| v.as_str()).unwrap_or("");
                    let host_port = binding
                        .get("HostPort")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let spec = if host_ip.is_empty() {
                        if host_port.is_empty() {
                            format!("{cport}/{proto}")
                        } else {
                            format!("{host_port}:{cport}/{proto}")
                        }
                    } else if host_port.is_empty() {
                        format!("{host_ip}::{cport}/{proto}")
                    } else {
                        format!("{host_ip}:{host_port}:{cport}/{proto}")
                    };
                    argv.push("-p".to_string());
                    argv.push(spec);
                }
            }
        }
    }

    // -v / --volume from .Mounts (array of mount specs). Docker
    // reports both bind mounts and named volumes here; the Type
    // field distinguishes them. tmpfs mounts (Type=tmpfs) round-trip
    // as --tmpfs <dst>.
    if let Some(mounts) = inspect.get("Mounts").and_then(|v| v.as_array()) {
        for m in mounts {
            let typ = m.get("Type").and_then(|v| v.as_str()).unwrap_or("");
            let dst = m.get("Destination").and_then(|v| v.as_str()).unwrap_or("");
            let rw = m.get("RW").and_then(|v| v.as_bool()).unwrap_or(true);
            let mode_suffix = if rw { "" } else { ":ro" };
            match typ {
                "volume" => {
                    let src = m.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                    if !src.is_empty() && !dst.is_empty() {
                        argv.push("-v".to_string());
                        argv.push(format!("{src}:{dst}{mode_suffix}"));
                    }
                }
                "bind" => {
                    let src = m.get("Source").and_then(|v| v.as_str()).unwrap_or("");
                    if !src.is_empty() && !dst.is_empty() {
                        argv.push("-v".to_string());
                        argv.push(format!("{src}:{dst}{mode_suffix}"));
                    }
                }
                "tmpfs" if !dst.is_empty() => {
                    argv.push("--tmpfs".to_string());
                    argv.push(dst.to_string());
                }
                _ => {} // unknown mount type; ignore
            }
        }
    }

    // --restart from .HostConfig.RestartPolicy
    if let Some(rp) = host_config.get("RestartPolicy") {
        let policy = rp.get("Name").and_then(|v| v.as_str()).unwrap_or("");
        if !policy.is_empty() && policy != "no" {
            let spec = match (policy, rp.get("MaximumRetryCount").and_then(|v| v.as_u64())) {
                ("on-failure", Some(n)) if n > 0 => format!("on-failure:{n}"),
                (p, _) => p.to_string(),
            };
            argv.push(format!("--restart={spec}"));
        }
    }

    // --network from .HostConfig.NetworkMode. Docker reports
    // "default" / "bridge" / "host" / "none" / "<container-name>" /
    // "<network-name>". We pass through; docker accepts all of
    // these as --network values. Omit when "default" since that's
    // docker's implicit choice.
    if let Some(nm) = host_config.get("NetworkMode").and_then(|v| v.as_str())
        && !nm.is_empty()
        && nm != "default"
    {
        argv.push("--network".to_string());
        argv.push(nm.to_string());
    }

    // --privileged
    if host_config
        .get("Privileged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        argv.push("--privileged".to_string());
    }

    // --read-only (.HostConfig.ReadonlyRootfs)
    if host_config
        .get("ReadonlyRootfs")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        argv.push("--read-only".to_string());
    }

    // --cap-add / --cap-drop
    if let Some(caps) = host_config.get("CapAdd").and_then(|v| v.as_array()) {
        for c in caps {
            if let Some(s) = c.as_str() {
                argv.push("--cap-add".to_string());
                argv.push(s.to_string());
            }
        }
    }
    if let Some(caps) = host_config.get("CapDrop").and_then(|v| v.as_array()) {
        for c in caps {
            if let Some(s) = c.as_str() {
                argv.push("--cap-drop".to_string());
                argv.push(s.to_string());
            }
        }
    }

    // --entrypoint (string form; docker also accepts an array but
    // the CLI flag takes a single string per docker convention).
    // Captured Entrypoint is an array; we join with spaces. If the
    // user's original entrypoint had spaces in a single arg this
    // round-trips imperfectly — documented limitation.
    if let Some(ep) = config.get("Entrypoint").and_then(|v| v.as_array())
        && !ep.is_empty()
    {
        let parts: Vec<String> = ep
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !parts.is_empty() {
            argv.push("--entrypoint".to_string());
            argv.push(parts.join(" "));
        }
    }

    // Image — the FINAL positional before cmd. Use image_override
    // when present (stash-commit for running containers), else
    // .Config.Image (the original tag). May be empty if neither is
    // populated; the caller (apply_rm) detects that and fails
    // cleanly before issuing the run.
    let image = image_override
        .map(String::from)
        .or_else(|| {
            config
                .get("Image")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .unwrap_or_default();
    argv.push(image);

    // Cmd — array of strings appended verbatim as positional args.
    if let Some(cmd) = config.get("Cmd").and_then(|v| v.as_array()) {
        for c in cmd {
            if let Some(s) = c.as_str() {
                argv.push(s.to_string());
            }
        }
    }

    argv
}

/// Docker auto-generates a hostname equal to the first 12 chars of
/// the container's full SHA-256 ID when the user doesn't pass
/// --hostname. Skip emitting --hostname if the captured value
/// matches that pattern, otherwise the restored container gets the
/// OLD container's id as a hostname which is wrong.
fn looks_like_auto_hostname(hostname: &str, inspect: &serde_json::Value) -> bool {
    let Some(id) = inspect.get("Id").and_then(|v| v.as_str()) else {
        return false;
    };
    hostname.len() == 12
        && id.starts_with(hostname)
        && hostname.chars().all(|c| c.is_ascii_hexdigit())
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

    // ----- Rm (AR10.9 / DR-CR-22: full reverse synthesis) -----

    fn rm_op_with_inspect(was_running: bool, stash: Option<&str>, inspect: &[u8]) -> InverseOp {
        InverseOp::ContainerRestore {
            runtime: ContainerRuntime::Docker,
            op: ContainerOp::Rm {
                id: "abc123".into(),
                name: Some("web".into()),
                was_running,
            },
            captured_config: inspect.to_vec(),
            stash_image: stash.map(String::from),
            stash_tarball: None,
            requires_confirmation: true,
        }
    }

    fn minimal_inspect() -> Vec<u8> {
        // Minimal-but-valid inspect: just enough that synthesize
        // produces an image positional.
        br#"{
            "Id": "abc123",
            "Name": "/web",
            "Config": {"Image": "nginx:alpine"},
            "HostConfig": {},
            "Mounts": []
        }"#
        .to_vec()
    }

    #[test]
    fn rm_running_with_existing_stash_runs_synthesized_argv() {
        let runner = SpyRunner::default();
        *runner.canned_inspect.borrow_mut() = b"{\"Id\":\"...\"}".to_vec();
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(
            &rm_op_with_inspect(
                true,
                Some("shit-stash:abc123:1700000000"),
                &minimal_inspect(),
            ),
            false,
            ConflictPolicy::Abort,
        );
        assert!(
            matches!(outcome, ExecutionOutcome::Applied),
            "got: {outcome:?}"
        );
        let calls = exe.runner.calls.borrow();
        // First: stash existence check (capture for image inspect).
        assert_eq!(calls[0].0, "capture");
        assert!(calls[0].1.contains(&"image".to_string()));
        // Second: the synthesized docker run.
        assert_eq!(calls[1].0, "run");
        let run_argv = &calls[1].1;
        assert_eq!(run_argv[0], "docker");
        assert_eq!(run_argv[1], "run");
        assert_eq!(run_argv[2], "-d");
        assert!(run_argv.contains(&"--name".into()));
        assert!(run_argv.contains(&"web".into()));
        // Image should be the STASH, not the original.
        assert!(run_argv.contains(&"shit-stash:abc123:1700000000".into()));
    }

    #[test]
    fn rm_running_missing_stash_image_fails() {
        let runner = SpyRunner::default();
        *runner.inspect_should_fail.borrow_mut() = true;
        let exe = ContainerExecutor::new(runner);
        match exe.execute(
            &rm_op_with_inspect(true, Some("shit-stash:gone:1700000000"), &minimal_inspect()),
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
        match exe.execute(
            &rm_op_with_inspect(true, None, &minimal_inspect()),
            false,
            ConflictPolicy::Abort,
        ) {
            ExecutionOutcome::Failed { err } => assert!(err.contains("no stash image")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rm_stopped_runs_synthesized_argv_from_original_image() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        let outcome = exe.execute(
            &rm_op_with_inspect(false, None, &minimal_inspect()),
            false,
            ConflictPolicy::Abort,
        );
        assert!(
            matches!(outcome, ExecutionOutcome::Applied),
            "got: {outcome:?}"
        );
        let calls = exe.runner.calls.borrow();
        assert_eq!(
            calls.len(),
            1,
            "no stash check needed for stopped container"
        );
        let run_argv = &calls[0].1;
        // Image should be the ORIGINAL, not a stash.
        assert!(run_argv.contains(&"nginx:alpine".into()));
        assert!(!run_argv.iter().any(|a| a.starts_with("shit-stash")));
    }

    #[test]
    fn rm_invalid_inspect_json_fails_cleanly() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        match exe.execute(
            &rm_op_with_inspect(false, None, b"{not json"),
            false,
            ConflictPolicy::Abort,
        ) {
            ExecutionOutcome::Failed { err } => assert!(err.contains("invalid")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rm_dry_run_returns_would_apply_without_executing() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        let outcome = exe.execute(
            &rm_op_with_inspect(false, None, &minimal_inspect()),
            true,
            ConflictPolicy::Abort,
        );
        assert!(matches!(outcome, ExecutionOutcome::WouldApply));
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn rm_missing_image_in_inspect_fails_cleanly() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        let inspect = br#"{
            "Id": "x",
            "Name": "/y",
            "Config": {},
            "HostConfig": {},
            "Mounts": []
        }"#;
        match exe.execute(
            &rm_op_with_inspect(false, None, inspect),
            false,
            ConflictPolicy::Abort,
        ) {
            ExecutionOutcome::Failed { err } => assert!(err.contains("no resolvable image")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rm_inspect_array_form_is_unwrapped() {
        // `docker inspect <id>` returns a single-element JSON array;
        // executor must unwrap it.
        let exe = ContainerExecutor::new(SpyRunner::default());
        let inspect = br#"[{
            "Id": "abc",
            "Name": "/web",
            "Config": {"Image": "alpine:3.20"},
            "HostConfig": {},
            "Mounts": []
        }]"#;
        let outcome = exe.execute(
            &rm_op_with_inspect(false, None, inspect),
            false,
            ConflictPolicy::Abort,
        );
        assert!(
            matches!(outcome, ExecutionOutcome::Applied),
            "got: {outcome:?}"
        );
        let calls = exe.runner.calls.borrow();
        assert!(calls[0].1.contains(&"alpine:3.20".into()));
    }

    // ----- synthesize_container_run unit tests -----

    fn syn(json: &str, image_override: Option<&str>) -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        synthesize_container_run("docker", "myapp", &v, image_override)
    }

    #[test]
    fn synth_minimal_emits_run_d_name_image() {
        let argv = syn(
            r#"{"Config":{"Image":"nginx:alpine"},"HostConfig":{}}"#,
            None,
        );
        assert_eq!(&argv[..5], &["docker", "run", "-d", "--name", "myapp"]);
        assert!(argv.contains(&"nginx:alpine".into()));
    }

    #[test]
    fn synth_image_override_wins() {
        let argv = syn(
            r#"{"Config":{"Image":"nginx:alpine"},"HostConfig":{}}"#,
            Some("shit-stash:abc:123"),
        );
        assert!(argv.contains(&"shit-stash:abc:123".into()));
        assert!(!argv.contains(&"nginx:alpine".into()));
    }

    #[test]
    fn synth_env_emits_dash_e_pairs() {
        let argv = syn(
            r#"{"Config":{"Image":"x","Env":["FOO=bar","BAZ=qux"]},"HostConfig":{}}"#,
            None,
        );
        let env_pairs: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "-e")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(env_pairs, vec!["FOO=bar", "BAZ=qux"]);
    }

    #[test]
    fn synth_port_bindings_render_host_container_proto() {
        let argv = syn(
            r#"{
                "Config":{"Image":"x"},
                "HostConfig":{
                    "PortBindings":{
                        "80/tcp":[{"HostIp":"","HostPort":"8080"}],
                        "443/tcp":[{"HostIp":"127.0.0.1","HostPort":"8443"}]
                    }
                }
            }"#,
            None,
        );
        let pubs: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "-p")
            .map(|(_, s)| s)
            .collect();
        assert!(pubs.contains(&&"8080:80/tcp".to_string()));
        assert!(pubs.contains(&&"127.0.0.1:8443:443/tcp".to_string()));
    }

    #[test]
    fn synth_named_volume_mount() {
        let argv = syn(
            r#"{
                "Config":{"Image":"x"},
                "HostConfig":{},
                "Mounts":[{"Type":"volume","Name":"pgdata","Destination":"/var/lib/postgresql/data","RW":true}]
            }"#,
            None,
        );
        let vols: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "-v")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(vols, vec!["pgdata:/var/lib/postgresql/data"]);
    }

    #[test]
    fn synth_bind_mount_with_ro() {
        let argv = syn(
            r#"{
                "Config":{"Image":"x"},
                "HostConfig":{},
                "Mounts":[{"Type":"bind","Source":"/etc/hosts","Destination":"/etc/hosts","RW":false}]
            }"#,
            None,
        );
        let vols: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "-v")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(vols, vec!["/etc/hosts:/etc/hosts:ro"]);
    }

    #[test]
    fn synth_tmpfs_mount_renders_tmpfs_flag() {
        let argv = syn(
            r#"{
                "Config":{"Image":"x"},
                "HostConfig":{},
                "Mounts":[{"Type":"tmpfs","Destination":"/run/secrets"}]
            }"#,
            None,
        );
        let tmpfs: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "--tmpfs")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(tmpfs, vec!["/run/secrets"]);
    }

    #[test]
    fn synth_restart_policy_unless_stopped() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}"#,
            None,
        );
        assert!(argv.contains(&"--restart=unless-stopped".to_string()));
    }

    #[test]
    fn synth_restart_policy_no_is_omitted() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"RestartPolicy":{"Name":"no"}}}"#,
            None,
        );
        assert!(!argv.iter().any(|s| s.starts_with("--restart")));
    }

    #[test]
    fn synth_restart_on_failure_with_retry_count() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":5}}}"#,
            None,
        );
        assert!(argv.contains(&"--restart=on-failure:5".to_string()));
    }

    #[test]
    fn synth_network_mode_default_is_omitted() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"NetworkMode":"default"}}"#,
            None,
        );
        assert!(!argv.iter().any(|s| s == "--network"));
    }

    #[test]
    fn synth_network_mode_custom_is_emitted() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"NetworkMode":"my-net"}}"#,
            None,
        );
        let nets: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "--network")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(nets, vec!["my-net"]);
    }

    #[test]
    fn synth_privileged_and_readonly() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"Privileged":true,"ReadonlyRootfs":true}}"#,
            None,
        );
        assert!(argv.contains(&"--privileged".to_string()));
        assert!(argv.contains(&"--read-only".to_string()));
    }

    #[test]
    fn synth_cap_add_drop() {
        let argv = syn(
            r#"{"Config":{"Image":"x"},"HostConfig":{"CapAdd":["NET_ADMIN"],"CapDrop":["ALL"]}}"#,
            None,
        );
        let adds: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "--cap-add")
            .map(|(_, s)| s)
            .collect();
        let drops: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "--cap-drop")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(adds, vec!["NET_ADMIN"]);
        assert_eq!(drops, vec!["ALL"]);
    }

    #[test]
    fn synth_cmd_appended_as_positionals_after_image() {
        let argv = syn(
            r#"{"Config":{"Image":"alpine","Cmd":["sh","-c","echo hi"]},"HostConfig":{}}"#,
            None,
        );
        // image at penultimate-ish position, then cmd tokens.
        let img_idx = argv.iter().position(|s| s == "alpine").unwrap();
        assert_eq!(&argv[img_idx..], &["alpine", "sh", "-c", "echo hi"]);
    }

    #[test]
    fn synth_workdir_user_hostname() {
        let argv = syn(
            r#"{
                "Id":"abc",
                "Config":{
                    "Image":"x",
                    "WorkingDir":"/srv",
                    "User":"1000:1000",
                    "Hostname":"my-host"
                },
                "HostConfig":{}
            }"#,
            None,
        );
        assert!(argv.windows(2).any(|w| w == ["-w", "/srv"]));
        assert!(argv.windows(2).any(|w| w == ["-u", "1000:1000"]));
        assert!(argv.windows(2).any(|w| w == ["--hostname", "my-host"]));
    }

    #[test]
    fn synth_auto_hostname_is_dropped() {
        // Hostname equal to first 12 chars of Id → auto-generated;
        // emitting --hostname would carry the OLD container's id
        // forward, which is wrong.
        let argv = syn(
            r#"{
                "Id":"abcdef0123456789",
                "Config":{"Image":"x","Hostname":"abcdef012345"},
                "HostConfig":{}
            }"#,
            None,
        );
        assert!(!argv.iter().any(|s| s == "--hostname"));
    }

    #[test]
    fn synth_labels_emitted_as_key_eq_value() {
        let argv = syn(
            r#"{
                "Config":{"Image":"x","Labels":{"app":"web","env":"prod"}},
                "HostConfig":{}
            }"#,
            None,
        );
        let labels: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && argv[*i - 1] == "--label")
            .map(|(_, s)| s)
            .collect();
        assert!(labels.contains(&&"app=web".to_string()));
        assert!(labels.contains(&&"env=prod".to_string()));
    }

    #[test]
    fn synth_entrypoint_joined_with_spaces() {
        let argv = syn(
            r#"{"Config":{"Image":"x","Entrypoint":["/bin/sh","-c"]},"HostConfig":{}}"#,
            None,
        );
        assert!(argv.windows(2).any(|w| w == ["--entrypoint", "/bin/sh -c"]));
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
