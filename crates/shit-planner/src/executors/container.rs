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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::container_lock::{
    ContainerEngineLockGuard, CooperativeContainerLockState, NoopContainerEngineLockGuard,
};
use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inode::BlobHash;
use crate::inverse::{ContainerOp, InverseOp};

/// Subprocess + stdin-piping abstraction. Tests inject a spy.
pub trait ContainerRunner {
    /// Hold the cooperative engine lock across a complete restore transaction.
    /// Injected runners default to a no-op; production runners override this.
    fn acquire_engine_lock(
        &self,
        _runtime: &str,
    ) -> Result<Box<dyn ContainerEngineLockGuard + '_>, String> {
        Ok(Box::new(NoopContainerEngineLockGuard))
    }
    /// Run an argv (no stdin). Returns `Ok` on exit 0.
    fn run(&self, argv: &[String]) -> Result<(), String>;
    /// Run an argv with `stdin_bytes` piped to stdin. Used for
    /// `docker load < tarball` and the volume `tar -xzf -` extract.
    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String>;
    /// Capture stdout of a command (used for stash-existence check
    /// via `docker image inspect ...`).
    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String>;
    /// Prove whether an image reference is absent, or return its immutable
    /// engine ID when present. Implementations must distinguish a real
    /// not-found result from daemon/context/auth failures; treating every
    /// non-zero `image inspect` as absence would let undo overwrite later
    /// state while the engine is unhealthy.
    fn probe_image_id(&self, runtime: &str, image: &str) -> Result<Option<String>, String> {
        Err(format!(
            "{runtime} image-state probe for `{image}` is not implemented by this runner"
        ))
    }
    /// Test-only: load tarball bytes for a stash blob hash. The
    /// production runner wraps the daemon-side container-stash store
    /// (C04.6). Returning `None` means the stash is missing.
    fn load_stash_tarball(&self, hash: &crate::inode::BlobHash) -> Option<Vec<u8>>;
}

/// Production runner: real `std::process::Command`. The
/// `SHIT_DURING_UNDO=1` env-var prevents the container wrapper from
/// re-capturing our own reverse invocation.
#[derive(Debug, Default)]
pub struct SystemContainerRunner {
    engine_lock: CooperativeContainerLockState,
}

/// Build a production undo subprocess with the routing boundary made
/// explicit. Docker's ambient context and endpoint environment must not be
/// able to redirect a captured local/default-context inverse at apply time.
///
/// `lock_token` is the cooperative engine-lock capability. When present, an
/// installed wrapper recognizes the exact token and enters reentrantly while
/// the Rust executor continues to own the lock across the complete restore.
pub fn configured_undo_command(runtime: &str, lock_token: Option<&str>) -> std::process::Command {
    let mut command = std::process::Command::new(runtime);
    command.env("SHIT_DURING_UNDO", "1");
    if let Some(token) = lock_token {
        command.env("SHIT_CONTAINER_LOCK_HELD", token);
    } else {
        command.env_remove("SHIT_CONTAINER_LOCK_HELD");
    }
    if runtime == "docker" {
        for name in [
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ] {
            command.env_remove(name);
        }
        command.args(["--context", "default"]);
    }
    command
}

impl ContainerRunner for SystemContainerRunner {
    fn acquire_engine_lock(
        &self,
        runtime: &str,
    ) -> Result<Box<dyn ContainerEngineLockGuard + '_>, String> {
        if runtime != "docker" {
            return Err(format!(
                "cooperative restore locking is not implemented for container runtime `{runtime}`"
            ));
        }
        self.engine_lock
            .acquire_docker()
            .map(|guard| Box::new(guard) as Box<dyn ContainerEngineLockGuard + '_>)
    }

    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let token = self.engine_lock.active_token()?;
        let status = configured_undo_command(cmd, token.as_deref())
            .args(args)
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
        let token = self.engine_lock.active_token()?;
        let mut child = configured_undo_command(cmd, token.as_deref())
            .args(args)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(error) = stdin.write_all(stdin_bytes) {
                // Dropping `Child` does not terminate or reap it. A restore
                // process that closes stdin early must not survive an
                // executor error and continue mutating container state in the
                // background.
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("write stdin to {cmd}: {error}"));
            }
        } else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("spawned {cmd} without a writable stdin pipe"));
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
        let token = self.engine_lock.active_token()?;
        let out = configured_undo_command(cmd, token.as_deref())
            .args(args)
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }

    fn probe_image_id(&self, runtime: &str, image: &str) -> Result<Option<String>, String> {
        let token = self.engine_lock.active_token()?;
        // Establish engine liveness first. This prevents a daemon outage from
        // being mistaken for proof that a tag is absent.
        let info = configured_undo_command(runtime, token.as_deref())
            .arg("info")
            .output()
            .map_err(|error| format!("spawn {runtime} info: {error}"))?;
        if !info.status.success() {
            return Err(format!(
                "{runtime} info exited {:?}: {}",
                info.status.code(),
                String::from_utf8_lossy(&info.stderr).trim()
            ));
        }

        let inspect = configured_undo_command(runtime, token.as_deref())
            .args(["image", "inspect", "--format", "{{.Id}}", image])
            .output()
            .map_err(|error| format!("spawn {runtime} image inspect: {error}"))?;
        if inspect.status.success() {
            let id = String::from_utf8(inspect.stdout).map_err(|error| {
                format!("{runtime} image inspect returned non-UTF-8 ID: {error}")
            })?;
            let id = id.trim();
            if id.is_empty() {
                return Err(format!(
                    "{runtime} image inspect succeeded for `{image}` without an image ID"
                ));
            }
            return Ok(Some(id.to_string()));
        }

        let stderr = String::from_utf8_lossy(&inspect.stderr);
        let normalized = stderr.to_ascii_lowercase();
        let proven_missing = normalized.contains("no such image")
            || normalized.contains("image not known")
            || normalized.contains("image not found")
            || normalized.contains("does not exist");
        if proven_missing {
            Ok(None)
        } else {
            Err(format!(
                "{runtime} image inspect `{image}` exited {:?}: {}",
                inspect.status.code(),
                stderr.trim()
            ))
        }
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
    /// Tarballs pinned in memory for the duration of one plan. Preflight loads
    /// every recovery-critical blob before the first mutation; execution must
    /// use those bytes so concurrent GC cannot invalidate the checked plan.
    preflighted_tarballs: Mutex<HashMap<BlobHash, Arc<[u8]>>>,
}

impl<R: ContainerRunner> ContainerExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            preflighted_tarballs: Mutex::new(HashMap::new()),
        }
    }

    fn preflight_tarball(&self, hash: &BlobHash, missing_error: String) -> Result<(), String> {
        {
            let tarballs = self
                .preflighted_tarballs
                .lock()
                .map_err(|_| "container preflight tarball cache lock poisoned".to_string())?;
            if tarballs.contains_key(hash) {
                return Ok(());
            }
        }

        let bytes = self.runner.load_stash_tarball(hash).ok_or(missing_error)?;
        self.preflighted_tarballs
            .lock()
            .map_err(|_| "container preflight tarball cache lock poisoned".to_string())?
            .insert(*hash, Arc::from(bytes));
        Ok(())
    }

    /// Prefer plan-pinned bytes, but preserve direct executor use by falling
    /// back to the runner when no orchestrator preflight has populated the
    /// cache.
    fn preflighted_or_live_tarball(&self, hash: &BlobHash) -> Result<Option<Arc<[u8]>>, String> {
        if let Some(bytes) = self
            .preflighted_tarballs
            .lock()
            .map_err(|_| "container preflight tarball cache lock poisoned".to_string())?
            .get(hash)
            .cloned()
        {
            return Ok(Some(bytes));
        }
        Ok(self.runner.load_stash_tarball(hash).map(Arc::from))
    }
}

impl<R: ContainerRunner> InverseOpExecutor for ContainerExecutor<R> {
    fn begin_plan_execution(&self, _dry_run: bool) {
        if let Ok(mut tarballs) = self.preflighted_tarballs.lock() {
            tarballs.clear();
        }
    }

    fn finish_plan_execution(&self) {
        if let Ok(mut tarballs) = self.preflighted_tarballs.lock() {
            tarballs.clear();
        }
    }

    fn preflight(&self, op: &InverseOp) -> Result<(), String> {
        let InverseOp::ContainerRestore {
            runtime,
            op: container_op,
            stash_tarball,
            ..
        } = op
        else {
            return Ok(());
        };

        match container_op {
            ContainerOp::Rmi { image, .. } => {
                let ContainerOp::Rmi { digest, .. } = container_op else {
                    unreachable!()
                };
                let expected_id = digest.as_deref().ok_or_else(|| {
                    format!(
                        "{} rmi reverse: capture for `{image}` has no immutable image ID; refusing to load a tag-only archive",
                        runtime.as_str()
                    )
                })?;
                match self.runner.probe_image_id(runtime.as_str(), image)? {
                    None => {}
                    Some(current_id) if same_image_id(&current_id, expected_id) => {}
                    Some(current_id) => {
                        return Err(format!(
                            "{} rmi reverse: image reference `{image}` now resolves to `{current_id}`, not captured `{expected_id}`; refusing to overwrite later state",
                            runtime.as_str()
                        ));
                    }
                }
                let hash = stash_tarball.as_ref().ok_or_else(|| {
                    format!(
                        "{} rmi reverse: no stash tarball recorded for image `{image}` \
                         (capture path missed `{} save`)",
                        runtime.as_str(),
                        runtime.as_str()
                    )
                })?;
                self.preflight_tarball(
                    hash,
                    format!(
                        "{} rmi reverse: stash tarball for `{image}` missing from store \
                         (GC'd past retention or manually removed)",
                        runtime.as_str()
                    ),
                )
            }
            ContainerOp::VolumeRm { name, .. } => {
                let hash = stash_tarball.as_ref().ok_or_else(|| {
                    format!(
                        "{} volume rm reverse: no stash tarball recorded for volume \
                         `{name}` (capture path missed the tar step)",
                        runtime.as_str()
                    )
                })?;
                self.preflight_tarball(
                    hash,
                    format!(
                        "{} volume rm reverse: stash tarball for `{name}` missing from \
                         store (GC'd past retention or manually removed)",
                        runtime.as_str()
                    ),
                )
            }
            _ => Ok(()),
        }
    }

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
            ContainerOp::Pull { image, resolved_id } => {
                self.apply_pull(image, resolved_id.as_deref(), dry_run)
            }
        }
    }
}

impl<R: ContainerRunner> ContainerExecutor<R> {
    /// AU23 / DR-CR-51 — `docker pull` is non-destructive and
    /// idempotent. The image is in the user's local store; the
    /// honest inverse would be `docker rmi <image>` but that's
    /// almost never what the user wants when they say "undo my
    /// pull". Emit `Skipped` with a clear human-readable note;
    /// the captured `resolved_id` lets `shit show` display which
    /// digest landed regardless of whether the floating tag has
    /// moved since.
    fn apply_pull(
        &self,
        image: &str,
        resolved_id: Option<&str>,
        dry_run: bool,
    ) -> ExecutionOutcome {
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        let detail = match resolved_id {
            Some(id) => format!(
                "docker pull {image} (resolved: {id}) — informational; pull is idempotent. To remove, run `docker rmi {image}` manually."
            ),
            None => format!(
                "docker pull {image} — informational; pull is idempotent. To remove, run `docker rmi {image}` manually."
            ),
        };
        ExecutionOutcome::Skipped { reason: detail }
    }

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

        // Running and stopped containers can both have writable-layer changes.
        // The capture path therefore commits every removed container and ships
        // that tag as `stash_image`. Falling back to `.Config.Image` would be
        // silently lossy for either state.
        if stash_image.is_none() {
            return ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rm reverse: container `{restored_name}` has no stash image \
                     (capture path missed `{bin} commit`). Restoring from the original \
                     image would lose writable-layer changes."
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

        let mut argv = synthesize_container_run(bin, &restored_name, &obj, stash_image.as_deref());
        if !was_running {
            // Preserve lifecycle state: `docker create` reconstructs a stopped
            // container, while the normal `run -d` path recreates a running one.
            argv[1] = "create".to_string();
            if argv.get(2).map(String::as_str) == Some("-d") {
                argv.remove(2);
            }
        }

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
        digest: Option<&str>,
        stash_tarball: &Option<crate::inode::BlobHash>,
        dry_run: bool,
    ) -> ExecutionOutcome {
        if bin != "docker" {
            return ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rmi reverse: the lossless restore boundary supports only Docker's local `default` context"
                ),
            };
        }
        let Some(expected_id) = digest else {
            return ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rmi reverse: capture for `{image}` has no immutable image ID; refusing to load a tag-only archive"
                ),
            };
        };
        // One guard spans the first conflict probe, archive load, conditional
        // retag, and final postcondition. Per-subprocess wrapper locking would
        // leave TOCTOU windows between those steps.
        let _engine_lock = if dry_run {
            None
        } else {
            match self.runner.acquire_engine_lock(bin) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    return ExecutionOutcome::Failed {
                        err: format!("{bin} rmi reverse: could not acquire engine lock: {error}"),
                    };
                }
            }
        };
        match self.runner.probe_image_id(bin, image) {
            Ok(None) => {}
            Ok(Some(current_id)) if same_image_id(&current_id, expected_id) => {
                return ExecutionOutcome::Skipped {
                    reason: format!(
                        "{bin} rmi reverse: `{image}` already resolves to captured image `{expected_id}`"
                    ),
                };
            }
            Ok(Some(current_id)) => {
                return ExecutionOutcome::Conflict {
                    kind: crate::inverse::Conflict::Hard {
                        detail: format!(
                            "{bin} rmi reverse: `{image}` now resolves to `{current_id}`, not captured `{expected_id}`; loading the archive would overwrite later state"
                        ),
                    },
                };
            }
            Err(error) => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rmi reverse: could not prove `{image}` is absent before load: {error}"
                    ),
                };
            }
        }
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
        let tarball = match self.preflighted_or_live_tarball(hash) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rmi reverse: stash tarball for `{image}` missing from store \
                         (GC'd past retention or manually removed)"
                    ),
                };
            }
            Err(err) => return ExecutionOutcome::Failed { err },
        };
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        let argv = vec![bin.to_string(), "load".to_string()];
        if let Err(error) = self.runner.run_with_stdin(&argv, tarball.as_ref()) {
            return ExecutionOutcome::Failed {
                err: format!("{bin} load: {error}"),
            };
        }

        // Archives are captured by immutable ID. They may therefore load
        // without recreating the user's original tag, and an archive from a
        // different engine may carry a normalized tag spelling. Re-probe
        // after the potentially long load before creating the tag so a
        // concurrent later-state change is never overwritten.
        match self.runner.probe_image_id(bin, image) {
            Ok(None) => {
                let tag_argv = vec![
                    bin.to_string(),
                    "tag".to_string(),
                    expected_id.to_string(),
                    image.to_string(),
                ];
                if let Err(error) = self.runner.run(&tag_argv) {
                    return ExecutionOutcome::Failed {
                        err: format!(
                            "{bin} rmi reverse loaded `{expected_id}` but could not restore tag `{image}`: {error}"
                        ),
                    };
                }
            }
            Ok(Some(current_id)) if same_image_id(&current_id, expected_id) => {}
            Ok(Some(current_id)) => {
                return ExecutionOutcome::Conflict {
                    kind: crate::inverse::Conflict::Hard {
                        detail: format!(
                            "{bin} rmi reverse loaded `{expected_id}`, but `{image}` concurrently appeared as `{current_id}`; refusing to retag later state"
                        ),
                    },
                };
            }
            Err(error) => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} rmi reverse loaded `{expected_id}` but could not re-check `{image}` before retagging: {error}"
                    ),
                };
            }
        }

        match self.runner.probe_image_id(bin, image) {
            Ok(Some(current_id)) if same_image_id(&current_id, expected_id) => {
                ExecutionOutcome::Applied
            }
            Ok(Some(current_id)) => ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rmi reverse postcondition failed: `{image}` resolves to `{current_id}`, not `{expected_id}`"
                ),
            },
            Ok(None) => ExecutionOutcome::Failed {
                err: format!(
                    "{bin} rmi reverse postcondition failed: restored tag `{image}` is absent"
                ),
            },
            Err(error) => ExecutionOutcome::Failed {
                err: format!("{bin} rmi reverse could not verify restored tag `{image}`: {error}"),
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
        let tarball = match self.preflighted_or_live_tarball(hash) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return ExecutionOutcome::Failed {
                    err: format!(
                        "{bin} volume rm reverse: stash tarball for `{name}` missing from \
                         store (GC'd past retention or manually removed)"
                    ),
                };
            }
            Err(err) => return ExecutionOutcome::Failed { err },
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
        match self.runner.run_with_stdin(&extract_argv, tarball.as_ref()) {
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

    // Docker's CLI accepts one executable for `--entrypoint`; any remaining
    // entrypoint elements must be placed after the image, ahead of Config.Cmd.
    // Joining the captured array with spaces changes argv boundaries and can
    // turn `["/bin/sh", "-c"]` into a lookup for a literal executable named
    // `/bin/sh -c`.
    let mut entrypoint_tail = Vec::new();
    if let Some(ep) = config.get("Entrypoint").and_then(|v| v.as_array()) {
        let mut parts = ep.iter().filter_map(|value| value.as_str());
        if let Some(executable) = parts.next().filter(|value| !value.is_empty()) {
            argv.push("--entrypoint".to_string());
            argv.push(executable.to_string());
            entrypoint_tail.extend(parts.map(String::from));
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

    // With an explicit entrypoint override Docker treats positionals after
    // the image as argv for that executable. Preserve the captured entrypoint
    // tail before appending Config.Cmd.
    argv.extend(entrypoint_tail);

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

fn same_image_id(actual: &str, expected: &str) -> bool {
    fn normalized(value: &str) -> &str {
        value.trim().strip_prefix("sha256:").unwrap_or(value.trim())
    }
    normalized(actual) == normalized(expected)
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
    use crate::events::{CommandId, CommandRecord};
    use crate::executor::OutcomeKind;
    use crate::inode::BlobHash;
    use crate::inverse::{ContainerRuntime, PlanNode, UndoPlan};
    use crate::orchestrator::Orchestrator;
    use crate::probe::mock::InMemoryProbe;
    use crate::time::TimePoint;
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;
    use uuid::Uuid;

    type CallRecord = (String, Vec<String>, Vec<u8>);

    #[derive(Default)]
    struct SpyRunner {
        calls: RefCell<Vec<CallRecord>>,
        canned_inspect: RefCell<Vec<u8>>,
        inspect_should_fail: RefCell<bool>,
        run_should_fail: RefCell<bool>,
        image_probe_error: RefCell<Option<String>>,
        image_ids: RefCell<std::collections::HashMap<String, String>>,
        stash_blobs: RefCell<std::collections::HashMap<BlobHash, Vec<u8>>>,
        require_lock: Cell<bool>,
        lock_held: Cell<bool>,
    }

    struct SpyLockGuard<'a>(&'a Cell<bool>);

    impl ContainerEngineLockGuard for SpyLockGuard<'_> {}

    impl Drop for SpyLockGuard<'_> {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }

    impl ContainerRunner for SpyRunner {
        fn acquire_engine_lock(
            &self,
            runtime: &str,
        ) -> Result<Box<dyn ContainerEngineLockGuard + '_>, String> {
            assert_eq!(runtime, "docker");
            assert!(!self.lock_held.replace(true), "test lock acquired twice");
            Ok(Box::new(SpyLockGuard(&self.lock_held)))
        }

        fn run(&self, argv: &[String]) -> Result<(), String> {
            assert!(!self.require_lock.get() || self.lock_held.get());
            self.calls
                .borrow_mut()
                .push(("run".into(), argv.to_vec(), Vec::new()));
            if *self.run_should_fail.borrow() {
                Err("simulated run failure".into())
            } else {
                if argv.get(1).map(String::as_str) == Some("tag")
                    && let (Some(id), Some(image)) = (argv.get(2), argv.get(3))
                {
                    self.image_ids
                        .borrow_mut()
                        .insert(image.clone(), id.clone());
                }
                Ok(())
            }
        }
        fn run_with_stdin(&self, argv: &[String], stdin: &[u8]) -> Result<(), String> {
            assert!(!self.require_lock.get() || self.lock_held.get());
            self.calls
                .borrow_mut()
                .push(("run_stdin".into(), argv.to_vec(), stdin.to_vec()));
            Ok(())
        }
        fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
            assert!(!self.require_lock.get() || self.lock_held.get());
            self.calls
                .borrow_mut()
                .push(("capture".into(), argv.to_vec(), Vec::new()));
            if *self.inspect_should_fail.borrow() {
                Err("not found".into())
            } else {
                Ok(self.canned_inspect.borrow().clone())
            }
        }
        fn probe_image_id(&self, runtime: &str, image: &str) -> Result<Option<String>, String> {
            assert!(!self.require_lock.get() || self.lock_held.get());
            self.calls.borrow_mut().push((
                "probe_image".into(),
                vec![runtime.into(), image.into()],
                Vec::new(),
            ));
            if let Some(error) = self.image_probe_error.borrow().clone() {
                return Err(error);
            }
            Ok(self.image_ids.borrow().get(image).cloned())
        }
        fn load_stash_tarball(&self, hash: &BlobHash) -> Option<Vec<u8>> {
            assert!(!self.require_lock.get() || self.lock_held.get());
            self.stash_blobs.borrow().get(hash).cloned()
        }
    }

    #[derive(Default)]
    struct SyncSpyRunner {
        calls: Mutex<Vec<CallRecord>>,
        stash_blobs: Mutex<HashMap<BlobHash, Vec<u8>>>,
        image_ids: Mutex<HashMap<String, String>>,
    }

    impl ContainerRunner for SyncSpyRunner {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(("run".into(), argv.to_vec(), Vec::new()));
            if argv.get(1).map(String::as_str) == Some("tag")
                && let (Some(id), Some(image)) = (argv.get(2), argv.get(3))
            {
                self.image_ids
                    .lock()
                    .unwrap()
                    .insert(image.clone(), id.clone());
            }
            Ok(())
        }

        fn run_with_stdin(&self, argv: &[String], stdin: &[u8]) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(("run_stdin".into(), argv.to_vec(), stdin.to_vec()));
            Ok(())
        }

        fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
            self.calls
                .lock()
                .unwrap()
                .push(("capture".into(), argv.to_vec(), Vec::new()));
            Ok(Vec::new())
        }

        fn probe_image_id(&self, runtime: &str, image: &str) -> Result<Option<String>, String> {
            self.calls.lock().unwrap().push((
                "probe_image".into(),
                vec![runtime.into(), image.into()],
                Vec::new(),
            ));
            Ok(self.image_ids.lock().unwrap().get(image).cloned())
        }

        fn load_stash_tarball(&self, hash: &BlobHash) -> Option<Vec<u8>> {
            self.stash_blobs.lock().unwrap().get(hash).cloned()
        }
    }

    fn plan_for(ops: Vec<InverseOp>) -> UndoPlan {
        UndoPlan {
            command: CommandRecord {
                command: CommandId {
                    session: Uuid::nil(),
                    seq: 1,
                },
                cmd_string: Some("container test".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 1,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::min(),
                ended_at: None,
                exit_code: None,
                event_ids: Vec::new(),
            },
            nodes: ops
                .into_iter()
                .enumerate()
                .map(|(cohort, op)| PlanNode {
                    op,
                    cohort: cohort as u32,
                    conflict: None,
                })
                .collect(),
            warnings: Vec::new(),
        }
    }

    fn mutating_network_rm_op() -> InverseOp {
        InverseOp::ContainerRestore {
            runtime: ContainerRuntime::Docker,
            op: ContainerOp::NetworkRm {
                name: "test-network".into(),
            },
            captured_config: b"{}".to_vec(),
            stash_image: None,
            stash_tarball: None,
            requires_confirmation: false,
        }
    }

    // ----- Rmi -----

    #[test]
    fn production_docker_commands_pin_default_route_and_scrub_overrides() {
        let command = configured_undo_command("docker", Some("docker-engine:42:nonce"));
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["--context", "default"]);

        let env: std::collections::HashMap<_, _> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(env.get("SHIT_DURING_UNDO"), Some(&Some("1".into())));
        assert_eq!(
            env.get("SHIT_CONTAINER_LOCK_HELD"),
            Some(&Some("docker-engine:42:nonce".into()))
        );
        for name in [
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ] {
            assert_eq!(env.get(name), Some(&None), "{name} must be removed");
        }
    }

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
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0].0, "probe_image");
        assert_eq!(calls[1].0, "run_stdin");
        assert_eq!(calls[1].1, vec!["docker".to_string(), "load".to_string()]);
        assert_eq!(calls[1].2, b"<tarball bytes>");
        assert_eq!(calls[2].0, "probe_image");
        assert_eq!(
            calls[3].1,
            vec![
                "docker".to_string(),
                "tag".to_string(),
                "sha256:deadbeef".to_string(),
                "nginx:1.25".to_string(),
            ]
        );
        assert_eq!(calls[4].0, "probe_image");
    }

    #[test]
    fn rmi_restore_holds_one_engine_lock_across_every_runtime_step() {
        let runner = SpyRunner::default();
        let hash = BlobHash::from_bytes([0x19; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(hash, b"archive".to_vec());
        runner.require_lock.set(true);
        let executor = ContainerExecutor::new(runner);

        assert_eq!(
            executor.execute(&rmi_op(Some(hash)), false, ConflictPolicy::Abort),
            ExecutionOutcome::Applied
        );
        assert!(
            !executor.runner.lock_held.get(),
            "engine lock must release after the final postcondition probe"
        );
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
    fn rmi_refuses_to_overwrite_a_later_tag_target() {
        let runner = SpyRunner::default();
        let hash = BlobHash::from_bytes([0x41; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(hash, b"archive".to_vec());
        runner
            .image_ids
            .borrow_mut()
            .insert("nginx:1.25".into(), "sha256:later".into());
        let exe = ContainerExecutor::new(runner);

        let outcome = exe.execute(&rmi_op(Some(hash)), false, ConflictPolicy::Force);
        assert!(matches!(
            outcome,
            ExecutionOutcome::Conflict {
                kind: crate::inverse::Conflict::Hard { ref detail }
            } if detail.contains("later state")
        ));
        assert!(
            exe.runner
                .calls
                .borrow()
                .iter()
                .all(|call| call.0 != "run_stdin")
        );
    }

    #[test]
    fn rmi_is_idempotent_when_tag_already_has_captured_id() {
        let runner = SpyRunner::default();
        let hash = BlobHash::from_bytes([0x42; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(hash, b"archive".to_vec());
        runner
            .image_ids
            .borrow_mut()
            .insert("nginx:1.25".into(), "deadbeef".into());
        let exe = ContainerExecutor::new(runner);

        assert!(matches!(
            exe.execute(&rmi_op(Some(hash)), false, ConflictPolicy::Abort),
            ExecutionOutcome::Skipped { reason } if reason.contains("already resolves")
        ));
    }

    #[test]
    fn rmi_probe_failure_is_not_mistaken_for_absence() {
        let runner = SpyRunner::default();
        let hash = BlobHash::from_bytes([0x43; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(hash, b"archive".to_vec());
        *runner.image_probe_error.borrow_mut() = Some("daemon unavailable".into());
        let exe = ContainerExecutor::new(runner);

        assert!(matches!(
            exe.execute(&rmi_op(Some(hash)), false, ConflictPolicy::Abort),
            ExecutionOutcome::Failed { err } if err.contains("could not prove")
        ));
    }

    #[test]
    fn rmi_requires_an_immutable_captured_image_id() {
        let mut op = rmi_op(Some(BlobHash::from_bytes([0x44; 32])));
        if let InverseOp::ContainerRestore {
            op: ContainerOp::Rmi { digest, .. },
            ..
        } = &mut op
        {
            *digest = None;
        }
        let exe = ContainerExecutor::new(SpyRunner::default());
        assert!(matches!(
            exe.execute(&op, false, ConflictPolicy::Abort),
            ExecutionOutcome::Failed { err } if err.contains("no immutable image ID")
        ));
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
        // Dry-run still proves the target tag is absent, but does not mutate.
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "probe_image");
    }

    #[test]
    fn rmi_preflight_pins_tarball_bytes_through_execution() {
        let runner = SpyRunner::default();
        let hash = BlobHash::from_bytes([0x31; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(hash, b"pinned tarball".to_vec());
        let exe = ContainerExecutor::new(runner);
        let op = rmi_op(Some(hash));

        exe.begin_plan_execution(false);
        exe.preflight(&op).unwrap();
        exe.runner.stash_blobs.borrow_mut().remove(&hash);
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        exe.finish_plan_execution();

        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[0].0, "probe_image");
        assert_eq!(calls[1].0, "probe_image");
        assert_eq!(calls[2].0, "run_stdin");
        assert_eq!(calls[2].2, b"pinned tarball");
        assert_eq!(calls[3].0, "probe_image");
        assert_eq!(calls[4].0, "run");
        assert_eq!(calls[5].0, "probe_image");
    }

    #[test]
    fn rmi_preflight_requires_hash_and_present_bytes() {
        let exe = ContainerExecutor::new(SpyRunner::default());
        let no_hash = exe.preflight(&rmi_op(None)).unwrap_err();
        assert!(no_hash.contains("no stash tarball"), "got: {no_hash}");

        let missing = exe
            .preflight(&rmi_op(Some(BlobHash::from_bytes([0x32; 32]))))
            .unwrap_err();
        assert!(missing.contains("missing from store"), "got: {missing}");
    }

    #[test]
    fn missing_late_rmi_stash_prevents_earlier_serial_container_mutation() {
        let exe = ContainerExecutor::new(SyncSpyRunner::default());
        let probe = InMemoryProbe::new();
        let plan = plan_for(vec![
            mutating_network_rm_op(),
            rmi_op(Some(BlobHash::from_bytes([0x33; 32]))),
        ]);

        let report = Orchestrator::new(&exe, &probe).run(&plan, false, ConflictPolicy::Force);

        assert_eq!(report.records[0].outcome_kind, OutcomeKind::Skipped);
        assert_eq!(report.records[1].outcome_kind, OutcomeKind::Failed);
        assert!(
            exe.runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.0 == "probe_image")
        );
    }

    #[test]
    fn missing_late_rmi_stash_prevents_earlier_parallel_container_mutation() {
        let exe = ContainerExecutor::new(SyncSpyRunner::default());
        let probe = InMemoryProbe::new();
        let plan = plan_for(vec![
            mutating_network_rm_op(),
            rmi_op(Some(BlobHash::from_bytes([0x34; 32]))),
        ]);

        let report =
            Orchestrator::new(&exe, &probe).run_parallel(&plan, false, ConflictPolicy::Skip, 2);

        assert_eq!(report.records[0].outcome_kind, OutcomeKind::Skipped);
        assert_eq!(report.records[1].outcome_kind, OutcomeKind::Failed);
        assert!(
            exe.runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.0 == "probe_image")
        );
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

    #[test]
    fn volume_preflight_requires_and_pins_tarball_bytes() {
        let runner = SpyRunner::default();
        let hash = BlobHash::from_bytes([0x35; 32]);
        runner
            .stash_blobs
            .borrow_mut()
            .insert(hash, b"pinned volume tarball".to_vec());
        let exe = ContainerExecutor::new(runner);
        let op = volume_rm_op(Some(hash), None);

        let no_hash = exe.preflight(&volume_rm_op(None, None)).unwrap_err();
        assert!(no_hash.contains("no stash tarball"), "got: {no_hash}");

        exe.begin_plan_execution(false);
        exe.preflight(&op).unwrap();
        exe.runner.stash_blobs.borrow_mut().remove(&hash);
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        exe.finish_plan_execution();

        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "run_stdin");
        assert_eq!(calls[1].2, b"pinned volume tarball");
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
    fn rm_stopped_recreates_stopped_container_from_stash_image() {
        let runner = SpyRunner::default();
        *runner.canned_inspect.borrow_mut() = b"{\"Id\":\"...\"}".to_vec();
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(
            &rm_op_with_inspect(
                false,
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
        assert_eq!(calls.len(), 2);
        let create_argv = &calls[1].1;
        assert_eq!(create_argv[1], "create");
        assert!(!create_argv.contains(&"-d".into()));
        assert!(create_argv.contains(&"shit-stash:abc123:1700000000".into()));
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
        let runner = SpyRunner::default();
        *runner.canned_inspect.borrow_mut() = b"{\"Id\":\"...\"}".to_vec();
        let exe = ContainerExecutor::new(runner);
        let outcome = exe.execute(
            &rm_op_with_inspect(false, Some("shit-stash:abc123"), &minimal_inspect()),
            true,
            ConflictPolicy::Abort,
        );
        assert!(matches!(outcome, ExecutionOutcome::WouldApply));
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1, "dry run may verify but must not mutate");
        assert_eq!(calls[0].0, "capture");
    }

    #[test]
    fn rm_stopped_without_recorded_stash_also_fails() {
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
            ExecutionOutcome::Failed { err } => assert!(err.contains("no stash image")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn rm_inspect_array_form_is_unwrapped() {
        // `docker inspect <id>` returns a single-element JSON array;
        // executor must unwrap it.
        let runner = SpyRunner::default();
        *runner.canned_inspect.borrow_mut() = b"{\"Id\":\"stash\"}".to_vec();
        let exe = ContainerExecutor::new(runner);
        let inspect = br#"[{
            "Id": "abc",
            "Name": "/web",
            "Config": {"Image": "alpine:3.20"},
            "HostConfig": {},
            "Mounts": []
        }]"#;
        let outcome = exe.execute(
            &rm_op_with_inspect(false, Some("shit-stash:abc"), inspect),
            false,
            ConflictPolicy::Abort,
        );
        assert!(
            matches!(outcome, ExecutionOutcome::Applied),
            "got: {outcome:?}"
        );
        let calls = exe.runner.calls.borrow();
        assert!(calls[1].1.contains(&"shit-stash:abc".into()));
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
    fn synth_entrypoint_preserves_argv_boundaries() {
        let argv = syn(
            r#"{"Config":{"Image":"x","Entrypoint":["/bin/sh","-c"],"Cmd":["echo hi"]},"HostConfig":{}}"#,
            None,
        );
        assert!(argv.windows(2).any(|w| w == ["--entrypoint", "/bin/sh"]));
        let image = argv.iter().position(|value| value == "x").unwrap();
        assert_eq!(&argv[image..], &["x", "-c", "echo hi"]);
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
