// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-helper container-event` — capture-time hook for container
//! destructive verbs (DR-CR-26 helper side, AR03 PR-B).
//!
//! Flow:
//! 1. Parse the user's argv (newline-separated in `target_argv`),
//!    classify via [`super::docker::classify_docker_argv`] /
//!    [`super::podman::classify_podman_argv`].
//! 2. For verbs that carry image/volume content (Rmi, VolumeRm), run
//!    the runtime's "save" command (`docker save`, `podman save`) to
//!    capture a tarball in-process; compute blake3 of the bytes.
//! 3. Build [`ContainerEventReq`] with the inline `stash_tarball_bytes`
//!    fast-path payload + verb descriptors in `extras`.
//! 4. Ship to the daemon ctl socket. Daemon writes the tarball to the
//!    blob store, registers the container_stash row, and journals the
//!    `CaptureEventKind::ContainerOp` event against the active command
//!    window.
//!
//! Hook-friendliness: any failure to capture or ship is logged and
//! swallowed; the wrapper script must still exec the real docker. A
//! torn daemon cannot break the user's container CLI. Hard-fail
//! protection is the user-facing `shit` policy, not this hook.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use shit_proto::{
    ContainerEventReq, ContainerRuntimeWire, ContainerVerbWire, CtlRequest, CtlResponse,
    decode_frame, encode_frame_large,
};

use super::compose::{ComposeVerb, classify_compose_argv};
use super::docker::{DockerVerb, classify_docker_argv};
use super::podman::{PodmanVerb, classify_podman_argv};

const CTL_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum tarball size we will inline into the IPC frame. AR03 PR-B
/// is the small-image fast path; anything larger routes through the
/// AR10.8 tempfile / SCM_RIGHTS path (not yet implemented — we drop
/// the stash and the event is journaled without a tarball, so undo
/// becomes informational rather than full restoration).
///
/// 64 MiB is comfortably under `shit-proto`'s `MAX_FRAME_SIZE` and
/// covers alpine (~5 MB), distroless (~20 MB), and small app images.
const INLINE_TARBALL_MAX_BYTES: usize = 64 * 1024 * 1024;

/// CLI entrypoint dispatched from `main.rs` for the `container-event`
/// subcommand.
pub async fn run_event(
    tool: &str,
    phase: &str,
    target_argv: &str,
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    // Avoid re-entry when an undo plan is shelling out to docker /
    // podman to actually perform restoration; the hook would loop.
    if std::env::var_os("SHIT_DURING_UNDO").is_some() {
        tracing::info!(
            tool,
            phase,
            "container-event suppressed (SHIT_DURING_UNDO=1)"
        );
        return Ok(());
    }

    // AU23 / DR-CR-51 — the wrapper fires both `pre` and `post`.
    // Pre handles destructive verbs (rm/rmi/volume rm/...) that need
    // their state snapshotted BEFORE the real docker invocation.
    // Post handles state reconciliation for verbs that need a value
    // only available AFTER the real docker exits — concretely,
    // `docker pull` whose resolved manifest digest comes from
    // `docker inspect`.
    //
    // Anything other than these two phases is a misconfigured hook;
    // treat as no-op rather than error so the CLI keeps working.
    match phase {
        "pre" | "post" => {}
        _ => {
            tracing::debug!(tool, phase, "container-event: unknown phase, ignoring");
            return Ok(());
        }
    }

    // The wrapper packs the user's argv after the tool name with
    // newline separators (NUL would be cleaner but is awkward to ship
    // through a shell `--target-argv=...` flag).
    let mut argv: Vec<String> = vec![tool.to_string()];
    for tok in target_argv.split('\n') {
        if !tok.is_empty() {
            argv.push(tok.to_string());
        }
    }

    let (runtime, verb_payload) = match tool {
        "docker" => {
            // Try the docker-verb classifier first (rm/rmi/volume rm/
            // network rm/stop/kill). If that doesn't match, fall
            // through to the compose classifier in case the user
            // invoked the v2 plugin form (`docker compose down ...`)
            // through the docker-wrapper rather than the
            // docker-compose standalone wrapper.
            match classify_docker_argv(&argv) {
                Some(v) => (ContainerRuntimeWire::Docker, VerbPayload::Docker(v)),
                None => match classify_compose_argv(&argv) {
                    Some(v) => (ContainerRuntimeWire::Docker, VerbPayload::Compose(v)),
                    None => {
                        tracing::debug!(
                            ?argv,
                            "docker argv didn't classify as destructive; skipping"
                        );
                        return Ok(());
                    }
                },
            }
        }
        "podman" => match classify_podman_argv(&argv) {
            Some(v) => (ContainerRuntimeWire::Podman, VerbPayload::Podman(v)),
            None => {
                tracing::debug!(
                    ?argv,
                    "podman argv didn't classify as destructive; skipping"
                );
                return Ok(());
            }
        },
        "docker-compose" => match classify_compose_argv(&argv) {
            Some(v) => (ContainerRuntimeWire::Docker, VerbPayload::Compose(v)),
            None => {
                tracing::debug!(
                    ?argv,
                    "docker-compose argv didn't classify as destructive; skipping"
                );
                return Ok(());
            }
        },
        other => {
            tracing::debug!(tool = other, "container-event: unsupported tool");
            return Ok(());
        }
    };

    // AU23 — phase-aware dispatch. Pre handles destructive verbs;
    // post handles Pull's digest reconciliation. Each phase short-
    // circuits cleanly for verbs it doesn't own.
    let Some(prepared) = (match phase {
        "pre" => prepare(tool, runtime, verb_payload),
        "post" => prepare_post(tool, runtime, verb_payload),
        _ => unreachable!("phase pre-validated above"),
    }) else {
        return Ok(());
    };

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = ContainerEventReq {
        runtime,
        verb: prepared.verb,
        captured_config: prepared.captured_config,
        stash_image: prepared.stash_image,
        stash_tarball: prepared.stash_tarball,
        stash_tarball_bytes: prepared.stash_tarball_bytes,
        extras: prepared.extras,
        pid,
        uid,
    };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };

    if let Err(e) = send_event(&ctl, &req) {
        tracing::warn!(
            tool,
            ctl = %ctl.display(),
            err = %e,
            "container-event: ship to daemon failed; continuing"
        );
    }
    Ok(())
}

enum VerbPayload {
    Docker(DockerVerb),
    Podman(PodmanVerb),
    Compose(ComposeVerb),
}

struct PreparedEvent {
    verb: ContainerVerbWire,
    captured_config: Vec<u8>,
    stash_tarball: Option<[u8; 32]>,
    stash_tarball_bytes: Option<Vec<u8>>,
    /// AR10.9 / DR-CR-22: stash-commit image tag for containers that
    /// were running at capture time. Populated by `prepare_rm` when
    /// it successfully `docker commit`s the running container. The
    /// executor uses this tag in the synthesized `docker run`
    /// instead of the original `.Config.Image` so in-place rootfs
    /// edits round-trip.
    stash_image: Option<String>,
    extras: BTreeMap<String, String>,
}

fn prepare(tool: &str, runtime: ContainerRuntimeWire, v: VerbPayload) -> Option<PreparedEvent> {
    // Compose verbs are a separate enum shape; route them out first
    // so the docker-verb normalisation below stays uniform.
    if let VerbPayload::Compose(c) = v {
        return prepare_compose(tool, c);
    }

    // Both docker and podman share the same verb enum after argv
    // classification; normalise to the docker side.
    let docker_verb: DockerVerb = match v {
        VerbPayload::Docker(d) => d,
        VerbPayload::Podman(p) => match p {
            PodmanVerb::Rm { ids, force } => DockerVerb::Rm { ids, force },
            PodmanVerb::Rmi { images } => DockerVerb::Rmi { images },
            PodmanVerb::VolumeRm { names } => DockerVerb::VolumeRm { names },
            PodmanVerb::NetworkRm { names } => DockerVerb::NetworkRm { names },
            PodmanVerb::StopOrKill { ids, was_kill } => DockerVerb::StopOrKill { ids, was_kill },
            PodmanVerb::Pull { images } => DockerVerb::Pull { images },
        },
        VerbPayload::Compose(_) => unreachable!("compose handled above"),
    };

    match docker_verb {
        DockerVerb::Rmi { images } => prepare_rmi(tool, runtime, images),
        DockerVerb::Rm { ids, force } => prepare_rm(tool, ids, force),
        DockerVerb::VolumeRm { names } => prepare_volume_rm(tool, names),
        DockerVerb::NetworkRm { names } => prepare_network_rm(tool, names),
        // stop/kill are restart-hint events; no destructive content
        // loss, no stash needed. PR-B does not ship them yet.
        DockerVerb::StopOrKill { .. } => None,
        // AU23 — pull doesn't ship at the pre-phase: pre-pull we
        // don't yet know the resolved digest, and the floating-tag
        // alone is exactly the moving-target the audit finding
        // wanted to fix. The post-phase handler (see
        // `prepare_pull_post`) runs `<tool> inspect` after the real
        // pull and emits the event with the resolved id.
        DockerVerb::Pull { .. } => None,
    }
}

/// AU23 / DR-CR-51 — post-phase handler. Returns Some(event) only
/// for verbs whose useful state is available AFTER the real
/// invocation. Today that's `docker pull` / `podman pull`; future
/// verbs can land here as small additives.
///
/// Compose verbs route through `prepare_compose` for the pre-only
/// path; they don't need a post hook (the captured state is the
/// rendered config + per-service Rm captures, both available pre).
fn prepare_post(
    tool: &str,
    _runtime: ContainerRuntimeWire,
    v: VerbPayload,
) -> Option<PreparedEvent> {
    let docker_verb: DockerVerb = match v {
        VerbPayload::Docker(d) => d,
        VerbPayload::Podman(p) => match p {
            PodmanVerb::Rm { ids, force } => DockerVerb::Rm { ids, force },
            PodmanVerb::Rmi { images } => DockerVerb::Rmi { images },
            PodmanVerb::VolumeRm { names } => DockerVerb::VolumeRm { names },
            PodmanVerb::NetworkRm { names } => DockerVerb::NetworkRm { names },
            PodmanVerb::StopOrKill { ids, was_kill } => DockerVerb::StopOrKill { ids, was_kill },
            PodmanVerb::Pull { images } => DockerVerb::Pull { images },
        },
        VerbPayload::Compose(_) => return None,
    };

    match docker_verb {
        DockerVerb::Pull { images } => prepare_pull_post(tool, images),
        // Every other verb's data ships at pre-phase; post is a
        // no-op for them.
        _ => None,
    }
}

/// AU23 — emit one ContainerEvent per pulled image with the
/// resolved digest captured via `<tool> inspect`. Ship even when
/// inspect fails so the journal records the pull attempt (the
/// renderer just shows "(digest unresolved)" in that case).
fn prepare_pull_post(tool: &str, images: Vec<String>) -> Option<PreparedEvent> {
    // AR03 PR-B convention: one event per invocation; first image
    // only. Multi-image pull batching parallels AR03 PR-B's rmi
    // batching follow-up (which AU24 covers).
    let image = images.into_iter().next()?;
    let resolved_id = inspect_image_digest(tool, &image);
    let mut extras = BTreeMap::new();
    extras.insert("image".into(), image);
    if let Some(id) = resolved_id {
        extras.insert("resolved_id".into(), id);
    }
    Some(PreparedEvent {
        verb: ContainerVerbWire::Pull,
        captured_config: Vec::new(),
        stash_tarball: None,
        stash_tarball_bytes: None,
        stash_image: None,
        extras,
    })
}

fn prepare_rmi(
    tool: &str,
    _runtime: ContainerRuntimeWire,
    images: Vec<String>,
) -> Option<PreparedEvent> {
    // AR03 PR-B: ship one event per invocation, image[0] only. Batch
    // multi-image rmi is a DR follow-up.
    let image = images.into_iter().next()?;

    // Capture optional digest for the inverse-restore planner.
    let digest = inspect_image_digest(tool, &image);

    let bytes = match docker_save(tool, &image) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                tool,
                image = %image,
                err = %e,
                "container-event: `{tool} save` failed; event will ship without a stash"
            );
            let mut extras = BTreeMap::new();
            extras.insert("image".into(), image);
            if let Some(d) = digest {
                extras.insert("digest".into(), d);
            }
            return Some(PreparedEvent {
                verb: ContainerVerbWire::Rmi,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                stash_image: None,
                extras,
            });
        }
    };

    if bytes.len() > INLINE_TARBALL_MAX_BYTES {
        // AR10.8 scaffolding: ship event without bytes; daemon
        // journals informational undo. Large-image shipping (tempfile
        // / SCM_RIGHTS) is the AR10.8 deliverable.
        tracing::warn!(
            tool,
            image = %image,
            bytes = bytes.len(),
            cap = INLINE_TARBALL_MAX_BYTES,
            "container-event: tarball exceeds inline cap (AR10.8 large-image path NYI); shipping without stash"
        );
        let mut extras = BTreeMap::new();
        extras.insert("image".into(), image);
        if let Some(d) = digest {
            extras.insert("digest".into(), d);
        }
        return Some(PreparedEvent {
            verb: ContainerVerbWire::Rmi,
            captured_config: Vec::new(),
            stash_tarball: None,
            stash_tarball_bytes: None,
            stash_image: None,
            extras,
        });
    }

    let hash = *blake3::hash(&bytes).as_bytes();

    let mut extras = BTreeMap::new();
    extras.insert("image".into(), image);
    if let Some(d) = digest {
        extras.insert("digest".into(), d);
    }

    Some(PreparedEvent {
        verb: ContainerVerbWire::Rmi,
        captured_config: Vec::new(),
        stash_tarball: Some(hash),
        stash_tarball_bytes: Some(bytes),
        stash_image: None,
        extras,
    })
}

/// Run `{tool} save <image>` and return the tarball bytes.
fn docker_save(tool: &str, image: &str) -> std::io::Result<Vec<u8>> {
    let out = Command::new(tool).args(["save", image]).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{tool} save {image} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// AR03.3 (DR-CR-26 volume-rm path): capture a volume's contents as a
/// gzipped tar. Spawns a transient busybox container with the volume
/// mounted read-only at `/src`, runs `tar -C /src -czf - .` and reads
/// the bytes off stdout. Matches the planner's [`ContainerExecutor::
/// apply_volume_rm`] inverse path, which extracts these bytes back into
/// a recreated volume via `docker run --rm -i -v <name>:/data busybox
/// tar -C /data -xzf -`.
///
/// `SHIT_DURING_UNDO=1` is propagated so the transient busybox `docker
/// run` invocation doesn't re-trigger capture via the wrapper.
fn docker_volume_tar(tool: &str, name: &str) -> std::io::Result<Vec<u8>> {
    let out = Command::new(tool)
        .args([
            "run", "--rm",
            "-v",
            // Mount read-only — we're only copying out. The trailing
            // `:ro` keeps the source pristine in the unlikely event
            // busybox's tar would touch atimes etc.
        ])
        .arg(format!("{name}:/src:ro"))
        .args(["busybox", "tar", "-C", "/src", "-czf", "-", "."])
        .env("SHIT_DURING_UNDO", "1")
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{tool} run busybox tar (volume {name}) exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Best-effort `{tool} volume inspect --format='{{.Driver}}' <name>`
/// to record the volume's driver so the inverse path can recreate it
/// with the same backing. Returns `None` for the default `local`
/// driver or when inspect fails (the planner treats `None` as "use
/// the default").
fn inspect_volume_driver(tool: &str, name: &str) -> Option<String> {
    let out = Command::new(tool)
        .args(["volume", "inspect", "--format", "{{.Driver}}", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "local" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Run `{tool} network inspect <name>` and return the raw JSON bytes
/// from stdout. Docker emits an array-of-one shape — the planner's
/// [`synthesize_network_create`] unwraps that.
fn docker_network_inspect(tool: &str, name: &str) -> std::io::Result<Vec<u8>> {
    let out = Command::new(tool)
        .args(["network", "inspect", name])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{tool} network inspect {name} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// AR03.4 (DR-CR-26 network-rm path): capture a network's config as
/// the JSON output of `docker network inspect`. No tarball — the
/// payload is small (~1-2 KiB) and fits comfortably in the standard
/// frame. Daemon-side [`ContainerExecutor::apply_network_rm`] parses
/// the JSON and feeds it through [`synthesize_network_create`] to
/// rebuild the `docker network create` argv.
fn prepare_network_rm(tool: &str, names: Vec<String>) -> Option<PreparedEvent> {
    // PR-B (AR03.4): one event per invocation; multi-name `docker
    // network rm n1 n2` is a follow-up.
    let name = names.into_iter().next()?;

    let mut extras = BTreeMap::new();
    extras.insert("name".into(), name.clone());

    match docker_network_inspect(tool, &name) {
        Ok(json_bytes) => Some(PreparedEvent {
            verb: ContainerVerbWire::NetworkRm,
            captured_config: json_bytes,
            stash_tarball: None,
            stash_tarball_bytes: None,
            stash_image: None,
            extras,
        }),
        Err(e) => {
            tracing::warn!(
                tool,
                network = %name,
                err = %e,
                "container-event: network inspect failed; event will ship without captured_config"
            );
            Some(PreparedEvent {
                verb: ContainerVerbWire::NetworkRm,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                stash_image: None,
                extras,
            })
        }
    }
}

/// AR10.9 / DR-CR-22 (`docker rm` capture path):
///
/// 1. Run `docker inspect <id>` to capture the full container config
///    (Config, HostConfig, Mounts, NetworkSettings, etc.) — the
///    daemon-side executor parses this JSON via `synthesize_container_run`
///    to rebuild the `docker run` argv.
/// 2. Detect whether the container was running at capture (`.State.Running`).
/// 3. If running, `docker commit <id> shit-stash-<short_id>-<ts>` to
///    preserve any in-place rootfs writes. The synthesized restore uses
///    this stash image instead of `.Config.Image` so the user's edits
///    round-trip.
///
/// `force` (the `-f` flag on `docker rm`) is the wire-level proxy for
/// "container may be running"; in reality the container's running
/// state is whatever inspect reports. We trust inspect over the flag.
fn prepare_rm(tool: &str, ids: Vec<String>, _force: bool) -> Option<PreparedEvent> {
    // PR-B (AR10.9): one event per invocation; multi-id batching is
    // tracked as DR-CR-52.
    let id = ids.into_iter().next()?;

    let mut extras = BTreeMap::new();
    extras.insert("id".into(), id.clone());

    let inspect_json = match docker_container_inspect(tool, &id) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                tool,
                id = %id,
                err = %e,
                "container-event: docker inspect failed; event will ship without captured_config"
            );
            extras.insert("was_running".into(), "false".into());
            return Some(PreparedEvent {
                verb: ContainerVerbWire::Rm,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                stash_image: None,
                extras,
            });
        }
    };

    let was_running = inspect_is_running(&inspect_json);
    extras.insert("was_running".into(), was_running.to_string());

    if let Some(name) = inspect_container_name(&inspect_json) {
        extras.insert("name".into(), name);
    }

    let stash_image = if was_running {
        match docker_commit_running_container(tool, &id) {
            Ok(tag) => Some(tag),
            Err(e) => {
                tracing::warn!(
                    tool,
                    id = %id,
                    err = %e,
                    "container-event: docker commit failed; restore will refuse to lose rootfs writes"
                );
                None
            }
        }
    } else {
        None
    };

    Some(PreparedEvent {
        verb: ContainerVerbWire::Rm,
        captured_config: inspect_json,
        stash_tarball: None,
        stash_tarball_bytes: None,
        stash_image,
        extras,
    })
}

/// Run `{tool} inspect <id>` and return the raw JSON bytes. Docker
/// emits an array-of-one shape — the planner's `apply_rm` unwraps it.
fn docker_container_inspect(tool: &str, id: &str) -> std::io::Result<Vec<u8>> {
    let out = Command::new(tool).args(["inspect", id]).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{tool} inspect {id} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Best-effort extraction of `.State.Running` from inspect JSON.
/// Returns false on any parse failure — restore then runs from the
/// original image (acceptable for a stopped container; lossy for a
/// running one, but if inspect's JSON is malformed there's nothing
/// the daemon could do anyway).
fn inspect_is_running(bytes: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let obj = match v {
        serde_json::Value::Array(arr) => arr.into_iter().next().unwrap_or(serde_json::Value::Null),
        other => other,
    };
    obj.get("State")
        .and_then(|s| s.get("Running"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Best-effort extraction of `.Name` (stripping the leading `/`
/// docker prepends).
fn inspect_container_name(bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = match v {
        serde_json::Value::Array(arr) => arr.into_iter().next()?,
        other => other,
    };
    obj.get("Name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

/// Run `{tool} commit <id> shit-stash-<short>-<ts>` to snapshot the
/// running container's rootfs into a tagged image. The tag includes
/// a short id prefix + unix timestamp so concurrent commits on
/// different containers don't collide and the `shit container-stashes
/// prune` retention path can age them out.
fn docker_commit_running_container(tool: &str, id: &str) -> std::io::Result<String> {
    let short = id.chars().take(12).collect::<String>();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tag = format!("shit-stash-{short}-{ts}");
    let out = Command::new(tool).args(["commit", id, &tag]).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{tool} commit {id} {tag} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(tag)
}

/// AR03.6 / DR-CR-53 (`docker compose down` capture path):
///
/// The destructive verbs we care about are `down` (with or without
/// `-v|--volumes`). Up / stop / rm route to follow-ups (Up is a
/// non-destructive bring-up, Stop is restart-hint, Rm needs per-
/// service container inspect + commit which mirrors AR10.9 multiplied
/// across the service set — bigger scope).
///
/// For Down: pack the compose-file path + project name into `extras`.
/// The daemon-side `ContainerExecutor::apply_compose_down` runs
/// `docker compose -f <file> -p <project> up -d` on restore; compose
/// reads the file as the source of truth so a vanilla `down` →
/// `up -d` round-trips cleanly for the happy path. Volume restoration
/// (when `--volumes` was passed) is scaffolded but not yet wired —
/// AR03.3's per-volume stash logic would need to apply per-named-volume.
fn prepare_compose(tool: &str, verb: ComposeVerb) -> Option<PreparedEvent> {
    match verb {
        ComposeVerb::Down {
            files,
            project_override,
            with_volumes,
        } => prepare_compose_down(tool, files, project_override, with_volumes),
        // Up is restart-hint (the project is starting; no destructive
        // capture needed — undo of `up` is `down` which the user runs
        // explicitly). Stop is a restart-hint. Rm needs per-service
        // inspect + commit (a multiplied AR10.9); deferred.
        ComposeVerb::Up { .. } | ComposeVerb::Stop { .. } | ComposeVerb::Rm { .. } => {
            tracing::debug!(
                ?verb,
                "container-event: compose verb not destructive in v1 (or deferred)"
            );
            None
        }
    }
}

fn prepare_compose_down(
    tool: &str,
    files: Vec<String>,
    project_override: Option<String>,
    with_volumes: bool,
) -> Option<PreparedEvent> {
    // Resolve the compose file. If the user passed -f, honour the
    // first path (multi-file overlays use the first as the base);
    // otherwise fall back to docker's default search of
    // `docker-compose.yml` then `compose.yaml` in cwd.
    let compose_file = files
        .into_iter()
        .next()
        .or_else(default_compose_file_in_cwd)
        .or_else(|| Some("docker-compose.yml".to_string()))?;

    // Resolve to absolute path so the daemon-side restore doesn't
    // depend on cwd at undo time. Best-effort — if canonicalize fails
    // (file doesn't exist where we think), ship the raw string and
    // let the executor's apply_compose_down surface the error.
    let compose_file_abs = std::path::PathBuf::from(&compose_file)
        .canonicalize()
        .map(|p| p.display().to_string())
        .unwrap_or(compose_file);

    // Project name: --project-name wins; otherwise docker compose
    // defaults to the basename of the compose file's parent dir,
    // lowercased with non-alnum stripped. Compute that here so the
    // restore uses the same name and addresses the same network /
    // containers.
    let project = project_override.unwrap_or_else(|| default_project_name(&compose_file_abs));

    let mut extras = BTreeMap::new();
    extras.insert("project".into(), project);
    extras.insert("compose_file".into(), compose_file_abs);
    extras.insert("with_volumes".into(), with_volumes.to_string());
    // Services empty → daemon restores all (compose default).
    // Capturing the resolved per-service list via `docker compose
    // config --services` would be more authoritative but adds an
    // extra subprocess; defer to follow-up.

    // No tarball / no stash_image — compose file is the source of
    // truth. `captured_config` left empty; the spec lives on disk
    // and the daemon re-reads it on restore.
    let _ = tool; // compose runtime always = docker engine; bin chosen daemon-side
    Some(PreparedEvent {
        verb: ContainerVerbWire::ComposeDown,
        captured_config: Vec::new(),
        stash_tarball: None,
        stash_tarball_bytes: None,
        stash_image: None,
        extras,
    })
}

/// Search cwd for docker compose's two default file names, in the
/// order compose itself checks (`compose.yaml` is the newer spec
/// name; `docker-compose.yml` the legacy). Returns the first one
/// that exists; None if neither does.
fn default_compose_file_in_cwd() -> Option<String> {
    for name in &[
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ] {
        let p = std::path::Path::new(name);
        if p.exists() {
            return Some((*name).to_string());
        }
    }
    None
}

/// Docker compose's default project-name algorithm: take the basename
/// of the compose file's parent directory, lowercase, strip
/// non-[a-z0-9_-] chars. Matches `docker compose config | grep name`.
fn default_project_name(compose_file_abs: &str) -> String {
    let p = std::path::Path::new(compose_file_abs);
    let parent = p
        .parent()
        .and_then(|d| d.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("default");
    parent
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

fn prepare_volume_rm(tool: &str, names: Vec<String>) -> Option<PreparedEvent> {
    // PR-B (AR03.3): one event per invocation; multi-name `docker
    // volume rm v1 v2 v3` is a follow-up.
    let name = names.into_iter().next()?;

    let driver = inspect_volume_driver(tool, &name);

    let bytes = match docker_volume_tar(tool, &name) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                tool,
                volume = %name,
                err = %e,
                "container-event: volume tar capture failed; event will ship without a stash"
            );
            let mut extras = BTreeMap::new();
            extras.insert("name".into(), name);
            if let Some(d) = driver {
                extras.insert("driver".into(), d);
            }
            return Some(PreparedEvent {
                verb: ContainerVerbWire::VolumeRm,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                stash_image: None,
                extras,
            });
        }
    };

    if bytes.len() > INLINE_TARBALL_MAX_BYTES {
        tracing::warn!(
            tool,
            volume = %name,
            bytes = bytes.len(),
            cap = INLINE_TARBALL_MAX_BYTES,
            "container-event: volume tar exceeds inline cap (AR10.8 large-image path NYI); shipping without stash"
        );
        let mut extras = BTreeMap::new();
        extras.insert("name".into(), name);
        if let Some(d) = driver {
            extras.insert("driver".into(), d);
        }
        return Some(PreparedEvent {
            verb: ContainerVerbWire::VolumeRm,
            captured_config: Vec::new(),
            stash_tarball: None,
            stash_tarball_bytes: None,
            stash_image: None,
            extras,
        });
    }

    let hash = *blake3::hash(&bytes).as_bytes();

    let mut extras = BTreeMap::new();
    extras.insert("name".into(), name);
    if let Some(d) = driver {
        extras.insert("driver".into(), d);
    }

    Some(PreparedEvent {
        verb: ContainerVerbWire::VolumeRm,
        captured_config: Vec::new(),
        stash_tarball: Some(hash),
        stash_tarball_bytes: Some(bytes),
        stash_image: None,
        extras,
    })
}

/// Best-effort `{tool} inspect --format='{{.Id}}' <image>` to record
/// the image's content digest alongside the tag. Returns `None` if
/// inspect fails — the digest is a hint for the planner, not a
/// blocker for stash capture.
fn inspect_image_digest(tool: &str, image: &str) -> Option<String> {
    let out = Command::new(tool)
        .args(["inspect", "--format", "{{.Id}}", image])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Mirror of [`super::super::pkg::default_ctl_socket_path`] —
/// duplicated to keep the modules independent.
fn default_ctl_socket_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("shit-ctl.sock");
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    // SAFETY: getuid always succeeds.
    let uid = unsafe { libc::getuid() };
    tmp.join(format!("shit-ctl-{uid}.sock"))
}

fn send_event(path: &Path, req: &ContainerEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    // ContainerEvent carries tarball bytes (alpine ~5 MB, distroless
    // ~20 MB) — well over MAX_FRAME_SIZE. encode_frame_large uses the
    // 64 MiB cap that matches our INLINE_TARBALL_MAX_BYTES. The
    // daemon ctl reader peeks the length prefix first and grows the
    // buffer when it sees a large frame.
    let frame = encode_frame_large(&CtlRequest::ContainerEvent(req.clone()))?;
    stream.write_all(&frame)?;
    // Ack is small; the standard MAX_FRAME_SIZE-sized buffer suffices.
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::ContainerEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_rm_extras_populated_under_docker_unavailable() {
        // No docker on PATH → inspect fails → event still ships with
        // id in extras (informational journal). was_running falls
        // back to "false" since we can't observe the real state.
        let prepared = prepare_rm(
            "shit-test-no-such-docker-binary",
            vec!["abc123".into(), "def456".into()],
            true,
        )
        .unwrap();
        assert!(matches!(prepared.verb, ContainerVerbWire::Rm));
        assert_eq!(
            prepared.extras.get("id").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            prepared.extras.get("was_running").map(String::as_str),
            Some("false")
        );
        assert!(prepared.captured_config.is_empty());
        assert!(prepared.stash_image.is_none());
    }

    #[test]
    fn inspect_is_running_handles_array_and_object() {
        let arr = br#"[{"State":{"Running":true}}]"#;
        let obj = br#"{"State":{"Running":true}}"#;
        let stopped = br#"{"State":{"Running":false}}"#;
        let malformed = b"{not json";
        let no_state = b"{}";
        assert!(inspect_is_running(arr));
        assert!(inspect_is_running(obj));
        assert!(!inspect_is_running(stopped));
        assert!(!inspect_is_running(malformed));
        assert!(!inspect_is_running(no_state));
    }

    #[test]
    fn inspect_container_name_strips_leading_slash() {
        let bytes = br#"[{"Name":"/web-prod"}]"#;
        assert_eq!(inspect_container_name(bytes).as_deref(), Some("web-prod"));
    }

    #[test]
    fn inspect_container_name_missing_returns_none() {
        assert!(inspect_container_name(b"{}").is_none());
        assert!(inspect_container_name(br#"{"Name":""}"#).is_none());
    }

    #[test]
    fn default_project_name_lowercases_and_filters() {
        assert_eq!(
            default_project_name("/srv/MyApp/docker-compose.yml"),
            "myapp"
        );
        assert_eq!(
            default_project_name("/home/u/My-Project_v2/compose.yaml"),
            "my-project_v2"
        );
        // Path with no parent should fall back to default.
        assert_eq!(default_project_name("/"), "default");
    }

    #[test]
    fn prepare_compose_down_packs_extras_for_explicit_file_and_project() {
        // Explicit -f + --project-name; canonicalize will fail (file
        // doesn't exist) and the prepared event ships the raw path —
        // ensures the warn-fallback shape works.
        let prepared = prepare_compose_down(
            "docker-compose",
            vec!["/nonexistent/path/docker-compose.yml".to_string()],
            Some("myproject".to_string()),
            false,
        )
        .unwrap();
        assert!(matches!(prepared.verb, ContainerVerbWire::ComposeDown));
        assert_eq!(
            prepared.extras.get("project").map(String::as_str),
            Some("myproject")
        );
        assert_eq!(
            prepared.extras.get("compose_file").map(String::as_str),
            Some("/nonexistent/path/docker-compose.yml")
        );
        assert_eq!(
            prepared.extras.get("with_volumes").map(String::as_str),
            Some("false")
        );
        assert!(prepared.captured_config.is_empty());
        assert!(prepared.stash_tarball.is_none());
    }

    #[test]
    fn prepare_compose_down_with_volumes_packs_flag() {
        let prepared = prepare_compose_down(
            "docker-compose",
            vec!["/x/docker-compose.yml".into()],
            Some("p".into()),
            true,
        )
        .unwrap();
        assert_eq!(
            prepared.extras.get("with_volumes").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn prepare_volume_rm_extras_populated_under_docker_unavailable() {
        // Path the docker invocation at a sentinel that's guaranteed
        // not to exist so docker_volume_tar takes the warn-fallback.
        // Asserts: even when capture fails (no docker, sandbox, etc.)
        // the event still ships with the volume name in extras so the
        // daemon can journal an informational entry.
        let tool = "shit-test-no-such-docker-binary";
        let prepared = prepare_volume_rm(tool, vec!["pgdata".into()]).unwrap();
        assert!(matches!(prepared.verb, ContainerVerbWire::VolumeRm));
        assert_eq!(
            prepared.extras.get("name").map(String::as_str),
            Some("pgdata")
        );
        assert!(prepared.stash_tarball.is_none());
        assert!(prepared.stash_tarball_bytes.is_none());
    }

    #[test]
    fn prepare_stop_or_kill_returns_none() {
        let v = VerbPayload::Docker(DockerVerb::StopOrKill {
            ids: vec!["web".into()],
            was_kill: false,
        });
        assert!(prepare("docker", ContainerRuntimeWire::Docker, v).is_none());
    }

    #[test]
    fn prepare_network_rm_extras_populated_under_docker_unavailable() {
        // No docker on PATH → inspect fails → event still ships with
        // name in extras and empty captured_config (informational
        // journal entry; undo would refuse cleanly).
        let tool = "shit-test-no-such-docker-binary";
        let prepared = prepare_network_rm(tool, vec!["frontend".into()]).unwrap();
        assert!(matches!(prepared.verb, ContainerVerbWire::NetworkRm));
        assert_eq!(
            prepared.extras.get("name").map(String::as_str),
            Some("frontend")
        );
        assert!(prepared.captured_config.is_empty());
        assert!(prepared.stash_tarball.is_none());
    }

    #[test]
    fn prepare_podman_rm_maps_to_docker_shape() {
        let v = VerbPayload::Podman(PodmanVerb::Rm {
            ids: vec!["c1".into()],
            force: false,
        });
        let p = prepare("podman", ContainerRuntimeWire::Podman, v).unwrap();
        assert!(matches!(p.verb, ContainerVerbWire::Rm));
        assert_eq!(p.extras.get("id").map(String::as_str), Some("c1"));
        assert_eq!(
            p.extras.get("was_running").map(String::as_str),
            Some("false")
        );
    }
}
