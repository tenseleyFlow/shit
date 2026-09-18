// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-helper container-event` — capture-time hook for container
//! destructive verbs (DR-CR-26 helper side, AR03 PR-B).
//!
//! Flow:
//! 1. Receive the user's argv losslessly (wrappers use NUL-delimited stdin),
//!    classify via [`super::docker::classify_docker_argv`] /
//!    [`super::podman::classify_podman_argv`].
//! 2. For verbs that carry image/volume content (Rmi, VolumeRm), run
//!    the runtime's "save" command (`docker save`, `podman save`) and
//!    stream stdout through a bounded, immediately-unlinked staging
//!    descriptor; compute blake3 incrementally.
//! 3. Build [`ContainerEventReq`] with the inline `stash_tarball_bytes`
//!    fast-path payload + verb descriptors in `extras`.
//! 4. Ship to the daemon ctl socket. Daemon writes the tarball to the
//!    blob store, registers the container_stash row, and journals the
//!    `CaptureEventKind::ContainerOp` event against the active command
//!    window.
//!
//! Loss-prevention contract: only reviewed read-only commands are transparent.
//! Unsupported or mutating commands fail closed. The one admitted destructive
//! shape must be fully captured and acknowledged before the wrapper may invoke
//! the real runtime.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use shit_proto::{
    ContainerBatchFinalizeReq, ContainerBatchPrepareReq, ContainerEventReq, ContainerRuntimeWire,
    ContainerTargetObservationWire, ContainerTargetStateWire, ContainerVerbWire, CtlRequest,
    CtlResponse, MAX_FRAME_SIZE, MAX_LARGE_FRAME_SIZE, decode_frame, encode_frame_large,
};
use uuid::Uuid;

use super::compose::{ComposeVerb, classify_compose_argv};
use super::docker::{
    DockerVerb, classify_docker_argv, has_global_prefix, is_explicitly_read_only_argv,
    looks_potentially_destructive,
};
use super::podman::{PodmanVerb, classify_podman_argv};
use super::staging::{self, CapturedArchive};

const CTL_TIMEOUT: Duration = Duration::from_secs(60);
const CTL_IO_ATTEMPTS: usize = 2;

/// Maximum tarball size we will inline into the IPC frame. Reserve a
/// MiB for postcard fields and framing: a payload of exactly 64 MiB
/// cannot fit inside a frame whose *total* cap is 64 MiB.
///
/// Until the AR10.8 SCM_RIGHTS request variant is accepted daemon-side,
/// exceeding this bound is a hard preflight error. The destructive
/// runtime command never runs without a restorable stash.
const INLINE_FRAME_HEADROOM: usize = 1024 * 1024;
const INLINE_TARBALL_MAX_BYTES: u64 = (MAX_LARGE_FRAME_SIZE - INLINE_FRAME_HEADROOM) as u64;
const CONFIG_CAPTURE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const TEXT_CAPTURE_MAX_BYTES: u64 = 1024 * 1024;
const PROBE_DETAIL_MAX_CHARS: usize = 512;
const COMMAND_SESSION_ENV: &str = "_SHIT_SESSION";
const COMMAND_SEQ_ENV: &str = "_SHIT_SEQ";
const COMMAND_SESSION_EXTRA: &str = "_shit_session";
const COMMAND_SEQ_EXTRA: &str = "_shit_seq";
const DOCKER_CONTEXT_EXTRA: &str = "_shit_docker_context";
const REQUIRED_DOCKER_CONTEXT: &str = "default";
const MUTABLE_DOCKER_ENV: [&str; 5] = [
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandIdentity {
    session: String,
    seq: String,
}

/// CLI entrypoint dispatched from `main.rs` for the `container-event`
/// subcommand.
pub async fn run_event(
    tool: &str,
    phase: &str,
    target_args: &[String],
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    // Avoid re-entry when an undo plan is shelling out to docker /
    // podman to actually perform restoration; the hook would loop.
    if during_undo(std::env::var_os("SHIT_DURING_UNDO").as_deref()) {
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

    let mut argv: Vec<String> = vec![tool.to_string()];
    argv.extend(target_args.iter().cloned());

    let (runtime, verb_payload) = match tool {
        "docker" => {
            // Try the docker-verb classifier first (rm/rmi/volume rm/
            // network rm/stop/kill). If that doesn't match, fall
            // through to the compose classifier in case the user
            // invoked the v2 plugin form (`docker compose down ...`)
            // through the docker-wrapper rather than the
            // docker-compose standalone wrapper.
            match classify_docker_argv(&argv) {
                Some(DockerVerb::Rm { .. })
                    if phase == "pre" && removes_anonymous_volumes(target_args) =>
                {
                    bail!(
                        "refusing container rm with --volumes: anonymous-volume capture is not implemented"
                    );
                }
                Some(DockerVerb::Rmi { .. })
                    if phase == "pre" && !rmi_disables_prune(target_args) =>
                {
                    bail!(
                        "refusing image removal without --no-prune: lossless undo cannot prove which parent images the runtime pruned"
                    );
                }
                Some(v) => (ContainerRuntimeWire::Docker, VerbPayload::Docker(v)),
                None => match classify_compose_argv(&argv) {
                    Some(v) => (ContainerRuntimeWire::Docker, VerbPayload::Compose(v)),
                    None if phase == "pre" && looks_potentially_destructive(&argv) => {
                        bail!(
                            "refusing potentially destructive docker invocation with unsupported verb or options: {target_args:?}"
                        );
                    }
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
            Some(PodmanVerb::Rm { .. })
                if phase == "pre" && removes_anonymous_volumes(target_args) =>
            {
                bail!(
                    "refusing container rm with --volumes: anonymous-volume capture is not implemented"
                );
            }
            Some(PodmanVerb::Rmi { .. }) if phase == "pre" && !rmi_disables_prune(target_args) => {
                bail!(
                    "refusing image removal without --no-prune: lossless undo cannot prove which parent images the runtime pruned"
                );
            }
            Some(v) => (ContainerRuntimeWire::Podman, VerbPayload::Podman(v)),
            None if phase == "pre" && looks_potentially_destructive(&argv) => {
                bail!(
                    "refusing potentially destructive podman invocation with unsupported verb or options: {target_args:?}"
                );
            }
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
            None if phase == "pre"
                && target_args
                    .iter()
                    .any(|arg| matches!(arg.as_str(), "down" | "rm" | "remove" | "prune")) =>
            {
                bail!(
                    "refusing potentially destructive docker-compose invocation with unsupported verb or options: {target_args:?}"
                );
            }
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

    // Destructive events must use the v2 prepare/finalize transaction. The
    // legacy one-event-at-a-time route can acknowledge target 1 and then lose
    // target 2, leaving the wrapper free to run without a complete pre-image.
    // Pull remains on the legacy post route because it is informational and
    // does not authorize deletion.
    if phase == "pre" && is_destructive_payload(&verb_payload) {
        bail!(
            "legacy container-event cannot authorize destructive commands; reinstall the container hooks to use atomic container-prepare/container-finalize"
        );
    }

    // AU23 — phase-aware dispatch. Pre handles destructive verbs;
    // post handles Pull's digest reconciliation. Each phase short-
    // circuits cleanly for verbs it doesn't own.
    //
    // AU24 / DR-CR-52 — `prepare` returns Vec<PreparedEvent> so a
    // single CLI invocation with N positionals (e.g.
    // `docker rmi alpine ubuntu busybox`) journals N events under
    // the same command_seq. Pre-AU24 only the first positional
    // shipped; the rest were silently dropped — destructive verbs
    // would partially restore on `shit undo`.
    let prepared = match phase {
        "pre" => prepare(tool, runtime, verb_payload)?,
        "post" => prepare_post(tool, runtime, verb_payload)?,
        _ => unreachable!("phase pre-validated above"),
    };
    if prepared.is_empty() {
        return Ok(());
    }

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };

    // Ship each prepared event sequentially. Same command_seq
    // (resolved daemon-side via pid → active command window), so
    // the daemon journals them as N entries under one command and
    // `shit undo` plans them as a single cohort.
    for one in prepared {
        let req = ContainerEventReq {
            runtime,
            verb: one.verb,
            captured_config: one.captured_config,
            stash_image: one.stash_image,
            stash_tarball: one.stash_tarball,
            stash_tarball_bytes: one.stash_tarball_bytes,
            extras: one.extras,
            pid,
            uid,
        };
        send_event(&ctl, &req).map_err(|error| {
            anyhow::anyhow!(
                "container-event: failed to durably ship capture for {tool} via {}: {error}",
                ctl.display()
            )
        })?;
    }
    Ok(())
}

/// Prepare an atomic destructive-container batch and return the opaque token
/// the wrapper must finalize after invoking the real runtime.
///
/// The first v2 implementation deliberately admits only image removal. The
/// other destructive families have unresolved inverse-model gaps, so
/// recognizing one is a hard refusal rather than a silent pass-through.
pub async fn prepare_batch(
    tool: &str,
    target_args: &[String],
    ctl_sock: Option<&Path>,
) -> anyhow::Result<Option<Uuid>> {
    if during_undo(std::env::var_os("SHIT_DURING_UNDO").as_deref()) {
        tracing::info!(tool, "container-prepare suppressed (SHIT_DURING_UNDO=1)");
        return Ok(None);
    }

    let Some((runtime, images)) = classify_batch_rmi(tool, target_args)? else {
        return Ok(None);
    };
    let identity = command_identity_from_env()?;
    validate_docker_environment()?;
    let mut events = prepare_rmi(tool, runtime, images)?;
    if events.len() != 1 {
        bail!("container image-removal authorization requires exactly one captured target");
    }
    for event in &mut events {
        // Daemon-side validation does not see the original argv. Make the
        // safety-critical classifier result explicit in every batch member.
        event.extras.insert("no_prune".into(), "true".into());
        event
            .extras
            .insert(COMMAND_SESSION_EXTRA.into(), identity.session.clone());
        event
            .extras
            .insert(COMMAND_SEQ_EXTRA.into(), identity.seq.clone());
        event
            .extras
            .insert(DOCKER_CONTEXT_EXTRA.into(), REQUIRED_DOCKER_CONTEXT.into());
    }

    // SAFETY: getpid/getuid have no failure mode on supported Unix targets.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };
    let wire_events = events
        .into_iter()
        .map(|event| ContainerEventReq {
            runtime,
            verb: event.verb,
            captured_config: event.captured_config,
            stash_image: event.stash_image,
            stash_tarball: event.stash_tarball,
            stash_tarball_bytes: event.stash_tarball_bytes,
            extras: event.extras,
            pid,
            uid,
        })
        .collect();
    let batch_id = Uuid::now_v7();
    let request = CtlRequest::ContainerBatchPrepare(ContainerBatchPrepareReq {
        batch_id,
        events: wire_events,
    });
    let ctl = ctl_sock
        .map(Path::to_path_buf)
        .unwrap_or_else(default_ctl_socket_path);
    match call_ctl_retry_io(&ctl, &request).with_context(|| {
        format!(
            "container-prepare: failed to durably publish batch via {}",
            ctl.display()
        )
    })? {
        CtlResponse::ContainerBatchPrepared { batch_id: ack } if ack == batch_id => {
            Ok(Some(batch_id))
        }
        CtlResponse::Error(error) => bail!("daemon: {error}"),
        other => bail!("unexpected daemon response: {other:?}"),
    }
}

/// Finalize a prepared batch using the real runtime status and one typed
/// observation per original target. A zero exit status is not enough: every
/// tag must be positively proven absent while the engine itself is healthy.
pub async fn finalize_batch(
    tool: &str,
    batch_id: Uuid,
    exit_code: i32,
    target_args: &[String],
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    if during_undo(std::env::var_os("SHIT_DURING_UNDO").as_deref()) {
        bail!("container-finalize cannot run with SHIT_DURING_UNDO set");
    }
    let Some((_runtime, images)) = classify_batch_rmi(tool, target_args)? else {
        bail!("container-finalize argv does not describe an image-removal batch");
    };
    command_identity_from_env()?;
    validate_docker_environment()?;

    let observations = if exit_code == 0 {
        match probe_runtime_liveness(tool) {
            Ok(()) => images
                .iter()
                .enumerate()
                .map(|(ordinal, image)| probe_removed_image(tool, ordinal, image))
                .collect(),
            Err(error) => {
                let detail = Some(bounded_probe_detail(&format!(
                    "runtime liveness probe failed: {error:#}"
                )));
                images
                    .iter()
                    .enumerate()
                    .map(|(ordinal, _)| ContainerTargetObservationWire {
                        ordinal: ordinal as u32,
                        state: ContainerTargetStateWire::ProbeFailed,
                        detail: detail.clone(),
                    })
                    .collect()
            }
        }
    } else {
        let detail = Some(format!("container runtime exited with status {exit_code}"));
        images
            .iter()
            .enumerate()
            .map(|(ordinal, _)| ContainerTargetObservationWire {
                ordinal: ordinal as u32,
                state: ContainerTargetStateWire::ProbeFailed,
                detail: detail.clone(),
            })
            .collect()
    };

    // SAFETY: getpid/getuid have no failure mode on supported Unix targets.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };
    let request = CtlRequest::ContainerBatchFinalize(ContainerBatchFinalizeReq {
        batch_id,
        pid,
        uid,
        exit_code,
        observations,
    });
    let ctl = ctl_sock
        .map(Path::to_path_buf)
        .unwrap_or_else(default_ctl_socket_path);
    match call_ctl_retry_io(&ctl, &request).with_context(|| {
        format!(
            "container-finalize: failed to durably finalize batch via {}",
            ctl.display()
        )
    })? {
        CtlResponse::ContainerBatchFinalized { batch_id: ack } if ack == batch_id => Ok(()),
        CtlResponse::Error(error) => bail!("daemon: {error}"),
        other => bail!("unexpected daemon response: {other:?}"),
    }
}

fn classify_batch_rmi(
    tool: &str,
    target_args: &[String],
) -> anyhow::Result<Option<(ContainerRuntimeWire, Vec<String>)>> {
    let mut argv = vec![tool.to_string()];
    argv.extend(target_args.iter().cloned());

    let candidate = match tool {
        "docker" => match classify_docker_argv(&argv) {
            Some(DockerVerb::Rmi { images }) => {
                if has_global_prefix(&argv) {
                    bail!(
                        "refusing Docker image removal with global prefix flags; the initial lossless boundary accepts only `docker rmi --no-prune TAG`"
                    );
                }
                validate_strict_docker_rmi(target_args, &images)?;
                Some((ContainerRuntimeWire::Docker, images))
            }
            Some(DockerVerb::Rm { .. }) => {
                bail!("container removal is not yet losslessly batch-undoable")
            }
            Some(DockerVerb::VolumeRm { .. }) => {
                bail!("volume removal is not yet losslessly batch-undoable")
            }
            Some(DockerVerb::NetworkRm { .. }) => {
                bail!("network removal is not yet losslessly batch-undoable")
            }
            Some(DockerVerb::StopOrKill { .. } | DockerVerb::Pull { .. }) => {
                bail!(
                    "refusing Docker state mutation outside the single-tag `rmi --no-prune` boundary"
                )
            }
            None => match classify_compose_argv(&argv) {
                Some(ComposeVerb::Down { .. } | ComposeVerb::Rm { .. }) => {
                    bail!("compose removal is not yet losslessly batch-undoable")
                }
                Some(ComposeVerb::Up { .. } | ComposeVerb::Stop { .. }) => bail!(
                    "refusing Docker Compose state mutation outside the initial lossless boundary"
                ),
                None if is_explicitly_read_only_argv(&argv) => None,
                None => bail!(
                    "refusing Docker invocation that is not on the reviewed read-only allow-list: {target_args:?}"
                ),
            },
        },
        "podman" => match classify_podman_argv(&argv) {
            Some(PodmanVerb::Rmi { .. }) => {
                bail!("Podman image removal is not enabled by the initial lossless boundary")
            }
            Some(PodmanVerb::Rm { .. }) => {
                bail!("container removal is not yet losslessly batch-undoable")
            }
            Some(PodmanVerb::VolumeRm { .. }) => {
                bail!("volume removal is not yet losslessly batch-undoable")
            }
            Some(PodmanVerb::NetworkRm { .. }) => {
                bail!("network removal is not yet losslessly batch-undoable")
            }
            Some(PodmanVerb::StopOrKill { .. } | PodmanVerb::Pull { .. }) => {
                bail!("refusing Podman state mutation outside the initial lossless boundary")
            }
            None if is_explicitly_read_only_argv(&argv) => None,
            None => bail!(
                "refusing Podman invocation that is not on the reviewed read-only allow-list: {target_args:?}"
            ),
        },
        "docker-compose" => match classify_compose_argv(&argv) {
            Some(ComposeVerb::Down { .. } | ComposeVerb::Rm { .. }) => {
                bail!("compose removal is not yet losslessly batch-undoable")
            }
            Some(ComposeVerb::Up { .. } | ComposeVerb::Stop { .. }) => bail!(
                "refusing Docker Compose state mutation outside the initial lossless boundary"
            ),
            None if is_explicitly_read_only_compose(target_args) => None,
            None => bail!(
                "refusing docker-compose invocation that is not on the reviewed read-only allow-list: {target_args:?}"
            ),
        },
        other => bail!("unsupported container runtime `{other}`"),
    };

    if candidate.is_some() && !rmi_disables_prune(target_args) {
        bail!(
            "refusing image removal without --no-prune: lossless undo cannot prove which parent images the runtime pruned"
        );
    }
    Ok(candidate)
}

fn is_explicitly_read_only_compose(target_args: &[String]) -> bool {
    matches!(
        target_args.first().map(String::as_str),
        Some("config" | "events" | "images" | "logs" | "ls" | "ps" | "top" | "version")
    )
}

fn validate_strict_docker_rmi(target_args: &[String], images: &[String]) -> anyhow::Result<()> {
    if target_args.first().map(String::as_str) != Some("rmi") {
        bail!(
            "refusing Docker image-removal alias; the initial lossless boundary accepts only `docker rmi --no-prune TAG`"
        );
    }
    if images.len() != 1 {
        bail!(
            "refusing Docker image removal with {} targets; exactly one named tag is supported",
            images.len()
        );
    }

    let no_prune_count = target_args
        .iter()
        .filter(|arg| matches!(arg.as_str(), "--no-prune" | "--no-prune=true"))
        .count();
    let any_no_prune = target_args
        .iter()
        .filter(|arg| arg.as_str() == "--no-prune" || arg.starts_with("--no-prune="))
        .count();
    if no_prune_count != 1 || any_no_prune != 1 {
        bail!(
            "refusing Docker image removal unless exactly one effective --no-prune=true flag is present"
        );
    }
    if target_args.iter().any(|arg| {
        arg == "-f"
            || arg == "--force"
            || arg.starts_with("--force=")
            || (arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.as_bytes()[1..].contains(&b'f'))
    }) {
        bail!("refusing Docker image removal with --force in the initial lossless boundary");
    }
    Ok(())
}

fn is_destructive_payload(payload: &VerbPayload) -> bool {
    match payload {
        VerbPayload::Docker(DockerVerb::Pull { .. } | DockerVerb::StopOrKill { .. })
        | VerbPayload::Podman(PodmanVerb::Pull { .. } | PodmanVerb::StopOrKill { .. })
        | VerbPayload::Compose(ComposeVerb::Up { .. } | ComposeVerb::Stop { .. }) => false,
        VerbPayload::Docker(_)
        | VerbPayload::Podman(_)
        | VerbPayload::Compose(ComposeVerb::Down { .. } | ComposeVerb::Rm { .. }) => true,
    }
}

fn probe_runtime_liveness(tool: &str) -> anyhow::Result<()> {
    capture_output(
        tool,
        docker_context_args(["info".into()]),
        TEXT_CAPTURE_MAX_BYTES,
    )
    .map(|_| ())
    .with_context(|| format!("run `{tool} --context {REQUIRED_DOCKER_CONTEXT} info`"))
}

fn probe_removed_image(tool: &str, ordinal: usize, image: &str) -> ContainerTargetObservationWire {
    let args = docker_context_args(["image".into(), "inspect".into(), image.into()]);
    let result = staging::capture_command(tool, &args, TEXT_CAPTURE_MAX_BYTES);
    let (state, detail) = match result {
        Ok(_) => (ContainerTargetStateWire::Present, None),
        Err(staging::CaptureError::Exit { stderr, .. }) if is_typed_image_absence(&stderr) => {
            (ContainerTargetStateWire::Absent, None)
        }
        Err(error) => (
            ContainerTargetStateWire::ProbeFailed,
            Some(bounded_probe_detail(&format!("{error:#}"))),
        ),
    };
    ContainerTargetObservationWire {
        ordinal: ordinal as u32,
        state,
        detail,
    }
}

fn is_typed_image_absence(stderr: &str) -> bool {
    let diagnostic = stderr.to_ascii_lowercase();
    [
        "no such image",
        "image not known",
        "image not found",
        "image does not exist",
    ]
    .iter()
    .any(|needle| diagnostic.contains(needle))
}

fn bounded_probe_detail(detail: &str) -> String {
    detail.chars().take(PROBE_DETAIL_MAX_CHARS).collect()
}

fn during_undo(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

fn command_identity_from_env() -> anyhow::Result<CommandIdentity> {
    command_identity_from_values(
        std::env::var_os(COMMAND_SESSION_ENV),
        std::env::var_os(COMMAND_SEQ_ENV),
    )
}

fn command_identity_from_values(
    session: Option<OsString>,
    seq: Option<OsString>,
) -> anyhow::Result<CommandIdentity> {
    let session = session
        .ok_or_else(|| anyhow::anyhow!("{COMMAND_SESSION_ENV} is not exported"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("{COMMAND_SESSION_ENV} is not valid UTF-8"))?;
    let parsed = Uuid::parse_str(&session)
        .with_context(|| format!("{COMMAND_SESSION_ENV} is not a valid UUID"))?;
    if parsed.is_nil() || parsed.to_string() != session {
        bail!("{COMMAND_SESSION_ENV} must be a non-nil canonical lowercase hyphenated UUID");
    }

    let seq = seq
        .ok_or_else(|| anyhow::anyhow!("{COMMAND_SEQ_ENV} is not exported"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("{COMMAND_SEQ_ENV} is not valid UTF-8"))?;
    let parsed_seq = seq
        .parse::<u64>()
        .with_context(|| format!("{COMMAND_SEQ_ENV} is not a positive decimal sequence"))?;
    if parsed_seq == 0 || parsed_seq.to_string() != seq {
        bail!("{COMMAND_SEQ_ENV} must be a canonical positive decimal sequence");
    }
    Ok(CommandIdentity { session, seq })
}

fn validate_docker_environment() -> anyhow::Result<()> {
    validate_docker_environment_with(|key| std::env::var_os(key))
}

fn validate_docker_environment_with(
    mut get: impl FnMut(&str) -> Option<OsString>,
) -> anyhow::Result<()> {
    for key in MUTABLE_DOCKER_ENV {
        if get(key).is_some() {
            bail!(
                "refusing Docker image removal while {key} is set; endpoint selection must be immutable and use context `default`"
            );
        }
    }
    Ok(())
}

fn docker_context_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut pinned = vec!["--context".into(), REQUIRED_DOCKER_CONTEXT.into()];
    pinned.extend(args);
    pinned
}

fn prove_default_docker_context(tool: &str) -> anyhow::Result<()> {
    let bytes = capture_output(
        tool,
        vec!["context".into(), "show".into()],
        TEXT_CAPTURE_MAX_BYTES,
    )
    .with_context(|| format!("prove ambient Docker context `{REQUIRED_DOCKER_CONTEXT}`"))?;
    let shown = std::str::from_utf8(&bytes)
        .context("Docker context name is not UTF-8")?
        .trim();
    if shown != REQUIRED_DOCKER_CONTEXT {
        bail!("ambient Docker context is `{shown}`; required `{REQUIRED_DOCKER_CONTEXT}`");
    }
    Ok(())
}

fn removes_anonymous_volumes(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--volumes"
            || (arg.starts_with("--volumes=") && arg != "--volumes=false")
            || (arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.as_bytes()[1..].contains(&b'v'))
    })
}

fn rmi_disables_prune(args: &[String]) -> bool {
    args.iter().fold(None, |effective, arg| match arg.as_str() {
        "--no-prune" | "--no-prune=true" => Some(true),
        "--no-prune=false" => Some(false),
        value if value.starts_with("--no-prune=") => Some(false),
        _ => effective,
    }) == Some(true)
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

/// AU24 — returns Vec<PreparedEvent> so a multi-target invocation
/// (`docker rmi a b c`) ships N events. Pre-AU24 returned
/// Option<PreparedEvent> and silently dropped non-first positionals.
fn prepare(
    tool: &str,
    runtime: ContainerRuntimeWire,
    v: VerbPayload,
) -> anyhow::Result<Vec<PreparedEvent>> {
    // Compose verbs are a separate enum shape; route them out first
    // so the docker-verb normalisation below stays uniform.
    if let VerbPayload::Compose(c) = v {
        return prepare_compose(tool, c).map(|event| event.into_iter().collect());
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
        DockerVerb::StopOrKill { .. } => Ok(Vec::new()),
        // AU23 — pull doesn't ship at the pre-phase: pre-pull we
        // don't yet know the resolved digest, and the floating-tag
        // alone is exactly the moving-target the audit finding
        // wanted to fix. The post-phase handler (see
        // `prepare_pull_post`) runs `<tool> inspect` after the real
        // pull and emits the event with the resolved id.
        DockerVerb::Pull { .. } => Ok(Vec::new()),
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
) -> anyhow::Result<Vec<PreparedEvent>> {
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
        VerbPayload::Compose(_) => return Ok(Vec::new()),
    };

    match docker_verb {
        DockerVerb::Pull { images } => Ok(prepare_pull_post(tool, images)),
        // Every other verb's data ships at pre-phase; post is a
        // no-op for them.
        _ => Ok(Vec::new()),
    }
}

/// AU23 — emit one ContainerEvent per pulled image with the
/// resolved digest captured via `<tool> inspect`. Ship even when
/// inspect fails so the journal records the pull attempt (the
/// renderer just shows "(digest unresolved)" in that case).
///
/// AU24 / DR-CR-52 — N images produce N events under the same
/// command_seq. Mirrors the rmi multi-target shape.
fn prepare_pull_post(tool: &str, images: Vec<String>) -> Vec<PreparedEvent> {
    images
        .into_iter()
        .map(|image| prepare_pull_post_one(tool, image))
        .collect()
}

fn prepare_pull_post_one(tool: &str, image: String) -> PreparedEvent {
    let resolved_id = inspect_image_digest(tool, &image);
    let mut extras = BTreeMap::new();
    extras.insert("image".into(), image);
    if let Some(id) = resolved_id {
        extras.insert("resolved_id".into(), id);
    }
    PreparedEvent {
        verb: ContainerVerbWire::Pull,
        captured_config: Vec::new(),
        stash_tarball: None,
        stash_tarball_bytes: None,
        stash_image: None,
        extras,
    }
}

/// Capture a runtime command's stdout without ever buffering more than `cap`
/// bytes in memory. The staging descriptor is unlinked before the child starts,
/// and [`CapturedArchive::into_inline`] re-proves its length and hash.
fn capture_output(tool: &str, args: Vec<String>, cap: u64) -> anyhow::Result<Vec<u8>> {
    let archive = staging::capture_command(tool, &args, cap)
        .with_context(|| format!("capture bounded output from `{tool} {}`", args.join(" ")))?;
    archive
        .into_inline(cap)
        .with_context(|| format!("verify bounded output from `{tool} {}`", args.join(" ")))
}

/// Capture the one image admitted by the initial lossless boundary.
fn prepare_rmi(
    tool: &str,
    runtime: ContainerRuntimeWire,
    images: Vec<String>,
) -> anyhow::Result<Vec<PreparedEvent>> {
    if images.len() != 1 {
        bail!(
            "container image removal has {} targets; exactly one is supported",
            images.len()
        );
    }
    let mut prepared = Vec::with_capacity(images.len());
    let mut aggregate_bytes = 0_u64;
    for image in images {
        let remaining = INLINE_TARBALL_MAX_BYTES.saturating_sub(aggregate_bytes);
        let event = prepare_rmi_one_with_cap(tool, runtime, image, remaining)?;
        aggregate_bytes = aggregate_bytes.saturating_add(
            event
                .stash_tarball_bytes
                .as_ref()
                .map_or(0, |bytes| bytes.len() as u64),
        );
        prepared.push(event);
    }
    Ok(prepared)
}

/// AU24 helper — per-image rmi capture. The destructive command is not
/// released unless the complete image archive fits the bounded inline path.
fn prepare_rmi_one(tool: &str, image: String) -> anyhow::Result<PreparedEvent> {
    prepare_rmi_one_with_cap(
        tool,
        ContainerRuntimeWire::Docker,
        image,
        INLINE_TARBALL_MAX_BYTES,
    )
}

fn prepare_rmi_one_with_cap(
    tool: &str,
    runtime: ContainerRuntimeWire,
    image: String,
    remaining_batch_bytes: u64,
) -> anyhow::Result<PreparedEvent> {
    if runtime != ContainerRuntimeWire::Docker {
        bail!("only Docker archives are accepted by the initial image-removal boundary");
    }
    if image.contains('@')
        || image.starts_with("sha256:")
        || image.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!(
            "refusing image removal for raw ID/digest `{image}`: the current archive inverse is proven only for named tags"
        );
    }
    // The immutable ID is required both for post-removal proof and for the
    // executor's later-state conflict guard. A tag-only snapshot is not
    // enough: that tag may resolve to a different image before undo.
    prove_default_docker_context(tool)?;
    let digest = inspect_docker_image_digest_default_context(tool, &image).ok_or_else(|| {
        anyhow::anyhow!("could not capture immutable image ID for `{image}` before image removal")
    })?;
    // Save by immutable image ID, never by the mutable tag. Otherwise a
    // concurrent retag between inspect and `save` could bind the archive
    // bytes to a different image than the conflict guard recorded.
    let args = docker_context_args(["save".to_string(), digest.clone()]);
    let archive = staging::capture_command(tool, &args, remaining_batch_bytes)
        .with_context(|| format!("capture `{tool} save {digest}` for tagged image `{image}`"))?;
    let raw_bytes = archive
        .into_inline(remaining_batch_bytes)
        .with_context(|| format!("verify `{tool} save {image}` archive"))?;
    let bytes = sanitize_docker_archive(&raw_bytes)
        .with_context(|| format!("strip mutable reference metadata from `{image}` archive"))?;
    validate_docker_archive_binding(&bytes, &digest)
        .with_context(|| format!("validate immutable archive for `{image}`"))?;
    let hash = *blake3::hash(&bytes).as_bytes();
    let post_save_digest =
        inspect_docker_image_digest_default_context(tool, &image).ok_or_else(|| {
            anyhow::anyhow!(
                "image tag `{image}` stopped resolving after its immutable archive was captured"
            )
        })?;
    if !same_image_id(&post_save_digest, &digest) {
        bail!(
            "image tag `{image}` changed from `{digest}` to `{post_save_digest}` while its pre-image was being captured"
        );
    }
    prove_default_docker_context(tool)
        .context("Docker context changed after the immutable archive was captured")?;

    let mut extras = BTreeMap::new();
    extras.insert("image".into(), image);
    extras.insert("digest".into(), digest);

    Ok(PreparedEvent {
        verb: ContainerVerbWire::Rmi,
        captured_config: Vec::new(),
        stash_tarball: Some(hash),
        stash_tarball_bytes: Some(bytes),
        stash_image: None,
        extras,
    })
}

/// Remove metadata that can create mutable names when `docker load` consumes
/// the archive. Docker 25+ emits an OCI layout alongside the backwards-
/// compatible `manifest.json`; retaining the blobs and classic manifest while
/// dropping the OCI entry point is both current-Docker compatible and leaves a
/// single tag-free import path for the executor.
fn sanitize_docker_archive(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    const TAR_BLOCK: usize = 512;
    let mut output = Vec::with_capacity(bytes.len());
    let mut offset = 0_usize;
    let mut saw_terminator = false;
    while offset
        .checked_add(TAR_BLOCK)
        .is_some_and(|end| end <= bytes.len())
    {
        let header = &bytes[offset..offset + TAR_BLOCK];
        if header.iter().all(|byte| *byte == 0) {
            if bytes
                .get(offset..offset.saturating_add(TAR_BLOCK * 2))
                .is_none_or(|blocks| blocks.iter().any(|byte| *byte != 0))
            {
                bail!("container archive does not have two zero terminator blocks");
            }
            saw_terminator = true;
            break;
        }
        let size = parse_tar_octal(&header[124..136])?;
        let data_start = offset
            .checked_add(TAR_BLOCK)
            .ok_or_else(|| anyhow::anyhow!("tar entry offset overflow"))?;
        let padded = size
            .checked_add(TAR_BLOCK - 1)
            .map(|value| value / TAR_BLOCK * TAR_BLOCK)
            .ok_or_else(|| anyhow::anyhow!("tar entry size overflow"))?;
        let entry_end = data_start
            .checked_add(padded)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| anyhow::anyhow!("tar entry extends past archive boundary"))?;
        let name = tar_entry_name(header)?;
        match header[156] {
            0 | b'0' | b'5' => {}
            other => bail!(
                "container archive uses unsupported tar typeflag {other:#x}; links and extended-name metadata are not accepted"
            ),
        }
        let normalized = name.trim_start_matches("./");
        if !matches!(normalized, "repositories" | "index.json" | "oci-layout") {
            output.extend_from_slice(&bytes[offset..entry_end]);
        }
        offset = entry_end;
    }
    if !saw_terminator {
        bail!("container archive has no canonical tar terminator");
    }
    output.resize(output.len() + TAR_BLOCK * 2, 0);
    Ok(output)
}

/// Prove that a one-image Docker archive identifies the immutable image ID
/// captured before the runtime is authorized. Docker and Podman's
/// `docker-archive` format put this binding in `manifest.json`'s Config
/// filename. Parsing directly from the bounded in-memory tar avoids extraction
/// and rejects truncated/ambiguous archives before they become undo evidence.
fn validate_docker_archive_binding(bytes: &[u8], expected_id: &str) -> anyhow::Result<()> {
    const TAR_BLOCK: usize = 512;
    let expected_hex = expected_id
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("expected image ID is not sha256-prefixed"))?;
    let mut offset = 0_usize;
    let mut manifest = None;
    let mut regular_entries: Vec<(String, &[u8])> = Vec::new();

    while offset
        .checked_add(TAR_BLOCK)
        .is_some_and(|end| end <= bytes.len())
    {
        let header = &bytes[offset..offset + TAR_BLOCK];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let size = parse_tar_octal(&header[124..136])?;
        let data_start = offset
            .checked_add(TAR_BLOCK)
            .ok_or_else(|| anyhow::anyhow!("tar entry offset overflow"))?;
        let data_end = data_start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| anyhow::anyhow!("tar entry extends past archive boundary"))?;
        let name = tar_entry_name(header)?;
        let normalized_name = name.trim_start_matches("./");
        if matches!(
            normalized_name,
            "repositories" | "index.json" | "oci-layout"
        ) {
            bail!("archive contains forbidden mutable-reference metadata `{normalized_name}`");
        }
        let typeflag = header[156];
        let is_regular = matches!(typeflag, 0 | b'0');
        if normalized_name == "manifest.json" {
            if !is_regular {
                bail!("archive manifest.json is not a regular file");
            }
            if manifest.is_some() {
                bail!("archive contains more than one manifest.json entry");
            }
            manifest = Some(&bytes[data_start..data_end]);
        }
        if is_regular {
            let normalized = normalized_name.to_string();
            if regular_entries
                .iter()
                .any(|(existing, _)| existing == &normalized)
            {
                bail!("archive contains duplicate regular entry `{normalized}`");
            }
            regular_entries.push((normalized, &bytes[data_start..data_end]));
        }
        let padded = size
            .checked_add(TAR_BLOCK - 1)
            .map(|value| value / TAR_BLOCK * TAR_BLOCK)
            .ok_or_else(|| anyhow::anyhow!("tar entry size overflow"))?;
        offset = data_start
            .checked_add(padded)
            .ok_or_else(|| anyhow::anyhow!("tar entry offset overflow"))?;
    }

    let manifest: serde_json::Value = serde_json::from_slice(
        manifest.ok_or_else(|| anyhow::anyhow!("archive has no manifest.json"))?,
    )
    .context("parse archive manifest.json")?;
    let entries = manifest
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("archive manifest.json is not an array"))?;
    if entries.len() != 1 {
        bail!(
            "archive manifest contains {} images; expected exactly one",
            entries.len()
        );
    }
    let entry = &entries[0];
    match entry.get("RepoTags") {
        Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(tags)) if tags.is_empty() => {}
        Some(_) => bail!(
            "archive manifest contains RepoTags; immutable-ID save must not preserve a mutable tag binding"
        ),
        None => bail!("archive manifest has no RepoTags field"),
    }
    let config = entry
        .get("Config")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("archive manifest has no Config filename"))?;
    let normalized_config = config.trim_start_matches("./");
    if normalized_config.is_empty()
        || normalized_config.starts_with('/')
        || normalized_config.split('/').any(|part| part == "..")
    {
        bail!("archive Config path `{config}` is not a safe relative tar member");
    }
    let config_name = config
        .rsplit('/')
        .next()
        .unwrap_or(config)
        .strip_suffix(".json")
        .unwrap_or_else(|| config.rsplit('/').next().unwrap_or(config));
    let config_hex = config_name.strip_prefix("sha256:").unwrap_or(config_name);
    if config_hex.len() != 64
        || !config_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !config_hex.eq_ignore_ascii_case(expected_hex)
    {
        bail!("archive Config `{config}` does not match captured image ID `{expected_id}`");
    }
    let config_bytes = regular_entries
        .iter()
        .find_map(|(name, bytes)| (name == normalized_config).then_some(*bytes))
        .ok_or_else(|| {
            anyhow::anyhow!("archive Config member `{config}` is absent or not a regular file")
        })?;
    let actual = Sha256::digest(config_bytes);
    let actual_hex = actual
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !actual_hex.eq_ignore_ascii_case(expected_hex) {
        bail!(
            "archive Config member bytes hash to sha256:{actual_hex}, not captured image ID `{expected_id}`"
        );
    }
    let config_json: serde_json::Value =
        serde_json::from_slice(config_bytes).context("parse archive Config member JSON")?;
    if config_json
        .pointer("/rootfs/type")
        .and_then(serde_json::Value::as_str)
        != Some("layers")
    {
        bail!("archive Config member has no rootfs.type=layers");
    }
    let diff_ids = config_json
        .pointer("/rootfs/diff_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("archive Config member has no rootfs.diff_ids array"))?;
    let layers = entry
        .get("Layers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("archive manifest has no Layers array"))?;
    if layers.len() != diff_ids.len() {
        bail!(
            "archive manifest has {} layers but Config rootfs has {} diff IDs",
            layers.len(),
            diff_ids.len()
        );
    }
    let mut seen_layers = std::collections::BTreeSet::new();
    for (layer, diff_id) in layers.iter().zip(diff_ids) {
        let layer = layer
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("archive manifest has a non-string layer path"))?;
        let diff_hex = diff_id
            .as_str()
            .and_then(|value| value.strip_prefix("sha256:"))
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| anyhow::anyhow!("archive Config has an invalid rootfs diff ID"))?;
        let normalized = layer.trim_start_matches("./");
        if normalized.is_empty()
            || normalized.starts_with('/')
            || normalized.split('/').any(|part| part == "..")
        {
            bail!("archive layer path `{layer}` is not a safe relative tar member");
        }
        if !seen_layers.insert(normalized) {
            bail!("archive manifest repeats layer member `{layer}`");
        }
        let layer_bytes = regular_entries
            .iter()
            .find_map(|(name, bytes)| (name == normalized).then_some(*bytes))
            .ok_or_else(|| anyhow::anyhow!("archive layer member `{layer}` is absent"))?;
        if let Some(hex) = normalized.strip_prefix("blobs/sha256/")
            && (hex.len() != 64
                || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                || sha256_hex(layer_bytes) != hex.to_ascii_lowercase())
        {
            bail!("archive layer blob `{layer}` does not match its sha256 path");
        }
        if !normalized.starts_with("blobs/sha256/")
            && sha256_hex(layer_bytes) != diff_hex.to_ascii_lowercase()
        {
            bail!("archive legacy layer `{layer}` does not match its rootfs diff ID");
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_tar_octal(field: &[u8]) -> anyhow::Result<usize> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        bail!("base-256 tar sizes are not accepted for container archives");
    }
    let digits = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ' || *byte == 0)
        .take_while(|byte| *byte != b' ' && *byte != 0)
        .collect::<Vec<_>>();
    if digits.is_empty() || !digits.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        bail!("tar entry has an invalid octal size");
    }
    let digits = std::str::from_utf8(&digits).context("tar size is not ASCII")?;
    usize::from_str_radix(digits, 8).context("tar entry size overflows usize")
}

fn tar_entry_name(header: &[u8]) -> anyhow::Result<String> {
    let field = |range: std::ops::Range<usize>| -> anyhow::Result<&str> {
        let raw = &header[range];
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        std::str::from_utf8(&raw[..end]).context("tar entry name is not UTF-8")
    };
    let name = field(0..100)?;
    let prefix = field(345..500)?;
    if prefix.is_empty() {
        Ok(name.to_string())
    } else {
        Ok(format!("{prefix}/{name}"))
    }
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
fn docker_volume_tar(tool: &str, name: &str) -> anyhow::Result<CapturedArchive> {
    let args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        // Mount read-only — we're only copying out. The trailing `:ro`
        // keeps the source pristine while tar traverses it.
        format!("{name}:/src:ro"),
        "busybox".to_string(),
        "tar".to_string(),
        "-C".to_string(),
        "/src".to_string(),
        "-czf".to_string(),
        "-".to_string(),
        ".".to_string(),
    ];
    staging::capture_command(tool, &args, INLINE_TARBALL_MAX_BYTES)
        .with_context(|| format!("capture volume `{name}` before removal"))
}

/// Capture and validate a volume's creation metadata. The current inverse
/// executor can recreate only the default local driver without labels or
/// driver options. Refuse richer volumes rather than silently changing their
/// backing semantics during undo.
fn inspect_volume(tool: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = capture_output(
        tool,
        vec!["volume".into(), "inspect".into(), name.into()],
        CONFIG_CAPTURE_MAX_BYTES,
    )
    .with_context(|| format!("inspect volume `{name}` before removal"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse `{tool} volume inspect {name}` JSON"))?;
    let object = inspect_object(&value)
        .with_context(|| format!("validate `{tool} volume inspect {name}` JSON"))?;
    let driver = object
        .get("Driver")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("local");
    if driver != "local" {
        bail!(
            "volume `{name}` uses unsupported driver `{driver}`; refusing removal because undo cannot reproduce its driver configuration"
        );
    }
    for field in ["Options", "Labels"] {
        if object
            .get(field)
            .and_then(serde_json::Value::as_object)
            .is_some_and(|map| !map.is_empty())
        {
            bail!(
                "volume `{name}` has non-empty {field}; refusing removal because undo cannot reproduce that metadata"
            );
        }
    }
    Ok(bytes)
}

/// Run `{tool} network inspect <name>` and return the raw JSON bytes
/// from stdout. Docker emits an array-of-one shape — the planner's
/// [`synthesize_network_create`] unwraps that.
fn docker_network_inspect(tool: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = capture_output(
        tool,
        vec!["network".into(), "inspect".into(), name.into()],
        CONFIG_CAPTURE_MAX_BYTES,
    )
    .with_context(|| format!("inspect network `{name}` before removal"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse `{tool} network inspect {name}` JSON"))?;
    inspect_object(&value)
        .with_context(|| format!("validate `{tool} network inspect {name}` JSON"))?;
    Ok(bytes)
}

/// AR03.4 (DR-CR-26 network-rm path): capture a network's config as
/// the JSON output of `docker network inspect`. No tarball — the
/// payload is small (~1-2 KiB) and fits comfortably in the standard
/// frame. Daemon-side [`ContainerExecutor::apply_network_rm`] parses
/// the JSON and feeds it through [`synthesize_network_create`] to
/// rebuild the `docker network create` argv.
///
/// AU24 / DR-CR-52 — multi-name `docker network rm n1 n2 n3`
/// produces N events under the shared command_seq, same shape as
/// rmi and pull batching.
fn prepare_network_rm(tool: &str, names: Vec<String>) -> anyhow::Result<Vec<PreparedEvent>> {
    names
        .into_iter()
        .map(|name| prepare_network_rm_one(tool, name))
        .collect()
}

fn prepare_network_rm_one(tool: &str, name: String) -> anyhow::Result<PreparedEvent> {
    let mut extras = BTreeMap::new();
    extras.insert("name".into(), name.clone());
    let json_bytes = docker_network_inspect(tool, &name)?;
    Ok(PreparedEvent {
        verb: ContainerVerbWire::NetworkRm,
        captured_config: json_bytes,
        stash_tarball: None,
        stash_tarball_bytes: None,
        stash_image: None,
        extras,
    })
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
fn prepare_rm(tool: &str, ids: Vec<String>, _force: bool) -> anyhow::Result<Vec<PreparedEvent>> {
    ids.into_iter().map(|id| prepare_rm_one(tool, id)).collect()
}

fn prepare_rm_one(tool: &str, id: String) -> anyhow::Result<PreparedEvent> {
    let mut extras = BTreeMap::new();
    extras.insert("id".into(), id.clone());
    let inspect_json = docker_container_inspect(tool, &id)?;
    let was_running = inspect_is_running(&inspect_json)
        .with_context(|| format!("read running state for container `{id}`"))?;
    extras.insert("was_running".into(), was_running.to_string());

    if let Some(name) = inspect_container_name(&inspect_json) {
        extras.insert("name".into(), name);
    }

    // A stopped container can have writable-layer changes too. Commit every
    // container, not just a running one, or undo would silently fall back to
    // the original image and lose those changes.
    let stash_image = Some(docker_commit_container(tool, &id)?);

    Ok(PreparedEvent {
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
fn docker_container_inspect(tool: &str, id: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = capture_output(
        tool,
        vec!["inspect".into(), id.into()],
        CONFIG_CAPTURE_MAX_BYTES,
    )
    .with_context(|| format!("inspect container `{id}` before removal"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse `{tool} inspect {id}` JSON"))?;
    inspect_object(&value).with_context(|| format!("validate `{tool} inspect {id}` JSON"))?;
    Ok(bytes)
}

/// Best-effort extraction of `.State.Running` from inspect JSON.
/// Returns false on any parse failure — restore then runs from the
/// original image (acceptable for a stopped container; lossy for a
/// running one, but if inspect's JSON is malformed there's nothing
/// the daemon could do anyway).
fn inspect_is_running(bytes: &[u8]) -> anyhow::Result<bool> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    inspect_object(&value)?
        .get("State")
        .and_then(|s| s.get("Running"))
        .and_then(|v| v.as_bool())
        .ok_or_else(|| anyhow::anyhow!("inspect JSON has no boolean State.Running"))
}

fn inspect_object(
    value: &serde_json::Value,
) -> anyhow::Result<&serde_json::Map<String, serde_json::Value>> {
    let value = match value {
        serde_json::Value::Array(items) if items.len() == 1 => &items[0],
        serde_json::Value::Array(items) => {
            bail!(
                "inspect JSON contained {} objects; expected exactly one",
                items.len()
            )
        }
        value => value,
    };
    value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("inspect JSON is not an object"))
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
fn docker_commit_container(tool: &str, id: &str) -> anyhow::Result<String> {
    let short = id.chars().take(12).collect::<String>();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tag = format!("shit-stash-{short}-{ts}");
    let _ = capture_output(
        tool,
        vec!["commit".into(), id.into(), tag.clone()],
        TEXT_CAPTURE_MAX_BYTES,
    )
    .with_context(|| format!("commit container `{id}` before removal"))?;
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
fn prepare_compose(tool: &str, verb: ComposeVerb) -> anyhow::Result<Option<PreparedEvent>> {
    match verb {
        ComposeVerb::Down {
            files: _,
            project_override: _,
            with_volumes: _,
        } => bail!(
            "`{tool} down` is not yet losslessly undoable; refusing to remove project containers, networks, or volumes"
        ),
        // Up is restart-hint (the project is starting; no destructive
        // capture needed — undo of `up` is `down` which the user runs
        // explicitly). Stop is a restart-hint. Rm needs per-service
        // inspect + commit (a multiplied AR10.9); deferred.
        ComposeVerb::Rm { .. } => bail!(
            "`{tool} rm` is not yet losslessly undoable; refusing to remove service container writable layers"
        ),
        ComposeVerb::Up { .. } | ComposeVerb::Stop { .. } => {
            tracing::debug!(
                ?verb,
                "container-event: compose verb not destructive in v1 (or deferred)"
            );
            Ok(None)
        }
    }
}

/// AU24 / DR-CR-52 — `docker volume rm v1 v2 v3` produces N
/// independently-stashed events under the shared command_seq.
/// Each volume gets its own `docker volume create` + tar capture.
fn prepare_volume_rm(tool: &str, names: Vec<String>) -> anyhow::Result<Vec<PreparedEvent>> {
    names
        .into_iter()
        .map(|name| prepare_volume_rm_one(tool, name))
        .collect()
}

fn prepare_volume_rm_one(tool: &str, name: String) -> anyhow::Result<PreparedEvent> {
    let captured_config = inspect_volume(tool, &name)?;
    let archive = docker_volume_tar(tool, &name)?;
    let hash = archive.hash();
    let bytes = archive
        .into_inline(INLINE_TARBALL_MAX_BYTES)
        .with_context(|| format!("verify volume `{name}` archive"))?;

    let mut extras = BTreeMap::new();
    extras.insert("name".into(), name);

    Ok(PreparedEvent {
        verb: ContainerVerbWire::VolumeRm,
        captured_config,
        stash_tarball: Some(hash),
        stash_tarball_bytes: Some(bytes),
        stash_image: None,
        extras,
    })
}

/// Resolve and validate the immutable content ID for one named image.
///
/// Rmi capture treats this as mandatory: it is both the operand used for the
/// archive save and the later-state conflict guard used during undo.
fn inspect_image_digest(tool: &str, image: &str) -> Option<String> {
    let bytes = capture_output(
        tool,
        vec![
            "inspect".into(),
            "--format".into(),
            "{{.Id}}".into(),
            image.into(),
        ],
        TEXT_CAPTURE_MAX_BYTES,
    )
    .ok()?;
    let s = String::from_utf8(bytes).ok()?;
    let trimmed = s.trim();
    let hex = trimmed.strip_prefix("sha256:")?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{}", hex.to_ascii_lowercase()))
}

fn inspect_docker_image_digest_default_context(tool: &str, image: &str) -> Option<String> {
    let bytes = capture_output(
        tool,
        docker_context_args([
            "image".into(),
            "inspect".into(),
            "--format".into(),
            "{{.Id}}".into(),
            image.into(),
        ]),
        TEXT_CAPTURE_MAX_BYTES,
    )
    .ok()?;
    normalize_image_digest(&bytes)
}

fn normalize_image_digest(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let trimmed = s.trim();
    let hex = trimmed.strip_prefix("sha256:")?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{}", hex.to_ascii_lowercase()))
}

fn same_image_id(actual: &str, expected: &str) -> bool {
    actual
        .strip_prefix("sha256:")
        .unwrap_or(actual)
        .eq_ignore_ascii_case(expected.strip_prefix("sha256:").unwrap_or(expected))
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
    match call_ctl(path, &CtlRequest::ContainerEvent(req.clone()))? {
        CtlResponse::ContainerEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}

fn call_ctl(path: &Path, request: &CtlRequest) -> anyhow::Result<CtlResponse> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    // ContainerEvent carries tarball bytes (alpine ~5 MB, distroless
    // ~20 MB) — well over MAX_FRAME_SIZE. encode_frame_large uses the
    // 64 MiB cap that matches our INLINE_TARBALL_MAX_BYTES. The
    // daemon ctl reader peeks the length prefix first and grows the
    // buffer when it sees a large frame.
    let frame = encode_frame_large(request)?;
    stream.write_all(&frame)?;
    // Stream reads can split a response anywhere. Read the prefix first, bound
    // the declared body, then read exactly one complete response frame.
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix)?;
    let body_len = u32::from_be_bytes(prefix) as usize;
    if body_len == 0 || body_len.saturating_add(4) > MAX_FRAME_SIZE {
        bail!("daemon returned invalid ctl frame length {body_len}");
    }
    let mut buf = Vec::with_capacity(body_len + 4);
    buf.extend_from_slice(&prefix);
    buf.resize(body_len + 4, 0);
    stream.read_exact(&mut buf[4..])?;
    decode_frame(&buf).map_err(Into::into)
}

/// Retry an ambiguous local transport failure with the exact same request.
/// Container batch requests carry a stable UUID and content hash, so daemon
/// replay is idempotent. Encoding/protocol errors are deterministic and must
/// not be retried.
fn call_ctl_retry_io(path: &Path, request: &CtlRequest) -> anyhow::Result<CtlResponse> {
    let mut last_error = None;
    for attempt in 0..CTL_IO_ATTEMPTS {
        match call_ctl(path, request) {
            Ok(response) => return Ok(response),
            Err(error)
                if error.downcast_ref::<std::io::Error>().is_some()
                    && attempt + 1 < CTL_IO_ATTEMPTS =>
            {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop always records an I/O error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn runtime_script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("fake-container-runtime");
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    const TEST_CONFIG: &[u8] =
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;

    fn sha256_id(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        format!(
            "sha256:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    fn push_tar_entry(archive: &mut Vec<u8>, name: &str, bytes: &[u8]) {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", bytes.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        archive.extend_from_slice(&header);
        archive.extend_from_slice(bytes);
        archive.resize(archive.len().div_ceil(512) * 512, 0);
    }

    fn test_docker_archive(config: &[u8], repo_tags: &str) -> Vec<u8> {
        let image_id = sha256_id(config);
        let config_hex = image_id.strip_prefix("sha256:").unwrap();
        let manifest =
            format!(r#"[{{"Config":"{config_hex}.json","RepoTags":{repo_tags},"Layers":[]}}]"#);
        let mut archive = Vec::new();
        push_tar_entry(&mut archive, "manifest.json", manifest.as_bytes());
        push_tar_entry(&mut archive, &format!("{config_hex}.json"), config);
        archive.resize(archive.len() + 1024, 0);
        archive
    }

    fn complete_fake_runtime(dir: &Path) -> PathBuf {
        let archive_path = dir.join("image.tar");
        let image_id = sha256_id(TEST_CONFIG);
        fs::write(&archive_path, test_docker_archive(TEST_CONFIG, "null")).unwrap();
        let body = r#"
if [ "${1:-}" = "--context" ]; then
  [ "${2:-}" = "default" ]
  shift 2
fi
case "$1" in
  context)
    [ "${2:-}" = "show" ]
    printf 'default\n'
    ;;
  image)
    [ "${2:-}" = "inspect" ]
    if [ "${3:-}" = "--format" ]; then
      printf '__IMAGE_ID__\n'
    else
      printf '[{"Id":"__IMAGE_ID__"}]'
    fi
    ;;
  inspect)
    if [ "${2:-}" = "--format" ]; then printf '__IMAGE_ID__\n'; else printf '[{"Id":"abc123","Name":"/web","State":{"Running":false},"Config":{"Image":"base:latest"},"HostConfig":{},"Mounts":[]}]'; fi
    ;;
  commit) printf 'sha256:stash-id\n' ;;
  save)
    [ "${2:-}" = "__IMAGE_ID__" ]
    cat '__ARCHIVE_PATH__'
    ;;
  volume)
    [ "${2:-}" = "inspect" ]
    printf '[{"Name":"%s","Driver":"local","Labels":{},"Options":{}}]' "${3:-volume}"
    ;;
  network)
    [ "${2:-}" = "inspect" ]
    printf '[{"Name":"%s","Driver":"bridge","Labels":{},"Options":{}}]' "${3:-network}"
    ;;
  run) printf 'volume-archive' ;;
  info) printf '{}\n' ;;
  *) echo "unexpected fake-runtime argv: $*" >&2; exit 64 ;;
esac
"#
        .replace("__IMAGE_ID__", &image_id)
        .replace("__ARCHIVE_PATH__", &archive_path.to_string_lossy());
        runtime_script(dir, &body)
    }

    #[test]
    fn rm_volume_flag_detection_handles_combined_and_explicit_forms() {
        for args in [
            vec!["rm".into(), "-fv".into(), "web".into()],
            vec![
                "container".into(),
                "rm".into(),
                "--volumes".into(),
                "web".into(),
            ],
            vec!["rm".into(), "--volumes=true".into(), "web".into()],
        ] {
            assert!(removes_anonymous_volumes(&args), "{args:?}");
        }
        assert!(!removes_anonymous_volumes(&[
            "rm".into(),
            "--volumes=false".into(),
            "web".into(),
        ]));
    }

    #[test]
    fn rmi_requires_explicit_no_prune() {
        assert!(rmi_disables_prune(&[
            "rmi".into(),
            "--no-prune".into(),
            "alpine:latest".into(),
        ]));
        assert!(rmi_disables_prune(&[
            "image".into(),
            "rm".into(),
            "--no-prune=true".into(),
            "alpine:latest".into(),
        ]));
        assert!(!rmi_disables_prune(&[
            "rmi".into(),
            "--no-prune=false".into(),
            "alpine:latest".into(),
        ]));
        assert!(!rmi_disables_prune(&[
            "rmi".into(),
            "--no-prune=true".into(),
            "--no-prune=false".into(),
            "alpine:latest".into(),
        ]));
        assert!(rmi_disables_prune(&[
            "rmi".into(),
            "--no-prune=false".into(),
            "--no-prune=true".into(),
            "alpine:latest".into(),
        ]));
        assert!(!rmi_disables_prune(&[
            "rmi".into(),
            "--no-prune=maybe".into(),
            "alpine:latest".into(),
        ]));
    }

    #[test]
    fn batch_classifier_accepts_only_explicit_no_prune_rmi() {
        let accepted = classify_batch_rmi(
            "docker",
            &["rmi".into(), "--no-prune".into(), "alpine:v1".into()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(accepted.0, ContainerRuntimeWire::Docker);
        assert_eq!(accepted.1, vec!["alpine:v1"]);

        assert!(classify_batch_rmi("docker", &["rmi".into(), "alpine:v1".into()]).is_err());
        assert!(
            classify_batch_rmi(
                "podman",
                &["rmi".into(), "--no-prune".into(), "alpine:v1".into()]
            )
            .is_err()
        );
        assert!(classify_batch_rmi("docker", &["rm".into(), "web".into()]).is_err());
        assert!(classify_batch_rmi("docker", &["system".into(), "prune".into()]).is_err());
        assert!(classify_batch_rmi("docker-compose", &["down".into()]).is_err());
        assert!(
            classify_batch_rmi("docker", &["ps".into()])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn batch_classifier_rejects_multi_target_alias_prefix_and_option_ambiguity() {
        for args in [
            vec![
                "rmi".into(),
                "--no-prune".into(),
                "one:v1".into(),
                "two:v1".into(),
            ],
            vec![
                "image".into(),
                "rm".into(),
                "--no-prune".into(),
                "one:v1".into(),
            ],
            vec![
                "--context".into(),
                "default".into(),
                "rmi".into(),
                "--no-prune".into(),
                "one:v1".into(),
            ],
            vec![
                "rmi".into(),
                "--no-prune".into(),
                "--no-prune=true".into(),
                "one:v1".into(),
            ],
            vec![
                "rmi".into(),
                "--no-prune=false".into(),
                "--no-prune".into(),
                "one:v1".into(),
            ],
            vec![
                "rmi".into(),
                "--no-prune".into(),
                "--force".into(),
                "one:v1".into(),
            ],
        ] {
            assert!(classify_batch_rmi("docker", &args).is_err(), "{args:?}");
        }
        for args in [
            vec!["pull".into(), "one:v1".into()],
            vec!["tag".into(), "one:v1".into(), "two:v1".into()],
            vec!["load".into()],
            vec!["build".into(), ".".into()],
            vec!["future-mutator".into(), "one:v1".into()],
        ] {
            assert!(classify_batch_rmi("docker", &args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn command_identity_requires_canonical_exported_values() {
        let session = Uuid::now_v7().to_string();
        assert_eq!(
            command_identity_from_values(Some(session.clone().into()), Some("42".into())).unwrap(),
            CommandIdentity {
                session: session.clone(),
                seq: "42".into(),
            }
        );
        for bad_session in [
            None,
            Some(OsString::from(Uuid::nil().to_string())),
            Some(OsString::from(session.to_ascii_uppercase())),
            Some(OsString::from(session.replace('-', ""))),
        ] {
            assert!(command_identity_from_values(bad_session, Some("1".into())).is_err());
        }
        for bad_seq in [None, Some("0".into()), Some("01".into()), Some("+1".into())] {
            assert!(command_identity_from_values(Some(session.clone().into()), bad_seq).is_err());
        }
    }

    #[test]
    fn mutable_docker_endpoint_environment_is_always_refused() {
        for rejected in MUTABLE_DOCKER_ENV {
            let result = validate_docker_environment_with(|key| {
                (key == rejected).then_some(OsString::new())
            });
            assert!(result.is_err(), "{rejected}");
        }
        validate_docker_environment_with(|_| None).unwrap();
    }

    #[tokio::test]
    async fn legacy_destructive_event_cannot_authorize_runtime() {
        let error = run_event(
            "docker",
            "pre",
            &["rmi".into(), "--no-prune".into(), "alpine:v1".into()],
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("legacy container-event"));
    }

    #[test]
    fn image_absence_probe_is_typed_and_fail_closed() {
        assert!(is_typed_image_absence(
            "Error response from daemon: No such image: alpine:v1"
        ));
        assert!(is_typed_image_absence("Error: busybox:v1: image not known"));
        assert!(!is_typed_image_absence(
            "Cannot connect to the Docker daemon at unix:///tmp/docker.sock"
        ));

        let present_dir = tempfile::tempdir().unwrap();
        let present = runtime_script(present_dir.path(), "printf '[{}]'\n");
        let observed = probe_removed_image(present.to_str().unwrap(), 0, "alpine:v1");
        assert_eq!(observed.state, ContainerTargetStateWire::Present);
        assert!(observed.detail.is_none());

        let absent_dir = tempfile::tempdir().unwrap();
        let absent = runtime_script(
            absent_dir.path(),
            "echo 'Error response from daemon: No such image: alpine:v1' >&2\nexit 1",
        );
        let observed = probe_removed_image(absent.to_str().unwrap(), 1, "alpine:v1");
        assert_eq!(observed.ordinal, 1);
        assert_eq!(observed.state, ContainerTargetStateWire::Absent);
        assert!(observed.detail.is_none());

        let failed_dir = tempfile::tempdir().unwrap();
        let failed = runtime_script(
            failed_dir.path(),
            "echo 'Cannot connect to runtime' >&2\nexit 1",
        );
        let observed = probe_removed_image(failed.to_str().unwrap(), 2, "alpine:v1");
        assert_eq!(observed.state, ContainerTargetStateWire::ProbeFailed);
        assert!(
            observed
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("Cannot connect"))
        );
    }

    #[test]
    fn recursion_guard_requires_the_explicit_one_value() {
        assert!(during_undo(Some(OsStr::new("1"))));
        assert!(!during_undo(None));
        assert!(!during_undo(Some(OsStr::new(""))));
        assert!(!during_undo(Some(OsStr::new("0"))));
        assert!(!during_undo(Some(OsStr::new("true"))));
    }

    #[test]
    fn ctl_io_retry_replays_the_identical_request() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut prefix = [0_u8; 4];
                stream.read_exact(&mut prefix).unwrap();
                let body_len = u32::from_be_bytes(prefix) as usize;
                let mut frame = Vec::with_capacity(body_len + 4);
                frame.extend_from_slice(&prefix);
                frame.resize(body_len + 4, 0);
                stream.read_exact(&mut frame[4..]).unwrap();
                assert!(matches!(
                    shit_proto::decode_frame_large::<CtlRequest>(&frame).unwrap(),
                    CtlRequest::Ping
                ));
                if attempt == 1 {
                    stream
                        .write_all(&shit_proto::encode_frame(&CtlResponse::Pong).unwrap())
                        .unwrap();
                }
            }
        });

        assert!(matches!(
            call_ctl_retry_io(&socket, &CtlRequest::Ping).unwrap(),
            CtlResponse::Pong
        ));
        server.join().unwrap();
    }

    #[test]
    fn rmi_raw_ids_and_digest_references_are_refused() {
        for image in [
            "sha256:0123456789abcdef",
            "deadbee",
            "0123456789abcdef0123456789abcdef",
            "alpine@sha256:0123456789abcdef",
        ] {
            let error = match prepare_rmi_one("unused-runtime", image.into()) {
                Err(error) => error,
                Ok(_) => panic!("raw image reference unexpectedly accepted: {image}"),
            };
            assert!(error.to_string().contains("raw ID/digest"), "{error}");
        }
    }

    #[test]
    fn rmi_capture_requires_one_named_tag_and_validates_its_archive() {
        let error = match prepare_rmi(
            "unused-runtime",
            ContainerRuntimeWire::Docker,
            vec!["one:v1".into(), "two:v1".into()],
        ) {
            Err(error) => error,
            Ok(_) => panic!("multi-target image capture unexpectedly accepted"),
        };
        assert!(error.to_string().contains("exactly one"));

        let temp = tempfile::tempdir().unwrap();
        let tool = complete_fake_runtime(temp.path());
        let prepared = prepare_rmi(
            tool.to_str().unwrap(),
            ContainerRuntimeWire::Docker,
            vec!["alpine:v1".into()],
        )
        .unwrap();
        assert_eq!(prepared.len(), 1);
        let test_image_id = sha256_id(TEST_CONFIG);
        assert!(prepared.iter().all(|event| {
            event.extras.get("digest").map(String::as_str) == Some(test_image_id.as_str())
                && event.stash_tarball_bytes.as_deref().is_some_and(|bytes| {
                    validate_docker_archive_binding(bytes, &test_image_id).is_ok()
                })
        }));
    }

    #[test]
    fn docker_archive_binding_rejects_a_different_config_digest() {
        let archive = test_docker_archive(b"different config bytes", "null");
        let error = validate_docker_archive_binding(&archive, &sha256_id(TEST_CONFIG)).unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error:#}");
    }

    #[test]
    fn docker_archive_binding_hashes_the_actual_config_member() {
        let expected = sha256_id(TEST_CONFIG);
        let mut archive = test_docker_archive(TEST_CONFIG, "null");
        let offset = archive
            .windows(TEST_CONFIG.len())
            .position(|window| window == TEST_CONFIG)
            .expect("config member bytes");
        archive[offset] ^= 1;
        let error = validate_docker_archive_binding(&archive, &expected).unwrap_err();
        assert!(error.to_string().contains("member bytes hash"), "{error:#}");
    }

    #[test]
    fn docker_archive_binding_rejects_mutable_repo_tags() {
        let expected = sha256_id(TEST_CONFIG);
        let archive = test_docker_archive(TEST_CONFIG, r#"["example/image:v1"]"#);
        let error = validate_docker_archive_binding(&archive, &expected).unwrap_err();
        assert!(error.to_string().contains("RepoTags"), "{error:#}");
        validate_docker_archive_binding(&test_docker_archive(TEST_CONFIG, "[]"), &expected)
            .unwrap();
    }

    #[test]
    fn docker_archive_binding_rejects_legacy_and_oci_reference_metadata() {
        let expected = sha256_id(TEST_CONFIG);
        for forbidden in ["repositories", "index.json", "oci-layout"] {
            let mut archive = test_docker_archive(TEST_CONFIG, "null");
            archive.truncate(archive.len() - 1024);
            push_tar_entry(&mut archive, forbidden, b"{}");
            archive.resize(archive.len() + 1024, 0);
            let error = validate_docker_archive_binding(&archive, &expected).unwrap_err();
            assert!(
                error.to_string().contains("forbidden mutable-reference"),
                "{forbidden}: {error:#}"
            );
        }
    }

    #[test]
    fn docker_25_metadata_is_stripped_to_a_tag_free_classic_archive() {
        let expected = sha256_id(TEST_CONFIG);
        let mut archive = test_docker_archive(TEST_CONFIG, "null");
        archive.truncate(archive.len() - 1024);
        push_tar_entry(
            &mut archive,
            "index.json",
            br#"{"schemaVersion":2,"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"latest"}}]}"#,
        );
        push_tar_entry(
            &mut archive,
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        push_tar_entry(
            &mut archive,
            "repositories",
            br#"{"image":{"latest":"id"}}"#,
        );
        archive.resize(archive.len() + 1024, 0);

        let sanitized = sanitize_docker_archive(&archive).unwrap();
        validate_docker_archive_binding(&sanitized, &expected).unwrap();
        for removed in [b"index.json".as_slice(), b"oci-layout", b"repositories"] {
            assert!(
                !sanitized
                    .windows(removed.len())
                    .any(|window| window == removed),
                "{} survived archive sanitization",
                String::from_utf8_lossy(removed)
            );
        }
    }

    #[test]
    fn image_id_comparison_accepts_optional_prefix_and_hex_case_only() {
        assert!(same_image_id(
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!same_image_id(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
    }

    #[tokio::test]
    async fn rm_with_combined_volume_flag_is_refused_before_runtime() {
        let error = run_event(
            "docker",
            "pre",
            &["rm".into(), "-fv".into(), "web".into()],
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("anonymous-volume capture"));
    }

    #[test]
    fn destructive_capture_fails_closed_when_runtime_is_unavailable() {
        let missing = "shit-test-no-such-container-runtime";
        assert!(prepare_rm(missing, vec!["abc123".into()], true).is_err());
        assert!(prepare_volume_rm(missing, vec!["pgdata".into()]).is_err());
        assert!(prepare_network_rm(missing, vec!["frontend".into()]).is_err());
    }

    #[test]
    fn rmi_capture_refuses_non_default_ambient_context_before_inspect_or_save() {
        let temp = tempfile::tempdir().unwrap();
        let tool = runtime_script(
            temp.path(),
            r#"
if [ "${1:-}" = "context" ] && [ "${2:-}" = "show" ]; then
  printf 'remote\n'
  exit 0
fi
echo "unexpected command: $*" >&2
exit 99
"#,
        );
        let error = match prepare_rmi_one(tool.to_str().unwrap(), "example/image:v1".into()) {
            Err(error) => error,
            Ok(_) => panic!("remote ambient context unexpectedly accepted"),
        };
        assert!(
            error.to_string().contains("ambient Docker context"),
            "{error:#}"
        );
    }

    #[test]
    fn rmi_capture_rechecks_ambient_context_after_archive() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("image.tar");
        let counter = temp.path().join("context-count");
        let image_id = sha256_id(TEST_CONFIG);
        fs::write(&archive, test_docker_archive(TEST_CONFIG, "null")).unwrap();
        fs::write(&counter, b"0").unwrap();
        let body = r#"
if [ "${1:-}" = "--context" ]; then
  [ "${2:-}" = "default" ]
  shift 2
fi
case "$1" in
  context)
    count=$(cat '__COUNTER__')
    count=$((count + 1))
    printf '%s' "$count" > '__COUNTER__'
    if [ "$count" -eq 1 ]; then printf 'default\n'; else printf 'remote\n'; fi
    ;;
  image) printf '__IMAGE_ID__\n' ;;
  save) cat '__ARCHIVE__' ;;
  *) echo "unexpected command: $*" >&2; exit 99 ;;
esac
"#
        .replace("__COUNTER__", &counter.to_string_lossy())
        .replace("__IMAGE_ID__", &image_id)
        .replace("__ARCHIVE__", &archive.to_string_lossy());
        let tool = runtime_script(temp.path(), &body);
        let error = match prepare_rmi_one(tool.to_str().unwrap(), "example/image:v1".into()) {
            Err(error) => error,
            Ok(_) => panic!("post-archive context change unexpectedly accepted"),
        };
        assert!(error.to_string().contains("context changed"), "{error:#}");
    }

    #[test]
    fn prepare_rm_captures_every_target_and_commits_stopped_layers() {
        let temp = tempfile::tempdir().unwrap();
        let tool = complete_fake_runtime(temp.path());
        let prepared = prepare_rm(
            tool.to_str().unwrap(),
            vec!["abc123".into(), "def456".into()],
            true,
        )
        .unwrap();
        assert_eq!(prepared.len(), 2);
        assert_eq!(
            prepared[0].extras.get("id").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            prepared[1].extras.get("id").map(String::as_str),
            Some("def456")
        );
        for event in prepared {
            assert!(matches!(event.verb, ContainerVerbWire::Rm));
            assert_eq!(
                event.extras.get("was_running").map(String::as_str),
                Some("false")
            );
            assert!(!event.captured_config.is_empty());
            assert!(event.stash_image.is_some());
        }
    }

    #[test]
    fn inspect_is_running_handles_array_and_object() {
        let arr = br#"[{"State":{"Running":true}}]"#;
        let obj = br#"{"State":{"Running":true}}"#;
        let stopped = br#"{"State":{"Running":false}}"#;
        let malformed = b"{not json";
        let no_state = b"{}";
        assert!(inspect_is_running(arr).unwrap());
        assert!(inspect_is_running(obj).unwrap());
        assert!(!inspect_is_running(stopped).unwrap());
        assert!(inspect_is_running(malformed).is_err());
        assert!(inspect_is_running(no_state).is_err());
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
    fn compose_destruction_is_refused_until_full_state_capture_exists() {
        let down = ComposeVerb::Down {
            files: vec!["compose.yaml".into()],
            project_override: Some("demo".into()),
            with_volumes: false,
        };
        assert!(prepare_compose("docker", down).is_err());
        let rm = ComposeVerb::Rm {
            files: vec!["compose.yaml".into()],
            project_override: Some("demo".into()),
            services: vec!["web".into()],
            force: true,
            with_volumes: false,
        };
        assert!(prepare_compose("docker", rm).is_err());
    }

    #[test]
    fn prepare_volume_rm_multi_name_produces_one_event_per_volume() {
        // AU24 / DR-CR-52: `docker volume rm v1 v2 v3` produces three
        // independent events, one per name. Pre-AU24 only v1 would have
        // been processed and v2/v3 silently dropped.
        let temp = tempfile::tempdir().unwrap();
        let tool = complete_fake_runtime(temp.path());
        let prepared = prepare_volume_rm(
            tool.to_str().unwrap(),
            vec!["v1".into(), "v2".into(), "v3".into()],
        )
        .unwrap();
        assert_eq!(prepared.len(), 3);
        let names: Vec<&str> = prepared
            .iter()
            .map(|p| p.extras.get("name").map(String::as_str).unwrap_or(""))
            .collect();
        assert_eq!(names, vec!["v1", "v2", "v3"]);
    }

    #[test]
    fn prepare_stop_or_kill_returns_empty() {
        let v = VerbPayload::Docker(DockerVerb::StopOrKill {
            ids: vec!["web".into()],
            was_kill: false,
        });
        assert!(
            prepare("docker", ContainerRuntimeWire::Docker, v)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn prepare_network_rm_multi_name_produces_one_event_per_network() {
        // AU24 / DR-CR-52: parity with multi-name volume rm and rmi.
        let temp = tempfile::tempdir().unwrap();
        let tool = complete_fake_runtime(temp.path());
        let prepared =
            prepare_network_rm(tool.to_str().unwrap(), vec!["n1".into(), "n2".into()]).unwrap();
        assert_eq!(prepared.len(), 2);
        let names: Vec<&str> = prepared
            .iter()
            .map(|p| p.extras.get("name").map(String::as_str).unwrap_or(""))
            .collect();
        assert_eq!(names, vec!["n1", "n2"]);
    }

    #[test]
    fn prepare_pull_post_multi_image_produces_one_event_per_image() {
        // AU24 / DR-CR-52: `docker pull a b c` produces three events.
        // inspect fails (no docker on PATH) so resolved_id is absent —
        // the events still ship with the image name so the journal
        // records the pull attempt.
        let tool = "shit-test-no-such-docker-binary";
        let prepared = prepare_pull_post(tool, vec!["alpine:3.20".into(), "busybox:1.36".into()]);
        assert_eq!(prepared.len(), 2);
        for p in &prepared {
            assert!(matches!(p.verb, ContainerVerbWire::Pull));
            assert!(p.extras.contains_key("image"));
            assert!(!p.extras.contains_key("resolved_id"));
        }
    }

    #[test]
    fn prepare_podman_rm_maps_to_docker_shape() {
        let temp = tempfile::tempdir().unwrap();
        let tool = complete_fake_runtime(temp.path());
        let v = VerbPayload::Podman(PodmanVerb::Rm {
            ids: vec!["c1".into()],
            force: false,
        });
        let prepared = prepare(tool.to_str().unwrap(), ContainerRuntimeWire::Podman, v).unwrap();
        assert_eq!(prepared.len(), 1);
        let p = &prepared[0];
        assert!(matches!(p.verb, ContainerVerbWire::Rm));
        assert_eq!(p.extras.get("id").map(String::as_str), Some("c1"));
        assert_eq!(
            p.extras.get("was_running").map(String::as_str),
            Some("false")
        );
    }
}
