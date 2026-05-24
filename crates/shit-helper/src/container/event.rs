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
    decode_frame, encode_frame,
};

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

    // The wrapper only fires for `pre`; reserve `post` for future
    // state-reconciliation needs (e.g. capturing the assigned image
    // digest after a successful pull). Treat unknown phases as a
    // no-op rather than an error so a misconfigured hook doesn't
    // wedge the CLI.
    if phase != "pre" {
        tracing::debug!(tool, phase, "container-event: non-pre phase, ignoring");
        return Ok(());
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
        "docker" => match classify_docker_argv(&argv) {
            Some(v) => (ContainerRuntimeWire::Docker, DockerOrPodman::Docker(v)),
            None => {
                tracing::debug!(
                    ?argv,
                    "docker argv didn't classify as destructive; skipping"
                );
                return Ok(());
            }
        },
        "podman" => match classify_podman_argv(&argv) {
            Some(v) => (ContainerRuntimeWire::Podman, DockerOrPodman::Podman(v)),
            None => {
                tracing::debug!(
                    ?argv,
                    "podman argv didn't classify as destructive; skipping"
                );
                return Ok(());
            }
        },
        // Compose flows through the docker-compose wrapper and rides
        // a parallel code path; AR03 PR-B ships docker rmi only.
        // Compose support lands in a follow-up.
        other => {
            tracing::debug!(
                tool = other,
                "container-event: unsupported tool (PR-B is docker only)"
            );
            return Ok(());
        }
    };

    let Some(prepared) = prepare(tool, runtime, verb_payload) else {
        return Ok(());
    };

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = ContainerEventReq {
        runtime,
        verb: prepared.verb,
        captured_config: prepared.captured_config,
        stash_image: None,
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

enum DockerOrPodman {
    Docker(DockerVerb),
    Podman(PodmanVerb),
}

struct PreparedEvent {
    verb: ContainerVerbWire,
    captured_config: Vec<u8>,
    stash_tarball: Option<[u8; 32]>,
    stash_tarball_bytes: Option<Vec<u8>>,
    extras: BTreeMap<String, String>,
}

fn prepare(tool: &str, runtime: ContainerRuntimeWire, v: DockerOrPodman) -> Option<PreparedEvent> {
    // Both docker and podman share the same verb enum after argv
    // classification; normalise to the docker side.
    let docker_verb: DockerVerb = match v {
        DockerOrPodman::Docker(d) => d,
        DockerOrPodman::Podman(p) => match p {
            PodmanVerb::Rm { ids, force } => DockerVerb::Rm { ids, force },
            PodmanVerb::Rmi { images } => DockerVerb::Rmi { images },
            PodmanVerb::VolumeRm { names } => DockerVerb::VolumeRm { names },
            PodmanVerb::NetworkRm { names } => DockerVerb::NetworkRm { names },
            PodmanVerb::StopOrKill { ids, was_kill } => DockerVerb::StopOrKill { ids, was_kill },
        },
    };

    match docker_verb {
        DockerVerb::Rmi { images } => prepare_rmi(tool, runtime, images),
        // PR-B ships Rmi only as the canonical AR03.2 path; the other
        // verbs are wired through to the daemon without a stash so the
        // event is journaled (informational undo), and per-verb stash
        // capture lands in follow-ups.
        DockerVerb::Rm { ids, force } => {
            let mut extras = BTreeMap::new();
            // Use the first id as the wire identifier; if the user
            // passed multiple, the others are still in argv but we
            // ship one event per invocation in PR-B. Multi-id batching
            // is a DR follow-up.
            if let Some(id) = ids.first() {
                extras.insert("id".into(), id.clone());
            }
            extras.insert("was_running".into(), force.to_string());
            Some(PreparedEvent {
                verb: ContainerVerbWire::Rm,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                extras,
            })
        }
        DockerVerb::VolumeRm { names } => {
            let mut extras = BTreeMap::new();
            if let Some(name) = names.first() {
                extras.insert("name".into(), name.clone());
            }
            Some(PreparedEvent {
                verb: ContainerVerbWire::VolumeRm,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                extras,
            })
        }
        DockerVerb::NetworkRm { names } => {
            let mut extras = BTreeMap::new();
            if let Some(name) = names.first() {
                extras.insert("name".into(), name.clone());
            }
            Some(PreparedEvent {
                verb: ContainerVerbWire::NetworkRm,
                captured_config: Vec::new(),
                stash_tarball: None,
                stash_tarball_bytes: None,
                extras,
            })
        }
        // stop/kill are restart-hint events; no destructive content
        // loss, no stash needed. PR-B does not ship them yet.
        DockerVerb::StopOrKill { .. } => None,
    }
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
    let frame = encode_frame(&CtlRequest::ContainerEvent(req.clone()))?;
    stream.write_all(&frame)?;
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
    fn prepare_rm_packs_first_id_into_extras() {
        let v = DockerOrPodman::Docker(DockerVerb::Rm {
            ids: vec!["abc123".into(), "def456".into()],
            force: true,
        });
        let p = prepare("docker", ContainerRuntimeWire::Docker, v).unwrap();
        assert!(matches!(p.verb, ContainerVerbWire::Rm));
        assert_eq!(p.extras.get("id").map(String::as_str), Some("abc123"));
        assert_eq!(
            p.extras.get("was_running").map(String::as_str),
            Some("true")
        );
        assert!(p.stash_tarball.is_none());
    }

    #[test]
    fn prepare_volume_rm_packs_first_name() {
        let v = DockerOrPodman::Docker(DockerVerb::VolumeRm {
            names: vec!["pgdata".into()],
        });
        let p = prepare("docker", ContainerRuntimeWire::Docker, v).unwrap();
        assert!(matches!(p.verb, ContainerVerbWire::VolumeRm));
        assert_eq!(p.extras.get("name").map(String::as_str), Some("pgdata"));
    }

    #[test]
    fn prepare_stop_or_kill_returns_none() {
        let v = DockerOrPodman::Docker(DockerVerb::StopOrKill {
            ids: vec!["web".into()],
            was_kill: false,
        });
        assert!(prepare("docker", ContainerRuntimeWire::Docker, v).is_none());
    }

    #[test]
    fn prepare_network_rm_packs_first_name() {
        let v = DockerOrPodman::Docker(DockerVerb::NetworkRm {
            names: vec!["frontend".into()],
        });
        let p = prepare("docker", ContainerRuntimeWire::Docker, v).unwrap();
        assert!(matches!(p.verb, ContainerVerbWire::NetworkRm));
        assert_eq!(p.extras.get("name").map(String::as_str), Some("frontend"));
    }

    #[test]
    fn prepare_podman_rm_maps_to_docker_shape() {
        let v = DockerOrPodman::Podman(PodmanVerb::Rm {
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
