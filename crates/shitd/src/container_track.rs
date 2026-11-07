// SPDX-License-Identifier: AGPL-3.0-or-later

//! DR-CR-26 — daemon-side container-event handler.
//!
//! Receives [`shit_proto::ContainerEventReq`] from
//! `shit-helper container-event`, resolves the helper's pid to an
//! active command window, builds a [`shit_planner::CaptureEventKind::
//! ContainerOp`] from the wire descriptors, and journals it via
//! [`Index::put_event`].
//!
//! Unlike [`crate::pkg`] / [`crate::svc_track`] / [`crate::net_track`]
//! which have Pre/Post phases (they need to diff before/after state),
//! container events are single-shot: the helper does all the
//! snapshotting (`docker save` / `docker inspect` / volume tar / etc.)
//! and stash registration BEFORE sending the request, so this
//! handler just converts wire → planner types and journals.
//!
//! The capture path that fills in `ContainerEventReq` lives in
//! `shit-helper container-event` (DR-CR-26, helper side).

use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inode::BlobHash;
use shit_planner::inverse::{ContainerOp, ContainerRuntime};
use shit_proto::{ContainerEventReq, ContainerRuntimeWire, ContainerVerbWire};
use shit_store::{BlobStore, Index, container_stash};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandleError {
    #[error("no active command window for pid {0}")]
    NoActiveCommand(u32),
    #[error("missing required extras field for verb {verb:?}: {key}")]
    MissingExtra {
        verb: ContainerVerbWire,
        key: &'static str,
    },
    #[error("strict capture refused the container event: {0}")]
    CaptureRefused(String),
    #[error("journal write failed: {0}")]
    JournalWrite(String),
    #[error("stash hash mismatch: helper claimed {claimed}, daemon computed {computed}")]
    StashHashMismatch { claimed: String, computed: String },
    #[error("blob store write failed: {0}")]
    BlobWrite(String),
    #[error("container_stash register failed: {0}")]
    StashRegister(String),
}

/// Handle one container-event request: resolve command window,
/// translate wire → planner types, journal the event. Returns the
/// journaled [`EventId`] on success.
///
/// With `strict` set (`SHIT_STRICT_CAPTURE`), an event the helper marked
/// as degraded (`capture_failed` extra) or whose evidence has the wrong
/// shape is replaced by a command-scoped `CaptureRefused` row. The event
/// is not journaled (its inverse would fail halfway and hide the refusal)
/// and the runtime command is never blocked.
pub fn handle(
    req: ContainerEventReq,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
    strict: bool,
) -> Result<EventId, HandleError> {
    let Some(command) = active.resolve_by_descendant(req.pid) else {
        tracing::warn!(
            pid = req.pid,
            runtime = ?req.runtime,
            verb = ?req.verb,
            "container-event not attributable to active command window; dropping"
        );
        return Err(HandleError::NoActiveCommand(req.pid));
    };

    if strict && let Some(detail) = capture_gap(&req) {
        if let Err(e) =
            crate::helper_link::journal_capture_refused(index, command, None, detail.clone())
        {
            tracing::error!(error = %e, %command, %detail, "strict container CaptureRefused journal failed");
        }
        return Err(HandleError::CaptureRefused(detail));
    }

    let runtime = wire_to_planner_runtime(req.runtime);
    let op = build_container_op(req.verb, &req.extras)?;
    let stash_tarball = req.stash_tarball.map(BlobHash::from_bytes);

    // AR03 PR-B (DR-CR-26 inline-bytes path): if the helper shipped
    // tarball bytes inline, write them to the blob store and
    // register the stash. Helper-claimed hash must match what the
    // blob store computes from the bytes (content-addressed; a
    // mismatch means corruption between helper and daemon). The
    // large-image SCM_RIGHTS path is AR10.8 scaffolding -- inline
    // is the small-image fast path.
    if let Some(bytes) = req.stash_tarball_bytes.as_ref() {
        let Some(claimed_hash) = stash_tarball else {
            return Err(HandleError::BlobWrite(
                "stash_tarball_bytes shipped without claimed hash".into(),
            ));
        };
        let (canonical_hash, stat) = blob_store
            .put(bytes)
            .map_err(|e| HandleError::BlobWrite(e.to_string()))?;
        if canonical_hash != claimed_hash {
            return Err(HandleError::StashHashMismatch {
                claimed: format!("{claimed_hash}"),
                computed: format!("{canonical_hash}"),
            });
        }
        let stash_name = req
            .extras
            .get("image")
            .or_else(|| req.extras.get("name"))
            .cloned()
            .unwrap_or_default();
        let kind = match req.verb {
            ContainerVerbWire::Rmi | ContainerVerbWire::Rm => container_stash::StashKind::ImageSave,
            ContainerVerbWire::VolumeRm => container_stash::StashKind::VolumeTar,
            // NetworkRm + ComposeDown don't ship tarballs in v1
            _ => container_stash::StashKind::ImageSave,
        };
        container_stash::register(
            index,
            container_stash::RegisterRequest {
                blob_hash: *canonical_hash.as_bytes(),
                kind,
                runtime: runtime.as_str(),
                name: &stash_name,
                size_bytes: stat.stored_bytes,
                command: Some(command),
                note: None,
            },
        )
        .map_err(|e| HandleError::StashRegister(e.to_string()))?;
        tracing::info!(
            pid = req.pid,
            blob_hash = %canonical_hash,
            stored_bytes = stat.stored_bytes,
            compressed_bytes = stat.compressed,
            "container stash bytes ingested + registered"
        );
    }

    let kind = CaptureEventKind::ContainerOp {
        runtime,
        op: op.clone(),
        captured_config: req.captured_config,
        stash_image: req.stash_image,
        stash_tarball,
    };
    let ev = CaptureEvent {
        id: EventId(0), // sqlite assigns
        command,
        ts: crate::server::next_ts(),
        partial: false,
        kind,
    };
    match index.put_event(&ev) {
        Ok(eid) => {
            tracing::info!(
                pid = req.pid,
                session = %command.session,
                seq = command.seq,
                %eid,
                runtime = ?runtime,
                verb = ?req.verb,
                stash_tarball = stash_tarball.is_some(),
                "container-event journaled (DR-CR-26)"
            );
            Ok(eid)
        }
        Err(e) => {
            tracing::error!(error = %e, pid = req.pid, "container-event journal write failed");
            Err(HandleError::JournalWrite(e.to_string()))
        }
    }
}

/// Extras key the helper sets when its pre-event capture could not gather
/// the evidence the inverse needs (inspect, save or tar failed, or the
/// tarball exceeded the inline cap). The value is the human-readable cause.
pub(crate) const CAPTURE_FAILED_EXTRA: &str = "capture_failed";

/// Why this request cannot support a faithful undo, if it cannot.
/// Request-shape checks stay narrow: each one is a state no healthy
/// helper produces, so flagging it never refuses a good capture.
fn capture_gap(req: &ContainerEventReq) -> Option<String> {
    let verb = format!("{:?}", req.verb);
    if let Some(cause) = req.extras.get(CAPTURE_FAILED_EXTRA) {
        return Some(format!("container {verb} pre-capture failed: {cause}"));
    }
    let has_hash = req.stash_tarball.is_some();
    let has_bytes = req.stash_tarball_bytes.is_some();
    if has_hash != has_bytes {
        return Some(format!(
            "container {verb} stash hash and bytes are not both present"
        ));
    }
    if req.stash_tarball_bytes.as_ref().is_some_and(Vec::is_empty) {
        return Some(format!("container {verb} stash tarball is empty"));
    }
    let config_is_object = || {
        serde_json::from_slice::<serde_json::Value>(&req.captured_config)
            .map(|v| match v {
                serde_json::Value::Array(items) => items.len() == 1 && items[0].is_object(),
                other => other.is_object(),
            })
            .unwrap_or(false)
    };
    match req.verb {
        ContainerVerbWire::Rm | ContainerVerbWire::NetworkRm if !config_is_object() => Some(
            format!("container {verb} captured configuration is missing or not one JSON object"),
        ),
        ContainerVerbWire::Rmi | ContainerVerbWire::VolumeRm if !has_hash => {
            Some(format!("container {verb} has no stash tarball"))
        }
        _ => None,
    }
}

fn wire_to_planner_runtime(w: ContainerRuntimeWire) -> ContainerRuntime {
    match w {
        ContainerRuntimeWire::Docker => ContainerRuntime::Docker,
        ContainerRuntimeWire::Podman => ContainerRuntime::Podman,
    }
}

/// Reconstruct the per-verb `ContainerOp` from wire descriptors.
/// The helper packed the verb-specific identifiers (image name,
/// volume name, etc.) into `extras` so the proto stays simple; here
/// we pull them back out into the planner's typed enum.
fn build_container_op(
    verb: ContainerVerbWire,
    extras: &BTreeMap<String, String>,
) -> Result<ContainerOp, HandleError> {
    match verb {
        ContainerVerbWire::Rm => {
            let id = extras
                .get("id")
                .cloned()
                .ok_or(HandleError::MissingExtra { verb, key: "id" })?;
            let name = extras.get("name").cloned();
            let was_running = extras
                .get("was_running")
                .map(|s| s == "true")
                .unwrap_or(false);
            Ok(ContainerOp::Rm {
                id,
                name,
                was_running,
            })
        }
        ContainerVerbWire::Rmi => {
            let image = extras
                .get("image")
                .cloned()
                .ok_or(HandleError::MissingExtra { verb, key: "image" })?;
            let digest = extras.get("digest").cloned();
            Ok(ContainerOp::Rmi { image, digest })
        }
        ContainerVerbWire::VolumeRm => {
            let name = extras
                .get("name")
                .cloned()
                .ok_or(HandleError::MissingExtra { verb, key: "name" })?;
            let driver = extras.get("driver").cloned();
            Ok(ContainerOp::VolumeRm { name, driver })
        }
        ContainerVerbWire::NetworkRm => {
            let name = extras
                .get("name")
                .cloned()
                .ok_or(HandleError::MissingExtra { verb, key: "name" })?;
            Ok(ContainerOp::NetworkRm { name })
        }
        ContainerVerbWire::ComposeDown => {
            let project = extras
                .get("project")
                .cloned()
                .ok_or(HandleError::MissingExtra {
                    verb,
                    key: "project",
                })?;
            let compose_file = extras
                .get("compose_file")
                .map(std::path::PathBuf::from)
                .ok_or(HandleError::MissingExtra {
                    verb,
                    key: "compose_file",
                })?;
            let services = extras
                .get("services")
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default();
            let with_volumes = extras
                .get("with_volumes")
                .map(|s| s == "true")
                .unwrap_or(false);
            Ok(ContainerOp::ComposeDown {
                project,
                services,
                compose_file,
                with_volumes,
            })
        }
        ContainerVerbWire::Pull => {
            // AU23 / DR-CR-51 — `image` is the user-typed
            // reference (e.g. `alpine:latest`); `resolved_id` is
            // the post-pull `docker inspect --format '{{.Id}}'`
            // result. Pre-post handlers may ship either or both,
            // depending on the wrapper's invocation phase.
            let image = extras
                .get("image")
                .cloned()
                .ok_or(HandleError::MissingExtra { verb, key: "image" })?;
            let resolved_id = extras.get("resolved_id").cloned();
            Ok(ContainerOp::Pull { image, resolved_id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rmi_extracts_image_from_extras() {
        let mut extras = BTreeMap::new();
        extras.insert("image".into(), "alpine:latest".into());
        extras.insert("digest".into(), "sha256:abc123".into());
        let op = build_container_op(ContainerVerbWire::Rmi, &extras).unwrap();
        assert!(matches!(
            op,
            ContainerOp::Rmi { ref image, digest: Some(ref d) }
                if image == "alpine:latest" && d == "sha256:abc123"
        ));
    }

    #[test]
    fn build_rmi_missing_image_returns_error() {
        let extras = BTreeMap::new();
        let err = build_container_op(ContainerVerbWire::Rmi, &extras).unwrap_err();
        assert!(matches!(
            err,
            HandleError::MissingExtra {
                verb: ContainerVerbWire::Rmi,
                key: "image"
            }
        ));
    }

    #[test]
    fn build_rm_default_was_running_false_when_absent() {
        let mut extras = BTreeMap::new();
        extras.insert("id".into(), "abc123".into());
        let op = build_container_op(ContainerVerbWire::Rm, &extras).unwrap();
        assert!(matches!(
            op,
            ContainerOp::Rm {
                was_running: false,
                ..
            }
        ));
    }

    #[test]
    fn build_compose_down_parses_services_csv() {
        let mut extras = BTreeMap::new();
        extras.insert("project".into(), "myapp".into());
        extras.insert("compose_file".into(), "/tmp/docker-compose.yml".into());
        extras.insert("services".into(), "web, db, worker".into());
        extras.insert("with_volumes".into(), "true".into());
        let op = build_container_op(ContainerVerbWire::ComposeDown, &extras).unwrap();
        if let ContainerOp::ComposeDown {
            project,
            services,
            compose_file,
            with_volumes,
        } = op
        {
            assert_eq!(project, "myapp");
            assert_eq!(services, vec!["web", "db", "worker"]);
            assert_eq!(
                compose_file,
                std::path::PathBuf::from("/tmp/docker-compose.yml")
            );
            assert!(with_volumes);
        } else {
            panic!("expected ComposeDown");
        }
    }

    #[test]
    fn wire_runtime_maps_1to1() {
        assert!(matches!(
            wire_to_planner_runtime(ContainerRuntimeWire::Docker),
            ContainerRuntime::Docker
        ));
        assert!(matches!(
            wire_to_planner_runtime(ContainerRuntimeWire::Podman),
            ContainerRuntime::Podman
        ));
    }

    #[test]
    fn build_pull_extracts_image_and_resolved_id() {
        // AU23 / DR-CR-51 — happy path: helper post-handler shipped
        // both the user-typed tag and the resolved sha256 digest.
        let mut extras = BTreeMap::new();
        extras.insert("image".into(), "alpine:latest".into());
        extras.insert("resolved_id".into(), "sha256:abc123".into());
        let op = build_container_op(ContainerVerbWire::Pull, &extras).unwrap();
        assert!(matches!(
            op,
            ContainerOp::Pull { ref image, resolved_id: Some(ref id) }
                if image == "alpine:latest" && id == "sha256:abc123"
        ));
    }

    #[test]
    fn build_pull_without_resolved_id_journals_with_none() {
        // AU23 — when `docker inspect` failed at capture time, the
        // helper still ships an event with image only. Planner
        // carries `resolved_id: None`; the renderer surfaces a
        // clear "(unavailable)" note rather than dropping.
        let mut extras = BTreeMap::new();
        extras.insert("image".into(), "nginx:alpine".into());
        let op = build_container_op(ContainerVerbWire::Pull, &extras).unwrap();
        assert!(matches!(
            op,
            ContainerOp::Pull { ref image, resolved_id: None }
                if image == "nginx:alpine"
        ));
    }

    #[test]
    fn build_pull_missing_image_returns_error() {
        let extras = BTreeMap::new();
        let err = build_container_op(ContainerVerbWire::Pull, &extras).unwrap_err();
        assert!(matches!(
            err,
            HandleError::MissingExtra {
                verb: ContainerVerbWire::Pull,
                key: "image"
            }
        ));
    }
}

#[cfg(test)]
mod capture_gap_tests {
    use super::*;

    fn req(verb: ContainerVerbWire) -> ContainerEventReq {
        ContainerEventReq {
            runtime: ContainerRuntimeWire::Docker,
            verb,
            captured_config: Vec::new(),
            stash_image: None,
            stash_tarball: None,
            stash_tarball_bytes: None,
            extras: BTreeMap::new(),
            pid: 1,
            uid: 0,
        }
    }

    #[test]
    fn helper_marked_failure_is_a_gap() {
        let mut r = req(ContainerVerbWire::Pull);
        r.extras
            .insert(CAPTURE_FAILED_EXTRA.into(), "docker inspect failed".into());
        let gap = capture_gap(&r).expect("gap");
        assert!(gap.contains("docker inspect failed"), "{gap}");
    }

    #[test]
    fn complete_rm_and_rmi_are_not_gaps() {
        let mut rm = req(ContainerVerbWire::Rm);
        rm.captured_config = br#"[{"Id":"abc"}]"#.to_vec();
        assert!(capture_gap(&rm).is_none());
        let mut rmi = req(ContainerVerbWire::Rmi);
        rmi.stash_tarball = Some([1; 32]);
        rmi.stash_tarball_bytes = Some(vec![1, 2, 3]);
        assert!(capture_gap(&rmi).is_none());
    }

    #[test]
    fn missing_evidence_is_a_gap() {
        assert!(capture_gap(&req(ContainerVerbWire::Rm)).is_some());
        assert!(capture_gap(&req(ContainerVerbWire::NetworkRm)).is_some());
        assert!(capture_gap(&req(ContainerVerbWire::Rmi)).is_some());
        assert!(capture_gap(&req(ContainerVerbWire::VolumeRm)).is_some());
        let mut half = req(ContainerVerbWire::Rmi);
        half.stash_tarball = Some([1; 32]);
        assert!(capture_gap(&half).is_some());
        let mut empty = req(ContainerVerbWire::Rmi);
        empty.stash_tarball = Some([1; 32]);
        empty.stash_tarball_bytes = Some(Vec::new());
        assert!(capture_gap(&empty).is_some());
    }

    #[test]
    fn compose_down_and_pull_have_no_shape_rule() {
        assert!(capture_gap(&req(ContainerVerbWire::ComposeDown)).is_none());
        assert!(capture_gap(&req(ContainerVerbWire::Pull)).is_none());
    }
}
