// SPDX-License-Identifier: AGPL-3.0-or-later

//! DR-CR-26 — daemon-side container-event handler.
//!
//! Receives [`shit_proto::ContainerEventReq`] from
//! `shit-helper container-event`, resolves the helper's pid to an
//! active command window, builds a [`shit_planner::CaptureEventKind::
//! ContainerOp`] from the wire descriptors, and journals it via
//! [`Index::put_event`].
//!
//! Informational pulls remain single-shot events. Destructive requests use an
//! atomic batch: the daemon validates all targets, durably installs and
//! re-hashes every inverse, publishes all partial rows in one transaction, and
//! confirms the complete batch before returning the authorization ACK. The
//! later finalize message is outcome telemetry and cannot revoke that capture.
//!
//! The capture path that fills in `ContainerEventReq` lives in
//! `shit-helper container-event` (DR-CR-26, helper side).

use shit_planner::CommandId;
use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inode::BlobHash;
use shit_planner::inverse::{ContainerOp, ContainerRuntime};
use shit_proto::{
    ContainerBatchFinalizeReq, ContainerBatchPrepareReq, ContainerEventReq, ContainerRuntimeWire,
    ContainerTargetStateWire, ContainerVerbWire,
};
use shit_store::{
    BlobError, BlobSharedGuard, BlobStore, ContainerBatchState, Index, container_stash,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use thiserror::Error;
use uuid::Uuid;

const COMMAND_SESSION_EXTRA: &str = "_shit_session";
const COMMAND_SEQ_EXTRA: &str = "_shit_seq";
const DOCKER_CONTEXT_EXTRA: &str = "_shit_docker_context";
/// Match the default whole-store soft cap with a hard admission boundary for
/// retained container archives. Unlike ordinary blobs, a CONFIRMED batch must
/// remain protected until its wrapper reports a terminal runtime outcome, so
/// aggressive GC cannot safely recover these bytes.
const MAX_RETAINED_CONTAINER_STASH_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Container prepare requests arrive on concurrent ctl tasks. Hold this guard
/// across capacity admission and publication so two new archives cannot both
/// observe the same remaining capacity and overcommit it.
static CONTAINER_STASH_ADMISSION: Mutex<()> = Mutex::new(());

#[derive(Debug, Error)]
pub enum HandleError {
    #[error("no active command window for pid {0}")]
    NoActiveCommand(u32),
    #[error("invalid container capture request for {verb:?}: {detail}")]
    InvalidRequest {
        verb: ContainerVerbWire,
        detail: &'static str,
    },
    #[error("missing required extras field for verb {verb:?}: {key}")]
    MissingExtra {
        verb: ContainerVerbWire,
        key: &'static str,
    },
    #[error("journal write failed: {0}")]
    JournalWrite(String),
    #[error("stash hash mismatch: helper claimed {claimed}, daemon computed {computed}")]
    StashHashMismatch { claimed: String, computed: String },
    #[error("blob store write failed: {0}")]
    BlobWrite(String),
    #[error("blob index registration failed: {0}")]
    BlobRecord(String),
    #[error("container_stash register failed: {0}")]
    StashRegister(String),
    #[error("container stash {hash} was not durably published: {detail}")]
    StashPublication { hash: BlobHash, detail: String },
    #[error(
        "container stash capacity exceeded: {current} bytes retained + {incoming} new bytes is above the {cap}-byte hard limit"
    )]
    StashCapacity {
        current: u64,
        incoming: u64,
        cap: u64,
    },
    #[error(
        "legacy container-event protocol is read-only; destructive verb {0:?} requires an atomic batch"
    )]
    LegacyDestructive(ContainerVerbWire),
    #[error("invalid container capture batch: {0}")]
    InvalidBatch(String),
    #[error("container batch store operation failed: {0}")]
    BatchStore(String),
    #[error("container batch request could not be encoded deterministically: {0}")]
    RequestEncoding(String),
}

fn invalid_request(verb: ContainerVerbWire, detail: &'static str) -> HandleError {
    HandleError::InvalidRequest { verb, detail }
}

fn require_nonempty_extra(
    req: &ContainerEventReq,
    key: &'static str,
    detail: &'static str,
) -> Result<(), HandleError> {
    if req
        .extras
        .get(key)
        .is_some_and(|value| !value.trim().is_empty())
    {
        Ok(())
    } else {
        Err(invalid_request(req.verb, detail))
    }
}

pub(crate) fn command_identity(req: &ContainerEventReq) -> Result<CommandId, HandleError> {
    let session_text = req.extras.get(COMMAND_SESSION_EXTRA).ok_or_else(|| {
        HandleError::InvalidBatch(format!(
            "batch member has no reserved {COMMAND_SESSION_EXTRA} identity"
        ))
    })?;
    let session = Uuid::parse_str(session_text).map_err(|_| {
        HandleError::InvalidBatch(format!(
            "batch member has invalid {COMMAND_SESSION_EXTRA} identity"
        ))
    })?;
    if session.is_nil() || session.to_string() != *session_text {
        return Err(HandleError::InvalidBatch(format!(
            "batch member {COMMAND_SESSION_EXTRA} is not a non-nil canonical lowercase UUID"
        )));
    }

    let seq_text = req.extras.get(COMMAND_SEQ_EXTRA).ok_or_else(|| {
        HandleError::InvalidBatch(format!(
            "batch member has no reserved {COMMAND_SEQ_EXTRA} identity"
        ))
    })?;
    let seq = seq_text.parse::<u64>().map_err(|_| {
        HandleError::InvalidBatch(format!(
            "batch member has invalid {COMMAND_SEQ_EXTRA} identity"
        ))
    })?;
    if seq == 0 || seq.to_string() != *seq_text {
        return Err(HandleError::InvalidBatch(format!(
            "batch member {COMMAND_SEQ_EXTRA} is not a canonical positive decimal sequence"
        )));
    }
    Ok(CommandId { session, seq })
}

/// Parse the inspect payload and normalize Docker's usual singleton-array
/// response to its one object. The daemon must not trust a helper merely
/// because it supplied non-empty bytes: malformed inspect data produces an
/// inverse that can only fail later, after the destructive command ran.
fn captured_object(req: &ContainerEventReq) -> Result<serde_json::Value, HandleError> {
    let value: serde_json::Value = serde_json::from_slice(&req.captured_config).map_err(|_| {
        invalid_request(req.verb, "captured inspect configuration is not valid JSON")
    })?;
    let value = match value {
        serde_json::Value::Array(mut items) if items.len() == 1 => items.remove(0),
        serde_json::Value::Array(_) => {
            return Err(invalid_request(
                req.verb,
                "captured inspect configuration must contain exactly one object",
            ));
        }
        value => value,
    };
    if !value.is_object() {
        return Err(invalid_request(
            req.verb,
            "captured inspect configuration is not an object",
        ));
    }
    Ok(value)
}

/// Enforce the evidence shape required by each inverse before accepting any
/// bytes into the store. In particular, a hash without inline bytes is not a
/// usable large-object transport: the SCM_RIGHTS protocol needs its own wire
/// variant before that shape can be accepted safely.
fn validate_request_shape(req: &ContainerEventReq) -> Result<(), HandleError> {
    let has_hash = req.stash_tarball.is_some();
    let has_bytes = req.stash_tarball_bytes.is_some();
    if has_hash != has_bytes {
        return Err(invalid_request(
            req.verb,
            "stash_tarball and stash_tarball_bytes must be present together",
        ));
    }
    if req.stash_tarball_bytes.as_ref().is_some_and(Vec::is_empty) {
        return Err(invalid_request(req.verb, "stash tarball is empty"));
    }

    match req.verb {
        ContainerVerbWire::Rmi => {
            require_nonempty_extra(req, "image", "image removal requires a non-empty image")?;
            let image = req
                .extras
                .get("image")
                .expect("required image extra was just validated");
            if image.contains('@')
                || image.starts_with("sha256:")
                || image.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(invalid_request(
                    req.verb,
                    "image removal requires a named image reference, not a raw ID or digest",
                ));
            }
            let digest = req.extras.get("digest").map(String::as_str).unwrap_or("");
            if !digest.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
                return Err(invalid_request(
                    req.verb,
                    "image removal requires a complete immutable sha256 image ID",
                ));
            }
            if !has_hash {
                return Err(invalid_request(
                    req.verb,
                    "image removal requires a complete stash tarball",
                ));
            }
            if req.stash_image.is_some() {
                return Err(invalid_request(
                    req.verb,
                    "image removal must not carry a container stash image tag",
                ));
            }
            if !req.captured_config.is_empty() {
                return Err(invalid_request(
                    req.verb,
                    "image removal must not carry inspect configuration",
                ));
            }
        }
        ContainerVerbWire::VolumeRm => {
            require_nonempty_extra(req, "name", "volume removal requires a non-empty name")?;
            if !has_hash {
                return Err(invalid_request(
                    req.verb,
                    "volume removal requires a complete stash tarball",
                ));
            }
            if req.captured_config.is_empty() {
                return Err(invalid_request(
                    req.verb,
                    "volume removal requires captured inspect configuration",
                ));
            }
            if req.stash_image.is_some() {
                return Err(invalid_request(
                    req.verb,
                    "volume removal must not carry a container stash image tag",
                ));
            }
            let config = captured_object(req)?;
            let driver = config
                .get("Driver")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("local");
            if driver != "local"
                || req
                    .extras
                    .get("driver")
                    .is_some_and(|extra| extra != "local")
            {
                return Err(invalid_request(
                    req.verb,
                    "volume removal supports only the local driver",
                ));
            }
            for field in ["Options", "Labels"] {
                if config.get(field).is_some_and(|value| {
                    !matches!(value, serde_json::Value::Null)
                        && !value.as_object().is_some_and(serde_json::Map::is_empty)
                }) {
                    return Err(invalid_request(
                        req.verb,
                        "volume removal cannot preserve non-empty options or labels",
                    ));
                }
            }
        }
        ContainerVerbWire::Rm => {
            require_nonempty_extra(req, "id", "container removal requires a non-empty id")?;
            if has_hash {
                return Err(invalid_request(
                    req.verb,
                    "container removal must not carry a tarball stash",
                ));
            }
            if req.captured_config.is_empty() {
                return Err(invalid_request(
                    req.verb,
                    "container removal requires captured inspect configuration",
                ));
            }
            if !req
                .stash_image
                .as_deref()
                .is_some_and(|tag| !tag.trim().is_empty())
            {
                return Err(invalid_request(
                    req.verb,
                    "container removal requires a non-empty committed stash image tag",
                ));
            }
            if !matches!(
                req.extras.get("was_running").map(String::as_str),
                Some("true" | "false")
            ) {
                return Err(invalid_request(
                    req.verb,
                    "container removal requires an exact was_running boolean",
                ));
            }
            let config = captured_object(req)?;
            let captured_running = config
                .get("State")
                .and_then(|state| state.get("Running"))
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    invalid_request(
                        req.verb,
                        "container inspect configuration has no boolean State.Running",
                    )
                })?;
            if req.extras.get("was_running").map(String::as_str)
                != Some(if captured_running { "true" } else { "false" })
            {
                return Err(invalid_request(
                    req.verb,
                    "container inspect state disagrees with was_running",
                ));
            }
        }
        ContainerVerbWire::NetworkRm => {
            require_nonempty_extra(req, "name", "network removal requires a non-empty name")?;
            if has_hash || req.stash_image.is_some() {
                return Err(invalid_request(
                    req.verb,
                    "network removal must use inspect configuration only",
                ));
            }
            if req.captured_config.is_empty() {
                return Err(invalid_request(
                    req.verb,
                    "network removal requires captured inspect configuration",
                ));
            }
            captured_object(req)?;
        }
        ContainerVerbWire::ComposeDown => {
            return Err(invalid_request(
                req.verb,
                "compose down has no lossless capture format and must remain refused",
            ));
        }
        ContainerVerbWire::Pull => {
            require_nonempty_extra(
                req,
                "image",
                "pull reconciliation requires a non-empty image",
            )?;
            if has_hash || req.stash_image.is_some() {
                return Err(invalid_request(
                    req.verb,
                    "pull reconciliation must not carry destructive-operation stashes",
                ));
            }
            if !req.captured_config.is_empty() {
                return Err(invalid_request(
                    req.verb,
                    "pull reconciliation must not carry inspect configuration",
                ));
            }
        }
    }
    Ok(())
}

/// Refuse a new archive before writing any of its bytes when retained
/// container evidence has reached its hard ceiling. Existing content hashes
/// contribute no additional bytes, which preserves idempotent prepare retries
/// even when the store is already full.
fn enforce_stash_capacity(
    events: &[ContainerEventReq],
    index: &Index,
    cap: u64,
) -> Result<(), HandleError> {
    let current = container_stash::total_size_bytes(index)
        .map_err(|error| HandleError::StashRegister(error.to_string()))?;
    let mut seen = BTreeSet::new();
    let mut incoming = 0_u64;
    for event in events {
        let (Some(hash), Some(bytes)) = (event.stash_tarball, &event.stash_tarball_bytes) else {
            continue;
        };
        if !seen.insert(hash) {
            continue;
        }
        if container_stash::get(index, &hash)
            .map_err(|error| HandleError::StashRegister(error.to_string()))?
            .is_none()
        {
            incoming = incoming.saturating_add(bytes.len() as u64);
        }
    }
    if incoming != 0 && current.saturating_add(incoming) > cap {
        return Err(HandleError::StashCapacity {
            current,
            incoming,
            cap,
        });
    }
    Ok(())
}

fn publish_stash(
    req: &ContainerEventReq,
    command: shit_planner::CommandId,
    runtime: ContainerRuntime,
    index: &Index,
    publication: &BlobSharedGuard<'_>,
) -> Result<(), HandleError> {
    let Some(bytes) = req.stash_tarball_bytes.as_ref() else {
        return Ok(());
    };
    let claimed_hash = req.stash_tarball.map(BlobHash::from_bytes).ok_or_else(|| {
        HandleError::BlobWrite("stash_tarball_bytes shipped without claimed hash".into())
    })?;

    // Reject a corrupt/malformed request before publishing anything at a
    // canonical blob path. A plain `put` necessarily keys the file by the
    // bytes' *actual* hash; comparing only after that call would leave an
    // unindexed physical orphan until the next daemon restart.
    let (canonical_hash, stat) = publication
        .put_verified_exact(
            bytes.as_slice(),
            claimed_hash,
            bytes.len() as u64,
            bytes.len() as u64,
        )
        .map_err(|error| match error {
            BlobError::HashMismatch { expected, actual } => HandleError::StashHashMismatch {
                claimed: format!("{expected}"),
                computed: format!("{actual}"),
            },
            other => HandleError::BlobWrite(other.to_string()),
        })?;
    debug_assert_eq!(canonical_hash, claimed_hash);
    let stash_ts = crate::server::next_ts();
    index
        .put_blob_record(canonical_hash, stat.stored_bytes, stat.compressed, stash_ts)
        .map_err(|e| HandleError::BlobRecord(e.to_string()))?;
    let stash_name = req
        .extras
        .get("image")
        .or_else(|| req.extras.get("name"))
        .cloned()
        .unwrap_or_default();
    let kind = match req.verb {
        ContainerVerbWire::Rmi | ContainerVerbWire::Rm => container_stash::StashKind::ImageSave,
        ContainerVerbWire::VolumeRm => container_stash::StashKind::VolumeTar,
        // NetworkRm + ComposeDown don't ship tarballs in v1.
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
        stash_ts.wallclock_unix_nanos / 1_000_000_000,
    )
    .map_err(|e| HandleError::StashRegister(e.to_string()))?;
    let registered = container_stash::get(index, canonical_hash.as_bytes())
        .map_err(|error| HandleError::StashPublication {
            hash: canonical_hash,
            detail: format!("could not verify owner row: {error}"),
        })?
        .ok_or_else(|| HandleError::StashPublication {
            hash: canonical_hash,
            detail: "owner row is absent after registration".into(),
        })?;
    let physical = publication
        .stat(&canonical_hash)
        .map_err(|error| HandleError::StashPublication {
            hash: canonical_hash,
            detail: format!("could not stat canonical bytes: {error}"),
        })?
        .ok_or_else(|| HandleError::StashPublication {
            hash: canonical_hash,
            detail: "canonical bytes are absent after blob install".into(),
        })?;
    if registered.size_bytes != physical.stored_bytes
        || physical.stored_bytes != stat.stored_bytes
        || physical.compressed != stat.compressed
    {
        return Err(HandleError::StashPublication {
            hash: canonical_hash,
            detail: "owner-row and canonical-file metadata disagree".into(),
        });
    }
    tracing::info!(
        pid = req.pid,
        blob_hash = %canonical_hash,
        stored_bytes = stat.stored_bytes,
        compressed_bytes = stat.compressed,
        "container stash bytes ingested + registered"
    );
    Ok(())
}

/// Re-read every canonical inverse through its decoder and verify its digest
/// while the caller retains shared lifecycle ownership. Publication already
/// verifies the helper stream; this second pass proves the bytes at the path
/// the confirmed journal will reference, including a newly installed file.
fn validate_published_stashes(
    events: &[ContainerEventReq],
    index: &Index,
    publication: &BlobSharedGuard<'_>,
) -> Result<(), HandleError> {
    for event in events {
        let hash = event
            .stash_tarball
            .map(BlobHash::from_bytes)
            .ok_or_else(|| HandleError::InvalidBatch("batch member has no stash hash".into()))?;
        let registered = container_stash::get(index, hash.as_bytes())
            .map_err(|error| HandleError::StashPublication {
                hash,
                detail: format!("could not verify owner row: {error}"),
            })?
            .ok_or_else(|| HandleError::StashPublication {
                hash,
                detail: "owner row is absent before confirmation".into(),
            })?;
        let physical =
            publication
                .validate(hash)
                .map_err(|error| HandleError::StashPublication {
                    hash,
                    detail: format!("canonical bytes failed streaming validation: {error}"),
                })?;
        if physical.stored_bytes != registered.size_bytes {
            return Err(HandleError::StashPublication {
                hash,
                detail: "owner-row and validated canonical-file sizes disagree".into(),
            });
        }
    }
    Ok(())
}

/// Handle one container-event request: resolve command window,
/// translate wire → planner types, journal the event. Returns the
/// journaled [`EventId`] on success.
pub fn handle(
    req: ContainerEventReq,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
) -> Result<EventId, HandleError> {
    if req.verb != ContainerVerbWire::Pull {
        return Err(HandleError::LegacyDestructive(req.verb));
    }
    let Some(command) = active.resolve_by_descendant(req.pid) else {
        tracing::warn!(
            pid = req.pid,
            runtime = ?req.runtime,
            verb = ?req.verb,
            "container-event not attributable to active command window; dropping"
        );
        return Err(HandleError::NoActiveCommand(req.pid));
    };

    validate_request_shape(&req)?;
    let runtime = wire_to_planner_runtime(req.runtime);
    let op = build_container_op(req.verb, &req.extras)?;
    let stash_tarball = req.stash_tarball.map(BlobHash::from_bytes);
    let publication = blob_store.shared_guard();
    publish_stash(&req, command, runtime, index, &publication)?;
    let pid = req.pid;
    let verb = req.verb;

    let kind = CaptureEventKind::ContainerOp {
        runtime,
        op,
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
                pid,
                session = %command.session,
                seq = command.seq,
                %eid,
                runtime = ?runtime,
                verb = ?verb,
                stash_tarball = stash_tarball.is_some(),
                "container-event journaled (DR-CR-26)"
            );
            Ok(eid)
        }
        Err(e) => {
            tracing::error!(error = %e, pid, "container-event journal write failed");
            Err(HandleError::JournalWrite(e.to_string()))
        }
    }
}

/// Validate and durably publish every target of one destructive runtime
/// invocation before authorizing that invocation. Only image removal is
/// enabled in the first atomic-batch revision: its inverse has complete,
/// independently verifiable bytes, while the other destructive verbs still
/// have unresolved fidelity gaps.
pub fn prepare_batch(
    req: ContainerBatchPrepareReq,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
) -> Result<ContainerBatchState, HandleError> {
    if req.events.is_empty() {
        return Err(HandleError::InvalidBatch(
            "batch must contain at least one target".into(),
        ));
    }
    if req.events.len() != 1 {
        return Err(HandleError::InvalidBatch(format!(
            "batch has {} targets; the initial lossless boundary requires exactly one",
            req.events.len()
        )));
    }

    let first = &req.events[0];
    let claimed_command = command_identity(first)?;
    let pid = first.pid;
    let uid = first.uid;
    let runtime_wire = first.runtime;
    if runtime_wire != ContainerRuntimeWire::Docker {
        return Err(HandleError::InvalidBatch(
            "the initial lossless boundary accepts only Docker image removal".into(),
        ));
    }
    // The control socket is per-user and mode 0600. Bind the redundant uid on
    // the request to the daemon's real uid as an additional fail-closed check.
    // SAFETY: getuid has no failure mode on supported POSIX targets.
    let daemon_uid = unsafe { libc::getuid() };
    if uid != daemon_uid {
        return Err(HandleError::InvalidBatch(format!(
            "request uid {uid} does not match daemon uid {daemon_uid}"
        )));
    }

    // Complete every semantic validation before resolving mutable active
    // command state or installing any blob/stash owner row. A malformed later
    // target must never leave the prefix of the batch published.
    for (ordinal, event_req) in req.events.iter().enumerate() {
        if event_req.pid != pid || event_req.uid != uid {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} has a different pid or uid"
            )));
        }
        if event_req.runtime != runtime_wire {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} uses a different container runtime"
            )));
        }
        if command_identity(event_req)? != claimed_command {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} carries a different shell command identity"
            )));
        }
        if event_req.verb != ContainerVerbWire::Rmi {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} uses unsupported destructive verb {:?}; only Rmi is enabled",
                event_req.verb
            )));
        }
        if event_req.extras.get("no_prune").map(String::as_str) != Some("true") {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} does not prove an explicit --no-prune invocation"
            )));
        }
        if event_req
            .extras
            .get(DOCKER_CONTEXT_EXTRA)
            .map(String::as_str)
            != Some("default")
        {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} is not pinned to Docker context `default`"
            )));
        }
        validate_request_shape(event_req)?;
        build_container_op(event_req.verb, &event_req.extras)?;
    }

    // The daemon serves control clients concurrently. Serialize the capacity
    // decision with every publication through this function, and perform it
    // before a canonical blob path or index row can be created.
    let _stash_admission = CONTAINER_STASH_ADMISSION
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    enforce_stash_capacity(&req.events, index, MAX_RETAINED_CONTAINER_STASH_BYTES)?;

    // BTreeMap-backed extras make postcard's representation deterministic.
    // Hash only immutable request content; batch_id is the lookup key and is
    // deliberately domain-separated from the content it identifies.
    let encoded = postcard::to_allocvec(&req.events)
        .map_err(|error| HandleError::RequestEncoding(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"shit/container-batch-prepare/v1\0");
    hasher.update(&encoded);
    let request_hash = *hasher.finalize().as_bytes();

    // A lost prepare ACK may be retried after the owning command has closed.
    // The durable batch id + request hash identify that retry independently of
    // mutable ActiveCommands state. Re-publish every stash under one lifecycle
    // guard, then ensure even a crash-left PREPARED batch is CONFIRMED before
    // granting the runtime permission to proceed.
    if let Some(existing) = index
        .container_batch_info(req.batch_id)
        .map_err(|error| HandleError::BatchStore(error.to_string()))?
    {
        if existing.request_hash != request_hash || existing.event_count != req.events.len() {
            return Err(HandleError::InvalidBatch(format!(
                "batch id {} is already bound to different request content",
                req.batch_id
            )));
        }
        if existing.command != claimed_command {
            return Err(HandleError::InvalidBatch(format!(
                "batch id {} is durably owned by {}, not claimed command {}",
                req.batch_id, existing.command, claimed_command
            )));
        }
        match existing.state {
            ContainerBatchState::Refused => {
                return Err(HandleError::InvalidBatch(format!(
                    "batch id {} was refused before authorization",
                    req.batch_id
                )));
            }
            ContainerBatchState::Finalized => {
                return Err(HandleError::InvalidBatch(format!(
                    "batch id {} was already consumed and finalized",
                    req.batch_id
                )));
            }
            ContainerBatchState::Prepared | ContainerBatchState::Confirmed => {}
        }

        let publication = blob_store.shared_guard();
        let runtime = wire_to_planner_runtime(runtime_wire);
        for event_req in &req.events {
            publish_stash(event_req, existing.command, runtime, index, &publication)?;
        }
        validate_published_stashes(&req.events, index, &publication)?;
        // Re-run the transactional authorization check for both PREPARED and
        // CONFIRMED. Besides validating durable members, this closes the race
        // where runtime finalization consumes the batch after our first read.
        let state = index
            .finalize_container_batch(req.batch_id, true)
            .map_err(|error| HandleError::BatchStore(error.to_string()))?;
        if state != ContainerBatchState::Confirmed {
            return Err(HandleError::InvalidBatch(format!(
                "batch id {} could not be confirmed before authorization ({state:?})",
                req.batch_id
            )));
        }
        tracing::info!(
            batch_id = %req.batch_id,
            session = %existing.command.session,
            seq = existing.command.seq,
            targets = req.events.len(),
            previous_state = ?existing.state,
            retry = true,
            "container capture batch prepare retried and confirmed"
        );
        drop(publication);
        return Ok(state);
    }

    let Some(command) = active.resolve_exact_by_descendant(pid, claimed_command) else {
        return Err(HandleError::NoActiveCommand(pid));
    };
    let mut events = Vec::with_capacity(req.events.len());
    for (ordinal, event_req) in req.events.iter().enumerate() {
        if active.resolve_exact_by_descendant(event_req.pid, command) != Some(command) {
            return Err(HandleError::InvalidBatch(format!(
                "target {ordinal} no longer resolves to the batch command"
            )));
        }
        let runtime = wire_to_planner_runtime(event_req.runtime);
        let op = build_container_op(event_req.verb, &event_req.extras)?;
        events.push(CaptureEvent {
            id: EventId(0),
            command,
            ts: crate::server::next_ts(),
            partial: true,
            kind: CaptureEventKind::ContainerOp {
                runtime,
                op,
                captured_config: event_req.captured_config.clone(),
                stash_image: event_req.stash_image.clone(),
                stash_tarball: event_req.stash_tarball.map(BlobHash::from_bytes),
            },
        });
    }

    let runtime = wire_to_planner_runtime(runtime_wire);
    // One guard spans publication, atomic batch insertion, and confirmation.
    // Before PREPARED is visible there is no batch-row exclusion for GC to
    // observe; after confirmation, releasing before the state transition would
    // let inverse bytes disappear in the authorization window.
    let publication = blob_store.shared_guard();
    for event_req in &req.events {
        publish_stash(event_req, command, runtime, index, &publication)?;
    }

    let result = index
        .prepare_container_batch(req.batch_id, request_hash, &events)
        .map_err(|error| HandleError::BatchStore(error.to_string()))?;
    validate_published_stashes(&req.events, index, &publication)?;
    let state = match result.state {
        ContainerBatchState::Prepared | ContainerBatchState::Confirmed => index
            .finalize_container_batch(req.batch_id, true)
            .map_err(|error| HandleError::BatchStore(error.to_string()))?,
        ContainerBatchState::Refused => ContainerBatchState::Refused,
        ContainerBatchState::Finalized => ContainerBatchState::Finalized,
    };
    if state != ContainerBatchState::Confirmed {
        return Err(HandleError::InvalidBatch(format!(
            "batch id {} could not be confirmed before authorization ({state:?})",
            req.batch_id
        )));
    }
    tracing::info!(
        batch_id = %req.batch_id,
        %pid,
        %uid,
        session = %command.session,
        seq = command.seq,
        targets = events.len(),
        retry = !result.inserted,
        "container capture batch confirmed before authorization"
    );
    drop(publication);
    Ok(state)
}

/// Validate post-runtime outcome telemetry and durably close an authorized
/// batch. Runtime failure and ambiguous target observations never revoke the
/// pre-runtime authorization: image removal undo is conditional/idempotent and
/// can safely restore targets that are absent while skipping the captured ID.
/// A repeated, well-formed request validates the same durable members and ACKs
/// without moving the original finalization timestamp.
pub fn finalize_batch(
    req: &ContainerBatchFinalizeReq,
    index: &Index,
) -> Result<ContainerBatchState, HandleError> {
    // SAFETY: getuid has no failure mode on supported POSIX targets.
    let daemon_uid = unsafe { libc::getuid() };
    if req.uid != daemon_uid {
        return Err(HandleError::InvalidBatch(format!(
            "request uid {} does not match daemon uid {daemon_uid}",
            req.uid
        )));
    }
    let info = index
        .container_batch_info(req.batch_id)
        .map_err(|error| HandleError::BatchStore(error.to_string()))?
        .ok_or_else(|| HandleError::InvalidBatch(format!("unknown batch id {}", req.batch_id)))?;
    if !matches!(
        info.state,
        ContainerBatchState::Confirmed | ContainerBatchState::Finalized
    ) {
        return Err(HandleError::InvalidBatch(format!(
            "batch id {} is not authorized ({:?})",
            req.batch_id, info.state
        )));
    }
    if req.observations.len() != info.event_count {
        return Err(HandleError::InvalidBatch(format!(
            "batch id {} reported {} observations for {} targets",
            req.batch_id,
            req.observations.len(),
            info.event_count
        )));
    }
    for (ordinal, observation) in req.observations.iter().enumerate() {
        if observation.ordinal as usize != ordinal {
            return Err(HandleError::InvalidBatch(format!(
                "batch id {} has non-contiguous observation ordinal {} at position {ordinal}",
                req.batch_id, observation.ordinal
            )));
        }
    }
    let absent = req
        .observations
        .iter()
        .filter(|observation| observation.state == ContainerTargetStateWire::Absent)
        .count();
    let present = req
        .observations
        .iter()
        .filter(|observation| observation.state == ContainerTargetStateWire::Present)
        .count();
    let probe_failed = req
        .observations
        .iter()
        .filter(|observation| observation.state == ContainerTargetStateWire::ProbeFailed)
        .count();
    let state = index
        .mark_container_batch_finalized(req.batch_id, crate::clock::now().unix_secs())
        .map_err(|error| HandleError::BatchStore(error.to_string()))?;
    tracing::info!(
        batch_id = %req.batch_id,
        command = %info.command,
        pid = req.pid,
        exit_code = req.exit_code,
        observations = req.observations.len(),
        absent,
        present,
        probe_failed,
        repeated = info.state == ContainerBatchState::Finalized,
        "container capture batch runtime outcome durably finalized"
    );
    Ok(state)
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
    use shit_planner::{CommandId, CommandRecord, PlannerStore, TimePoint};
    use shit_proto::{ContainerTargetObservationWire, ShellKind};
    use uuid::Uuid;

    struct BatchFixture {
        _tmp: tempfile::TempDir,
        index: Index,
        blobs: BlobStore,
        active: crate::active_commands::ActiveCommands,
        command: CommandId,
        pid: u32,
    }

    fn batch_fixture() -> BatchFixture {
        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("index.sqlite")).unwrap();
        let blobs = BlobStore::open(tmp.path().join("blob-store")).unwrap();
        let command = CommandId {
            session: Uuid::parse_str("018f1234-5678-7abc-8def-0123456789ab").unwrap(),
            seq: 1,
        };
        let pid = std::process::id();
        index
            .put_session(command.session, "bash", pid, None, TimePoint::new(1, 1))
            .unwrap();
        assert!(
            index
                .begin_command(&CommandRecord {
                    command,
                    cmd_string: Some("docker rmi --no-prune image".into()),
                    cwd: tmp.path().to_path_buf(),
                    pid,
                    shell_kind: ShellKind::Bash,
                    started_at: TimePoint::new(2, 2),
                    ended_at: None,
                    exit_code: None,
                    event_ids: Vec::new(),
                })
                .unwrap()
        );
        let active = crate::active_commands::ActiveCommands::new();
        assert!(active.insert(pid, command));
        BatchFixture {
            _tmp: tmp,
            index,
            blobs,
            active,
            command,
            pid,
        }
    }

    fn rmi_request(image: &str, bytes: &[u8], pid: u32) -> ContainerEventReq {
        // SAFETY: getuid has no failure mode on supported POSIX targets.
        let uid = unsafe { libc::getuid() };
        ContainerEventReq {
            runtime: ContainerRuntimeWire::Docker,
            verb: ContainerVerbWire::Rmi,
            captured_config: Vec::new(),
            stash_image: None,
            stash_tarball: Some(*blake3::hash(bytes).as_bytes()),
            stash_tarball_bytes: Some(bytes.to_vec()),
            extras: BTreeMap::from([
                ("image".into(), image.into()),
                ("digest".into(), format!("sha256:{}", "a".repeat(64))),
                ("no_prune".into(), "true".into()),
                (
                    COMMAND_SESSION_EXTRA.into(),
                    "018f1234-5678-7abc-8def-0123456789ab".into(),
                ),
                (COMMAND_SEQ_EXTRA.into(), "1".into()),
                (DOCKER_CONTEXT_EXTRA.into(), "default".into()),
            ]),
            pid,
            uid,
        }
    }

    #[test]
    fn stash_capacity_refuses_new_bytes_before_publication() {
        let fixture = batch_fixture();
        let event = rmi_request("bounded:latest", b"four", fixture.pid);

        assert!(matches!(
            enforce_stash_capacity(&[event], &fixture.index, 3),
            Err(HandleError::StashCapacity {
                current: 0,
                incoming: 4,
                cap: 3,
            })
        ));
        assert!(
            container_stash::list_all(&fixture.index)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            container_stash::total_size_bytes(&fixture.index).unwrap(),
            0
        );
    }

    #[test]
    fn stash_capacity_deduplicates_requests_and_allows_existing_retry() {
        let fixture = batch_fixture();
        let event = rmi_request("deduplicated:latest", b"same", fixture.pid);

        enforce_stash_capacity(
            &[event.clone(), event.clone()],
            &fixture.index,
            b"same".len() as u64,
        )
        .unwrap();

        let publication = fixture.blobs.shared_guard();
        publish_stash(
            &event,
            fixture.command,
            ContainerRuntime::Docker,
            &fixture.index,
            &publication,
        )
        .unwrap();
        drop(publication);

        // An upgrade may encounter a pre-existing store above the newly added
        // hard cap. Retrying the same content consumes no more space and must
        // remain able to close its durable lifecycle.
        enforce_stash_capacity(&[event], &fixture.index, 0).unwrap();
    }

    fn observation(
        ordinal: u32,
        state: ContainerTargetStateWire,
    ) -> ContainerTargetObservationWire {
        ContainerTargetObservationWire {
            ordinal,
            state,
            detail: None,
        }
    }

    fn request_for(verb: ContainerVerbWire) -> ContainerEventReq {
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
    fn destructive_tarball_verbs_require_hash_and_nonempty_bytes_together() {
        for verb in [ContainerVerbWire::Rmi, ContainerVerbWire::VolumeRm] {
            let missing = request_for(verb);
            assert!(matches!(
                validate_request_shape(&missing),
                Err(HandleError::InvalidRequest { verb: got, .. }) if got == verb
            ));

            let mut hash_only = request_for(verb);
            hash_only.stash_tarball = Some([0x11; 32]);
            assert!(matches!(
                validate_request_shape(&hash_only),
                Err(HandleError::InvalidRequest { verb: got, .. }) if got == verb
            ));

            let mut empty = request_for(verb);
            empty.stash_tarball = Some(*blake3::hash(&[]).as_bytes());
            empty.stash_tarball_bytes = Some(Vec::new());
            if verb == ContainerVerbWire::VolumeRm {
                empty.captured_config = br#"[{"Driver":"local"}]"#.to_vec();
            }
            assert!(matches!(
                validate_request_shape(&empty),
                Err(HandleError::InvalidRequest { verb: got, .. }) if got == verb
            ));
        }
    }

    #[test]
    fn non_tarball_destructive_verbs_require_their_inverse_evidence() {
        let mut rm = request_for(ContainerVerbWire::Rm);
        rm.extras.insert("id".into(), "container-1".into());
        rm.captured_config = br#"[{"State":{"Running":false}}]"#.to_vec();
        rm.extras.insert("was_running".into(), "false".into());
        assert!(matches!(
            validate_request_shape(&rm),
            Err(HandleError::InvalidRequest { .. })
        ));
        rm.stash_image = Some("shit-stash-container-1".into());
        validate_request_shape(&rm).unwrap();

        let network = request_for(ContainerVerbWire::NetworkRm);
        assert!(matches!(
            validate_request_shape(&network),
            Err(HandleError::InvalidRequest { .. })
        ));
        let mut network = network;
        network.extras.insert("name".into(), "frontend".into());
        network.captured_config = br#"[{"Name":"frontend"}]"#.to_vec();
        validate_request_shape(&network).unwrap();

        assert!(matches!(
            validate_request_shape(&request_for(ContainerVerbWire::ComposeDown)),
            Err(HandleError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn inspect_evidence_must_be_parseable_and_internally_consistent() {
        let mut rm = request_for(ContainerVerbWire::Rm);
        rm.extras.insert("id".into(), "container-1".into());
        rm.extras.insert("was_running".into(), "true".into());
        rm.stash_image = Some("shit-stash-container-1".into());
        rm.captured_config = br#"[{"State":{"Running":false}}]"#.to_vec();
        assert!(matches!(
            validate_request_shape(&rm),
            Err(HandleError::InvalidRequest { .. })
        ));

        rm.extras.insert("was_running".into(), "false".into());
        validate_request_shape(&rm).unwrap();
        rm.captured_config = b"not-json".to_vec();
        assert!(matches!(
            validate_request_shape(&rm),
            Err(HandleError::InvalidRequest { .. })
        ));

        let bytes = b"volume archive".to_vec();
        let mut volume = request_for(ContainerVerbWire::VolumeRm);
        volume.extras.insert("name".into(), "database".into());
        volume.stash_tarball = Some(*blake3::hash(&bytes).as_bytes());
        volume.stash_tarball_bytes = Some(bytes);
        volume.captured_config =
            br#"[{"Driver":"local","Options":{"device":"/host/data"}}]"#.to_vec();
        assert!(matches!(
            validate_request_shape(&volume),
            Err(HandleError::InvalidRequest { .. })
        ));
        volume.captured_config = br#"[{"Driver":"local","Options":{},"Labels":{}}]"#.to_vec();
        validate_request_shape(&volume).unwrap();
    }

    #[test]
    fn inline_stash_bytes_are_owned_until_runtime_finalization() {
        let fixture = batch_fixture();
        let bytes = b"container tarball".to_vec();
        let hash = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
        let batch_id = Uuid::now_v7();
        let req = ContainerBatchPrepareReq {
            batch_id,
            events: vec![rmi_request("alpine:latest", &bytes, fixture.pid)],
        };

        assert_eq!(
            prepare_batch(req, &fixture.active, &fixture.index, &fixture.blobs).unwrap(),
            ContainerBatchState::Confirmed
        );

        assert_eq!(fixture.index.events_for_command(fixture.command).len(), 1);
        assert!(
            container_stash::get(&fixture.index, hash.as_bytes())
                .unwrap()
                .is_some()
        );
        assert!(!fixture.index.unreferenced_blobs().unwrap().contains(&hash));

        assert!(
            !container_stash::remove(&fixture.index, hash.as_bytes()).unwrap(),
            "an open command must retain its inverse bytes"
        );
        assert!(
            fixture
                .index
                .finish_command(fixture.command, TimePoint::new(3, 3), 1)
                .unwrap()
        );
        fixture
            .index
            .mark_container_batch_finalized(batch_id, 4)
            .unwrap();
        assert!(container_stash::remove(&fixture.index, hash.as_bytes()).unwrap());
        assert_eq!(fixture.blobs.get(hash).unwrap(), bytes);
        assert!(
            fixture.index.unreferenced_blobs().unwrap().contains(&hash),
            "container event keeps historical hash metadata, not physical ownership"
        );
        let events = fixture.index.events_for_command(fixture.command);
        assert_eq!(events.len(), 1);
        assert!(!events[0].partial);
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::ContainerOp {
                stash_tarball: Some(recorded),
                ..
            } if recorded == hash
        ));
        fixture.index.drop_command(fixture.command).unwrap();
        assert!(
            fixture.index.unreferenced_blobs().unwrap().contains(&hash),
            "dropping historical event metadata must not change stash ownership"
        );
    }

    #[test]
    fn hash_mismatch_is_rejected_before_canonical_publication() {
        let fixture = batch_fixture();
        let bytes = b"bytes that do not match the claimed hash".to_vec();
        let actual = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
        let claimed = [0xAA; 32];
        assert_ne!(actual.as_bytes(), &claimed);
        let mut event = rmi_request("alpine:latest", &bytes, fixture.pid);
        event.stash_tarball = Some(claimed);
        let req = ContainerBatchPrepareReq {
            batch_id: Uuid::now_v7(),
            events: vec![event],
        };

        assert!(matches!(
            prepare_batch(req, &fixture.active, &fixture.index, &fixture.blobs),
            Err(HandleError::StashHashMismatch { .. })
        ));
        assert!(
            !fixture.blobs.contains(&actual),
            "invalid request bytes must not become an unindexed canonical blob"
        );
        assert!(fixture.index.events_for_command(fixture.command).is_empty());
        assert!(
            container_stash::list_all(&fixture.index)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn legacy_protocol_rejects_destructive_events_but_keeps_pull_informational() {
        let fixture = batch_fixture();
        let bytes = b"legacy destructive bytes";
        assert!(matches!(
            handle(
                rmi_request("legacy:latest", bytes, fixture.pid),
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            ),
            Err(HandleError::LegacyDestructive(ContainerVerbWire::Rmi))
        ));
        assert!(fixture.index.events_for_command(fixture.command).is_empty());
        assert!(
            container_stash::list_all(&fixture.index)
                .unwrap()
                .is_empty()
        );

        let mut pull = request_for(ContainerVerbWire::Pull);
        pull.pid = fixture.pid;
        // SAFETY: getuid has no failure mode on supported POSIX targets.
        pull.uid = unsafe { libc::getuid() };
        pull.extras.insert("image".into(), "alpine:latest".into());
        handle(pull, &fixture.active, &fixture.index, &fixture.blobs).unwrap();
        let events = fixture.index.events_for_command(fixture.command);
        assert_eq!(events.len(), 1);
        assert!(!events[0].partial);
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::ContainerOp {
                op: ContainerOp::Pull { .. },
                ..
            }
        ));
    }

    #[test]
    fn batch_rejects_multiple_targets_before_publishing_any_stash() {
        let fixture = batch_fixture();
        let first_bytes = b"first valid tarball";
        let second_bytes = b"second invalid tarball";
        let first_hash = BlobHash::from_bytes(*blake3::hash(first_bytes).as_bytes());
        let second_hash = BlobHash::from_bytes(*blake3::hash(second_bytes).as_bytes());
        let first = rmi_request("one:latest", first_bytes, fixture.pid);
        let second = rmi_request("two:latest", second_bytes, fixture.pid);
        let batch_id = Uuid::now_v7();

        assert!(matches!(
            prepare_batch(
                ContainerBatchPrepareReq {
                    batch_id,
                    events: vec![first, second],
                },
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            ),
            Err(HandleError::InvalidBatch(_))
        ));
        assert!(!fixture.blobs.contains(&first_hash));
        assert!(!fixture.blobs.contains(&second_hash));
        assert!(
            container_stash::list_all(&fixture.index)
                .unwrap()
                .is_empty()
        );
        assert!(fixture.index.events_for_command(fixture.command).is_empty());
        assert_eq!(fixture.index.container_batch_info(batch_id).unwrap(), None);
    }

    #[test]
    fn batch_requires_docker_default_context_and_canonical_command_identity() {
        let fixture = batch_fixture();
        let bytes = b"inverse";

        let mut podman = rmi_request("image:v1", bytes, fixture.pid);
        podman.runtime = ContainerRuntimeWire::Podman;
        assert!(matches!(
            prepare_batch(
                ContainerBatchPrepareReq {
                    batch_id: Uuid::now_v7(),
                    events: vec![podman],
                },
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            ),
            Err(HandleError::InvalidBatch(_))
        ));

        for key in [
            COMMAND_SESSION_EXTRA,
            COMMAND_SEQ_EXTRA,
            DOCKER_CONTEXT_EXTRA,
        ] {
            let mut event = rmi_request("image:v1", bytes, fixture.pid);
            event.extras.remove(key);
            assert!(matches!(
                prepare_batch(
                    ContainerBatchPrepareReq {
                        batch_id: Uuid::now_v7(),
                        events: vec![event],
                    },
                    &fixture.active,
                    &fixture.index,
                    &fixture.blobs,
                ),
                Err(HandleError::InvalidBatch(_))
            ));
        }

        for (key, value) in [
            (COMMAND_SESSION_EXTRA, Uuid::nil().to_string()),
            (COMMAND_SEQ_EXTRA, "01".into()),
            (DOCKER_CONTEXT_EXTRA, "remote".into()),
        ] {
            let mut event = rmi_request("image:v1", bytes, fixture.pid);
            event.extras.insert(key.into(), value);
            assert!(matches!(
                prepare_batch(
                    ContainerBatchPrepareReq {
                        batch_id: Uuid::now_v7(),
                        events: vec![event],
                    },
                    &fixture.active,
                    &fixture.index,
                    &fixture.blobs,
                ),
                Err(HandleError::InvalidBatch(_))
            ));
        }
        assert!(fixture.index.events_for_command(fixture.command).is_empty());
        assert!(
            container_stash::list_all(&fixture.index)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn daemon_rejects_short_truncated_image_ids_as_named_tags() {
        let fixture = batch_fixture();
        assert!(matches!(
            prepare_batch(
                ContainerBatchPrepareReq {
                    batch_id: Uuid::now_v7(),
                    events: vec![rmi_request("deadbee", b"inverse", fixture.pid)],
                },
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            ),
            Err(HandleError::InvalidRequest {
                verb: ContainerVerbWire::Rmi,
                ..
            })
        ));
        assert!(fixture.index.events_for_command(fixture.command).is_empty());
        assert!(
            container_stash::list_all(&fixture.index)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn background_batch_binds_exported_identity_instead_of_stack_top() {
        let fixture = batch_fixture();
        let foreground = CommandId {
            session: fixture.command.session,
            seq: 2,
        };
        assert!(
            fixture
                .index
                .begin_command(&CommandRecord {
                    command: foreground,
                    cmd_string: Some("echo foreground".into()),
                    cwd: fixture._tmp.path().to_path_buf(),
                    pid: fixture.pid,
                    shell_kind: ShellKind::Bash,
                    started_at: TimePoint::new(3, 3),
                    ended_at: None,
                    exit_code: None,
                    event_ids: Vec::new(),
                })
                .unwrap()
        );
        assert!(fixture.active.insert(fixture.pid, foreground));
        assert_eq!(
            fixture.active.resolve_by_descendant(fixture.pid),
            Some(foreground)
        );

        prepare_batch(
            ContainerBatchPrepareReq {
                batch_id: Uuid::now_v7(),
                events: vec![rmi_request(
                    "background:v1",
                    b"background inverse",
                    fixture.pid,
                )],
            },
            &fixture.active,
            &fixture.index,
            &fixture.blobs,
        )
        .unwrap();

        assert_eq!(fixture.index.events_for_command(fixture.command).len(), 1);
        assert!(fixture.index.events_for_command(foreground).is_empty());
    }

    #[test]
    fn batch_prepare_confirms_before_ack_and_confirmed_retry_survives_active_close() {
        let fixture = batch_fixture();
        let batch_id = Uuid::now_v7();
        let prepare = ContainerBatchPrepareReq {
            batch_id,
            events: vec![rmi_request("one:latest", b"image one tar", fixture.pid)],
        };

        assert_eq!(
            prepare_batch(
                prepare.clone(),
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            )
            .unwrap(),
            ContainerBatchState::Confirmed
        );
        assert_eq!(
            fixture.index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Confirmed)
        );
        assert!(
            fixture
                .index
                .events_for_command(fixture.command)
                .iter()
                .all(|event| !event.partial),
            "prepare cannot return authorization while any member remains partial"
        );
        assert!(fixture.active.remove_command(fixture.command));
        assert!(
            fixture
                .index
                .finish_command(fixture.command, TimePoint::new(50, 500), 0)
                .unwrap()
        );
        let newer_command = CommandId {
            session: fixture.command.session,
            seq: fixture.command.seq + 1,
        };
        assert!(
            fixture
                .index
                .begin_command(&CommandRecord {
                    command: newer_command,
                    cmd_string: Some("echo newer foreground".into()),
                    cwd: fixture._tmp.path().to_path_buf(),
                    pid: fixture.pid,
                    shell_kind: ShellKind::Bash,
                    started_at: TimePoint::new(51, 510),
                    ended_at: None,
                    exit_code: None,
                    event_ids: Vec::new(),
                })
                .unwrap()
        );
        assert!(fixture.active.insert(fixture.pid, newer_command));
        assert_eq!(
            prepare_batch(
                prepare.clone(),
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            )
            .unwrap(),
            ContainerBatchState::Confirmed
        );
        let events = fixture.index.events_for_command(fixture.command);
        assert_eq!(events.len(), 1);
        assert!(events.iter().all(|event| !event.partial));
        assert_eq!(container_stash::list_all(&fixture.index).unwrap().len(), 1);

        // SAFETY: getuid has no failure mode on supported POSIX targets.
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            finalize_batch(
                &ContainerBatchFinalizeReq {
                    batch_id,
                    pid: fixture.pid,
                    uid,
                    exit_code: 0,
                    observations: vec![observation(0, ContainerTargetStateWire::Absent)],
                },
                &fixture.index,
            )
            .unwrap(),
            ContainerBatchState::Finalized
        );
        assert!(matches!(
            prepare_batch(
                prepare.clone(),
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            ),
            Err(HandleError::InvalidBatch(detail)) if detail.contains("consumed")
        ));

        let mut changed = prepare;
        changed.events[0]
            .extras
            .insert("image".into(), "different:latest".into());
        assert!(matches!(
            prepare_batch(changed, &fixture.active, &fixture.index, &fixture.blobs,),
            Err(HandleError::InvalidBatch(_))
        ));
    }

    #[test]
    fn nonzero_runtime_outcome_finalizes_batch_without_revoking_actionability() {
        let fixture = batch_fixture();
        let batch_id = Uuid::now_v7();
        assert_eq!(
            prepare_batch(
                ContainerBatchPrepareReq {
                    batch_id,
                    events: vec![rmi_request("failed:latest", b"failed tarball", fixture.pid,)],
                },
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            )
            .unwrap(),
            ContainerBatchState::Confirmed
        );
        // SAFETY: getuid has no failure mode on supported POSIX targets.
        let uid = unsafe { libc::getuid() };
        let finalize = ContainerBatchFinalizeReq {
            batch_id,
            pid: fixture.pid,
            uid,
            exit_code: 42,
            observations: vec![observation(0, ContainerTargetStateWire::ProbeFailed)],
        };

        assert_eq!(
            finalize_batch(&finalize, &fixture.index).unwrap(),
            ContainerBatchState::Finalized
        );
        assert_eq!(
            fixture.index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Finalized)
        );
        assert!(
            fixture
                .index
                .events_for_command(fixture.command)
                .iter()
                .all(|event| !event.partial)
        );
        let finalized_at = fixture
            .index
            .container_batch_info(batch_id)
            .unwrap()
            .unwrap()
            .finalized_unix_secs;
        assert!(finalized_at.is_some());
        assert_eq!(
            finalize_batch(&finalize, &fixture.index).unwrap(),
            ContainerBatchState::Finalized
        );
        assert_eq!(
            fixture
                .index
                .container_batch_info(batch_id)
                .unwrap()
                .unwrap()
                .finalized_unix_secs,
            finalized_at,
            "a repeated finalize must preserve the first durable timestamp"
        );
    }

    #[test]
    fn malformed_runtime_telemetry_is_rejected_without_revoking_confirmation() {
        let fixture = batch_fixture();
        let batch_id = Uuid::now_v7();
        prepare_batch(
            ContainerBatchPrepareReq {
                batch_id,
                events: vec![rmi_request(
                    "telemetry:latest",
                    b"telemetry tarball",
                    fixture.pid,
                )],
            },
            &fixture.active,
            &fixture.index,
            &fixture.blobs,
        )
        .unwrap();
        // SAFETY: getuid has no failure mode on supported POSIX targets.
        let uid = unsafe { libc::getuid() };
        let finalize = ContainerBatchFinalizeReq {
            batch_id,
            pid: fixture.pid,
            uid,
            exit_code: 0,
            observations: vec![observation(1, ContainerTargetStateWire::Absent)],
        };

        assert!(matches!(
            finalize_batch(&finalize, &fixture.index),
            Err(HandleError::InvalidBatch(_))
        ));
        assert_eq!(
            fixture.index.container_batch_state(batch_id).unwrap(),
            Some(ContainerBatchState::Confirmed)
        );
        assert!(!fixture.index.events_for_command(fixture.command)[0].partial);
    }

    #[test]
    fn prepare_repairs_present_corrupt_blob_before_confirmation() {
        let fixture = batch_fixture();
        let batch_id = Uuid::now_v7();
        let bytes = b"inverse whose canonical bytes will be replaced";
        let hash = BlobHash::from_bytes(*blake3::hash(bytes).as_bytes());
        fixture.blobs.put(bytes).unwrap();

        let hex = hash.to_hex();
        let path = fixture
            .blobs
            .root()
            .join("blobs")
            .join(&hex[..2])
            .join(&hex[2..4])
            .join(&hex);
        let mut corrupt = vec![0_u8]; // raw-storage flag
        corrupt.extend(std::iter::repeat_n(b'X', bytes.len()));
        std::fs::write(&path, corrupt).unwrap();
        assert!(
            fixture.blobs.stat(&hash).unwrap().is_some(),
            "header and stored size alone still consider the corrupt blob present"
        );

        assert_eq!(
            prepare_batch(
                ContainerBatchPrepareReq {
                    batch_id,
                    events: vec![rmi_request("corrupt:latest", bytes, fixture.pid)],
                },
                &fixture.active,
                &fixture.index,
                &fixture.blobs,
            )
            .unwrap(),
            ContainerBatchState::Confirmed
        );
        assert_eq!(fixture.blobs.get(hash).unwrap(), bytes);
        assert!(!fixture.index.events_for_command(fixture.command)[0].partial);
    }

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
