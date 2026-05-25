// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR04 PR-A — daemon-side cloud-event handler.
//!
//! Receives [`shit_proto::CloudEventReq`] from the `shit-helper
//! cloud-event` capture sidecar (terraform / kubectl / gh / aws),
//! resolves the helper's pid to an active command window, builds a
//! [`shit_planner::CaptureEventKind::TerraformOp`] (or per-runtime
//! equivalent as later AR04.x sub-sprints land) from the wire
//! descriptors, and journals via [`Index::put_event`].
//!
//! Unlike the kernel-tier capture path (which streams events as the
//! syscalls fire), cloud events are single-shot: the helper does all
//! the snapshotting (`terraform state pull` / `kubectl get -o yaml`
//! / `gh api`) BEFORE the user's destructive verb runs, so this
//! handler just converts wire → planner types and journals.

use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inverse::TerraformOp;
use shit_proto::{CloudEventReq, CloudRuntimeWire, CloudVerbWire};
use shit_store::Index;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandleError {
    #[error("no active command window for pid {0}")]
    NoActiveCommand(u32),
    #[error("cloud verb {verb:?} not supported by runtime {runtime:?}")]
    VerbRuntimeMismatch {
        runtime: CloudRuntimeWire,
        verb: CloudVerbWire,
    },
    #[error("cloud verb {0:?} not yet implemented (deferred sub-sprint)")]
    VerbNotImplemented(CloudVerbWire),
    #[error("journal write failed: {0}")]
    JournalWrite(String),
}

/// Handle one cloud-event request: resolve command window, translate
/// wire → planner types, journal the event. Returns the journaled
/// [`EventId`] on success.
pub fn handle(
    req: CloudEventReq,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> Result<EventId, HandleError> {
    let Some(command) = active.resolve_by_descendant(req.pid) else {
        tracing::warn!(
            pid = req.pid,
            runtime = ?req.runtime,
            verb = ?req.verb,
            "cloud-event not attributable to active command window; dropping"
        );
        return Err(HandleError::NoActiveCommand(req.pid));
    };

    let kind = build_event_kind(&req)?;

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
                runtime = ?req.runtime,
                verb = ?req.verb,
                prior_state_bytes = req.prior_state.len(),
                "cloud-event journaled (AR04 PR-A)"
            );
            Ok(eid)
        }
        Err(e) => {
            tracing::error!(error = %e, pid = req.pid, "cloud-event journal write failed");
            Err(HandleError::JournalWrite(e.to_string()))
        }
    }
}

/// Translate a wire cloud-event into the matching
/// [`CaptureEventKind`]. AR04.1 lands the Terraform path; kubectl /
/// gh / aws return `VerbNotImplemented` so they journal-fail cleanly
/// rather than silently drop until their sub-sprints land.
fn build_event_kind(req: &CloudEventReq) -> Result<CaptureEventKind, HandleError> {
    match (req.runtime, req.verb) {
        (CloudRuntimeWire::Terraform, verb) => {
            let tf_op = match verb {
                CloudVerbWire::TerraformApply => TerraformOp::Apply,
                CloudVerbWire::TerraformDestroy => TerraformOp::Destroy,
                CloudVerbWire::TerraformStateRm => TerraformOp::StateRm,
                CloudVerbWire::TerraformImport => TerraformOp::Import,
                _ => {
                    return Err(HandleError::VerbRuntimeMismatch {
                        runtime: req.runtime,
                        verb,
                    });
                }
            };
            let workdir = std::path::PathBuf::from(&req.workdir);
            Ok(CaptureEventKind::TerraformOp {
                workdir,
                op: tf_op,
                prior_state: req.prior_state.clone(),
            })
        }
        // AR04.3 / .4 / .5 land these.
        (CloudRuntimeWire::Kubectl, _) | (CloudRuntimeWire::Gh, _) | (CloudRuntimeWire::Aws, _) => {
            Err(HandleError::VerbNotImplemented(req.verb))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn tf_req(verb: CloudVerbWire) -> CloudEventReq {
        CloudEventReq {
            runtime: CloudRuntimeWire::Terraform,
            verb,
            workdir: "/tmp/tf".into(),
            prior_state: b"{\"version\":4}".to_vec(),
            extras: BTreeMap::new(),
            pid: 1,
            uid: 1000,
        }
    }

    #[test]
    fn build_terraform_apply_event_kind() {
        let req = tf_req(CloudVerbWire::TerraformApply);
        match build_event_kind(&req).unwrap() {
            CaptureEventKind::TerraformOp {
                op, prior_state, ..
            } => {
                assert!(matches!(op, TerraformOp::Apply));
                assert_eq!(prior_state, b"{\"version\":4}");
            }
            other => panic!("expected TerraformOp, got {other:?}"),
        }
    }

    #[test]
    fn build_terraform_destroy_event_kind() {
        let req = tf_req(CloudVerbWire::TerraformDestroy);
        match build_event_kind(&req).unwrap() {
            CaptureEventKind::TerraformOp { op, .. } => {
                assert!(matches!(op, TerraformOp::Destroy));
            }
            other => panic!("expected TerraformOp, got {other:?}"),
        }
    }

    #[test]
    fn kubectl_returns_not_implemented_until_ar04_3() {
        let mut req = tf_req(CloudVerbWire::KubectlApply);
        req.runtime = CloudRuntimeWire::Kubectl;
        match build_event_kind(&req) {
            Err(HandleError::VerbNotImplemented(CloudVerbWire::KubectlApply)) => {}
            other => panic!("expected VerbNotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn terraform_runtime_with_gh_verb_is_mismatch() {
        let mut req = tf_req(CloudVerbWire::GhReleaseCreate);
        req.runtime = CloudRuntimeWire::Terraform;
        match build_event_kind(&req) {
            Err(HandleError::VerbRuntimeMismatch { .. }) => {}
            other => panic!("expected VerbRuntimeMismatch, got {other:?}"),
        }
    }
}
