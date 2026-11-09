// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU28 / DR-15 stage-1 — daemon-side `PrivilegedOpRouter` impl
//! that dispatches chown (and, post-AU22, mknod) requests to the
//! helper via the existing `HelperLink` request/reply primitive.
//!
//! ## Why
//!
//! `shit-planner::FileExecutor` calls `PrivilegedOpRouter::chown`
//! when a `RestoreMetadata` op needs to chown to a foreign uid and
//! the local syscall returns `EPERM` (daemon lacks `CAP_CHOWN`).
//! The trait has two production-friendly outcomes pre-AU28:
//!
//! - `NoOpPrivilegedOpRouter` returns `PermissionDenied` for every
//!   call (used when no helper is wired).
//! - `InMemoryPrivilegedOpRouter` is for unit tests.
//!
//! Neither actually performs the syscall. AU28 ships
//! `HelperLinkPrivilegedOpRouter`, the missing production link: it
//! serializes the op as `HelperRequest::ApplyChown`, blocks via
//! `HelperLink::request_priv_op_blocking`, and converts the
//! response's `PrivilegedOpOutcome` (wire) back to the planner's
//! local mirror.
//!
//! Mknod stays `PermissionDenied` until AU22 ships the helper-side
//! `libc::mkfifo` / `libc::mknod` handler.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shit_planner::{
    NoOpPrivilegedOpRouter, PrivilegedOpOutcome as PlannerOutcome, PrivilegedOpRouter,
};
use shit_proto::{HelperRequest, PrivilegedOpOutcome as WireOutcome};
use uuid::Uuid;

use crate::helper_link::HelperLink;

/// Wall-clock budget for a single privileged-op request. The
/// FileExecutor is synchronous; an unbounded block would hang
/// `shit undo` indefinitely if the helper wedges. 5s is generous
/// for a chown(2) and tight enough that operators notice a wedge.
const PRIV_OP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct HelperLinkPrivilegedOpRouter {
    helper: Arc<HelperLink>,
    /// Synthetic session per router instance. The helper uses
    /// `(session, command_seq)` only as a correlation key + for
    /// audit logs — not for cross-referencing with capture-time
    /// session ids.
    session: Uuid,
    next_seq: AtomicU64,
}

impl HelperLinkPrivilegedOpRouter {
    pub fn new(helper: Arc<HelperLink>) -> Self {
        // Workspace's uuid build enables only v7 (time-ordered);
        // good enough for our internal correlation key.
        let session = Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext));
        Self {
            helper,
            session,
            next_seq: AtomicU64::new(1),
        }
    }

    fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }
}

impl PrivilegedOpRouter for HelperLinkPrivilegedOpRouter {
    fn chown(&self, path: &Path, uid: u32, gid: u32, no_dereference: bool) -> PlannerOutcome {
        let seq = self.next_seq();
        let req = HelperRequest::ApplyChown {
            session: self.session,
            command_seq: seq,
            path: path.to_string_lossy().into_owned(),
            uid,
            gid,
            no_dereference,
            // #227: the Linux helper refuses a chown without a token it
            // issued for the file. Capture does not issue ownership tokens
            // yet, nor does the journal carry them, so on Linux every
            // routed chown is refused with a reason. That loses nothing:
            // the helper holds no CAP_CHOWN (D-28), so it could not do
            // more than the daemon's own failed chown. The macOS and
            // FreeBSD helpers ignore this field.
            owner: None,
        };
        let outcome = self
            .helper
            .request_priv_op_blocking(self.session, seq, req, PRIV_OP_TIMEOUT);
        wire_to_planner(outcome)
    }

    fn mknod(
        &self,
        path: &Path,
        mode: u32,
        dev: u64,
        device: Option<&shit_planner::DeviceNode>,
    ) -> PlannerOutcome {
        // AU22 / DR-15.1 — Fifo/Socket dispatch through the helper
        // (which calls libc::mknod with the S_IFIFO/S_IFSOCK |
        // perm_bits composite). L4b - BlockDevice/CharDevice carry the
        // journaled capture and the helper's token back; the helper
        // checks the token against every field before it acts.
        // A capture without a token is refused by the executor before
        // it gets here; none is sent if one slips through.
        let device = device.and_then(|d| {
            d.token.map(|t| shit_proto::DeviceEvidence {
                uid: d.uid,
                gid: d.gid,
                dev: d.inode.dev,
                inode: d.inode.inode,
                session: d.removed_by.session,
                command_seq: d.removed_by.seq,
                token: shit_proto::CaptureToken {
                    helper: t.helper,
                    mac: t.mac,
                },
            })
        });
        let seq = self.next_seq();
        let req = HelperRequest::ApplyMknod {
            session: self.session,
            command_seq: seq,
            path: path.to_string_lossy().into_owned(),
            mode,
            dev,
            device,
        };
        let outcome = self
            .helper
            .request_priv_op_blocking(self.session, seq, req, PRIV_OP_TIMEOUT);
        wire_to_planner(outcome)
    }
}

/// Boot-time dispatch wrapper. `FileExecutor` is generic over P
/// (its PrivilegedOpRouter); to keep `MultiTierExecutor` non-
/// generic we collapse the production choice (HelperLink-backed
/// vs NoOp degraded) into one enum that implements the trait.
pub enum EitherRouter {
    Helper(HelperLinkPrivilegedOpRouter),
    NoOp(NoOpPrivilegedOpRouter),
}

impl EitherRouter {
    /// Construct from the optional helper link the daemon holds.
    /// When the helper is alive, dispatch through it; in degraded
    /// mode, every priv op returns PermissionDenied.
    pub fn from_optional_link(link: Option<Arc<HelperLink>>) -> Self {
        match link {
            Some(l) => EitherRouter::Helper(HelperLinkPrivilegedOpRouter::new(l)),
            None => EitherRouter::NoOp(NoOpPrivilegedOpRouter),
        }
    }
}

impl PrivilegedOpRouter for EitherRouter {
    fn chown(&self, path: &Path, uid: u32, gid: u32, no_dereference: bool) -> PlannerOutcome {
        match self {
            EitherRouter::Helper(r) => r.chown(path, uid, gid, no_dereference),
            EitherRouter::NoOp(r) => r.chown(path, uid, gid, no_dereference),
        }
    }
    fn mknod(
        &self,
        path: &Path,
        mode: u32,
        dev: u64,
        device: Option<&shit_planner::DeviceNode>,
    ) -> PlannerOutcome {
        match self {
            EitherRouter::Helper(r) => r.mknod(path, mode, dev, device),
            EitherRouter::NoOp(r) => r.mknod(path, mode, dev, device),
        }
    }
}

fn wire_to_planner(w: WireOutcome) -> PlannerOutcome {
    match w {
        WireOutcome::Applied => PlannerOutcome::Applied,
        WireOutcome::OutOfScope => PlannerOutcome::OutOfScope,
        WireOutcome::PermissionDenied => PlannerOutcome::PermissionDenied,
        WireOutcome::NotFound => PlannerOutcome::NotFound,
        WireOutcome::Conflict { detail } => PlannerOutcome::Conflict { detail },
        WireOutcome::Refused { reason } => PlannerOutcome::Refused { reason },
        WireOutcome::Failed { err } => PlannerOutcome::Failed { err },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_to_planner_round_trip_all_variants() {
        assert_eq!(
            wire_to_planner(WireOutcome::Applied),
            PlannerOutcome::Applied
        );
        assert_eq!(
            wire_to_planner(WireOutcome::OutOfScope),
            PlannerOutcome::OutOfScope
        );
        assert_eq!(
            wire_to_planner(WireOutcome::PermissionDenied),
            PlannerOutcome::PermissionDenied
        );
        assert_eq!(
            wire_to_planner(WireOutcome::NotFound),
            PlannerOutcome::NotFound
        );
        assert_eq!(
            wire_to_planner(WireOutcome::Conflict { detail: "c".into() }),
            PlannerOutcome::Conflict { detail: "c".into() }
        );
        assert_eq!(
            wire_to_planner(WireOutcome::Refused { reason: "r".into() }),
            PlannerOutcome::Refused { reason: "r".into() }
        );
        assert_eq!(
            wire_to_planner(WireOutcome::Failed { err: "x".into() }),
            PlannerOutcome::Failed { err: "x".into() }
        );
    }
}
