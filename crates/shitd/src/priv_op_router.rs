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
        };
        let outcome = self
            .helper
            .request_priv_op_blocking(self.session, seq, req, PRIV_OP_TIMEOUT);
        wire_to_planner(outcome)
    }

    fn mknod(&self, _path: &Path, _mode: u32, _dev: u64) -> PlannerOutcome {
        // AU22 lands the mknod side. Stub here so we don't
        // silently route mknod requests into a helper handler that
        // also returns PermissionDenied — same end result, fewer
        // round-trips, clearer trace when AU22 surfaces this path.
        PlannerOutcome::PermissionDenied
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
    fn mknod(&self, path: &Path, mode: u32, dev: u64) -> PlannerOutcome {
        match self {
            EitherRouter::Helper(r) => r.mknod(path, mode, dev),
            EitherRouter::NoOp(r) => r.mknod(path, mode, dev),
        }
    }
}

fn wire_to_planner(w: WireOutcome) -> PlannerOutcome {
    match w {
        WireOutcome::Applied => PlannerOutcome::Applied,
        WireOutcome::OutOfScope => PlannerOutcome::OutOfScope,
        WireOutcome::PermissionDenied => PlannerOutcome::PermissionDenied,
        WireOutcome::NotFound => PlannerOutcome::NotFound,
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
            wire_to_planner(WireOutcome::Failed { err: "x".into() }),
            PlannerOutcome::Failed { err: "x".into() }
        );
    }
}
