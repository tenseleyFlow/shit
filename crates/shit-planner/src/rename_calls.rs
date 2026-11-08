// SPDX-License-Identifier: AGPL-3.0-or-later

//! L5 (PR B): rename-family calls the shim reported, joined by call id.
//!
//! For every rename-family call the shim journals the rows its pre-call
//! note produced (the Rename, the destination's pre-image, the subtree
//! pre-images, a refusal) and lists them in a
//! [`CaptureEventKind::RenameCall`] under the call's id. After the call
//! it journals a [`CaptureEventKind::RenameOutcome`] under the same id.
//! `(pid, call_id)` names one call, so the planner joins those rows by
//! the id alone, never by timestamp or journal position.
//!
//! What follows from one outcome per call:
//!
//! - A call that failed (errno set) moved nothing. Every row its notes
//!   journaled is dropped, and so is the kernel tier's report of the same
//!   call. Its refusals stay: a path the shim could not key is still
//!   reported at undo (AU10), whether or not the call then failed.
//! - A call that succeeded is one rename. The kernel tier's report of it
//!   is dropped, so undo reverses it once.
//!
//! The kernel tier's report is told apart by inode, not path: it is a
//! Rename that no call lists whose inode is the outcome's source inode
//! (the tiers may spell the same path differently, as macOS's `/var` and
//! `/private/var`). Each kernel Rename pairs with at most one call, the
//! nearest in the journal.

use crate::events::{CaptureEvent, CaptureEventKind, EventId, TreeOp};
use crate::inode::InodeRef;
use std::collections::{HashMap, HashSet};

/// One call's journaled rows and its outcome.
#[derive(Default)]
struct Call {
    events: HashSet<EventId>,
    /// The call's own Rename, when its pre-call note journaled one.
    has_rename: bool,
    /// `(errno, source inode, outcome's position in the journal)`.
    outcome: Option<(i32, InodeRef, crate::time::TimePoint)>,
}

/// The events the call outcomes say to leave out of the plan.
pub(crate) fn dropped_by_rename_calls(events: &[&CaptureEvent]) -> HashSet<EventId> {
    let renames: HashMap<EventId, InodeRef> = events
        .iter()
        .filter_map(|e| match &e.kind {
            CaptureEventKind::TreeOp(TreeOp::Rename { inode, .. }) => Some((e.id, *inode)),
            _ => None,
        })
        .collect();
    // A call's refusals stay even when it failed: the shim could not key
    // a path the command named (AU10), which undo still reports.
    let refusals: HashSet<EventId> = events
        .iter()
        .filter(|e| matches!(e.kind, CaptureEventKind::CaptureRefused { .. }))
        .map(|e| e.id)
        .collect();
    let mut calls: HashMap<(u32, u64), Call> = HashMap::new();
    for e in events {
        match &e.kind {
            CaptureEventKind::RenameCall {
                pid,
                call_id,
                events: ids,
            } => {
                let c = calls.entry((*pid, *call_id)).or_default();
                c.has_rename |= ids.iter().any(|id| renames.contains_key(id));
                c.events.extend(ids.iter().copied());
            }
            CaptureEventKind::RenameOutcome {
                pid,
                call_id,
                errno,
                source,
                ..
            } => {
                calls.entry((*pid, *call_id)).or_default().outcome = Some((*errno, *source, e.ts));
            }
            _ => {}
        }
    }
    let listed: HashSet<EventId> = calls
        .values()
        .flat_map(|c| c.events.iter().copied())
        .collect();
    // Kernel-tier Renames: not listed by any call, with a real inode.
    let mut kernel: Vec<(&CaptureEvent, InodeRef)> = events
        .iter()
        .filter(|e| !listed.contains(&e.id))
        .filter_map(|e| renames.get(&e.id).map(|i| (*e, *i)))
        .filter(|(_, i)| *i != InodeRef::new(0, 0))
        .collect();

    let mut out = HashSet::new();
    // Deterministic order: by the outcome's place in the journal.
    let mut with_outcome: Vec<&Call> = calls.values().filter(|c| c.outcome.is_some()).collect();
    with_outcome.sort_by_key(|c| c.outcome.map(|o| o.2));
    for call in with_outcome {
        let (errno, source, at) = call.outcome.expect("filtered");
        if errno != 0 {
            out.extend(
                call.events
                    .iter()
                    .copied()
                    .filter(|id| !refusals.contains(id)),
            );
        }
        // The kernel tier's report of this call: same source inode,
        // nearest in the journal, each paired once.
        if source == InodeRef::new(0, 0) || (errno == 0 && !call.has_rename) {
            continue;
        }
        let twin = kernel
            .iter()
            .enumerate()
            .filter(|(_, (_, inode))| *inode == source)
            .min_by_key(|(_, (e, _))| e.ts.logical.abs_diff(at.logical))
            .map(|(i, _)| i);
        if let Some(i) = twin {
            out.insert(kernel.swap_remove(i).0.id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::CommandId;
    use crate::time::TimePoint;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn ev(id: u64, kind: CaptureEventKind) -> CaptureEvent {
        CaptureEvent {
            id: EventId(id),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(id, 0),
            partial: false,
            kind,
        }
    }

    fn rename(id: u64, from: &str, to: &str, inode: InodeRef) -> CaptureEvent {
        ev(
            id,
            CaptureEventKind::TreeOp(TreeOp::Rename {
                from: PathBuf::from(from),
                to: PathBuf::from(to),
                inode,
            }),
        )
    }

    fn call(id: u64, pid: u32, call_id: u64, events: &[u64]) -> CaptureEvent {
        ev(
            id,
            CaptureEventKind::RenameCall {
                pid,
                call_id,
                events: events.iter().map(|i| EventId(*i)).collect(),
            },
        )
    }

    fn outcome(id: u64, pid: u32, call_id: u64, errno: i32, source: InodeRef) -> CaptureEvent {
        ev(
            id,
            CaptureEventKind::RenameOutcome {
                pid,
                call_id,
                from: PathBuf::from("/a"),
                to: PathBuf::from("/b"),
                errno,
                source,
                dest: if errno == 0 {
                    source
                } else {
                    InodeRef::new(0, 0)
                },
            },
        )
    }

    fn dropped(events: &[CaptureEvent]) -> Vec<u64> {
        let refs: Vec<&CaptureEvent> = events.iter().collect();
        let mut v: Vec<u64> = dropped_by_rename_calls(&refs)
            .into_iter()
            .map(|e| e.0)
            .collect();
        v.sort_unstable();
        v
    }

    const SHIM: InodeRef = InodeRef { dev: 0, inode: 0 };
    const FILE: InodeRef = InodeRef { dev: 8, inode: 42 };

    /// The call id joins a call's rows to its outcome: a failed call's
    /// Rename goes, its refusal stays, another call's rows stay.
    #[test]
    fn a_failed_call_drops_exactly_its_own_rows() {
        let refusal = ev(
            2,
            CaptureEventKind::CaptureRefused {
                class: "capture-gap".into(),
                path: PathBuf::from("/b"),
                detail: "x".into(),
            },
        );
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            refusal,
            call(3, 10, 1, &[1, 2]),
            rename(4, "/c", "/d", SHIM),
            call(5, 10, 2, &[4]),
            outcome(6, 10, 1, libc::EXDEV, FILE),
            outcome(7, 10, 2, 0, InodeRef::new(8, 43)),
        ];
        assert_eq!(dropped(&events), vec![1]);
    }

    /// The same call id in another process is another call.
    #[test]
    fn call_ids_are_scoped_to_their_process() {
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/c", "/d", SHIM),
            call(4, 11, 1, &[3]),
            outcome(5, 11, 1, libc::ENOENT, InodeRef::new(8, 50)),
        ];
        assert_eq!(dropped(&events), vec![3]);
    }

    /// The kernel tier's report of a call pairs by inode even when it
    /// spells the paths differently (macOS `/private/var` against `/var`).
    /// A successful call keeps one Rename; a failed one keeps none.
    #[test]
    fn kernel_twins_pair_by_inode_not_path() {
        let ok = vec![
            rename(1, "/private/var/t/a", "/private/var/t/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/var/t/a", "/var/t/b", FILE),
            outcome(4, 10, 1, 0, FILE),
        ];
        assert_eq!(dropped(&ok), vec![3]);
        let failed = vec![
            rename(1, "/private/var/t/a", "/private/var/t/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/var/t/a", "/var/t/b", FILE),
            outcome(4, 10, 1, libc::EXDEV, FILE),
        ];
        assert_eq!(dropped(&failed), vec![1, 3]);
    }

    /// A kernel Rename of another inode is not a twin, and one kernel
    /// Rename pairs with one call: the second call on the same inode finds
    /// none left.
    #[test]
    fn a_kernel_rename_pairs_with_one_call_only() {
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/a", "/b", InodeRef::new(8, 99)),
            rename(4, "/a", "/b", FILE),
            outcome(5, 10, 1, 0, FILE),
            rename(6, "/b", "/c", SHIM),
            call(7, 10, 2, &[6]),
            outcome(8, 10, 2, 0, FILE),
        ];
        assert_eq!(dropped(&events), vec![4]);
    }

    /// A call with no outcome (the process died in the call) changes
    /// nothing.
    #[test]
    fn no_outcome_no_change() {
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/a", "/b", FILE),
        ];
        assert!(dropped(&events).is_empty());
    }
}
