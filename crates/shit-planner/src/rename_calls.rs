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
//! - A call that failed (errno set) moved nothing. The rows its notes
//!   journaled are dropped, except its refusals: a path the shim could
//!   not key is still reported at undo (AU10).
//! - The kernel tier's report of the same call is its twin. The eBPF
//!   LSM hook `inode_rename` fires before `vfs_rename` applies the
//!   rename, which can still fail (a non-empty target directory), so a
//!   failed call can have a twin too; it is dropped with the call. For a
//!   successful call the twin and the shim's Rename are one rename: the
//!   shim's row is kept, because its paths are the ones the call's
//!   pre-images are keyed by, and it takes the twin's real
//!   `(dev, inode)`, which the cross-device check in `disproved_renames`
//!   reads (the shim's own row carries `(0, 0)`).
//!
//! A twin must match on everything both tiers know: it is a Rename no
//! call lists; its inode is the outcome's source inode; its `from` and
//! `to` names and its `to` parent agree with the shim's Rename once
//! macOS's `/private` prefix is set aside; and it was journaled after
//! the call's RenameCall and before the same process's next call (the
//! kernel reports a call while it runs, after the shim's pre-call note
//! was acked). Each kernel Rename pairs with at most one call.

use crate::events::{CaptureEvent, CaptureEventKind, EventId, TreeOp};
use crate::inode::InodeRef;
use crate::time::TimePoint;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// The non-partial events of a command as undo and redo both read them:
/// rename calls applied. One builder so the two plans cannot drift.
pub(crate) fn live_events(events: &[CaptureEvent]) -> Vec<CaptureEvent> {
    let live: Vec<&CaptureEvent> = events.iter().filter(|e| !e.partial).collect();
    let adj = adjust(&live);
    live.into_iter()
        .filter(|e| !adj.dropped.contains(&e.id))
        .map(|e| {
            let mut e = e.clone();
            if let Some(real) = adj.inode_for.get(&e.id)
                && let CaptureEventKind::TreeOp(TreeOp::Rename { inode, .. }) = &mut e.kind
            {
                *inode = *real;
            }
            e
        })
        .collect()
}

/// What the call outcomes change in a command's events.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Adjustment {
    pub dropped: HashSet<EventId>,
    /// A surviving shim Rename and the real identity its kernel twin had.
    pub inode_for: HashMap<EventId, InodeRef>,
}

struct ShimRename {
    id: EventId,
    from: PathBuf,
    to: PathBuf,
}

#[derive(Default)]
struct Call {
    events: HashSet<EventId>,
    /// The call's own Rename, when its pre-call note journaled one.
    rename: Option<ShimRename>,
    /// The earliest of the call's RenameCall rows.
    start: Option<TimePoint>,
    /// `(errno, source inode)`.
    outcome: Option<(i32, InodeRef)>,
}

pub(crate) fn adjust(events: &[&CaptureEvent]) -> Adjustment {
    let renames: HashMap<EventId, (&Path, &Path, InodeRef, TimePoint)> = events
        .iter()
        .filter_map(|e| match &e.kind {
            CaptureEventKind::TreeOp(TreeOp::Rename { from, to, inode }) => {
                Some((e.id, (from.as_path(), to.as_path(), *inode, e.ts)))
            }
            _ => None,
        })
        .collect();
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
                c.events.extend(ids.iter().copied());
                c.start = Some(c.start.map_or(e.ts, |s| s.min(e.ts)));
                if c.rename.is_none()
                    && let Some((id, (from, to, ..))) =
                        ids.iter().find_map(|id| renames.get(id).map(|r| (*id, *r)))
                {
                    c.rename = Some(ShimRename {
                        id,
                        from: from.to_path_buf(),
                        to: to.to_path_buf(),
                    });
                }
            }
            CaptureEventKind::RenameOutcome {
                pid,
                call_id,
                errno,
                source,
            } => {
                calls.entry((*pid, *call_id)).or_default().outcome = Some((*errno, *source));
            }
            _ => {}
        }
    }
    let listed: HashSet<EventId> = calls
        .values()
        .flat_map(|c| c.events.iter().copied())
        .collect();
    // Each call's window ends where the same process's next call starts.
    let mut starts: HashMap<u32, Vec<TimePoint>> = HashMap::new();
    for ((pid, _), c) in &calls {
        if let Some(s) = c.start {
            starts.entry(*pid).or_default().push(s);
        }
    }
    for v in starts.values_mut() {
        v.sort_unstable();
    }
    let mut kernel: Vec<(EventId, &Path, &Path, InodeRef, TimePoint)> = renames
        .iter()
        .filter(|(id, (.., inode, _))| !listed.contains(id) && *inode != InodeRef::new(0, 0))
        .map(|(id, (from, to, inode, ts))| (*id, *from, *to, *inode, *ts))
        .collect();
    kernel.sort_by_key(|k| (k.4, k.0));

    let mut out = Adjustment::default();
    let mut ordered: Vec<(&(u32, u64), &Call)> = calls.iter().collect();
    ordered.sort_by_key(|(k, c)| (c.start, **k));
    for ((pid, _), call) in ordered {
        let Some((errno, source)) = call.outcome else {
            continue;
        };
        if errno != 0 {
            out.dropped.extend(
                call.events
                    .iter()
                    .copied()
                    .filter(|id| !refusals.contains(id)),
            );
        }
        let (Some(shim), Some(start)) = (&call.rename, call.start) else {
            continue;
        };
        if source == InodeRef::new(0, 0) {
            continue;
        }
        let end = starts
            .get(pid)
            .and_then(|v| v.iter().find(|s| **s > start).copied());
        let twin = kernel.iter().position(|(_, from, to, inode, ts)| {
            *inode == source
                && *ts > start
                && end.is_none_or(|e| *ts < e)
                && same_rename(from, to, &shim.from, &shim.to)
        });
        if let Some(i) = twin {
            let (kid, _, _, kinode, _) = kernel.remove(i);
            out.dropped.insert(kid);
            if errno == 0 {
                out.inode_for.insert(shim.id, kinode);
            }
        }
    }
    out
}

/// The two tiers' paths for one rename agree: the same names, and the
/// same destination directory once macOS's `/private` is set aside.
fn same_rename(kfrom: &Path, kto: &Path, sfrom: &Path, sto: &Path) -> bool {
    kfrom.file_name() == sfrom.file_name()
        && kto.file_name() == sto.file_name()
        && kto.parent().map(spelled) == sto.parent().map(spelled)
}

/// `/private/var/x` and `/var/x` (likewise `/tmp`, `/etc`) name the same
/// directory on macOS.
fn spelled(p: &Path) -> PathBuf {
    match p.strip_prefix("/private") {
        Ok(rest) if ["var", "tmp", "etc"].iter().any(|d| rest.starts_with(d)) => {
            Path::new("/").join(rest)
        }
        _ => p.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::CommandId;
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
                errno,
                source,
            },
        )
    }

    fn run(events: &[CaptureEvent]) -> Adjustment {
        let refs: Vec<&CaptureEvent> = events.iter().collect();
        adjust(&refs)
    }

    fn dropped(events: &[CaptureEvent]) -> Vec<u64> {
        let mut v: Vec<u64> = run(events).dropped.into_iter().map(|e| e.0).collect();
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

    /// The kernel tier's report pairs across `/private/var` and `/var`.
    /// A successful call keeps the shim's Rename with the twin's real
    /// identity; a failed one (ENOTEMPTY, after the LSM hook fired)
    /// keeps neither.
    #[test]
    fn kernel_twins_pair_across_spellings_and_lend_their_inode() {
        let ok = vec![
            rename(1, "/private/var/t/a", "/private/var/t/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/var/t/a", "/var/t/b", FILE),
            outcome(4, 10, 1, 0, FILE),
        ];
        let adj = run(&ok);
        assert_eq!(adj.dropped, HashSet::from([EventId(3)]));
        assert_eq!(adj.inode_for, HashMap::from([(EventId(1), FILE)]));
        let failed = vec![
            rename(1, "/private/var/t/a", "/private/var/t/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/var/t/a", "/var/t/b", FILE),
            outcome(4, 10, 1, libc::ENOTEMPTY, FILE),
        ];
        assert_eq!(dropped(&failed), vec![1, 3]);
    }

    /// Review item 3: a failed call (EXDEV, which the kernel rejects
    /// before the LSM hook) followed by the command's own fallback, a real
    /// kernel-only rename of the same inode after the process's next
    /// call started. The real rename is not the failed call's twin.
    #[test]
    fn a_later_kernel_rename_of_the_same_inode_is_not_a_failed_calls_twin() {
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            call(2, 10, 1, &[1]),
            outcome(3, 10, 1, libc::EXDEV, FILE),
            rename(4, "/c", "/d", SHIM),
            call(5, 10, 2, &[4]),
            outcome(6, 10, 2, 0, InodeRef::new(8, 7)),
            rename(7, "/a", "/b", FILE),
        ];
        assert_eq!(dropped(&events), vec![1]);
    }

    /// Review item 4: a shim rename the kernel tier did not watch, then a
    /// different kernel rename of the same inode in the window: the names
    /// disagree, so it is no twin.
    #[test]
    fn a_kernel_rename_with_other_names_is_not_a_twin() {
        let events = vec![
            rename(1, "/w/a", "/w/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/w/b", "/w/c", FILE),
            outcome(4, 10, 1, 0, FILE),
        ];
        let adj = run(&events);
        assert!(adj.dropped.is_empty(), "{adj:?}");
        assert!(adj.inode_for.is_empty(), "{adj:?}");
        let other_dir = vec![
            rename(1, "/w/a", "/w/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/x/a", "/x/b", FILE),
            outcome(4, 10, 1, 0, FILE),
        ];
        assert!(run(&other_dir).dropped.is_empty());
    }

    /// One kernel Rename pairs with one call, and a kernel Rename journaled
    /// before the call's note is never its twin.
    #[test]
    fn pairing_is_one_to_one_and_after_the_call_starts() {
        let events = vec![
            rename(1, "/a", "/b", FILE),
            rename(2, "/a", "/b", SHIM),
            call(3, 10, 1, &[2]),
            rename(4, "/a", "/b", FILE),
            rename(5, "/a", "/b", FILE),
            outcome(6, 10, 1, 0, FILE),
        ];
        assert_eq!(dropped(&events), vec![4]);
    }

    /// A call with no outcome (the outcome never arrived) changes nothing.
    #[test]
    fn no_outcome_no_change() {
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/a", "/b", FILE),
        ];
        assert_eq!(run(&events), Adjustment::default());
    }

    /// `live_events` applies the adjustment: the twin leaves, the shim's
    /// Rename carries the real inode, partial events are left out.
    #[test]
    fn live_events_apply_the_adjustment() {
        let mut partial = rename(9, "/p", "/q", SHIM);
        partial.partial = true;
        let events = vec![
            rename(1, "/a", "/b", SHIM),
            call(2, 10, 1, &[1]),
            rename(3, "/a", "/b", FILE),
            outcome(4, 10, 1, 0, FILE),
            partial,
        ];
        let live = live_events(&events);
        let ids: Vec<u64> = live.iter().map(|e| e.id.0).collect();
        assert_eq!(ids, vec![1, 2, 4]);
        assert!(matches!(
            &live[0].kind,
            CaptureEventKind::TreeOp(TreeOp::Rename { inode, .. }) if *inode == FILE
        ));
    }
}
