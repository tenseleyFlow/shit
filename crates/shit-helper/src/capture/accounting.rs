// SPDX-License-Identifier: AGPL-3.0-or-later

//! Close-time loss accounting for one command (R3 slice B).
//!
//! A producer records three kinds of fact while a command runs: which
//! identities existed when the command started (the baseline walk),
//! which identities the command created (the born set), and which
//! mutations it could not capture evidence for. At close the producer
//! asks for the observations, and each one goes to the daemon as a
//! `CaptureRefused`. The daemon journals them only in strict mode, so
//! nothing here changes default-mode capture.
//!
//! The rule: a path absent when the command started has pre-state
//! "absent", and undoing it needs no pre-image. Any create, write,
//! chmod, rename-away or unlink of an entry born inside the command is
//! therefore never loss. Only identities in the baseline can lose
//! evidence. An identity that is neither in the baseline nor provably
//! born is "unlocated": it is either outside the watched tree, which
//! trunk never claimed to capture, or inside a part of the tree the
//! baseline walk did not reach. Unlocated changes count only when the
//! walk was incomplete.
//!
//! Every check runs at close, so the answer does not depend on the
//! order in which per-hook ring readers deliver events. A file whose
//! unlink is handled before its creating open is still born.

// The kqueue producer uses a subset: it has no walk cap, unlisted
// directories, renames or kernel loss counter.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};

/// `(dev, inode)` in the userspace (glibc) encoding.
pub type Id = (u64, u64);

/// Bound on path-scoped observations per command. Past it, one summary
/// observation carries the remaining count.
pub const MAX_PATH_OBSERVATIONS: usize = 16;

/// What the accounting knows about where an identity came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Existed when the command started. Losing its evidence is loss.
    Baseline,
    /// Created inside the command. Needs no pre-image.
    Born,
    /// Neither, on a filesystem the tree spans: outside the tree, or
    /// inside an unwalked part of it.
    Unlocated,
    /// On a filesystem the tree does not span (devices, pipes, sockets,
    /// other mounts). Never inside the watched tree.
    Outside,
}

/// One observation for the daemon. `path: None` is command-scoped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct CloseAccounting {
    /// Every identity the baseline walk saw, whatever its kind and
    /// whether or not it could be opened.
    baseline: BTreeSet<Id>,
    /// Path of every baseline entry, for rename-over checks on entries
    /// the capture maps do not index (unopenable files, symlinks).
    baseline_paths: BTreeMap<std::path::PathBuf, Id>,
    /// A baseline walk ran for this command.
    walked: bool,
    /// Filesystems the watched tree spans: the root's, plus any
    /// submount the walk skipped.
    tree_devs: BTreeSet<u64>,
    /// The walk stopped at its file cap.
    capped: bool,
    /// Directories the walk recorded but did not list completely
    /// (depth limit, read error, cap hit while inside them).
    unwalked_dirs: BTreeSet<Id>,
    /// Command-scoped reason the tier does not see the whole tree.
    uncovered: Option<String>,
    born: BTreeSet<Id>,
    /// Identities with a pre-image or metadata capture on the wire.
    captured: BTreeSet<Id>,
    /// Identities whose bytes a delete capture read from a held fd.
    /// Evidence only if this command never wrote the identity: after a
    /// write the fd holds post-write bytes.
    delete_captured: BTreeSet<Id>,
    /// Identities this command opened for write, wrote, or changed the
    /// attributes of.
    written: BTreeSet<Id>,
    lost: BTreeMap<Id, Observation>,
    unlocated: BTreeSet<Id>,
    /// Losses with no identity (an fstat that failed).
    unkeyed: Vec<String>,
    /// `(label, value)` of a tier-wide loss counter when the watch began.
    kernel_mark: Option<(&'static str, u64)>,
}

impl CloseAccounting {
    pub fn note_baseline_entry(&mut self, id: Id, path: &std::path::Path) {
        self.baseline.insert(id);
        self.baseline_paths.insert(path.to_path_buf(), id);
    }

    pub fn note_walked(&mut self) {
        self.walked = true;
    }

    pub fn note_tree_dev(&mut self, dev: u64) {
        self.tree_devs.insert(dev);
    }

    pub fn note_capped(&mut self) {
        self.capped = true;
    }

    pub fn note_unwalked_dir(&mut self, dir: Id) {
        self.unwalked_dirs.insert(dir);
    }

    /// True when a walk ran and listed every directory it recorded,
    /// without hitting its cap.
    pub fn listing_complete(&self) -> bool {
        self.walked && !self.capped && self.unwalked_dirs.is_empty()
    }

    /// True when the walk listed `dir` completely.
    pub fn dir_walked(&self, dir: Id) -> bool {
        self.walked && !self.unwalked_dirs.contains(&dir)
    }

    pub fn note_uncovered(&mut self, reason: String) {
        self.uncovered = Some(reason);
    }

    pub fn note_born(&mut self, id: Id) {
        if id != (0, 0) {
            self.born.insert(id);
        }
    }

    pub fn note_captured(&mut self, id: Id) {
        self.captured.insert(id);
    }

    /// A delete's capture went out, read from an fd that survives the
    /// unlink. See [`Self::note_written`].
    pub fn note_delete_captured(&mut self, id: Id) {
        self.delete_captured.insert(id);
    }

    /// This command wrote `id` (or opened it for write, or changed its
    /// attributes). A later delete capture of it holds post-write state.
    pub fn note_written(&mut self, id: Id) {
        self.written.insert(id);
    }

    fn has_evidence(&self, id: &Id) -> bool {
        self.captured.contains(id)
            || (self.delete_captured.contains(id) && !self.written.contains(id))
    }

    pub fn baseline_id_at(&self, path: &std::path::Path) -> Option<Id> {
        self.baseline_paths.get(path).copied()
    }

    pub fn mark_kernel_losses(&mut self, label: &'static str, value: u64) {
        self.kernel_mark = Some((label, value));
    }

    /// Classify `id`. `parent_walked` is the caller's proof that the
    /// entry's parent directory was listed completely by the walk, or
    /// was itself created inside the command; an identity absent from
    /// such a directory's listing was born. Baseline wins over born, so
    /// a reused inode number never hides the loss of the file that
    /// first had it.
    pub fn classify(&mut self, id: Id, parent_walked: bool) -> Provenance {
        if self.baseline.contains(&id) {
            return Provenance::Baseline;
        }
        if self.born.contains(&id) {
            return Provenance::Born;
        }
        if parent_walked && id != (0, 0) {
            self.born.insert(id);
            return Provenance::Born;
        }
        if id != (0, 0) && !self.tree_devs.is_empty() && !self.tree_devs.contains(&id.0) {
            return Provenance::Outside;
        }
        Provenance::Unlocated
    }

    /// Record that a mutation of `id` reached the producer and its
    /// evidence could not be captured. Born identities are exempt.
    pub fn note_missing(
        &mut self,
        id: Id,
        parent_walked: bool,
        path: Option<String>,
        detail: impl Into<String>,
    ) {
        match self.classify(id, parent_walked) {
            Provenance::Born | Provenance::Outside => {}
            Provenance::Baseline => {
                self.lost.entry(id).or_insert(Observation {
                    path,
                    detail: detail.into(),
                });
            }
            Provenance::Unlocated => {
                self.unlocated.insert(id);
            }
        }
    }

    /// A loss with no identity to classify.
    pub fn note_unkeyed(&mut self, detail: impl Into<String>) {
        self.unkeyed.push(detail.into());
    }

    fn incomplete_reason(&self) -> Option<String> {
        if !self.walked {
            return None;
        }
        let mut parts = Vec::new();
        if self.capped {
            parts.push("the baseline walk stopped at its file cap".to_string());
        }
        if !self.unwalked_dirs.is_empty() {
            parts.push(format!(
                "{} director{} not listed completely",
                self.unwalked_dirs.len(),
                if self.unwalked_dirs.len() == 1 {
                    "y was"
                } else {
                    "ies were"
                }
            ));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }

    /// Observations for the daemon, consumed at close.
    ///
    /// `send_failures` is the producer's count of capture responses
    /// that never reached the daemon. `kernel_now` is the current value
    /// of the counter given to [`Self::mark_kernel_losses`].
    pub fn close(mut self, send_failures: u32, kernel_now: Option<u64>) -> Vec<Observation> {
        let mut out = Vec::new();
        let reason = self.incomplete_reason();
        let mut lost: Vec<Observation> = std::mem::take(&mut self.lost)
            .into_iter()
            .filter(|(id, _)| !self.has_evidence(id))
            .map(|(_, obs)| obs)
            .collect();
        let hidden = lost.len().saturating_sub(MAX_PATH_OBSERVATIONS);
        lost.truncate(MAX_PATH_OBSERVATIONS);
        out.extend(lost);
        if hidden > 0 {
            out.push(Observation {
                path: None,
                detail: format!(
                    "{hidden} more pre-existing file(s) changed without captured evidence"
                ),
            });
        }
        let unlocated = self
            .unlocated
            .iter()
            .filter(|id| !self.born.contains(id) && !self.has_evidence(id))
            .count();
        if unlocated > 0
            && let Some(reason) = reason
        {
            out.push(Observation {
                path: None,
                detail: format!(
                    "{unlocated} changed file(s) could not be placed in the baseline ({reason})"
                ),
            });
        }
        for detail in self.unkeyed {
            out.push(Observation { path: None, detail });
        }
        if let Some(reason) = self.uncovered {
            out.push(Observation {
                path: None,
                detail: reason,
            });
        }
        if send_failures > 0 {
            out.push(Observation {
                path: None,
                detail: format!(
                    "{send_failures} capture response(s) could not be sent to the daemon"
                ),
            });
        }
        if let (Some((label, start)), Some(now)) = (self.kernel_mark, kernel_now) {
            let delta = now.wrapping_sub(start);
            if delta > 0 {
                out.push(Observation {
                    path: None,
                    detail: format!("{label} dropped {delta} event(s) while this command ran"),
                });
            }
        }
        out
    }
}

/// Send each observation as a `CaptureRefused` for `command`.
pub fn send_observations(
    conn: &crate::ipc::Conn,
    command: shit_planner::events::CommandId,
    observations: Vec<Observation>,
) {
    for obs in observations {
        tracing::warn!(%command, path = ?obs.path, detail = %obs.detail, "capture loss at close");
        let resp = shit_proto::HelperResponse::CaptureRefused {
            session: command.session,
            seq: command.seq,
            path: obs.path,
            detail: obs.detail,
        };
        if let Err(e) = conn.send_response(&resp) {
            tracing::warn!(err = %e, %command, "CaptureRefused observation send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn walked() -> CloseAccounting {
        let mut a = CloseAccounting::default();
        a.note_walked();
        a.note_baseline_entry((1, 10), Path::new("/w/a"));
        a
    }

    #[test]
    fn born_identity_is_never_loss() {
        let mut a = walked();
        a.note_born((1, 20));
        a.note_missing((1, 20), false, Some("/w/t".into()), "no snapshot");
        assert!(a.close(0, None).is_empty());
    }

    #[test]
    fn absence_from_a_walked_parent_proves_birth() {
        let mut a = walked();
        a.note_missing((1, 21), true, Some("/w/t.lock".into()), "unlink race lost");
        assert!(a.close(0, None).is_empty());
    }

    #[test]
    fn baseline_identity_without_evidence_is_loss() {
        let mut a = walked();
        a.note_missing((1, 10), true, Some("/w/a".into()), "no snapshot");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_deref(), Some("/w/a"));
    }

    #[test]
    fn baseline_wins_over_born_for_a_reused_inode() {
        let mut a = walked();
        a.note_born((1, 10));
        a.note_missing((1, 10), true, None, "no snapshot");
        assert_eq!(a.close(0, None).len(), 1);
    }

    #[test]
    fn evidence_captured_in_either_order_clears_the_loss() {
        let mut a = walked();
        a.note_missing((1, 10), true, None, "unlink race lost");
        a.note_captured((1, 10));
        assert!(a.close(0, None).is_empty());
    }

    #[test]
    fn delete_capture_is_evidence_only_without_an_earlier_write() {
        let mut a = walked();
        a.note_missing((1, 10), true, None, "unlink race lost");
        a.note_delete_captured((1, 10));
        assert!(a.close(0, None).is_empty());

        let mut a = walked();
        a.note_written((1, 10));
        a.note_missing((1, 10), true, None, "no snapshot");
        a.note_delete_captured((1, 10));
        assert_eq!(a.close(0, None).len(), 1);
    }

    #[test]
    fn unlocated_changes_count_only_when_the_walk_was_incomplete() {
        let mut a = walked();
        a.note_missing((1, 30), false, None, "no snapshot");
        assert!(a.close(0, None).is_empty(), "outside the tree is not loss");

        let mut a = walked();
        a.note_capped();
        a.note_missing((1, 30), false, None, "no snapshot");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].detail.contains("file cap"), "{}", obs[0].detail);
    }

    #[test]
    fn unlocated_identity_later_proven_born_is_not_counted() {
        let mut a = walked();
        a.note_unwalked_dir((1, 2));
        a.note_missing((1, 31), false, None, "no snapshot");
        a.note_born((1, 31));
        assert!(a.close(0, None).is_empty());
    }

    #[test]
    fn unwalked_parent_does_not_prove_birth() {
        let mut a = walked();
        a.note_unwalked_dir((1, 2));
        assert!(!a.dir_walked((1, 2)));
        assert!(a.dir_walked((1, 3)));
        let mut b = CloseAccounting::default();
        assert!(!b.dir_walked((1, 3)), "no walk proves nothing");
        assert_eq!(b.classify((1, 9), false), Provenance::Unlocated);
    }

    #[test]
    fn no_walk_reports_no_unlocated_summary() {
        // The attach observation already covers a command with no walk.
        let mut a = CloseAccounting::default();
        a.note_missing((1, 30), false, None, "no snapshot");
        assert!(a.close(0, None).is_empty());
    }

    #[test]
    fn path_observations_are_bounded() {
        let mut a = CloseAccounting::default();
        a.note_walked();
        for i in 0..(MAX_PATH_OBSERVATIONS as u64 + 3) {
            a.note_baseline_entry((1, 100 + i), Path::new("/w/x"));
            a.note_missing((1, 100 + i), true, None, "no snapshot");
        }
        let obs = a.close(0, None);
        assert_eq!(obs.len(), MAX_PATH_OBSERVATIONS + 1);
        assert!(obs.last().unwrap().detail.starts_with("3 more"));
    }

    #[test]
    fn send_failures_and_kernel_drops_are_reported() {
        let mut a = CloseAccounting::default();
        a.mark_kernel_losses("eBPF ring buffers", 5);
        let obs = a.close(2, Some(9));
        assert_eq!(obs.len(), 2);
        assert!(obs[0].detail.contains("2 capture response(s)"));
        assert!(obs[1].detail.contains("dropped 4 event(s)"));

        let mut a = CloseAccounting::default();
        a.mark_kernel_losses("eBPF ring buffers", 5);
        assert!(a.close(0, Some(5)).is_empty());
    }

    #[test]
    fn uncovered_tree_is_command_scoped() {
        let mut a = CloseAccounting::default();
        a.note_uncovered("fanotify marks cover only direct children".into());
        let obs = a.close(0, None);
        assert_eq!(
            obs,
            vec![Observation {
                path: None,
                detail: "fanotify marks cover only direct children".into()
            }]
        );
    }

    #[test]
    fn other_filesystems_are_outside_the_tree() {
        let mut a = walked();
        a.note_tree_dev(1);
        a.note_capped();
        assert_eq!(a.classify((7, 5), false), Provenance::Outside);
        assert_eq!(a.classify((1, 5), false), Provenance::Unlocated);
        a.note_missing((7, 5), false, None, "tty open");
        assert!(a.close(0, None).is_empty());
    }

    #[test]
    fn unknown_identity_marker_is_never_born() {
        let mut a = walked();
        assert_eq!(a.classify((0, 0), true), Provenance::Unlocated);
    }
}
