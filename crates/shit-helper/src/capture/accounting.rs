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

// The kqueue producer uses a subset: it has no walk cap or kernel loss
// counter, and it counts an entry that arrived from outside the walk
// (by its birth time) as an unresolved rename.
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
    /// The watch root. A loss whose path is known and not under it is
    /// outside the tree.
    root: Option<std::path::PathBuf>,
    /// The walk stopped at its file cap.
    capped: bool,
    /// Directories the walk recorded but did not list completely
    /// (depth limit, read error, cap hit while inside them).
    unwalked_dirs: BTreeSet<Id>,
    /// Command-scoped reason the tier does not see the whole tree.
    uncovered: Option<String>,
    born: BTreeSet<Id>,
    /// Identities a producer found missing from a listing taken when the
    /// command started (the kqueue dir diff). Absence proves birth only
    /// under [`Self::absence_proves_birth`].
    absent: BTreeSet<Id>,
    /// Identities with a pre-image or metadata capture on the wire.
    captured: BTreeSet<Id>,
    /// Identities whose bytes a delete capture read from a held fd.
    /// Evidence only if this command never wrote the identity: after a
    /// write the fd holds post-write bytes.
    delete_captured: BTreeSet<Id>,
    /// Identities this command opened for write, wrote, or changed the
    /// attributes of.
    written: BTreeSet<Id>,
    /// Mutations whose evidence was not captured, keyed by identity:
    /// the first observation, whether any event placed the identity in
    /// a parent the walk listed completely, and the order in which the
    /// first record arrived. Classified at close.
    missing: BTreeMap<Id, (Observation, bool, u64)>,
    /// The same for mutations whose identity is unknown, `(0, 0)`. Each
    /// is its own loss; they never share an entry.
    missing_unknown: Vec<(Observation, bool, u64)>,
    /// Arrival counter for `missing` and `born_paths`.
    order: u64,
    /// Renames dropped because a source or destination parent could not
    /// be resolved. Each could have moved a pre-existing file into a
    /// walked directory, so absence from a listing stops proving birth.
    renames_unresolved: u32,
    /// Paths a create hook fired for whose entry was already gone when
    /// the handler opened it: created and removed inside the command.
    /// The value is the arrival order of the first such create.
    born_paths: BTreeMap<String, u64>,
    /// Paths some rename in the command moved an entry onto. A born
    /// path that is also a rename target proves nothing about whatever
    /// was removed there later.
    rename_targets: BTreeSet<String>,
    /// Losses with no identity (an fstat that failed).
    unkeyed: Vec<String>,
    /// `(label, value)` of a tier-wide loss counter when the watch began.
    kernel_mark: Option<(&'static str, u64)>,
    /// Parent directories of the removals recorded in `missing`, per
    /// identity. `None` once any loss of the identity came without a
    /// parent, so the parent rule below never applies to it.
    missing_parents: BTreeMap<Id, Option<BTreeSet<Id>>>,
    /// Identities some rename in this command moved, resolved or not.
    moved: BTreeSet<Id>,
    /// Directories this command removed.
    removed_dirs: BTreeSet<Id>,
    /// `(dev, root inode, inodes above the root)`, when no mount lies
    /// under the root (#233).
    root_ancestry: Option<(u64, u64, BTreeSet<u64>)>,
    /// Per identity in `missing`: true while every loss of it came with
    /// a dentry chain that placed it outside the root.
    dentry_outside: BTreeMap<Id, bool>,
    /// Set by [`Self::enable_dentry_rule`].
    dentry_rule_on: bool,
    /// Set by [`Self::disable_dentry_rule`]; overrides `dentry_rule_on`.
    dentry_rule_off: bool,
}

impl CloseAccounting {
    pub fn note_baseline_entry(&mut self, id: Id, path: &std::path::Path) {
        self.note_baseline_id(id);
        self.baseline_paths.insert(path.to_path_buf(), id);
    }

    /// A baseline identity whose path no rename check needs.
    pub fn note_baseline_id(&mut self, id: Id) {
        self.baseline.insert(id);
    }

    pub fn note_walked(&mut self) {
        self.walked = true;
    }

    pub fn note_root(&mut self, root: &std::path::Path) {
        self.root = Some(root.to_path_buf());
    }

    /// True when `path` is known and not under the watch root.
    fn outside_root(&self, path: Option<&str>) -> bool {
        match (path, self.root.as_deref()) {
            (Some(p), Some(root)) => !std::path::Path::new(p).starts_with(root),
            _ => false,
        }
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

    /// A diff found `id` in a directory whose start-of-command listing
    /// did not hold it. That is birth only if the whole walk completed
    /// and nothing could have moved a pre-existing file in.
    // Only the kqueue producer diffs listings.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn note_absent_from_listing(&mut self, id: Id) {
        if id != (0, 0) {
            self.absent.insert(id);
        }
    }

    /// True when the baseline walk saw `id`.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn is_baseline(&self, id: Id) -> bool {
        self.baseline.contains(&id)
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

    /// A create fired for `path` and the entry was gone (ENOENT) by the
    /// time the handler opened it.
    pub fn note_born_path(&mut self, path: String) {
        let order = self.next_order();
        self.born_paths.entry(path).or_insert(order);
    }

    fn next_order(&mut self) -> u64 {
        self.order += 1;
        self.order
    }

    /// A rename moved `moved` from `from` to `to`: nothing is at `from`
    /// any more, and `to` now holds `moved`.
    pub fn note_renamed(&mut self, from: &std::path::Path, to: &std::path::Path, moved: Id) {
        self.baseline_paths.remove(from);
        self.baseline_paths.insert(to.to_path_buf(), moved);
    }

    /// A directory moved from `from` to `to`: every baseline path
    /// strictly under `from` now lives under `to`.
    pub fn note_dir_renamed(&mut self, from: &std::path::Path, to: &std::path::Path) {
        rekey_under(&mut self.baseline_paths, from, to);
    }

    /// A rename moved an entry onto `path`.
    pub fn note_rename_target(&mut self, path: String) {
        self.rename_targets.insert(path);
    }

    /// True when a loss first recorded at `order` for `path` is the file
    /// an ENOENT create proved born. Only a loss recorded after that
    /// create qualifies: one recorded before it may be the entry that was
    /// at the path before the command created its own.
    fn born_at(&self, path: Option<&str>, order: u64) -> bool {
        path.is_some_and(|p| {
            self.born_paths
                .get(p)
                .is_some_and(|&created| created < order)
                && !self.rename_targets.contains(p)
        })
    }

    /// A rename was dropped because a parent could not be resolved.
    pub fn note_unresolved_rename(&mut self) {
        self.renames_unresolved = self.renames_unresolved.saturating_add(1);
    }

    /// Absence from a walked parent's listing proves birth only when the
    /// whole walk completed and no rename went unresolved: otherwise a
    /// pre-existing file can arrive in a walked directory from a part of
    /// the tree, or a place outside it, that the walk never listed.
    fn absence_proves_birth(&self) -> bool {
        self.listing_complete() && self.renames_unresolved == 0
    }

    /// Classify `id` at close. `absent_from_walked_parent` means some
    /// event placed `id` in a directory the walk listed completely (or
    /// one created in the command) and the listing did not contain it.
    /// Positive evidence of creation (FMODE_CREATED, a create stat) is
    /// in `born`; absence counts only under [`Self::absence_proves_birth`].
    /// Baseline wins over born, so a reused inode number never hides the
    /// loss of the file that first had it.
    pub fn classify(&self, id: Id, absent_from_walked_parent: bool) -> Provenance {
        if self.baseline.contains(&id) {
            return Provenance::Baseline;
        }
        if self.born.contains(&id) {
            return Provenance::Born;
        }
        if (absent_from_walked_parent || self.absent.contains(&id))
            && id != (0, 0)
            && self.absence_proves_birth()
        {
            return Provenance::Born;
        }
        if id != (0, 0) && !self.tree_devs.is_empty() && !self.tree_devs.contains(&id.0) {
            return Provenance::Outside;
        }
        Provenance::Unlocated
    }

    /// Record that a mutation of `id` reached the producer and its
    /// evidence could not be captured. Whether that is loss is decided
    /// at close, once every event for the command has been seen.
    pub fn note_missing(
        &mut self,
        id: Id,
        parent_walked: bool,
        path: Option<String>,
        detail: impl Into<String>,
    ) {
        if id != (0, 0) {
            self.missing_parents.insert(id, None);
        }
        self.record_missing(id, parent_walked, false, path, detail);
    }

    /// [`Self::note_missing`] for a change to `id` whose event carries
    /// no path. `outside` is [`Self::dentry_outside_root`] for the
    /// event's dentry chain (#233).
    pub fn note_missing_by_dentry(&mut self, id: Id, outside: bool, detail: impl Into<String>) {
        if id != (0, 0) {
            self.missing_parents.insert(id, None);
        }
        self.record_missing(id, false, outside, None, detail);
    }

    /// Record the watch root's place in its filesystem: its inode and
    /// the inodes of the directories above it on the same filesystem.
    /// Only call this when no mount lies under the root, since a file
    /// reached through such a mount has ancestors outside the root
    /// while its path is inside it.
    pub fn note_root_ancestry(&mut self, dev: u64, root_ino: u64, above: BTreeSet<u64>) {
        self.root_ancestry = Some((dev, root_ino, above));
    }

    /// True when the dentry chain proves `id` lives outside the watch
    /// root (#233). `ancestors` are the inode numbers of the directories
    /// above the file's dentry, nearest first. Walking up, the first
    /// directory that is either the root or one of the root's own
    /// ancestors decides: the root means inside, an ancestor of the root
    /// means the file's path left the root's line below that ancestor.
    /// A chain that meets neither proves nothing. A file with more than
    /// one link may have another name inside the tree, so it never
    /// counts as outside.
    pub fn dentry_outside_root(&self, id: Id, nlink: u32, ancestors: &[u64]) -> bool {
        let Some((dev, root_ino, above)) = &self.root_ancestry else {
            return false;
        };
        if nlink != 1 || id.0 != *dev || id == (0, 0) {
            return false;
        }
        for a in ancestors {
            if a == root_ino {
                return false;
            }
            if above.contains(a) {
                return true;
            }
        }
        false
    }

    /// [`Self::note_missing`] for the removal of `id` from directory
    /// `parent`, whose path may not be resolvable yet (#248).
    pub fn note_missing_in_dir(
        &mut self,
        id: Id,
        parent: Id,
        parent_walked: bool,
        path: Option<String>,
        detail: impl Into<String>,
    ) {
        if id != (0, 0) {
            match self.missing_parents.entry(id) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(Some(BTreeSet::from([parent])));
                }
                std::collections::btree_map::Entry::Occupied(mut o) => {
                    if let Some(set) = o.get_mut() {
                        set.insert(parent);
                    }
                }
            }
        }
        self.record_missing(id, parent_walked, false, path, detail);
    }

    /// A rename in this command moved `id`.
    pub fn note_moved(&mut self, id: Id) {
        self.moved.insert(id);
    }

    /// True when every recorded loss of `id` removed it from a directory
    /// this command created, and no rename moved it (#248). Such a
    /// directory held nothing when the command started, and the only
    /// way a pre-existing file gets into it is a rename, so `id` was
    /// created in the command (or is a hard link whose other names are
    /// accounted for separately). This holds whatever order the mkdir,
    /// create and unlink records were handled in.
    ///
    /// A directory this command also removed does not count: after
    /// `rm -r old; mkdir new` the new directory can reuse the old one's
    /// inode number, and files removed from `old` would look as if they
    /// were removed from `new`.
    ///
    /// Neither does a directory the walk saw or a rename moved: the
    /// mkdir handler stats its path late, so `born` can hold a
    /// pre-existing directory renamed onto the new name (`mkdir d;
    /// rmdir d; mv deep d; rm d/x`).
    fn removed_from_born_dir(&self, id: &Id) -> bool {
        !self.moved.contains(id)
            && matches!(
                self.missing_parents.get(id),
                Some(Some(parents)) if !parents.is_empty()
                    && parents.iter().all(|p| {
                        self.born.contains(p)
                            && !self.removed_dirs.contains(p)
                            && !self.baseline.contains(p)
                            && !self.moved.contains(p)
                    })
            )
    }

    /// True when the dentry chain of every loss of `id` placed it
    /// outside the root, and nothing in the command could have moved a
    /// pre-existing file out of the tree first: `id` was not renamed, no
    /// rename went unresolved (an unresolved rename may have moved a
    /// directory holding `id` out), and the rule is on: turned on by
    /// [`Self::enable_dentry_rule`] and never turned off.
    fn dentry_places_outside(&self, id: &Id) -> bool {
        self.dentry_rule_on
            && !self.dentry_rule_off
            && self.renames_unresolved == 0
            && !self.moved.contains(id)
            && self.dentry_outside.get(id) == Some(&true)
    }

    /// Stop using dentry chains for this command: something (a mount,
    /// another mount namespace) may have broken the match between the
    /// dentry tree and paths under the root.
    pub fn disable_dentry_rule(&mut self) {
        self.dentry_rule_off = true;
    }

    /// Use dentry chains for this command: its mount table was checked
    /// at WatchTree. The rule is off until this is called, and a later
    /// [`Self::disable_dentry_rule`] wins.
    pub fn enable_dentry_rule(&mut self) {
        self.dentry_rule_on = true;
    }

    /// This command removed directory `id`.
    pub fn note_dir_removed(&mut self, id: Id) {
        self.removed_dirs.insert(id);
    }

    fn record_missing(
        &mut self,
        id: Id,
        parent_walked: bool,
        outside: bool,
        path: Option<String>,
        detail: impl Into<String>,
    ) {
        let order = self.next_order();
        let obs = Observation {
            path,
            detail: detail.into(),
        };
        if id == (0, 0) {
            self.missing_unknown.push((obs, parent_walked, order));
            return;
        }
        self.dentry_outside
            .entry(id)
            .and_modify(|o| *o &= outside)
            .or_insert(outside);
        self.missing
            .entry(id)
            .and_modify(|(_, absent, _)| *absent |= parent_walked)
            .or_insert((obs, parent_walked, order));
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
        if self.renames_unresolved > 0 {
            parts.push(format!(
                "{} rename(s) had a source or destination outside the walked tree",
                self.renames_unresolved
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
        // `(observation, identity known)`: a pre-existing file, or a
        // change whose file could not be identified at all.
        let mut lost: Vec<(Observation, bool)> = Vec::new();
        let mut unlocated = 0usize;
        let keyed = std::mem::take(&mut self.missing)
            .into_iter()
            .map(|(id, (obs, absent, order))| (id, obs, absent, order));
        let unknown = std::mem::take(&mut self.missing_unknown)
            .into_iter()
            .map(|(obs, absent, order)| ((0, 0), obs, absent, order));
        for (id, obs, absent, order) in keyed.chain(unknown) {
            if id == (0, 0) {
                // No identity: nothing places it outside the tree, and
                // no evidence can be matched to it. Only a known path
                // can excuse it.
                if !self.born_at(obs.path.as_deref(), order)
                    && !self.outside_root(obs.path.as_deref())
                {
                    lost.push((obs, false));
                }
                continue;
            }
            if self.has_evidence(&id) {
                continue;
            }
            match self.classify(id, absent) {
                Provenance::Baseline => lost.push((obs, true)),
                Provenance::Born | Provenance::Outside => {}
                Provenance::Unlocated if self.born_at(obs.path.as_deref(), order) => {}
                Provenance::Unlocated if self.removed_from_born_dir(&id) => {}
                Provenance::Unlocated if self.dentry_places_outside(&id) => {}
                Provenance::Unlocated if self.outside_root(obs.path.as_deref()) => {}
                Provenance::Unlocated => unlocated += 1,
            }
        }
        let folded = lost.split_off(lost.len().min(MAX_PATH_OBSERVATIONS));
        out.extend(lost.into_iter().map(|(obs, _)| obs));
        let hidden_known = folded.iter().filter(|(_, known)| *known).count();
        let hidden_unknown = folded.len() - hidden_known;
        if hidden_known > 0 {
            out.push(Observation {
                path: None,
                detail: format!(
                    "{hidden_known} more pre-existing file(s) changed without captured evidence"
                ),
            });
        }
        if hidden_unknown > 0 {
            out.push(Observation {
                path: None,
                detail: format!(
                    "{hidden_unknown} more change(s) to file(s) whose identity could not be read, without captured evidence"
                ),
            });
        }
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

/// Move every key strictly under `from` to the same place under `to`.
/// The key equal to `from` is left alone: after `mv d e; mkdir d` it may
/// already name the new directory.
pub fn rekey_under<V>(
    map: &mut BTreeMap<std::path::PathBuf, V>,
    from: &std::path::Path,
    to: &std::path::Path,
) {
    let moved: Vec<std::path::PathBuf> = map
        .keys()
        .filter(|k| k.as_path() != from && k.starts_with(from))
        .cloned()
        .collect();
    for old in moved {
        if let (Some(v), Ok(rest)) = (map.remove(&old), old.strip_prefix(from)) {
            map.insert(to.join(rest), v);
        }
    }
}

/// Send a `CaptureRefused` observation. The daemon decides whether it
/// becomes a journal row (strict mode) or a log line.
pub fn send_capture_observation(
    conn: &crate::ipc::Conn,
    command: shit_planner::events::CommandId,
    path: Option<String>,
    detail: String,
) {
    let resp = shit_proto::HelperResponse::CaptureRefused {
        session: command.session,
        seq: command.seq,
        path,
        detail,
    };
    if let Err(e) = conn.send_response(&resp) {
        tracing::warn!(err = %e, %command, "CaptureRefused observation send failed");
    }
}

/// Send each close-time observation for `command`.
pub fn send_observations(
    conn: &crate::ipc::Conn,
    command: shit_planner::events::CommandId,
    observations: Vec<Observation>,
) {
    for obs in observations {
        tracing::warn!(%command, path = ?obs.path, detail = %obs.detail, "capture loss at close");
        send_capture_observation(conn, command, obs.path, obs.detail);
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
    fn unresolved_rename_stops_absence_proving_birth() {
        let mut a = walked();
        a.note_unresolved_rename();
        a.note_missing((1, 21), true, None, "unlink race lost");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 1, "{obs:?}");
        assert!(obs[0].detail.contains("rename"), "{obs:?}");

        let mut a = walked();
        a.note_unresolved_rename();
        a.note_born((1, 21));
        a.note_missing((1, 21), true, None, "unlink race lost");
        assert!(
            a.close(0, None).is_empty(),
            "positive evidence still counts"
        );
    }

    #[test]
    fn known_path_outside_the_watch_root_is_outside() {
        let mut a = walked();
        a.note_root(Path::new("/w"));
        a.note_capped();
        a.note_missing(
            (1, 99),
            false,
            Some("/home/u/.bash_history".into()),
            "no snapshot",
        );
        a.note_missing((1, 98), false, Some("/wx/f".into()), "no snapshot");
        let obs = a.close(0, None);
        assert!(obs.is_empty(), "{obs:?}");

        let mut a = walked();
        a.note_root(Path::new("/w"));
        a.note_capped();
        a.note_missing((1, 97), false, Some("/w/deep/f".into()), "no snapshot");
        a.note_missing((1, 96), false, None, "no snapshot");
        assert!(a.close(0, None)[0].detail.starts_with("2 changed file(s)"));
    }

    #[test]
    fn unknown_identity_losses_are_counted_one_by_one() {
        let mut a = walked();
        a.note_capped();
        a.note_missing((0, 0), false, Some("/w/a".into()), "no identity");
        a.note_missing((0, 0), false, Some("/w/b".into()), "no identity");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 2, "{obs:?}");
        assert_eq!(obs[0].path.as_deref(), Some("/w/a"));
        assert_eq!(obs[1].path.as_deref(), Some("/w/b"));
    }

    /// #234 item 4: a complete walk says nothing about an identity it
    /// cannot look up, so an unknown identity is loss there too.
    #[test]
    fn unknown_identity_is_loss_after_a_complete_walk() {
        let mut a = walked();
        a.note_root(Path::new("/w"));
        assert!(a.listing_complete());
        a.note_missing((0, 0), false, Some("/w/a".into()), "no identity");
        a.note_missing((0, 0), false, None, "no identity");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 2, "{obs:?}");

        // A known path outside the root, or one an ENOENT create proved
        // born, still excuses it.
        let mut a = walked();
        a.note_root(Path::new("/w"));
        a.note_missing((0, 0), false, Some("/elsewhere/a".into()), "no identity");
        a.note_born_path("/w/t".into());
        a.note_missing((0, 0), false, Some("/w/t".into()), "no identity");
        let obs = a.close(0, None);
        assert!(obs.is_empty(), "{obs:?}");
    }

    #[test]
    fn absence_from_a_listing_proves_birth_only_after_a_complete_walk() {
        let mut a = walked();
        a.note_absent_from_listing((1, 40));
        a.note_missing((1, 40), false, Some("/w/n".into()), "no snapshot");
        assert!(a.close(0, None).is_empty());

        let mut a = walked();
        a.note_unwalked_dir((1, 2));
        a.note_absent_from_listing((1, 40));
        a.note_missing((1, 40), false, Some("/w/n".into()), "no snapshot");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 1, "{obs:?}");
        assert!(obs[0].detail.contains("not listed completely"), "{obs:?}");

        let mut a = walked();
        a.note_unresolved_rename();
        a.note_absent_from_listing((1, 40));
        a.note_missing((1, 40), false, Some("/w/n".into()), "no snapshot");
        assert_eq!(a.close(0, None).len(), 1);
    }

    #[test]
    fn born_path_excuses_only_losses_recorded_after_its_create() {
        let mut a = walked();
        a.note_capped();
        a.note_missing((1, 50), false, Some("/w/p".into()), "unlink race lost");
        a.note_born_path("/w/p".into());
        a.note_missing((1, 51), false, Some("/w/p".into()), "unlink race lost");
        let obs = a.close(0, None);
        assert_eq!(obs.len(), 1, "{obs:?}");
        assert!(obs[0].detail.starts_with("1 changed file(s)"), "{obs:?}");
    }

    #[test]
    fn incomplete_walk_stops_absence_proving_birth() {
        let mut a = walked();
        a.note_unwalked_dir((1, 2));
        a.note_missing((1, 21), true, None, "unlink race lost");
        assert_eq!(a.close(0, None).len(), 1);
    }

    #[test]
    fn unwalked_parent_does_not_prove_birth() {
        let mut a = walked();
        a.note_unwalked_dir((1, 2));
        assert!(!a.dir_walked((1, 2)));
        assert!(a.dir_walked((1, 3)));
        let b = CloseAccounting::default();
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
    fn folded_unknown_identity_losses_are_not_called_pre_existing() {
        let mut a = CloseAccounting::default();
        a.note_walked();
        for i in 0..(MAX_PATH_OBSERVATIONS as u64 + 2) {
            a.note_baseline_entry((1, 100 + i), Path::new("/w/x"));
            a.note_missing((1, 100 + i), true, None, "no snapshot");
        }
        for _ in 0..3 {
            a.note_missing((0, 0), false, None, "no identity");
        }
        let obs = a.close(0, None);
        assert_eq!(obs.len(), MAX_PATH_OBSERVATIONS + 2, "{obs:?}");
        assert!(
            obs[MAX_PATH_OBSERVATIONS]
                .detail
                .starts_with("2 more pre-existing")
        );
        let last = &obs[MAX_PATH_OBSERVATIONS + 1].detail;
        assert!(last.starts_with("3 more change(s)"), "{last}");
        assert!(!last.contains("pre-existing"), "{last}");
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
        let a = walked();
        assert_eq!(a.classify((0, 0), true), Provenance::Unlocated);
    }
}
