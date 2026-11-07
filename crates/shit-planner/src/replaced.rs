// SPDX-License-Identifier: AGPL-3.0-or-later

//! L5 — directory renames the shim proved, and the replaced-subtree rule.
//!
//! The shim journals a Rename before the syscall. After the syscall it
//! sends a [`CaptureEventKind::RenameOutcome`] for a directory rename and
//! for any failed rename. Two things follow from that here:
//!
//! - [`failed_renames`]: a Rename whose outcome is an errno did not
//!   happen, so it has no inverse.
//! - [`ReplacedSubtrees`]: a directory rename `F -> T` whose destination
//!   the command deleted again (pip's stash) is undone by rebuilding `F`
//!   from the shim's walk, instead of the reverse rename that has nothing
//!   left to move. It fires only when every precondition below is proven;
//!   otherwise the Rename keeps its ordinary inverses.
//!
//! Proof that the rename happened is an inode, never a name: the
//! outcome's inode at `T` after the call equals the walk's inode for `F`
//! before it. Every event under `T` afterwards must then be accounted for
//! by the walk's own identities (inode, and for bytes the blob), which is
//! what makes dropping those events lose nothing.

use crate::events::{
    CaptureEvent, CaptureEventKind, EventId, FilePreImageSource, TreeOp, WalkEntry,
};
use crate::inode::{BlobHash, InodeRef};
use crate::metadata::{FileKind, FileMetadata};
use crate::plan::EventPathIndex;
use crate::probe::StateProbe;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Events a failed [`CaptureEventKind::RenameOutcome`] retracts.
///
/// The shim sends an outcome for every rename-family call, and the
/// daemon names in it the Rename (and any CaptureRefused) that the same
/// call's pre-syscall notification journaled, matched by the shim's
/// per-call id. A failure retracts exactly those.
///
/// A second tier's report of the same call (the LSM hook fires before the
/// filesystem refuses) is retracted too, and only when it is provably
/// that: a Rename of the same pair that no outcome names (so it is not
/// any shim call's own), whose inode is the outcome's pre-call source
/// inode (never the sentinel), next to the call's own Rename among the
/// events naming `from` or `to`.
pub(crate) fn failed_renames(index: &EventPathIndex<'_>) -> HashSet<EventId> {
    let mut out = HashSet::new();
    let named: HashSet<EventId> = index
        .chrono
        .iter()
        .filter_map(|ev| match &ev.kind {
            CaptureEventKind::RenameOutcome { rename, .. } => *rename,
            _ => None,
        })
        .collect();
    let position: HashMap<EventId, usize> = index
        .chrono
        .iter()
        .enumerate()
        .map(|(i, ev)| (ev.id, i))
        .collect();
    for (i, ev) in index.chrono.iter().enumerate() {
        let CaptureEventKind::RenameOutcome {
            from,
            to,
            errno,
            source,
            rename,
            refusal,
            ..
        } = &ev.kind
        else {
            continue;
        };
        if *errno == 0 {
            continue;
        }
        out.extend(refusal.iter().copied());
        // Without the call's own Rename there is nothing to anchor a
        // twin to; leave the rest to the ordinary inverses (loud).
        let Some(own_id) = rename else {
            continue;
        };
        out.insert(*own_id);
        let Some(&own) = position.get(own_id) else {
            continue;
        };
        if source.dev == 0 && source.inode == 0 {
            continue;
        }
        let is_pair = |e: &CaptureEvent| {
            matches!(&e.kind, CaptureEventKind::TreeOp(TreeOp::Rename { from: f, to: t, .. })
                if f == from && t == to)
        };
        let mut near: Vec<usize> = index.touching(from);
        near.extend(index.touching(to));
        near.push(i);
        near.sort_unstable();
        near.dedup();
        let Some(at) = near.iter().position(|p| *p == own) else {
            continue;
        };
        let twin = |p: usize| {
            let e = index.chrono[p];
            match &e.kind {
                CaptureEventKind::TreeOp(TreeOp::Rename { inode, .. }) if is_pair(e) => {
                    Some(*inode == *source && !named.contains(&e.id))
                }
                // The walk and the outcome itself sit between the shim's
                // Rename and a late twin.
                CaptureEventKind::RenameOutcome { .. } | CaptureEventKind::RenameWalk { .. } => {
                    None
                }
                CaptureEventKind::FilePreImage {
                    source: FilePreImageSource::ShimRenameSubtree,
                    ..
                } => None,
                _ => Some(false),
            }
        };
        for dir in [-1isize, 1] {
            let mut k = at as isize + dir;
            while k >= 0 && (k as usize) < near.len() {
                let p = near[k as usize];
                match twin(p) {
                    Some(true) => {
                        out.insert(index.chrono[p].id);
                    }
                    Some(false) => break,
                    None => {}
                }
                k += dir;
            }
        }
    }
    out
}

/// Directories to recreate for one replaced rename, `(path, mode)`,
/// parent first.
pub(crate) type DirRebuild = Vec<(PathBuf, u32)>;

/// A rebuilt directory's recorded metadata: `(inode, path, metadata)`.
pub(crate) type RebuiltDirMetadata = (InodeRef, PathBuf, FileMetadata);

/// Directory renames rebuilt from their walk. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct ReplacedSubtrees {
    /// The proven Rename -> directories to recreate at `from`.
    pub by_rename: HashMap<EventId, DirRebuild>,
    /// Events under `to` (and second-tier copies) the rebuild replaces.
    pub dropped_events: HashSet<EventId>,
    /// The walk's file pre-images, which restore the files in place.
    pub walk_restores: HashSet<EventId>,
    /// The walk event (emitted after its Rename's inverse, before its
    /// pre-images) or its earliest pre-image -> directory metadata to
    /// apply after the files, deepest first.
    pub dir_metadata: HashMap<EventId, Vec<RebuiltDirMetadata>>,
}

struct Walked<'a> {
    rel: PathBuf,
    entry: &'a WalkEntry,
    /// For files: the walk pre-image's id and blob.
    pre: Option<(EventId, BlobHash)>,
}

impl ReplacedSubtrees {
    /// `scratch` are events the provenance pass already found to be a
    /// closed scratch generation (pip's `mkdir ~x; rmdir ~x` before the
    /// rename): they do not count as an earlier generation at `to`.
    pub(crate) fn from_events(
        index: &EventPathIndex<'_>,
        disproved: &HashSet<EventId>,
        scratch: &HashSet<EventId>,
        probe: &dyn StateProbe,
    ) -> Self {
        let mut out = Self::default();
        for (i, ev) in index.chrono.iter().enumerate() {
            if let CaptureEventKind::RenameWalk {
                root,
                complete: true,
                files,
                entries,
            } = &ev.kind
                && let Some(found) =
                    Self::check(index, i, root, *files, entries, disproved, scratch, probe)
            {
                out.absorb(found);
            }
        }
        out
    }

    fn absorb(&mut self, f: Found) {
        self.dropped_events.extend(f.dropped);
        self.walk_restores.extend(f.restores.iter().copied());
        self.by_rename.insert(f.rename, f.dirs);
        let key = f.restores.first().copied().unwrap_or(f.walk);
        self.dir_metadata.insert(key, f.metadata);
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        index: &EventPathIndex<'_>,
        w: usize,
        from: &Path,
        files: u32,
        entries: &[WalkEntry],
        disproved: &HashSet<EventId>,
        scratch: &HashSet<EventId>,
        probe: &dyn StateProbe,
    ) -> Option<Found> {
        let chrono = &index.chrono;
        let walk_ev = chrono[w];
        let root = entries.first().filter(|e| e.path == from)?;
        if root.kind != FileKind::Directory || (root.inode.dev == 0 && root.inode.inode == 0) {
            return None;
        }
        // The walk's pre-images: the `files` events just before it, from
        // the same notification.
        let first = w.checked_sub(files as usize)?;
        let mut walked: HashMap<PathBuf, Walked<'_>> = HashMap::new();
        for e in entries {
            let rel = e.path.strip_prefix(from).ok()?.to_path_buf();
            walked.insert(
                rel.clone(),
                Walked {
                    rel,
                    entry: e,
                    pre: None,
                },
            );
        }
        let mut restores = Vec::new();
        for ev in &chrono[first..w] {
            let CaptureEventKind::FilePreImage {
                path,
                inode,
                blob,
                source: FilePreImageSource::ShimRenameSubtree,
                ..
            } = &ev.kind
            else {
                return None;
            };
            if ev.ts != walk_ev.ts {
                return None;
            }
            let rel = path.strip_prefix(from).ok()?;
            let wk = walked.get_mut(rel)?;
            if wk.entry.kind != FileKind::Regular || wk.entry.inode != *inode || wk.pre.is_some() {
                return None;
            }
            wk.pre = Some((ev.id, *blob));
            restores.push(ev.id);
        }
        if walked
            .values()
            .any(|wk| wk.entry.kind == FileKind::Regular && wk.pre.is_none())
        {
            return None;
        }
        // The Rename, from the same notification.
        let r = w + 1;
        let rename = chrono.get(r)?;
        let CaptureEventKind::TreeOp(TreeOp::Rename { from: rf, to, .. }) = &rename.kind else {
            return None;
        };
        if rf != from || disproved.contains(&rename.id) || rename.ts != walk_ev.ts {
            return None;
        }
        // Inode proof: what is at `to` after the call is what was at
        // `from` before it.
        // The outcome must be this call's own, named by the daemon.
        let proven = chrono[r + 1..].iter().find_map(|e| match &e.kind {
            CaptureEventKind::RenameOutcome {
                from: of,
                to: ot,
                errno,
                dest,
                rename: Some(id),
                ..
            } if *id == rename.id && of == from && ot == to => {
                Some(*errno == 0 && *dest == root.inode)
            }
            _ => None,
        });
        if proven != Some(true) {
            return None;
        }
        // The reverse rename is impossible only if `to` is gone.
        if probe.stat(to).is_some() {
            return None;
        }
        // One generation of each: nothing earlier names either side,
        // except a scratch entry at `to` that was already gone again.
        let start = first;
        let earlier = |p: &Path| {
            index
                .touching(p)
                .into_iter()
                .any(|j| j < start && !scratch.contains(&chrono[j].id))
        };
        if earlier(from) || earlier(to) {
            return None;
        }
        let mut dropped = HashSet::new();
        let mut unlinked: HashSet<PathBuf> = HashSet::new();
        let mut needs_pre: HashSet<PathBuf> = HashSet::new();
        let mut proved_pre: HashSet<PathBuf> = HashSet::new();
        for j in index.touching(to).into_iter().filter(|j| *j > r) {
            let ev = chrono[j];
            match &ev.kind {
                // A second tier reporting the same rename.
                CaptureEventKind::TreeOp(TreeOp::Rename { from: f, to: t, .. })
                    if f == from && t == to => {}
                CaptureEventKind::FilePreImage {
                    path,
                    inode,
                    blob,
                    source,
                    ..
                } if source.has_content() => {
                    let wk = walked.get(path.strip_prefix(to).ok()?)?;
                    if wk.entry.inode != *inode || wk.pre.map(|(_, b)| b) != Some(*blob) {
                        return None;
                    }
                    proved_pre.insert(wk.rel.clone());
                }
                CaptureEventKind::TreeOp(TreeOp::Unlink {
                    path, inode, kind, ..
                }) => {
                    let wk = walked.get(path.strip_prefix(to).ok()?)?;
                    let sentinel = inode.dev == 0 && inode.inode == 0;
                    if !sentinel && *inode != wk.entry.inode {
                        return None;
                    }
                    match (wk.entry.kind, kind) {
                        (FileKind::Directory, FileKind::Directory) => {}
                        // The shim's unlink defaults to Regular when its
                        // stat lost the race; a directory says Directory.
                        (FileKind::Regular, FileKind::Regular) => {
                            if sentinel {
                                needs_pre.insert(wk.rel.clone());
                            }
                            unlinked.insert(wk.rel.clone());
                        }
                        _ => return None,
                    }
                }
                CaptureEventKind::TreeOp(TreeOp::Create { path, inode, .. }) => {
                    let wk = walked.get(path.strip_prefix(to).ok()?)?;
                    if *inode != wk.entry.inode {
                        return None;
                    }
                }
                _ => return None,
            }
            dropped.insert(ev.id);
        }
        if !needs_pre.is_subset(&proved_pre) {
            return None;
        }
        let all_files_unlinked = walked
            .values()
            .filter(|wk| wk.entry.kind == FileKind::Regular)
            .all(|wk| unlinked.contains(&wk.rel));
        if !all_files_unlinked {
            return None;
        }
        // A second tier reporting the walked entries leaving `from`.
        let by_inode: HashMap<InodeRef, &Walked<'_>> =
            walked.values().map(|wk| (wk.entry.inode, wk)).collect();
        for j in index.touching(from).into_iter().filter(|j| *j > r) {
            let ev = chrono[j];
            if let CaptureEventKind::TreeOp(TreeOp::Unlink { path, inode, .. }) = &ev.kind
                && let Some(wk) = by_inode.get(inode)
                && from.join(&wk.rel) == *path
            {
                dropped.insert(ev.id);
            }
        }
        let mut dirs: DirRebuild = walked
            .values()
            .filter(|wk| wk.entry.kind == FileKind::Directory)
            .map(|wk| (wk.entry.path.clone(), wk.entry.meta.mode | 0o700))
            .collect();
        dirs.sort();
        let mut metadata: Vec<RebuiltDirMetadata> = walked
            .values()
            .filter(|wk| wk.entry.kind == FileKind::Directory)
            .map(|wk| (wk.entry.inode, wk.entry.path.clone(), wk.entry.meta.clone()))
            .collect();
        metadata.sort_by(|a, b| b.1.cmp(&a.1));
        Some(Found {
            rename: rename.id,
            walk: walk_ev.id,
            dirs,
            dropped,
            // Chronological; the first is emitted last.
            restores,
            metadata,
        })
    }
}

struct Found {
    rename: EventId,
    walk: EventId,
    dirs: DirRebuild,
    dropped: HashSet<EventId>,
    restores: Vec<EventId>,
    metadata: Vec<RebuiltDirMetadata>,
}
