// SPDX-License-Identifier: AGPL-3.0-or-later

//! `plan()` — derive an [`UndoPlan`] from a command's events.
//!
//! Pure function: input is captured events + a `StateProbe` over the current
//! filesystem + a `PlannerStore` (consulted only for blob presence). Output is
//! a topologically-ordered DAG of inverse ops.
//!
//! ## v1 semantics
//!
//! - One inverse op per relevant event field (no within-command coalescing yet).
//! - All ops land in cohort `0` (sequential execution). Cohort partitioning
//!   for parallelism is a v2 optimization.
//! - Events emitted in **reverse-chronological** order so tree-recreate ops
//!   come before content-restore ops naturally (file is created before bytes
//!   land in it).
//! - Conflict detection is path/inode + post-image-hash. When the capture
//!   tier recorded `post_content_hash` and the current file content differs,
//!   we emit `Conflict::Hard` rather than silently overwrite the user's
//!   later edits.
//! - Partial events are dropped with a warning; the rest of the plan still
//!   produces actionable output.

use crate::events::{CaptureEvent, CaptureEventKind, CommandRecord, PackageManager, TreeOp};
use crate::inode::InodeRef;
use crate::inverse::{
    Conflict, ContainerOp, InverseOp, NativeDelegation, PlanNode, PlanWarning, UndoPlan,
};
use crate::probe::StateProbe;
use crate::store::PlannerStore;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn plan(
    command: CommandRecord,
    events: &[CaptureEvent],
    probe: &dyn StateProbe,
    store: &dyn PlannerStore,
) -> UndoPlan {
    // AR07.1: refuse-list short-circuit. If the original command
    // matches a refuse-list entry, the plan is a single Refuse node
    // carrying the catalog reason + remediation. We skip per-event
    // analysis entirely — a partial inverse for a refused class
    // would be worse than honest refusal (the user might apply it
    // and end up in a half-state, with the OOS effects still in
    // place). Refusal lives in `nodes`, not `warnings`, so
    // `shit undo --dry-run` renders it with the same weight as an
    // applicable op.
    if let Some(cmd_str) = command.cmd_string.as_deref()
        && let Some(entry) = crate::refuse::match_command(cmd_str)
    {
        return UndoPlan {
            command,
            nodes: vec![PlanNode {
                op: InverseOp::Refuse {
                    class: entry.class.to_string(),
                    reason: entry.reason.to_string(),
                    remediation: entry.remediation.map(str::to_string),
                },
                cohort: 0,
                conflict: None,
            }],
            warnings: Vec::new(),
        };
    }

    let mut nodes = Vec::new();
    let mut warnings = Vec::new();

    let partial_count = events.iter().filter(|e| e.partial).count();
    if partial_count > 0 {
        warnings.push(PlanWarning::PartialEvents {
            dropped: partial_count,
        });
    }

    if command.ended_at.is_none() {
        warnings.push(PlanWarning::UnclosedCommand);
    }

    let mut live: Vec<&CaptureEvent> = events.iter().filter(|e| !e.partial).collect();
    // Reverse-chronological: latest events first.
    live.sort_by_key(|e| std::cmp::Reverse((e.ts, e.id)));

    // W01.B.fix-rename-coalescing — recognize atomic-rename / replace
    // patterns (git commit, vim :wq, sed -i, etc.) where a single
    // logical "edit P" produces three events:
    //   - TreeOp::Create at P (the new inode appears via rename)
    //   - FilePreImage of P (the OLD inode's bytes, captured before unlink)
    //   - TreeOp::Unlink at P (the old inode disappears)
    //
    // Two semantic flavors of the signature:
    //   a) ATOMIC REPLACE — path EXISTS at undo time (rename completed,
    //      different inode lives there). User's mental model is "edit
    //      P"; inverse is "restore P from FilePreImage blob". Skip the
    //      Tree-op inverses; keep RestoreContent.
    //   b) TRANSIENT LOCK — path DOES NOT EXIST at undo time (e.g.
    //      git's `.git/index.lock` is created, written, renamed-away
    //      within one command; the captured FilePreImage is of an
    //      already-gone file). No user-meaningful change to undo.
    //      Skip all three inverses entirely.
    let class = classify_replace_paths(&live, probe);

    for ev in &live {
        // W01.B.fix-rename-coalescing: skip the entire event if the
        // path is transient (Create+PreImage+Unlink AND gone at undo).
        if let Some(p) = event_path(ev)
            && class.transient_paths.contains(p)
        {
            continue;
        }
        // W09.20: skip the entire event for the LIVE side of a
        // hardlink-aliased inode. bar in `ln foo bar; rm foo`
        // generated spurious FilePreImage + Unlink events (kqueue
        // NOTE_DELETE fires on every fd opened on the inode, not just
        // the unlinked-name fd), but bar is currently correct on
        // disk — emit nothing and leave it alone. The dead-side
        // events (foo) emit one CreateHardlink that aliases foo back
        // to bar.
        if let Some(p) = event_path(ev)
            && class.hardlink_live_paths.contains(p)
        {
            continue;
        }
        emit_for_event(ev, probe, store, &class, &mut nodes, &mut warnings);
    }

    // DR-14: partition nodes into cohorts so the orchestrator's
    // `run_parallel` only runs commuting ops concurrently. Without
    // this pass every node would land in cohort 0 and the parallel
    // path would race conflicting ops on the same path/inode.
    crate::cohort::assign_cohorts(&mut nodes);

    UndoPlan {
        command,
        nodes,
        warnings,
    }
}

/// Output of [`classify_replace_paths`].
#[derive(Debug, Default)]
struct EventClassification {
    atomic_replace_paths: HashSet<PathBuf>,
    transient_paths: HashSet<PathBuf>,
    rename_subsumed_creates: HashSet<PathBuf>,
    /// W09.20 — paths that share an inode with another path AND
    /// still exist on disk at undo time. The pre-mutation events for
    /// these paths are spurious noise from kqueue NOTE_DELETE firing
    /// on every fd opened on the inode (not just the unlinked-name
    /// fd). Skip ALL inverses for live aliases — they're correct
    /// on disk.
    hardlink_live_paths: HashSet<PathBuf>,
    /// W09.20 — paths that share an inode with a `hardlink_live_paths`
    /// entry AND are NOT currently on disk. The unlinked-name half
    /// of a hardlink pair. Maps each dead path → the surviving alias
    /// the planner will hardlink it back to. Suppresses the dead
    /// path's normal RecreatePath/RestoreContent inverses; emits a
    /// single CreateHardlink instead.
    hardlink_dead_to_source: std::collections::HashMap<PathBuf, PathBuf>,
}

fn classify_replace_paths(events: &[&CaptureEvent], probe: &dyn StateProbe) -> EventClassification {
    let mut creates: HashSet<PathBuf> = HashSet::new();
    let mut unlinks: HashSet<PathBuf> = HashSet::new();
    let mut pre_images: HashSet<PathBuf> = HashSet::new();
    let mut rename_destinations: HashSet<PathBuf> = HashSet::new();
    // W09.20 — collect (dev, inode) → set of paths from Unlink events
    // so we can detect hardlink groups: same inode appearing under
    // multiple names.
    let mut paths_by_inode: std::collections::HashMap<crate::inode::InodeRef, HashSet<PathBuf>> =
        std::collections::HashMap::new();
    for ev in events {
        match &ev.kind {
            CaptureEventKind::FilePreImage { path, .. } => {
                pre_images.insert(path.clone());
            }
            CaptureEventKind::TreeOp(TreeOp::Create { path, .. }) => {
                creates.insert(path.clone());
            }
            CaptureEventKind::TreeOp(TreeOp::Unlink { path, inode }) => {
                unlinks.insert(path.clone());
                // W09.20 — only index real inodes. The shim's
                // Unlink path uses (0, 0) as a sentinel (it doesn't
                // know the inode of the path it intercepted), and
                // multiple unrelated shim-Unlinks under sentinel
                // (0, 0) would falsely appear as a "hardlink group"
                // in the classifier. Real inodes come from the
                // helper's kqueue NOTE_DELETE flow, which is the
                // only signal that meaningfully detects hardlink
                // aliasing.
                if inode.dev != 0 || inode.inode != 0 {
                    paths_by_inode
                        .entry(*inode)
                        .or_default()
                        .insert(path.clone());
                }
            }
            // AR01.1 follow-up: the Linux LSM `inode_rename` hook is
            // emitted by the helper as a single TreeOp::Rename plus a
            // CapturedPreImage(is_delete=true) for the clobbered
            // destination -- i.e. PreImage + Unlink on the destination
            // path with NO accompanying Create. The W01.B classifier
            // (Create + PreImage + Unlink) missed this shape and the
            // planner fell through to per-event inverses (RestoreContent +
            // RecreatePath + ReverseRename) which raced ordering at
            // apply time and intermittently deleted the destination
            // outright. Treating the rename's destination identically
            // to a Create for classification purposes closes the gap.
            CaptureEventKind::TreeOp(TreeOp::Rename { to, .. }) => {
                rename_destinations.insert(to.clone());
            }
            _ => {}
        }
    }
    let mut atomic = HashSet::new();
    let mut transient = HashSet::new();
    for p in creates.iter().chain(rename_destinations.iter()) {
        if !unlinks.contains(p) {
            continue;
        }
        // Three shapes (two transient, one atomic) for paths with BOTH
        // Create AND Unlink events in the same command:
        //   - Create + Unlink, NO pre-image → pure scratch (e.g.
        //     .git/index.lock that never had prior content). Inverse
        //     is a no-op.
        //   - Create + Unlink + pre-image, path GONE at undo → file
        //     existed, was renamed away, never restored. Same no-op.
        //   - Create + Unlink + pre-image, path EXISTS at undo →
        //     atomic-replace: restore bytes over the current inode,
        //     suppress Tree-op inverses (which would rmdir/recreate
        //     and conflict with the new inode).
        if !pre_images.contains(p) {
            transient.insert(p.clone());
            continue;
        }
        if probe.stat(p).is_some() {
            atomic.insert(p.clone());
        } else {
            transient.insert(p.clone());
        }
    }
    // Additional transient shape: pure TreeOp::Create whose path is
    // GONE at undo time. The capture layer's rename pairing on BSD
    // isn't always able to emit TreeOp::Unlink for the rename source
    // (kqueue races between the two NOTE_WRITE events on the parent
    // dir — the source disappearance can get coalesced into the
    // destination's appearance). Without this rule, the planner emits
    // an Unlink inverse for a path that's already gone, and the
    // orchestrator reports ConflictMissing at undo time. Real-world
    // example: git renames .git/index.lock → .git/index; the pump
    // captures only Create(index.lock), missing its Unlink. The user's
    // expectation is the lock path stays gone — same as transient.
    for p in &creates {
        if unlinks.contains(p) {
            continue;
        }
        if probe.stat(p).is_none() {
            transient.insert(p.clone());
        }
    }
    // W06.A.5: Create + Rename(to=path) with NO Unlink → the shim
    // and the kqueue dir-diff both observed the same mv. Surface
    // these to suppress the Create's Unlink-inverse; the Rename's
    // ReverseRename is authoritative.
    //
    // W09.9 extension: directory renames carry their contents.
    // When `mv srcdir dstdir` runs, the kqueue dir-diff sees:
    //   1. dstdir appearing in the parent cwd → Create(dstdir)
    //   2. dstdir/foo.txt, dstdir/bar.txt, ... appearing as entries
    //      in the newly-watched dstdir → Create(dstdir/foo.txt) etc.
    // These child Creates' Unlink inverses would race the Rename's
    // ReverseRename — if Unlinks fire first the children get deleted
    // BEFORE the directory is renamed back, leaving an empty
    // restored srcdir (data loss). Suppress any Create whose path
    // is a strict descendant of a rename destination.
    let mut rename_subsumed_creates: HashSet<PathBuf> = HashSet::new();
    for p in &creates {
        if unlinks.contains(p) {
            continue;
        }
        if rename_destinations.contains(p) {
            rename_subsumed_creates.insert(p.clone());
            continue;
        }
        // Strict descendant of any rename destination — the dir
        // rename inverse will carry it along.
        if rename_destinations
            .iter()
            .any(|d| p.starts_with(d) && p != d)
        {
            rename_subsumed_creates.insert(p.clone());
        }
    }
    // W06.A.4: Rename(to=path) + PreImage(path) with NO Unlink → the
    // shim captured a pre-image of the rename destination's prior
    // content. Treat as atomic_replace: the RestoreContent inverse
    // from the PreImage restores the right bytes, and the Rename's
    // ReverseRename must be suppressed (it would move the new bytes
    // back to the tmpfile path instead of restoring the dst). This
    // is the `install(1)` / `mv` over-existing shape on FreeBSD.
    for p in &rename_destinations {
        if unlinks.contains(p) {
            continue;
        }
        if !pre_images.contains(p) {
            continue;
        }
        if probe.stat(p).is_some() {
            atomic.insert(p.clone());
        }
    }
    // W09.5: Unlink(P) + PreImage(P) with NO Create and NO Rename
    // AND P exists at undo time → the "unlink-then-create" shape
    // used by tar / cpio / gzip. The shim captured the pre-image at
    // unlink time (W09.5 interposer extension), then a subsequent
    // open(O_CREAT) recreated the path with new bytes — that open's
    // pre-image capture returned None (file gone) so no Create event
    // is journaled. Classify as atomic_replace: the FilePreImage's
    // RestoreContent restores the bytes; the Unlink's RecreatePath
    // inverse is suppressed (would race with RestoreContent or
    // create an empty file racing the restore).
    //
    // We deliberately do NOT classify the file-gone-at-undo case
    // here. That's the `rm foo` shape: file unlinked, not recreated.
    // The user wants RecreatePath(foo) + RestoreContent(foo) + meta
    // — the existing per-event inverse emission already handles it
    // correctly (RecreatePath drops an empty file with the right
    // mode/uid/gid, then RestoreContent overwrites with the captured
    // bytes). Suppressing those would silently break `rm` undo.
    for p in &unlinks {
        if !pre_images.contains(p) {
            continue;
        }
        if creates.contains(p) || rename_destinations.contains(p) {
            continue;
        }
        if probe.stat(p).is_some() {
            atomic.insert(p.clone());
        }
    }
    // W09.20 — hardlink classification. For each (dev, inode) group
    // with multiple paths (i.e. the original setup had a hardlink
    // alias), check which paths are alive on disk at undo time:
    //   - If ≥1 path is alive, the unlinked path was hardlinked to
    //     it. The dead paths get CreateHardlink inverses pointing
    //     back to the alive path. The alive path(s) get all their
    //     inverses skipped — they're correct on disk already.
    //   - If 0 paths are alive (all aliases were unlinked in the
    //     same command), don't classify as hardlink — fall through
    //     to the per-path RecreatePath + RestoreContent logic.
    //     Restoring inode aliasing in that case is a stage-2
    //     concern (would need post-RecreatePath link(2) chaining).
    let mut hardlink_live_paths: HashSet<PathBuf> = HashSet::new();
    let mut hardlink_dead_to_source: std::collections::HashMap<PathBuf, PathBuf> =
        std::collections::HashMap::new();
    for (captured_inode, paths) in &paths_by_inode {
        if paths.len() < 2 {
            continue;
        }
        // CONSERVATIVE GATE (W09.20.1) — a path qualifies as a live
        // alias ONLY if its CURRENT lstat inode matches the captured
        // inode_ref. Without this, ZFS-on-FreeBSD-14.2 (and likely
        // any FS that aggressively reuses freed st_ino under churn)
        // makes two unrelated event-time inode collisions look like
        // a hardlink group. `patch script.sh` surfaces this on CI:
        // patch's temp+rename sequence produces an Unlink event for
        // the OLD script.sh inode; if that inode is later reused by
        // an unrelated tempfile that gets its own Unlink, both
        // paths land under the same key and the alive-test (just
        // probe.exists) trips on the new script.sh. The current-
        // inode equality check pins the classifier to genuine
        // aliasing — at undo time, a real hardlink survivor still
        // carries the captured inode; a coincidental reuse won't.
        let alive_with_matching_inode: Vec<&PathBuf> = paths
            .iter()
            .filter(|p| match probe.stat(p) {
                Some(s) => s.inode == *captured_inode,
                None => false,
            })
            .collect();
        if alive_with_matching_inode.is_empty() {
            continue;
        }
        let mut alive_sorted: Vec<&PathBuf> = alive_with_matching_inode;
        alive_sorted.sort();
        let source = alive_sorted[0].clone();
        for p in &alive_sorted {
            hardlink_live_paths.insert((*p).clone());
        }
        for p in paths {
            // Dead = not alive WITH the matching inode. A path that
            // exists at undo time but with a different inode (the
            // patch case) is treated as dead-for-this-group, which
            // means the per-path RecreatePath+RestoreContent logic
            // owns its undo — exactly what we want.
            let alive_match = matches!(probe.stat(p), Some(s) if s.inode == *captured_inode);
            if alive_match {
                continue;
            }
            hardlink_dead_to_source.insert(p.clone(), source.clone());
        }
    }
    EventClassification {
        atomic_replace_paths: atomic,
        transient_paths: transient,
        rename_subsumed_creates,
        hardlink_live_paths,
        hardlink_dead_to_source,
    }
}

/// Path the event targets (for the event-level skip in the transient
/// case). Returns `None` for events with no single path (env diffs,
/// tier ops, Rename which has two paths, Link which targets an inode
/// not a path). The caller's only use is "is this path in the
/// transient set?" — non-path events fall through naturally.
///
/// **MUST stay aligned with `emit_for_event`'s match arms.** If an
/// event kind emits an inverse that targets a path, the skip pass
/// must be able to see that path here — otherwise inverses leak
/// through for transient paths and the orchestrator hits
/// ConflictMissing at undo. W02.B surfaced this for MetadataChange:
/// vim's swap file gets created + a stat captured + unlinked all
/// in one command, the classifier correctly flagged it transient,
/// but the skip pass missed the MetadataChange event so a
/// RestoreMetadata inverse leaked through and tripped ConflictMissing
/// because the swap path is gone at undo time.
fn event_path(ev: &CaptureEvent) -> Option<&PathBuf> {
    match &ev.kind {
        CaptureEventKind::FilePreImage { path, .. } => Some(path),
        CaptureEventKind::MetadataChange { path, .. } => Some(path),
        CaptureEventKind::TreeOp(TreeOp::Create { path, .. })
        | CaptureEventKind::TreeOp(TreeOp::Unlink { path, .. })
        | CaptureEventKind::TreeOp(TreeOp::Symlink { path, .. }) => Some(path),
        _ => None,
    }
}

fn emit_for_event(
    ev: &CaptureEvent,
    probe: &dyn StateProbe,
    store: &dyn PlannerStore,
    class: &EventClassification,
    nodes: &mut Vec<PlanNode>,
    warnings: &mut Vec<PlanWarning>,
) {
    let atomic_replace_paths = &class.atomic_replace_paths;
    match &ev.kind {
        CaptureEventKind::FilePreImage {
            inode,
            path,
            blob,
            meta,
            post_content_hash,
        } => {
            // W09.20 — for the dead side of a hardlink pair, the
            // surviving alias has the right content already; the
            // CreateHardlink emitted from the Unlink branch will
            // re-alias. Skip RestoreContent + RestoreMetadata here
            // so we don't tmpfile+rename a fresh inode at `path`
            // (which would defeat the hardlink restoration).
            if class.hardlink_dead_to_source.contains_key(path) {
                return;
            }
            // W01.B.fix-rename-coalescing: skip the inode-match check
            // for atomic-replace paths. The captured inode IS supposed
            // to differ from what's on disk now — that's the signature.
            // We still check existence (Missing branch) below by
            // re-probing.
            let mut conflict = if atomic_replace_paths.contains(path) {
                if probe.stat(path).is_none() {
                    Some(Conflict::Missing {
                        detail: format!("{} no longer exists", path.display()),
                    })
                } else {
                    None
                }
            } else {
                file_path_conflict(path, *inode, probe)
            };
            if conflict.is_none() && store.blob_size_hint(*blob).is_none() {
                conflict = Some(Conflict::Missing {
                    detail: format!("blob {blob} no longer in store (GC'd or evicted)"),
                });
            }
            // Post-image check: if the capture tier recorded the post-mutation
            // content hash and the current content doesn't match, the user has
            // edited the file since our command — applying the restore would
            // clobber those edits. Surface as Hard so the user must opt in.
            if conflict.is_none()
                && let Some(expected_post) = post_content_hash
                && let Some(current) = probe.content_hash(path)
                && &current != expected_post
            {
                conflict = Some(Conflict::Hard {
                    detail: format!(
                        "{} has been modified since the original command; \
                         restore would overwrite the later edits",
                        path.display()
                    ),
                });
            }
            nodes.push(PlanNode {
                op: InverseOp::RestoreContent {
                    inode: *inode,
                    path: path.clone(),
                    blob: *blob,
                },
                cohort: 0,
                conflict: conflict.clone(),
            });
            nodes.push(PlanNode {
                op: InverseOp::RestoreMetadata {
                    inode: *inode,
                    path: path.clone(),
                    target: meta.clone(),
                },
                cohort: 0,
                conflict,
            });
        }
        CaptureEventKind::MetadataChange {
            inode,
            path,
            before,
            ..
        } => {
            let conflict = file_path_conflict(path, *inode, probe);
            nodes.push(PlanNode {
                op: InverseOp::RestoreMetadata {
                    inode: *inode,
                    path: path.clone(),
                    target: before.clone(),
                },
                cohort: 0,
                conflict,
            });
        }
        CaptureEventKind::TreeOp(op) => emit_for_tree_op(op, probe, class, nodes),
        CaptureEventKind::ShellStateDiff {
            pwd_before,
            pwd_after,
        } => {
            // AR06.1 — emit a ShellStateRestore. Snippet is the
            // canonical bash `cd '<before>'`; quoting follows the
            // existing snippet renderer used by render_bash. zsh
            // gets the same body (cd quoting is shell-compatible);
            // fish lands when the C06 state.rs diff machinery is
            // wired through the hook.
            if pwd_before == pwd_after {
                return; // No-op; defensive.
            }
            let pwd_before_str = pwd_before.to_string_lossy();
            // POSIX single-quote escape: ' -> '\''
            let escaped = pwd_before_str.replace('\'', "'\\''");
            let snippet = format!("cd '{escaped}'\n");
            nodes.push(PlanNode {
                op: InverseOp::ShellStateRestore {
                    pwd_before: Some(pwd_before.clone()),
                    opts_diff: Vec::new(),
                    aliases_diff: Vec::new(),
                    funcs_diff: Vec::new(),
                    snippet_bash: Some(snippet.clone()),
                    snippet_zsh: Some(snippet),
                    // fish: no precmd-queue equivalent (per
                    // existing executor doc); leave None so
                    // the executor surfaces the deferral.
                    snippet_fish: None,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::EnvDiff {
            added,
            removed,
            modified,
        } => {
            // Inverse: unset what was added, restore what was removed,
            // restore old value for modified.
            for name in added.keys() {
                nodes.push(PlanNode {
                    op: InverseOp::UnsetEnv { name: name.clone() },
                    cohort: 0,
                    conflict: None,
                });
            }
            for (name, old_value) in removed {
                nodes.push(PlanNode {
                    op: InverseOp::SetEnv {
                        name: name.clone(),
                        value: old_value.clone(),
                    },
                    cohort: 0,
                    conflict: None,
                });
            }
            for (name, (before, _after)) in modified {
                nodes.push(PlanNode {
                    op: InverseOp::SetEnv {
                        name: name.clone(),
                        value: before.clone(),
                    },
                    cohort: 0,
                    conflict: None,
                });
            }
        }
        CaptureEventKind::PackageOp {
            manager,
            op,
            packages_before,
            packages_after,
            repo_state_hint,
        } => {
            // C02.7: when the capture tier supplied a manager-native
            // transaction id (apt 3.2 `apt_tx_id`, dnf `dnf_history_id`),
            // emit a delegation hint so the executor runs the native
            // rollback verb instead of synthesizing per-package
            // install/remove. Falls through to `None` for managers and
            // versions that don't support native rollback.
            let delegation = native_delegation_for(*manager, repo_state_hint.as_deref());
            nodes.push(PlanNode {
                op: InverseOp::PackageRollback {
                    manager: *manager,
                    original_op: *op,
                    packages_before: packages_before.clone(),
                    packages_after: packages_after.clone(),
                    repo_state_hint: repo_state_hint.clone(),
                    delegation,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::NetworkOp {
            tool,
            before_state,
            after_state,
            inverse_invocations,
        } => {
            // DR-46: for DiffApply tools the capture path leaves
            // inverse_invocations empty; synthesise them from the
            // pre/after JSON dumps here. FullReload tools (iptables,
            // nft, pfctl) reload before_state directly so we don't
            // synthesise. DR-47: ufw is DiffApplyWithReset — its
            // synthesiser decides between per-rule delete/add and a
            // single `ufw --force reset` + reapply based on a
            // threshold.
            let mut invs = inverse_invocations.clone();
            if invs.is_empty() {
                match crate::network::restore_method(*tool) {
                    crate::network::RestoreMethod::DiffApply => {
                        invs = crate::network_diff::synthesise_diff_apply_inverse(
                            *tool,
                            before_state,
                            after_state,
                        );
                    }
                    crate::network::RestoreMethod::DiffApplyWithReset => {
                        if matches!(*tool, crate::events::NetworkTool::Ufw) {
                            invs = crate::network_diff::synthesise_ufw_inverse(
                                before_state,
                                after_state,
                            );
                        }
                    }
                    _ => {}
                }
                if invs.is_empty() {
                    warnings.push(PlanWarning::Informational {
                        tier: crate::inverse::InverseTier::Network,
                        message: format!(
                            "no DiffApply inverse synthesised for {tool:?}; \
                             review captured before/after states for manual rollback"
                        ),
                    });
                }
            }
            nodes.push(PlanNode {
                op: InverseOp::NetworkRollback {
                    tool: *tool,
                    before_state: before_state.clone(),
                    inverse_invocations: invs,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::SystemdOp {
            scope,
            unit,
            before,
            after,
        } => {
            nodes.push(PlanNode {
                op: InverseOp::SystemdRollback {
                    scope: *scope,
                    unit: unit.clone(),
                    before: before.clone(),
                    after: after.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::ProcessOp {
            argv,
            cwd,
            env_summary,
            ..
        } => {
            nodes.push(PlanNode {
                op: InverseOp::ProcessNote {
                    argv: argv.clone(),
                    cwd: cwd.clone(),
                    env_summary: env_summary.clone(),
                    message: "process lifecycle is informational — undo cannot resurrect"
                        .to_string(),
                },
                cohort: 0,
                conflict: None,
            });
            warnings.push(PlanWarning::Informational {
                tier: crate::inverse::InverseTier::Processes,
                message: "process events cannot be mechanically undone".to_string(),
            });
        }
        CaptureEventKind::DbOp {
            engine,
            target,
            statements,
            transaction_state,
        } => {
            // DR-58: every DbOp becomes an InverseOp::DbNote. For
            // sqlite3 the file tier captures the database file
            // separately, so the rollback hint just records the path;
            // the actual restore happens via the file tier's
            // RestoreContent op. For psql/mysql the hint is
            // informational only — the planner never executes SQL.
            let inverse_engine = match engine {
                crate::events::DbEngine::Postgres => crate::inverse::DbEngine::Postgres,
                crate::events::DbEngine::Mysql => crate::inverse::DbEngine::Mysql,
                crate::events::DbEngine::Sqlite3 => crate::inverse::DbEngine::Sqlite3,
            };
            let rollback_hint = match engine {
                crate::events::DbEngine::Postgres => crate::inverse::RollbackHint::Postgres {
                    pitr_recommended: matches!(
                        transaction_state,
                        crate::events::DbTxState::Committed
                    ),
                    wal_position: None,
                    statements_for_review: statements.clone(),
                },
                crate::events::DbEngine::Mysql => crate::inverse::RollbackHint::Mysql {
                    binlog_position: None,
                    statements_for_review: statements.clone(),
                },
                crate::events::DbEngine::Sqlite3 => crate::inverse::RollbackHint::Sqlite {
                    path: std::path::PathBuf::from(target),
                    file_blob: None,
                },
            };
            // If the engine explicitly observed a rollback, skip
            // emitting the hint — there's nothing to undo. We still
            // surface the tier in warnings so the renderer can say
            // "DB statements were observed but engine rolled back."
            if *transaction_state == crate::events::DbTxState::RolledBack {
                warnings.push(PlanWarning::Informational {
                    tier: crate::inverse::InverseTier::Database,
                    message: format!(
                        "{} statements observed against `{target}` but engine rolled back",
                        engine_label(*engine)
                    ),
                });
                return;
            }
            nodes.push(PlanNode {
                op: InverseOp::DbNote {
                    engine: inverse_engine,
                    target: target.clone(),
                    statements: statements.clone(),
                    rollback_hint,
                },
                cohort: 0,
                conflict: None,
            });
            warnings.push(PlanWarning::Informational {
                tier: crate::inverse::InverseTier::Database,
                message: format!(
                    "{} statements against `{target}` need manual rollback review",
                    engine_label(*engine)
                ),
            });
        }
        CaptureEventKind::ContainerOp {
            runtime,
            op,
            captured_config,
            stash_image,
            stash_tarball,
        } => {
            // DR-CR-26: 1:1 mapping from the capture-side ContainerOp
            // event to the executor-side ContainerRestore InverseOp.
            // The helper subcommand already snapshotted state +
            // registered the stash; the planner's job here is purely
            // to forward the descriptors.
            //
            // Rm specifically: requires_confirmation=true since
            // DR-CR-22's full inverse synthesis from inspect JSON is
            // still deferred (stage-1 informational per C04.5).
            nodes.push(PlanNode {
                op: InverseOp::ContainerRestore {
                    runtime: *runtime,
                    op: op.clone(),
                    captured_config: captured_config.clone(),
                    stash_image: stash_image.clone(),
                    stash_tarball: *stash_tarball,
                    requires_confirmation: matches!(op, ContainerOp::Rm { .. }),
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::KubectlOp {
            context,
            namespace,
            op,
            captured_yaml,
        } => {
            // AR04.3: 1:1 mapping from KubectlOp event → KubectlReverse
            // inverse op. The helper captured `kubectl get -o yaml`
            // before the user's destructive verb; the executor pipes
            // it back via `kubectl apply -f -`. Context guard at
            // execute time refuses if kube-context drifted.
            nodes.push(PlanNode {
                op: InverseOp::KubectlReverse {
                    context: context.clone(),
                    namespace: namespace.clone(),
                    op: op.clone(),
                    captured_yaml: captured_yaml.clone(),
                    requires_confirmation: true,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::TerraformOp {
            workdir,
            op,
            prior_state,
        } => {
            // AR04 PR-A: 1:1 mapping from the capture-side TerraformOp
            // event to the executor-side TerraformReverse InverseOp.
            // The helper-side cloud-event wrapper already captured
            // `terraform state pull` before the user's apply/destroy
            // ran; the planner just forwards.
            //
            // requires_confirmation=true for Apply/Destroy since the
            // reverse is destructive (state push + apply -refresh-only
            // can clobber intervening user changes); StateRm/Import
            // ride the executor's informational-skip path.
            nodes.push(PlanNode {
                op: InverseOp::TerraformReverse {
                    workdir: workdir.clone(),
                    op: *op,
                    prior_state: prior_state.clone(),
                    plan_json: None,
                    requires_confirmation: true,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::GhOp { op, captured_json } => {
            // AR04.4: 1:1 mapping from GhOp event → GhReverse inverse
            // op. Helper captured the resource metadata before the
            // destructive verb; the executor dispatches per-op
            // (release delete → re-create with captured tag+body,
            // issue close → reopen, etc).
            nodes.push(PlanNode {
                op: InverseOp::GhReverse {
                    op: op.clone(),
                    captured_json: captured_json.clone(),
                    requires_confirmation: true,
                },
                cohort: 0,
                conflict: None,
            });
        }
    }
}

fn engine_label(e: crate::events::DbEngine) -> &'static str {
    match e {
        crate::events::DbEngine::Postgres => "psql",
        crate::events::DbEngine::Mysql => "mysql",
        crate::events::DbEngine::Sqlite3 => "sqlite3",
    }
}

/// C02.7: synthesize a `NativeDelegation` from the captured transaction
/// id when the manager exposes a native rollback verb. Returns `None`
/// to fall through to the per-package synthesis path in the package
/// executor (the historical behavior).
///
/// Native verbs covered:
/// - apt ≥3.2: `apt history-rollback <id>`. The inspector emits the id
///   under `extras["apt_tx_id"]` (gated on `apt --version` ≥ 3.2); the
///   daemon forwards it into `repo_state_hint`.
/// - dnf: `dnf history undo -y <id>`. Inspector key `dnf_history_id`
///   (DR-26, S14.6).
///
/// Brew / pacman / pkg do not have a native transaction-id-keyed
/// rollback, so they always synthesize.
///
/// The guard re-queries the manager's history to confirm the captured
/// transaction is still the most recent. If a subsequent install
/// happened in the interim, the rollback would also undo it
/// (transaction history is a stack), so we refuse rather than corrupt.
fn native_delegation_for(
    manager: PackageManager,
    repo_state_hint: Option<&str>,
) -> Option<NativeDelegation> {
    let id = repo_state_hint?;
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    match manager {
        PackageManager::Apt => Some(NativeDelegation {
            argv: vec![
                "apt".to_string(),
                "history-rollback".to_string(),
                id.to_string(),
            ],
            privileged: true,
            guard_command: Some(vec![
                "apt".to_string(),
                "history".to_string(),
                "list".to_string(),
            ]),
            // `apt history list` prints lines like `<id>: <date> ...`;
            // we look for the captured id as the most-recent entry.
            guard_match: Some(format!("{id}:")),
        }),
        PackageManager::Dnf => Some(NativeDelegation {
            argv: vec![
                "dnf".to_string(),
                "history".to_string(),
                "undo".to_string(),
                "-y".to_string(),
                id.to_string(),
            ],
            privileged: true,
            guard_command: Some(vec![
                "dnf".to_string(),
                "history".to_string(),
                "list".to_string(),
                "--reverse".to_string(),
            ]),
            // `dnf history list --reverse` prints the most-recent first;
            // the first column is the id. Confirm the captured id is
            // still the top entry by looking for `^ *<id> ` shape.
            guard_match: Some(format!("{id} ")),
        }),
        PackageManager::Dpkg
        | PackageManager::Pacman
        | PackageManager::Brew
        | PackageManager::Pkg => None,
    }
}

fn emit_for_tree_op(
    op: &TreeOp,
    probe: &dyn StateProbe,
    class: &EventClassification,
    nodes: &mut Vec<PlanNode>,
) {
    let atomic_replace_paths = &class.atomic_replace_paths;
    let rename_subsumed_creates = &class.rename_subsumed_creates;
    match op {
        TreeOp::Create { path, .. } => {
            // W01.B.fix-rename-coalescing: if this path was atomically
            // replaced (Create + PreImage + Unlink all observed for one
            // logical edit), the FilePreImage's RestoreContent handles
            // the full undo. Emitting an Unlink here would race with it.
            if atomic_replace_paths.contains(path) {
                return;
            }
            // W06.A.5: a sibling TreeOp::Rename already covers this
            // destination path. The Rename's ReverseRename moves the
            // file back to its origin; an Unlink inverse here would
            // either race and delete the moved-back file or beat the
            // rename to it and leave the original location empty.
            if rename_subsumed_creates.contains(path) {
                return;
            }
            // The user's command created this path; inverse is unlink.
            // Phantom conflict if the path was *deleted* since capture
            // (an unlink of a non-existent path will succeed-or-noop).
            let conflict = match probe.stat(path) {
                None => Some(Conflict::Missing {
                    detail: format!("{} already gone; unlink will no-op", path.display()),
                }),
                Some(_) => None,
            };
            nodes.push(PlanNode {
                op: InverseOp::Unlink { path: path.clone() },
                cohort: 0,
                conflict,
            });
        }
        TreeOp::Unlink { path, .. } => {
            // W01.B.fix-rename-coalescing: ditto Create's note above —
            // atomic-replace paths get their inverse from FilePreImage.
            if atomic_replace_paths.contains(path) {
                return;
            }
            // W09.20 — hardlink-aware restoration. If this unlinked
            // path is part of a hardlink group whose other alias is
            // alive on disk at undo time, emit a single
            // `CreateHardlink { source: alive_alias, target: path }`
            // — preserves the inode aliasing instead of giving the
            // restored path a fresh inode via RecreatePath/RestoreContent.
            // The companion FilePreImage's RestoreContent was already
            // suppressed at the emit_for_event entry above.
            if let Some(source) = class.hardlink_dead_to_source.get(path) {
                // Phantom only if the path is currently present (it
                // should be gone — it's the dead side of the pair).
                let conflict = probe.stat(path).map(|_| Conflict::Phantom {
                    detail: format!(
                        "{} exists now but didn't expect it to; hardlink restore aborted",
                        path.display()
                    ),
                });
                nodes.push(PlanNode {
                    op: InverseOp::CreateHardlink {
                        source: source.clone(),
                        target: path.clone(),
                    },
                    cohort: 0,
                    conflict,
                });
                return;
            }
            // The user's command deleted this path; we want to recreate it.
            // We don't know mode/kind from the unlink alone — those come from
            // a paired FilePreImage / FileMetadata. Recreate with conservative
            // defaults; the FilePreImage's RestoreMetadata will overwrite.
            let conflict = probe.stat(path).map(|_| Conflict::Phantom {
                detail: format!("{} exists now but didn't expect it to", path.display()),
            });
            nodes.push(PlanNode {
                op: InverseOp::RecreatePath {
                    path: path.clone(),
                    kind: crate::metadata::FileKind::Regular,
                    mode: 0o100644,
                },
                cohort: 0,
                conflict,
            });
        }
        TreeOp::Rename { from, to, .. } => {
            // AR01.1 follow-up: if the rename's destination is in
            // atomic_replace_paths (Rename + PreImage + Unlink + path
            // present at undo), the FilePreImage's RestoreContent
            // overwrites the destination with the OLD content -- a
            // ReverseRename here would race with that and either
            // un-clobber to the source side (leaving an orphan at
            // `from`) OR delete the destination outright if the
            // RestoreContent applies first. The atomic-replace path
            // doesn't need the rename inverse: the source side is
            // a transient lock file whose Create + Unlink already
            // classify as transient (no inverse) and whose path is
            // gone at undo time anyway. Same suppression principle as
            // TreeOp::Create above.
            if atomic_replace_paths.contains(to) {
                return;
            }
            // Inverse of `from -> to` is `to -> from`.
            nodes.push(PlanNode {
                op: InverseOp::Rename {
                    from: to.clone(),
                    to: from.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        TreeOp::Link { target, .. } => {
            nodes.push(PlanNode {
                op: InverseOp::Unlink {
                    path: target.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        TreeOp::Symlink { path, .. } => {
            nodes.push(PlanNode {
                op: InverseOp::Unlink { path: path.clone() },
                cohort: 0,
                conflict: None,
            });
        }
    }
}

fn file_path_conflict(
    path: &Path,
    expected_inode: InodeRef,
    probe: &dyn StateProbe,
) -> Option<Conflict> {
    match probe.stat(path) {
        None => Some(Conflict::Missing {
            detail: format!("{} no longer exists", path.display()),
        }),
        Some(s) if s.inode != expected_inode => Some(Conflict::Phantom {
            detail: format!(
                "{} now points at inode {} (was {})",
                path.display(),
                s.inode,
                expected_inode
            ),
        }),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CaptureEvent, CaptureEventKind, CommandId, EventId};
    use crate::inode::{BlobHash, InodeRef};
    use crate::metadata::FileMetadata;
    use crate::probe::ProbeStat;
    use crate::probe::mock::InMemoryProbe;
    use crate::store::mock::InMemoryStore;
    use crate::time::TimePoint;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn meta(size: u64) -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
        }
    }

    fn dummy_command() -> CommandRecord {
        CommandRecord {
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            cmd_string: Some("touch /tmp/x".to_string()),
            cwd: PathBuf::from("/tmp"),
            pid: 0,
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(1, 0),
            ended_at: Some(TimePoint::new(2, 0)),
            exit_code: Some(0),
            event_ids: vec![EventId(1)],
        }
    }

    #[test]
    fn empty_events_yields_empty_plan() {
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let plan = plan(dummy_command(), &[], &probe, &store);
        assert!(plan.is_empty());
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn refuse_list_short_circuits_per_event_analysis() {
        // AR07.1: a command matching the refuse-list catalog produces
        // a single Refuse node, regardless of what events were
        // captured. The events would normally drive per-event
        // inverses; the refuse path skips them.
        let mut cmd = dummy_command();
        cmd.cmd_string = Some("git push origin main".to_string());
        // Construct a FilePreImage event that — if not short-
        // circuited — would normally emit a RestoreContent op.
        let event = CaptureEvent {
            id: EventId(1),
            command: cmd.command,
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(64, 1234),
                path: PathBuf::from("/tmp/refuse-probe.txt"),
                blob: BlobHash::from_bytes([0u8; 32]),
                meta: meta(10),
                post_content_hash: None,
            },
        };
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let p = plan(cmd, &[event], &probe, &store);
        assert_eq!(p.nodes.len(), 1, "expected exactly one Refuse node");
        match &p.nodes[0].op {
            InverseOp::Refuse { class, reason, .. } => {
                assert_eq!(class, "remote-push");
                assert!(!reason.is_empty());
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
        assert!(
            p.warnings.is_empty(),
            "refuse short-circuit should not emit warnings"
        );
    }

    #[test]
    fn non_refused_command_still_processes_events_normally() {
        // Sanity: a normal command (touch /tmp/x — not on the refuse
        // list) goes through the per-event pipeline as before. This
        // anchors the test that the short-circuit is gated on a
        // catalog match, not always-on.
        let cmd = dummy_command(); // cmd_string is "touch /tmp/x"
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let p = plan(cmd, &[], &probe, &store);
        assert!(
            !p.nodes
                .iter()
                .any(|n| matches!(n.op, InverseOp::Refuse { .. })),
            "non-refused command should never emit Refuse nodes"
        );
    }

    #[test]
    fn unclosed_command_warns() {
        let mut cmd = dummy_command();
        cmd.ended_at = None;
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let plan = plan(cmd, &[], &probe, &store);
        assert!(
            plan.warnings
                .iter()
                .any(|w| matches!(w, PlanWarning::UnclosedCommand))
        );
    }

    #[test]
    fn partial_events_are_dropped_with_warning() {
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: true,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/x"),
                blob: BlobHash::from_bytes([1; 32]),
                meta: meta(0),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(p.is_empty());
        assert!(
            p.warnings
                .iter()
                .any(|w| matches!(w, PlanWarning::PartialEvents { dropped: 1 }))
        );
    }

    #[test]
    fn file_pre_image_emits_content_and_metadata() {
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAB; 32]);
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(100),
            },
            None,
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert_eq!(p.nodes.len(), 2);
        assert!(matches!(p.nodes[0].op, InverseOp::RestoreContent { .. }));
        assert!(matches!(p.nodes[1].op, InverseOp::RestoreMetadata { .. }));
        assert!(p.nodes[0].conflict.is_none(), "{:?}", p.nodes[0].conflict);
        assert!(!p.has_blocking_conflicts());
        assert_eq!(p.content_restore_count(), 1);
    }

    #[test]
    fn missing_blob_yields_missing_conflict() {
        let mut probe = InMemoryProbe::new();
        let store = InMemoryStore::new(); // no blobs inserted
        let inode = InodeRef::new(1, 5);
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(100),
            },
            None,
        );
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob: BlobHash::from_bytes([0xFF; 32]),
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(
            p.nodes[0].conflict,
            Some(Conflict::Missing { .. })
        ));
    }

    #[test]
    fn missing_path_yields_missing_conflict() {
        let probe = InMemoryProbe::new(); // path not inserted
        let mut store = InMemoryStore::new();
        let blob = BlobHash::from_bytes([0xCD; 32]);
        store.put_blob(blob, 10);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 5),
                path: PathBuf::from("/tmp/gone"),
                blob,
                meta: meta(10),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(
            p.nodes[0].conflict,
            Some(Conflict::Missing { .. })
        ));
    }

    #[test]
    fn inode_changed_yields_phantom_conflict() {
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let captured_inode = InodeRef::new(1, 5);
        let current_inode = InodeRef::new(1, 999); // different
        let path = PathBuf::from("/tmp/x");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode: current_inode,
                meta: meta(100),
            },
            None,
        );
        let blob = BlobHash::from_bytes([0xAA; 32]);
        store.put_blob(blob, 10);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: captured_inode,
                path,
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(
            p.nodes[0].conflict,
            Some(Conflict::Phantom { .. })
        ));
        assert!(p.has_blocking_conflicts());
    }

    #[test]
    fn reverse_chronological_order_puts_unlink_before_preimage() {
        // Simulate `rm foo`: T1 = FilePreImage, T2 = TreeOp::Unlink.
        // Reverse order should put RecreatePath (from Unlink) before
        // RestoreContent (from FilePreImage).
        let probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 7);
        let blob = BlobHash::from_bytes([1; 32]);
        store.put_blob(blob, 10);
        let path = PathBuf::from("/tmp/foo");
        let pre = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(2),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(2, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[pre, unlink], &probe, &store);
        assert!(matches!(p.nodes[0].op, InverseOp::RecreatePath { .. }));
        assert!(matches!(p.nodes[1].op, InverseOp::RestoreContent { .. }));
        assert!(matches!(p.nodes[2].op, InverseOp::RestoreMetadata { .. }));
    }

    #[test]
    fn atomic_rename_coalesces_to_single_restore() {
        // W01.B.fix-rename-coalescing — the signature is:
        //   TreeOp::Create at P (new inode appears via rename)
        //   FilePreImage of P (OLD inode bytes, captured pre-unlink)
        //   TreeOp::Unlink at P (old inode disappears)
        // The user wrote "modify P"; the inverse is just RestoreContent(P).
        // We must NOT emit Unlink (from Create) or RecreatePath (from
        // Unlink) for that path — they'd race with RestoreContent and
        // trip the orchestrator's precondition_conflict.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let old_inode = InodeRef::new(1, 100);
        let new_inode = InodeRef::new(1, 200);
        let path = PathBuf::from("/tmp/atomic-replace");
        // Current state on disk: the NEW inode lives at the path
        // (mirrors what's on disk after the user's atomic-rename).
        probe.insert(
            path.clone(),
            ProbeStat {
                inode: new_inode,
                meta: meta(60),
            },
            None,
        );
        let blob = BlobHash::from_bytes([0xCC; 32]);
        store.put_blob(blob, 42);

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let create = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode: new_inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let pre = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: old_inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(3),
            command: cmd,
            ts: TimePoint::new(12, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: old_inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[create, pre, unlink], &probe, &store);

        // Expect ONLY RestoreContent + RestoreMetadata (from FilePreImage).
        // NO Unlink (from Create) and NO RecreatePath (from Unlink).
        let has_restore_content = p
            .nodes
            .iter()
            .any(|n| matches!(n.op, InverseOp::RestoreContent { .. }));
        let has_restore_metadata = p
            .nodes
            .iter()
            .any(|n| matches!(n.op, InverseOp::RestoreMetadata { .. }));
        let has_unlink = p.nodes.iter().any(|n| matches!(&n.op, InverseOp::Unlink { path: p } if p == &PathBuf::from("/tmp/atomic-replace")));
        let has_recreate = p.nodes.iter().any(|n| matches!(&n.op, InverseOp::RecreatePath { path: p, .. } if p == &PathBuf::from("/tmp/atomic-replace")));

        assert!(has_restore_content, "RestoreContent inverse missing");
        assert!(has_restore_metadata, "RestoreMetadata inverse missing");
        assert!(
            !has_unlink,
            "atomic-replace path should NOT get a Unlink inverse"
        );
        assert!(
            !has_recreate,
            "atomic-replace path should NOT get a RecreatePath inverse"
        );
        assert!(
            !p.has_blocking_conflicts(),
            "plan should not have blocking conflicts"
        );
    }

    #[test]
    fn lsm_rename_target_clobber_coalesces_to_single_restore() {
        // AR01.1 follow-up — the Linux LSM `inode_rename` hook
        // produces a different shape than BSD kqueue:
        //   TreeOp::Rename(.lock -> P)           (existing rename emit)
        //   FilePreImage of P (OLD inode bytes)  (fix-rename-target-preimage)
        //   TreeOp::Unlink at P (OLD inode)      (is_delete=true paired)
        // i.e. PreImage + Unlink on the destination path with NO
        // Create. The W01.B classifier missed this and the planner
        // emitted RestoreContent + RecreatePath + ReverseRename, all
        // three of which raced ordering and intermittently deleted P
        // outright (PR #29 forensics). Treating the rename's
        // destination identically to a Create for classification
        // purposes closes the gap: classify_replace_paths buckets
        // P as atomic_replace, and the Rename + Unlink inverses get
        // suppressed.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let old_inode = InodeRef::new(1, 100);
        let new_inode = InodeRef::new(1, 200);
        let dest = PathBuf::from("/tmp/.git/HEAD");
        let src = PathBuf::from("/tmp/.git/HEAD.lock");
        // Current on-disk state: NEW inode lives at the destination
        // (post-rename) and the source path is gone.
        probe.insert(
            dest.clone(),
            ProbeStat {
                inode: new_inode,
                meta: meta(60),
            },
            None,
        );
        let blob = BlobHash::from_bytes([0xDD; 32]);
        store.put_blob(blob, 42);

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let pre = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: old_inode,
                path: dest.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: old_inode,
                path: dest.clone(),
            }),
        };
        let rename = CaptureEvent {
            id: EventId(3),
            command: cmd,
            ts: TimePoint::new(12, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Rename {
                inode: new_inode,
                from: src.clone(),
                to: dest.clone(),
            }),
        };
        let p = plan(dummy_command(), &[pre, unlink, rename], &probe, &store);

        // Expect ONLY RestoreContent + RestoreMetadata for the dest.
        // The Unlink and Rename inverses must be suppressed.
        let has_restore_content = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::RestoreContent { path, .. } if path == &dest));
        let has_recreate = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::RecreatePath { path, .. } if path == &dest));
        let has_reverse_rename = p.nodes.iter().any(
            |n| matches!(&n.op, InverseOp::Rename { from, to } if from == &dest && to == &src),
        );
        assert!(has_restore_content, "RestoreContent inverse missing");
        assert!(
            !has_recreate,
            "rename-destination atomic-replace must NOT emit RecreatePath inverse"
        );
        assert!(
            !has_reverse_rename,
            "rename-destination atomic-replace must NOT emit ReverseRename inverse"
        );
        assert!(
            !p.has_blocking_conflicts(),
            "plan should not have blocking conflicts"
        );
    }

    #[test]
    fn transient_lock_pattern_suppresses_all_inverses() {
        // Signature: TreeOp::Create + FilePreImage + TreeOp::Unlink
        // for one path, AND the path is gone at undo time. Real-world
        // example: git's `.git/index.lock` — created, written,
        // renamed-away within one command. The user has no
        // meaningful state to undo here. We should produce ZERO
        // inverses for this path.
        let probe = InMemoryProbe::new(); // NOTE: path NOT inserted.
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 333);
        let path = PathBuf::from("/tmp/git/index.lock");
        let blob = BlobHash::from_bytes([0xDD; 32]);
        store.put_blob(blob, 0);

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let create = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let pre = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(3),
            command: cmd,
            ts: TimePoint::new(12, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[create, pre, unlink], &probe, &store);

        let nodes_for_path: Vec<_> = p
            .nodes
            .iter()
            .filter(|n| {
                matches!(&n.op,
                    InverseOp::RestoreContent { path: p, .. }
                    | InverseOp::RestoreMetadata { path: p, .. }
                    | InverseOp::Unlink { path: p }
                    | InverseOp::RecreatePath { path: p, .. }
                    if p == &PathBuf::from("/tmp/git/index.lock")
                )
            })
            .collect();
        assert!(
            nodes_for_path.is_empty(),
            "transient lock should produce zero inverses, got: {:?}",
            nodes_for_path.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scratch_file_no_preimage_suppresses_inverses() {
        // A file created AND unlinked in the same command with NO
        // pre-image (it never existed before): the inverse is a no-op.
        // Real-world example: git creates `.git/index.lock` as a
        // brand-new file then renames it onto `.git/index`. The lock
        // path itself has no pre-existing content to restore — the
        // planner used to emit Unlink+RecreatePath, the latter
        // tripping ConflictMissing because we have no bytes for it.
        let probe = InMemoryProbe::new(); // path absent at undo
        let store = InMemoryStore::new();
        let inode = InodeRef::new(1, 999);
        let path = PathBuf::from("/tmp/git/index.lock");
        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let create = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let unlink = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[create, unlink], &probe, &store);
        let nodes_for_path: Vec<_> = p
            .nodes
            .iter()
            .filter(|n| {
                matches!(&n.op,
                    InverseOp::Unlink { path: p } | InverseOp::RecreatePath { path: p, .. }
                    if p == &PathBuf::from("/tmp/git/index.lock")
                )
            })
            .collect();
        assert!(
            nodes_for_path.is_empty(),
            "scratch file with no pre-image should produce zero inverses, got: {:?}",
            nodes_for_path.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pure_create_still_gets_unlink_inverse() {
        // Coalescing should ONLY trigger when the path is also gone
        // at undo time. A pure TreeOp::Create whose path STILL EXISTS
        // (the command genuinely created something that survived)
        // keeps its Unlink inverse.
        let inode = InodeRef::new(1, 42);
        let path = PathBuf::from("/tmp/newdir");
        let mut probe = InMemoryProbe::new();
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(0),
            },
            None,
        );
        let store = InMemoryStore::new();
        let create = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Directory,
                mode: 0o040755,
            }),
        };
        let p = plan(dummy_command(), &[create], &probe, &store);
        assert!(matches!(p.nodes[0].op, InverseOp::Unlink { .. }));
    }

    #[test]
    fn rename_plus_duplicate_create_suppresses_unlink_inverse() {
        // W06.A.5: on FreeBSD, an LD_PRELOAD'd `mv` fires the shim's
        // rename interposer (TreeOp::Rename) AND the kqueue dir-diff
        // observes the new file appearing (TreeOp::Create) — two
        // views of one logical move. Pre-W06.A.5 the planner emitted
        // both inverses; ReverseRename moved the file back to src
        // and the duplicate Unlink then deleted it, leaving src
        // empty. This test pins the suppression: when Create.path ==
        // Rename.to and no Unlink fires, drop the Create's Unlink
        // inverse and let the Rename inverse handle restoration.
        let dst = PathBuf::from("/tmp/dst/file.txt");
        let src = PathBuf::from("/tmp/src/file.txt");
        let inode = InodeRef::new(1, 42);
        let mut probe = InMemoryProbe::new();
        probe.insert(
            dst.clone(),
            ProbeStat {
                inode,
                meta: meta(0),
            },
            None,
        );
        let store = InMemoryStore::new();
        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let rename = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Rename {
                from: src.clone(),
                to: dst.clone(),
                inode,
            }),
        };
        let create = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: dst.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let p = plan(dummy_command(), &[rename, create], &probe, &store);
        let unlinks_for_dst: Vec<_> = p
            .nodes
            .iter()
            .filter(|n| matches!(&n.op, InverseOp::Unlink { path } if path == &dst))
            .collect();
        assert!(
            unlinks_for_dst.is_empty(),
            "duplicate Create at rename destination should NOT emit Unlink; got: {:?}",
            unlinks_for_dst.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
        // The Rename's inverse must still be present (Rename inverse
        // moves dst → src to undo the user's mv).
        let has_reverse_rename = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::Rename { from, to } if from == &dst && to == &src));
        assert!(
            has_reverse_rename,
            "Rename inverse missing; nodes: {:?}",
            p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn rename_carries_children_via_subsumed_creates() {
        // W09.9: `mv srcdir dstdir` renames a directory. The kqueue
        // dir-diff observes the new dir's entries appearing in cwd:
        //   - Create(dstdir) — the renamed-in dir itself
        //   - Create(dstdir/foo.txt), Create(dstdir/bar.txt) — the
        //     contained files (they moved with the dir, but dir-diff
        //     sees them as fresh entries in the newly-watched dstdir)
        // Without the W09.9 rule, the children's Unlink inverses race
        // the Rename's ReverseRename — if Unlinks fire first the
        // children are deleted, leaving an empty srcdir post-undo
        // (data loss). The rename_subsumed_creates set must include
        // strict descendants of every rename destination so child
        // Unlink inverses are suppressed.
        let src = PathBuf::from("/w/srcdir");
        let dst = PathBuf::from("/w/dstdir");
        let foo = dst.join("foo.txt");
        let bar = dst.join("bar.txt");
        let dir_inode = InodeRef::new(1, 100);
        let foo_inode = InodeRef::new(1, 101);
        let bar_inode = InodeRef::new(1, 102);

        let mut probe = InMemoryProbe::new();
        probe.insert(
            dst.clone(),
            ProbeStat {
                inode: dir_inode,
                meta: meta(0),
            },
            None,
        );
        probe.insert(
            foo.clone(),
            ProbeStat {
                inode: foo_inode,
                meta: meta(10),
            },
            None,
        );
        probe.insert(
            bar.clone(),
            ProbeStat {
                inode: bar_inode,
                meta: meta(10),
            },
            None,
        );
        let store = InMemoryStore::new();
        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let rename = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Rename {
                from: src.clone(),
                to: dst.clone(),
                inode: dir_inode,
            }),
        };
        let create_dir = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode: dir_inode,
                path: dst.clone(),
                kind: crate::metadata::FileKind::Directory,
                mode: 0o040755,
            }),
        };
        let create_foo = CaptureEvent {
            id: EventId(3),
            command: cmd,
            ts: TimePoint::new(12, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode: foo_inode,
                path: foo.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let create_bar = CaptureEvent {
            id: EventId(4),
            command: cmd,
            ts: TimePoint::new(13, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode: bar_inode,
                path: bar.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let p = plan(
            dummy_command(),
            &[rename, create_dir, create_foo, create_bar],
            &probe,
            &store,
        );

        // NO Unlink inverse for foo or bar — they're carried by the
        // dir rename.
        for child in [&foo, &bar] {
            let has_unlink = p
                .nodes
                .iter()
                .any(|n| matches!(&n.op, InverseOp::Unlink { path } if path == child));
            assert!(
                !has_unlink,
                "Unlink({}) leaked through; would race ReverseRename — nodes: {:?}",
                child.display(),
                p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
            );
        }
        // The Rename inverse IS present (rename dstdir → srcdir).
        let has_reverse_rename = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::Rename { from, to } if from == &dst && to == &src));
        assert!(
            has_reverse_rename,
            "ReverseRename missing — undo can't restore srcdir; nodes: {:?}",
            p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn rename_with_preimage_dest_classifies_as_atomic_replace() {
        // W06.A.4: install(1) writes a tmpfile then renames it
        // over an existing destination. The shim emits BOTH a
        // TreeOp::Rename(from=tmpfile, to=dst) AND a FilePreImage
        // for `dst` with the old bytes. Without this fix, the
        // planner emits ReverseRename(dst→tmpfile) + RestoreContent
        // — the rename moves the new bytes back to the tmpfile path
        // and leaves dst empty, racing with RestoreContent. The fix
        // routes the dst path through atomic_replace_paths: the
        // Rename inverse is suppressed, the FilePreImage's
        // RestoreContent does all the work.
        let dst = PathBuf::from("/target/bin/hello");
        let tmpfile = PathBuf::from("/target/bin/INS@x3p");
        let inode = InodeRef::new(1, 7777);
        let blob = BlobHash::from_bytes([0xAB; 32]);

        let mut store = InMemoryStore::new();
        store.put_blob(blob, 11);

        // Dst exists at undo time (it's the post-rename state,
        // holding the new bytes).
        let mut probe = InMemoryProbe::new();
        probe.insert(
            dst.clone(),
            ProbeStat {
                inode,
                meta: meta(11),
            },
            None,
        );

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let rename = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Rename {
                from: tmpfile.clone(),
                to: dst.clone(),
                inode,
            }),
        };
        let pre_image = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: dst.clone(),
                blob,
                meta: meta(11),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[rename, pre_image], &probe, &store);

        // ReverseRename for dst MUST NOT be emitted — it would
        // race with RestoreContent.
        let has_reverse_rename = p.nodes.iter().any(
            |n| matches!(&n.op, InverseOp::Rename { from, to } if from == &dst && to == &tmpfile),
        );
        assert!(
            !has_reverse_rename,
            "ReverseRename for atomic-replace dst leaked through; nodes: {:?}",
            p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
        // RestoreContent for dst MUST be emitted.
        let has_restore = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::RestoreContent { path, .. } if path == &dst));
        assert!(
            has_restore,
            "RestoreContent missing; nodes: {:?}",
            p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unlink_plus_preimage_path_exists_classifies_as_atomic_replace() {
        // W09.5: tar / cpio / gzip use unlink(P) then open(P, O_CREAT)
        // to replace a file's content. The shim captures the
        // pre-image at unlink time; the subsequent open's pre-image
        // capture returns None (file already gone) so no Create event
        // is journaled. At undo time P exists with the NEW bytes.
        //
        // The planner must classify this Unlink+PreImage shape as
        // atomic_replace: suppress the Unlink's RecreatePath (would
        // race / create empty file), let the FilePreImage's
        // RestoreContent restore the old bytes.
        let dst = PathBuf::from("/dst/alpha.txt");
        let inode = InodeRef::new(1, 7777);
        let blob = BlobHash::from_bytes([0xAB; 32]);

        let mut store = InMemoryStore::new();
        store.put_blob(blob, 20);

        // Path exists at undo (post-tar, with new bytes).
        let mut probe = InMemoryProbe::new();
        probe.insert(
            dst.clone(),
            ProbeStat {
                inode,
                meta: meta(20),
            },
            None,
        );

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let unlink = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: dst.clone(),
            }),
        };
        let pre_image = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(9, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: dst.clone(),
                blob,
                meta: meta(20),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[pre_image, unlink], &probe, &store);

        // RecreatePath for dst MUST NOT fire — would race with
        // RestoreContent and possibly land an empty file.
        let has_recreate_path = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::RecreatePath { path, .. } if path == &dst));
        assert!(
            !has_recreate_path,
            "RecreatePath leaked through for atomic-replace shape; nodes: {:?}",
            p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
        // RestoreContent for dst MUST be present.
        let has_restore = p
            .nodes
            .iter()
            .any(|n| matches!(&n.op, InverseOp::RestoreContent { path, .. } if path == &dst));
        assert!(
            has_restore,
            "RestoreContent missing; nodes: {:?}",
            p.nodes.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn env_diff_emits_inverses_with_old_values() {
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let mut added = BTreeMap::new();
        added.insert("NEW".to_string(), "v".to_string());
        let mut removed = BTreeMap::new();
        removed.insert("OLD".to_string(), "was-here".to_string());
        let mut modified = BTreeMap::new();
        modified.insert(
            "CHANGED".to_string(),
            ("pre".to_string(), "post".to_string()),
        );
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::EnvDiff {
                added,
                removed,
                modified,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert_eq!(p.nodes.len(), 3);

        let has = |needle: &InverseOp| p.nodes.iter().any(|n| &n.op == needle);
        assert!(has(&InverseOp::UnsetEnv {
            name: "NEW".to_string(),
        }));
        assert!(has(&InverseOp::SetEnv {
            name: "OLD".to_string(),
            value: "was-here".to_string(),
        }));
        assert!(has(&InverseOp::SetEnv {
            name: "CHANGED".to_string(),
            value: "pre".to_string(),
        }));
    }

    #[test]
    fn post_image_match_no_conflict() {
        // Captured post_hash matches current content → undo is safe; the
        // file is still in the post-mutation state.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAA; 32]); // pre-image content
        let post = BlobHash::from_bytes([0xBB; 32]); // post-mutation content
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(50),
            },
            Some(post), // current content matches expected post
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob,
                meta: meta(100),
                post_content_hash: Some(post),
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(p.nodes[0].conflict.is_none(), "{:?}", p.nodes[0].conflict);
    }

    #[test]
    fn post_image_mismatch_yields_hard_conflict() {
        // Captured post_hash differs from current content → user has edited
        // the file since the original command. Hard conflict.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAA; 32]);
        let expected_post = BlobHash::from_bytes([0xBB; 32]);
        let current = BlobHash::from_bytes([0xCC; 32]); // != expected_post
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(50),
            },
            Some(current),
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob,
                meta: meta(100),
                post_content_hash: Some(expected_post),
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(p.nodes[0].conflict, Some(Conflict::Hard { .. })));
        assert!(p.has_blocking_conflicts());
    }

    #[test]
    fn post_image_none_disables_check() {
        // Degraded tier: no post_content_hash recorded. Even if current
        // content is "wrong", we can't detect it; plan proceeds without
        // Hard conflict.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAA; 32]);
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(50),
            },
            Some(BlobHash::from_bytes([0xFF; 32])),
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob,
                meta: meta(100),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(p.nodes[0].conflict.is_none());
    }

    // ----- C02.7: native_delegation_for -----

    #[test]
    fn delegation_for_apt_with_tx_id_emits_history_rollback() {
        let d = native_delegation_for(PackageManager::Apt, Some("42")).unwrap();
        assert_eq!(d.argv, vec!["apt", "history-rollback", "42"]);
        assert!(d.privileged);
        assert!(d.guard_command.is_some());
        assert_eq!(d.guard_match.as_deref(), Some("42:"));
    }

    #[test]
    fn delegation_for_dnf_with_history_id_emits_history_undo() {
        let d = native_delegation_for(PackageManager::Dnf, Some("7")).unwrap();
        assert_eq!(d.argv, vec!["dnf", "history", "undo", "-y", "7"]);
        assert!(d.privileged);
        assert_eq!(d.guard_match.as_deref(), Some("7 "));
    }

    #[test]
    fn delegation_for_managers_without_native_rollback_is_none() {
        for mgr in [
            PackageManager::Dpkg,
            PackageManager::Pacman,
            PackageManager::Brew,
            PackageManager::Pkg,
        ] {
            assert!(
                native_delegation_for(mgr, Some("99")).is_none(),
                "expected None for {mgr:?}"
            );
        }
    }

    #[test]
    fn delegation_for_missing_hint_is_none_even_for_supported_manager() {
        assert!(native_delegation_for(PackageManager::Apt, None).is_none());
        assert!(native_delegation_for(PackageManager::Dnf, None).is_none());
    }

    #[test]
    fn delegation_for_empty_or_whitespace_hint_is_none() {
        assert!(native_delegation_for(PackageManager::Apt, Some("")).is_none());
        assert!(native_delegation_for(PackageManager::Dnf, Some("   ")).is_none());
    }
}
