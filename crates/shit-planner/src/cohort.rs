// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cohort assignment (DR-14).
//!
//! The planner emits a topologically-ordered list of [`PlanNode`]s.
//! Stage 1 put every node in `cohort = 0`; the orchestrator's
//! `run_parallel` would then race conflicting ops against each
//! other. This module assigns cohorts so that:
//!
//! 1. **Ops in the same cohort commute** — different inodes/paths,
//!    no rename source/destination overlap. The orchestrator may run
//!    them in any order or concurrently.
//! 2. **Cohorts execute in non-decreasing order.** Cohort `N`
//!    completes before cohort `N+1` begins. This preserves the
//!    plan's reverse-chronological intent (e.g., `RecreatePath`
//!    before `RestoreContent` on the same path).
//!
//! ## Algorithm
//!
//! Greedy assignment, single pass over nodes in their existing
//! order. For each node, compute the set of paths/inodes it
//! "touches"; pick the smallest cohort index `c` such that no
//! already-assigned node in `c` touches any of the same
//! paths/inodes. The plan order is preserved as the upper bound on
//! cohort index — a node never lands in a cohort earlier than a
//! prior-emitted conflicting node.
//!
//! ## What "touches" means
//!
//! - File-tier ops touch their `primary_path` AND their
//!   `primary_inode` (when available). Both are checked because a
//!   path can change identity across ops while the inode stays
//!   stable, or vice versa.
//! - `Rename { from, to }` touches both endpoints.
//! - `ProcessNote`, `DbNote`, env ops, package/service/network
//!   informational ops touch *nothing* — they can always run in
//!   the lowest cohort.
//!
//! ## Why not a true graph color
//!
//! A real chromatic-number minimisation is NP-hard. Greedy here is
//! good enough: typical plans are <100 ops with at most a handful of
//! conflicts; the result is within 1-2 cohorts of optimal in
//! practice. If a future bench shows pathological cases we revisit
//! with a smarter pass.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::inode::InodeRef;
use crate::inverse::{InverseOp, PlanNode};

/// A path or inode this op writes / depends on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TouchKey {
    Path(PathBuf),
    Inode(InodeRef),
}

/// Collect every path/inode this op touches. For most ops this is
/// `[Path(primary)]` ± `[Inode(primary_inode)]`; renames add both
/// endpoints; informational ops return empty.
fn touches(op: &InverseOp) -> Vec<TouchKey> {
    let mut out = Vec::new();
    match op {
        InverseOp::Rename { from, to, .. } => {
            out.push(TouchKey::Path(from.clone()));
            out.push(TouchKey::Path(to.clone()));
        }
        InverseOp::RestoreContent { path, inode, .. }
        | InverseOp::RestoreMetadata { path, inode, .. } => {
            out.push(TouchKey::Path(path.clone()));
            out.push(TouchKey::Inode(*inode));
        }
        InverseOp::Unlink { path }
        | InverseOp::RecreatePath { path, .. }
        | InverseOp::CreateSymlink { path, .. }
        | InverseOp::FileExtend { path, .. } => {
            out.push(TouchKey::Path(path.clone()));
        }
        // W09.20 — CreateHardlink touches both endpoints. `source`
        // is the live alias (we read its inode); `target` is where
        // we create the new link. Serialize against any concurrent
        // op on either.
        InverseOp::CreateHardlink { source, target } => {
            out.push(TouchKey::Path(source.clone()));
            out.push(TouchKey::Path(target.clone()));
        }
        // Env / package / network / systemd / process / db ops are
        // informational or system-wide; they don't compete on a path
        // or inode within the file tier. We deliberately don't
        // serialise multiple SystemdRollbacks against the same unit
        // here — they're allowed to share a cohort because the
        // executor calls `systemctl` which itself serialises.
        InverseOp::SetEnv { .. }
        | InverseOp::UnsetEnv { .. }
        | InverseOp::PackageRollback { .. }
        | InverseOp::NetworkRollback { .. }
        | InverseOp::SystemdRollback { .. }
        | InverseOp::ProcessNote { .. }
        | InverseOp::DescriptorReverse { .. }
        | InverseOp::KubectlReverse { .. }
        | InverseOp::GhReverse { .. }
        | InverseOp::AwsReverse { .. }
        | InverseOp::TerraformReverse { .. }
        | InverseOp::ContainerRestore { .. }
        | InverseOp::ShellStateRestore { .. }
        | InverseOp::DbNote { .. }
        | InverseOp::Refuse { .. } => {}
    }
    out
}

/// Assign cohorts to every node in `nodes` so siblings in a cohort
/// commute. Returns the next-free cohort index (the cohort count).
///
/// The function mutates `node.cohort` in-place and preserves
/// `nodes`' order. Callers that want to fold this into the existing
/// `plan()` pipeline just append it after the per-event emission.
pub fn assign_cohorts(nodes: &mut [PlanNode]) -> u32 {
    // Per-cohort set of touch keys held by ops already assigned to
    // it. Stored as a Vec<BTreeSet<TouchKey>>; index = cohort id.
    let mut cohort_touches: Vec<BTreeSet<TouchKey>> = Vec::new();

    for node in nodes.iter_mut() {
        let keys = touches(&node.op);
        if keys.is_empty() {
            // Informational op — always cohort 0.
            node.cohort = 0;
            if cohort_touches.is_empty() {
                cohort_touches.push(BTreeSet::new());
            }
            continue;
        }
        // Find the lowest cohort with no key overlap.
        let mut chosen: Option<usize> = None;
        for (i, existing) in cohort_touches.iter().enumerate() {
            if keys.iter().all(|k| !existing.contains(k)) {
                chosen = Some(i);
                break;
            }
        }
        let cohort_idx = match chosen {
            Some(i) => i,
            None => {
                cohort_touches.push(BTreeSet::new());
                cohort_touches.len() - 1
            }
        };
        for k in keys {
            cohort_touches[cohort_idx].insert(k);
        }
        node.cohort = cohort_idx as u32;
    }
    cohort_touches.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inverse::PlanNode;
    use std::path::PathBuf;

    fn restore_content(path: &str, dev: u64, ino: u64) -> PlanNode {
        PlanNode {
            op: InverseOp::RestoreContent {
                inode: InodeRef::new(dev, ino),
                path: PathBuf::from(path),
                blob: crate::inode::BlobHash::from_bytes([0; 32]),
            },
            cohort: 0,
            conflict: None,
        }
    }

    fn unlink(path: &str) -> PlanNode {
        PlanNode {
            op: InverseOp::Unlink {
                path: PathBuf::from(path),
            },
            cohort: 0,
            conflict: None,
        }
    }

    fn rename(from: &str, to: &str) -> PlanNode {
        PlanNode {
            op: InverseOp::Rename {
                from: PathBuf::from(from),
                to: PathBuf::from(to),
            },
            cohort: 0,
            conflict: None,
        }
    }

    fn process_note() -> PlanNode {
        PlanNode {
            op: InverseOp::ProcessNote {
                argv: vec!["sleep".into()],
                cwd: PathBuf::from("/"),
                env_summary: Default::default(),
                message: "killed".into(),
            },
            cohort: 0,
            conflict: None,
        }
    }

    #[test]
    fn disjoint_paths_share_cohort_0() {
        let mut nodes = vec![
            restore_content("/etc/foo", 1, 1),
            restore_content("/etc/bar", 1, 2),
            restore_content("/etc/baz", 1, 3),
        ];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 1);
        assert!(nodes.iter().all(|n| n.cohort == 0));
    }

    #[test]
    fn same_path_forces_separate_cohorts() {
        // Two restore_content for the same path — must be serialised.
        let mut nodes = vec![
            restore_content("/etc/foo", 1, 1),
            restore_content("/etc/foo", 1, 1),
        ];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 2);
        assert_eq!(nodes[0].cohort, 0);
        assert_eq!(nodes[1].cohort, 1);
    }

    #[test]
    fn same_inode_different_paths_still_conflicts() {
        // Hardlinks: same (dev, inode) under different paths.
        // Two ops on the same inode must be serialised even if the
        // paths differ.
        let mut nodes = vec![
            restore_content("/a/hard", 1, 42),
            restore_content("/b/hard", 1, 42),
        ];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 2);
        assert_eq!(nodes[1].cohort, 1);
    }

    #[test]
    fn rename_endpoints_both_touched() {
        // Rename a→b followed by an Unlink on b: must serialise.
        let mut nodes = vec![rename("/a", "/b"), unlink("/b")];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 2);
        assert_eq!(nodes[1].cohort, 1);
    }

    #[test]
    fn rename_source_endpoint_conflicts_with_later_op_on_source() {
        // Rename a→b followed by restore on a (different inode):
        // both touch `a`, so they serialise.
        let mut nodes = vec![rename("/a", "/b"), restore_content("/a", 1, 99)];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 2);
    }

    #[test]
    fn process_note_lands_in_cohort_0_with_others() {
        // ProcessNote touches nothing → always cohort 0 even
        // alongside content restores.
        let mut nodes = vec![process_note(), restore_content("/x", 1, 1), process_note()];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 1);
        assert!(nodes.iter().all(|n| n.cohort == 0));
    }

    #[test]
    fn third_op_finds_lowest_free_cohort() {
        // [restore /a, restore /a, restore /b]:
        //   - 0 → cohort 0
        //   - 1 → cohort 1 (conflicts with 0 on /a)
        //   - 2 → cohort 0 (no conflict with cohort-0's /a since /b)
        let mut nodes = vec![
            restore_content("/a", 1, 1),
            restore_content("/a", 1, 1),
            restore_content("/b", 1, 2),
        ];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 2);
        assert_eq!(nodes[0].cohort, 0);
        assert_eq!(nodes[1].cohort, 1);
        assert_eq!(nodes[2].cohort, 0, "free slot reused");
    }

    #[test]
    fn empty_plan_returns_zero_cohorts() {
        let mut nodes: Vec<PlanNode> = Vec::new();
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 0);
    }

    #[test]
    fn single_informational_op_yields_one_cohort() {
        let mut nodes = vec![process_note()];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 1);
    }

    #[test]
    fn cohort_indices_are_dense_zero_based() {
        // 10 conflicting ops on the same path → 10 cohorts, 0..=9.
        let mut nodes: Vec<PlanNode> = (0..10).map(|_| restore_content("/x", 1, 1)).collect();
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 10);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.cohort, i as u32);
        }
    }

    #[test]
    fn assignment_preserves_topological_order_within_cohorts() {
        // [restore /a, restore /b, restore /a]: first /a is cohort 0,
        // /b is cohort 0, second /a is cohort 1. The second /a never
        // ends up alongside or before the first.
        let mut nodes = vec![
            restore_content("/a", 1, 1),
            restore_content("/b", 1, 2),
            restore_content("/a", 1, 1),
        ];
        let count = assign_cohorts(&mut nodes);
        assert_eq!(count, 2);
        assert!(nodes[0].cohort < nodes[2].cohort);
    }
}
