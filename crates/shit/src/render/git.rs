// SPDX-License-Identifier: AGPL-3.0-or-later

//! `.git/`-aware plan summarization (DR-18 / S12.11).
//!
//! ## What it does
//!
//! When `shit undo --dry-run` or `shit show <id>` renders a plan, the
//! raw output would be a list of inverse ops:
//!
//! ```text
//! restore content   /repo/.git/HEAD
//! restore content   /repo/.git/refs/heads/main
//! restore content   /repo/.git/index
//! restore content   /repo/.git/logs/HEAD
//! ```
//!
//! That's correct but unhelpful. The user knows they ran
//! `git reset --hard`; they want to see the *effect*. This renderer
//! detects contiguous `.git/`-subtree restores and presents a single
//! line:
//!
//! ```text
//! revert branch main (in /repo): restores HEAD, refs/heads/main, index, reflog
//! ```
//!
//! Future iterations parse the captured `HEAD` / `refs/heads/<X>`
//! blob contents to render the actual SHAs:
//! `revert branch main from a1b2c3d (current) to f4e5d6c (captured)`.
//! That needs a `BlobReader` argument and lands once the renderer is
//! wired into a command that has one.
//!
//! ## Why this isn't a per-tool integration
//!
//! The whole project's design promise is "no per-tool integrations."
//! This renderer reads only the **content** of files we already
//! captured generically. We don't shell out to `git`, we don't
//! special-case `git`'s argv. Any tool whose state is structured
//! files we capture can get the same treatment (e.g. a future
//! `.hg/`-aware renderer would be analogous). The CaptureEvent /
//! InverseOp pipeline doesn't change.
//!
//! ## Why detection happens at render time, not plan time
//!
//! The plan's inverse-op DAG remains a flat list of file restores —
//! that's what the executor actually does. The grouping is purely
//! presentation. Keeping it at render time means:
//! 1. The plan stays simple and round-trippable.
//! 2. `--raw` is a one-line bypass (skip this renderer, dump the list).
//! 3. The exec log records the literal ops, not the summary.

use std::path::{Path, PathBuf};

use shit_planner::{InverseOp, UndoPlan};

/// One detected `.git/`-subtree restore group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRestoreGroup {
    /// The repo's `.git/` directory (parent of the captured files).
    pub git_dir: PathBuf,
    /// The branch name if `HEAD` is among the restored files and we
    /// could parse it as `ref: refs/heads/<name>`. None for detached
    /// HEAD or when HEAD wasn't among the restores.
    ///
    /// Stage 1: always None (we don't read blob content yet).
    pub branch: Option<String>,
    /// Files within `.git/` that this group covers.
    pub affected_files: Vec<PathBuf>,
}

impl GitRestoreGroup {
    /// Render a single-line summary for `shit show` / `shit undo --dry-run`.
    pub fn summary_line(&self) -> String {
        let basenames: Vec<String> = self
            .affected_files
            .iter()
            .filter_map(|p| p.strip_prefix(&self.git_dir).ok())
            .map(|rel| rel.display().to_string())
            .collect();
        let branch_bit = match &self.branch {
            Some(b) => format!("branch {b} "),
            None => String::new(),
        };
        format!(
            "revert {branch_bit}(in {}): restores {}",
            self.git_dir.display(),
            basenames.join(", ")
        )
    }
}

/// Walk the plan's nodes and group contiguous file-tier restores
/// whose path is under a `.git/` directory. Returns one group per
/// distinct `.git/` ancestor.
pub fn detect_git_restores(plan: &UndoPlan) -> Vec<GitRestoreGroup> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<PathBuf, GitRestoreGroup> = BTreeMap::new();

    for node in &plan.nodes {
        let Some(path) = node.op.primary_path() else {
            continue;
        };
        let Some(git_dir) = find_git_dir(path) else {
            continue;
        };
        // Only RestoreContent / RestoreMetadata / Unlink — the
        // operations a `git reset --hard` produces in capture. We
        // skip Rename/Symlink to keep the heuristic tight.
        if !matches!(
            node.op,
            InverseOp::RestoreContent { .. }
                | InverseOp::RestoreMetadata { .. }
                | InverseOp::Unlink { .. }
        ) {
            continue;
        }
        groups
            .entry(git_dir.clone())
            .or_insert_with(|| GitRestoreGroup {
                git_dir,
                branch: None,
                affected_files: Vec::new(),
            })
            .affected_files
            .push(path.to_path_buf());
    }
    groups.into_values().collect()
}

/// Return the nearest ancestor of `path` named `.git`, if any.
fn find_git_dir(path: &Path) -> Option<PathBuf> {
    for ancestor in path.ancestors() {
        if ancestor.file_name().is_some_and(|n| n == ".git") {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{BlobHash, CommandId, CommandRecord, InodeRef, PlanNode, TimePoint};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn empty_plan() -> UndoPlan {
        UndoPlan {
            command: CommandRecord {
                command: CommandId {
                    session: Uuid::nil(),
                    seq: 0,
                },
                cmd_string: Some("git reset --hard HEAD~3".into()),
                cwd: PathBuf::from("/repo"),
                pid: 1,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::min(),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            },
            nodes: vec![],
            warnings: vec![],
        }
    }

    fn restore_node(path: PathBuf) -> PlanNode {
        PlanNode {
            op: InverseOp::RestoreContent {
                inode: InodeRef::new(1, 1),
                path,
                blob: BlobHash::from_bytes([0; 32]),
            },
            cohort: 0,
            conflict: None,
        }
    }

    #[test]
    fn detects_single_git_repo() {
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/HEAD")));
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/refs/heads/main")));
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/index")));
        let groups = detect_git_restores(&plan);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].git_dir, PathBuf::from("/repo/.git"));
        assert_eq!(groups[0].affected_files.len(), 3);
    }

    #[test]
    fn detects_multiple_repos() {
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo-a/.git/HEAD")));
        plan.nodes
            .push(restore_node(PathBuf::from("/repo-b/.git/HEAD")));
        let groups = detect_git_restores(&plan);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn ignores_non_git_paths() {
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/src/main.rs")));
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.gitignore")));
        let groups = detect_git_restores(&plan);
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn summary_line_lists_affected_files() {
        let g = GitRestoreGroup {
            git_dir: PathBuf::from("/repo/.git"),
            branch: None,
            affected_files: vec![
                PathBuf::from("/repo/.git/HEAD"),
                PathBuf::from("/repo/.git/index"),
            ],
        };
        let s = g.summary_line();
        assert!(s.contains("/repo/.git"), "{s}");
        assert!(s.contains("HEAD"), "{s}");
        assert!(s.contains("index"), "{s}");
    }
}
