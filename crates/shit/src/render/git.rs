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
    /// `detect_git_restores` always returns None here.
    /// [`detect_git_restores_enriched`] reads the captured HEAD blob
    /// and parses the symref to populate it.
    pub branch: Option<String>,
    /// Captured HEAD's commit SHA. Populated by
    /// [`detect_git_restores_enriched`] when the captured `HEAD`
    /// or `refs/heads/<branch>` blob is a 40-hex SHA. None on
    /// parse failure or when the relevant blob wasn't in the plan.
    pub head_sha: Option<String>,
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
        let sha_bit = match &self.head_sha {
            Some(sha) if sha.len() >= 7 => format!(" → {}", &sha[..7]),
            _ => String::new(),
        };
        format!(
            "revert {branch_bit}(in {}){sha_bit}: restores {}",
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
                head_sha: None,
                affected_files: Vec::new(),
            })
            .affected_files
            .push(path.to_path_buf());
    }
    groups.into_values().collect()
}

/// DR-18 enrichment: walk the plan as [`detect_git_restores`] does,
/// but for each group also read the captured `HEAD` and (if present)
/// `refs/heads/<branch>` blobs through `reader`. Populates
/// `group.branch` from `HEAD` (`ref: refs/heads/<name>` symref) and
/// `group.head_sha` from the branch ref or directly from HEAD when
/// detached.
///
/// `reader` is anything that can read a blob by hash. The CLI wires
/// up the daemon's blob store as the reader; tests use an in-memory
/// mock.
pub fn detect_git_restores_enriched<R: BlobByPath>(
    plan: &UndoPlan,
    reader: &R,
) -> Vec<GitRestoreGroup> {
    let mut groups = detect_git_restores(plan);
    for g in &mut groups {
        // Try to read the captured HEAD blob first.
        let head_path = g.git_dir.join("HEAD");
        if let Some(content) = reader.read_blob_for(plan, &head_path) {
            match parse_head_blob(&content) {
                ParsedHead::Symref(branch) => {
                    // Symref → branch is the symref target; SHA
                    // comes from the captured refs/heads/<branch>
                    // blob if that's in the plan.
                    let ref_path = g.git_dir.join("refs").join("heads").join(&branch);
                    let sha = reader
                        .read_blob_for(plan, &ref_path)
                        .and_then(|b| parse_ref_blob(&b));
                    g.branch = Some(branch);
                    g.head_sha = sha;
                }
                ParsedHead::Detached(sha) => {
                    g.head_sha = Some(sha);
                }
                ParsedHead::Unparseable => {}
            }
        }
    }
    groups
}

/// Trait that lets the enrichment pass read the blob behind a captured
/// path *without* the renderer depending on `shit-store`. The CLI
/// implements this against the daemon's blob store; tests use an
/// in-memory map.
pub trait BlobByPath {
    /// Look up the captured blob for `path` within `plan` and return
    /// its bytes. `None` when the path isn't in the plan or the blob
    /// isn't available.
    fn read_blob_for(&self, plan: &UndoPlan, path: &Path) -> Option<Vec<u8>>;
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedHead {
    /// `HEAD` was a symref: `ref: refs/heads/<branch>\n`.
    Symref(String),
    /// `HEAD` was a detached-mode 40-hex SHA + newline.
    Detached(String),
    Unparseable,
}

fn parse_head_blob(content: &[u8]) -> ParsedHead {
    let s = match std::str::from_utf8(content) {
        Ok(s) => s.trim(),
        Err(_) => return ParsedHead::Unparseable,
    };
    if let Some(rest) = s.strip_prefix("ref: refs/heads/") {
        let branch = rest.trim().to_string();
        if branch.is_empty() {
            ParsedHead::Unparseable
        } else {
            ParsedHead::Symref(branch)
        }
    } else if is_hex_sha(s) {
        ParsedHead::Detached(s.to_string())
    } else {
        ParsedHead::Unparseable
    }
}

/// Parse a `refs/heads/<branch>` blob: 40-hex SHA + optional newline.
fn parse_ref_blob(content: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(content).ok()?.trim();
    if is_hex_sha(s) {
        Some(s.to_string())
    } else {
        None
    }
}

fn is_hex_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
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
            head_sha: None,
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

    // -----------------------------------------------------------------
    // DR-18 enrichment: HEAD/refs parsing + summary integration
    // -----------------------------------------------------------------

    /// Stub BlobByPath impl that maps captured paths → bytes.
    struct StubBlobs(std::collections::HashMap<PathBuf, Vec<u8>>);
    impl BlobByPath for StubBlobs {
        fn read_blob_for(&self, _: &UndoPlan, path: &Path) -> Option<Vec<u8>> {
            self.0.get(path).cloned()
        }
    }

    #[test]
    fn parse_head_blob_recognises_symref() {
        let v = parse_head_blob(b"ref: refs/heads/main\n");
        assert_eq!(v, ParsedHead::Symref("main".to_string()));
    }

    #[test]
    fn parse_head_blob_recognises_detached_sha() {
        let v = parse_head_blob(b"a1b2c3d4e5f607182930414253647586979a0b1c\n");
        assert!(matches!(v, ParsedHead::Detached(_)));
    }

    #[test]
    fn parse_head_blob_rejects_invalid() {
        assert_eq!(parse_head_blob(b"garbage"), ParsedHead::Unparseable);
        assert_eq!(
            parse_head_blob(b"ref: refs/heads/"),
            ParsedHead::Unparseable
        );
        assert_eq!(parse_head_blob(b"a1b2c3"), ParsedHead::Unparseable);
    }

    #[test]
    fn parse_ref_blob_accepts_sha() {
        assert_eq!(
            parse_ref_blob(b"a1b2c3d4e5f607182930414253647586979a0b1c\n"),
            Some("a1b2c3d4e5f607182930414253647586979a0b1c".to_string())
        );
    }

    #[test]
    fn parse_ref_blob_rejects_non_sha() {
        assert_eq!(parse_ref_blob(b"not-a-sha"), None);
    }

    #[test]
    fn enriched_detection_populates_branch_and_sha_from_symref() {
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/HEAD")));
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/refs/heads/main")));
        let mut blobs = std::collections::HashMap::new();
        blobs.insert(
            PathBuf::from("/repo/.git/HEAD"),
            b"ref: refs/heads/main\n".to_vec(),
        );
        blobs.insert(
            PathBuf::from("/repo/.git/refs/heads/main"),
            b"a1b2c3d4e5f607182930414253647586979a0b1c\n".to_vec(),
        );
        let stub = StubBlobs(blobs);
        let groups = detect_git_restores_enriched(&plan, &stub);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].branch.as_deref(), Some("main"));
        assert_eq!(
            groups[0].head_sha.as_deref(),
            Some("a1b2c3d4e5f607182930414253647586979a0b1c")
        );
        // Summary line includes both branch and short SHA.
        let s = groups[0].summary_line();
        assert!(s.contains("branch main"), "got: {s}");
        assert!(s.contains("a1b2c3d"), "got: {s}");
    }

    #[test]
    fn enriched_detection_handles_detached_head() {
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/HEAD")));
        let mut blobs = std::collections::HashMap::new();
        blobs.insert(
            PathBuf::from("/repo/.git/HEAD"),
            b"a1b2c3d4e5f607182930414253647586979a0b1c\n".to_vec(),
        );
        let stub = StubBlobs(blobs);
        let groups = detect_git_restores_enriched(&plan, &stub);
        assert_eq!(groups.len(), 1);
        // Detached HEAD → no branch, but SHA populated.
        assert_eq!(groups[0].branch, None);
        assert_eq!(
            groups[0].head_sha.as_deref(),
            Some("a1b2c3d4e5f607182930414253647586979a0b1c")
        );
    }

    #[test]
    fn enriched_detection_falls_back_when_head_blob_absent() {
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/index")));
        // No HEAD restore in this plan → enrichment leaves branch/sha None.
        let stub = StubBlobs(std::collections::HashMap::new());
        let groups = detect_git_restores_enriched(&plan, &stub);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].branch, None);
        assert_eq!(groups[0].head_sha, None);
    }

    #[test]
    fn enriched_detection_handles_unparseable_head() {
        // Captured HEAD is corrupt — enrichment doesn't populate
        // branch but doesn't panic either.
        let mut plan = empty_plan();
        plan.nodes
            .push(restore_node(PathBuf::from("/repo/.git/HEAD")));
        let mut blobs = std::collections::HashMap::new();
        blobs.insert(
            PathBuf::from("/repo/.git/HEAD"),
            b"\xff\xff\xff garbage \x00".to_vec(),
        );
        let stub = StubBlobs(blobs);
        let groups = detect_git_restores_enriched(&plan, &stub);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].branch, None);
        assert_eq!(groups[0].head_sha, None);
    }
}
