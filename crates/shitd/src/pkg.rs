// SPDX-License-Identifier: AGPL-3.0-or-later

//! Package-manager hook ingestion (S14.9).
//!
//! `shit-helper pkg-event ...` sends one `PkgEventReq` per Pre/Post
//! phase. The daemon stashes Pre events in memory keyed by pid; on
//! Post it pairs them, computes the diff, and records the result.
//!
//! **Journal write is deferred (DR-25).** Recording a `CaptureEvent::
//! PackageOp` requires binding to an open command window
//! `(session, seq)`, which in turn requires the helper-side
//! process-ancestor lookup that ties the helper's pid back to the
//! shell process that launched the package manager. That binding
//! lands together with the capture-runtime pipeline (DR-01..DR-13).
//! Stage 1 logs the diff via `tracing` so the wiring is verifiable;
//! the planner-facing journal write becomes a one-line addition
//! once the (session, seq) lookup exists.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shit_planner::events::{
    CaptureEvent, CaptureEventKind, EventId, PackageManager, PackageOpKind,
};
use shit_proto::{PkgEventReq, PkgManagerWire, PkgPhase};
use shit_store::Index;

use crate::active_commands::ActiveCommands;

/// How long a Pre event sits in the stash without a matching Post
/// before the janitor evicts it. Five minutes is generous; a real
/// `apt upgrade` of every package on a slow system fits comfortably.
pub const PRE_STASH_TTL: Duration = Duration::from_secs(300);

/// In-memory Pre-phase stash, keyed by helper pid. Cleared by a
/// matching Post or by the janitor TTL pass.
pub struct PkgPreStash {
    inner: Mutex<HashMap<u32, (PkgEventReq, Instant)>>,
}

impl PkgPreStash {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record a Pre event. If a previous Pre with the same pid is
    /// still in the stash (orphan from a torn earlier run) it is
    /// replaced.
    pub fn insert_pre(&self, req: PkgEventReq) {
        let mut g = self.inner.lock().unwrap();
        g.insert(req.pid, (req, Instant::now()));
    }

    /// Take the Pre stash for `pid` if present.
    pub fn take_pre(&self, pid: u32) -> Option<PkgEventReq> {
        let mut g = self.inner.lock().unwrap();
        g.remove(&pid).map(|(req, _)| req)
    }

    /// Evict entries older than `PRE_STASH_TTL`. Returns the number
    /// evicted.
    pub fn sweep_expired(&self) -> usize {
        let mut g = self.inner.lock().unwrap();
        let cutoff = Instant::now()
            .checked_sub(PRE_STASH_TTL)
            .unwrap_or_else(Instant::now);
        let before = g.len();
        g.retain(|_, (_, ts)| *ts >= cutoff);
        before - g.len()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

impl Default for PkgPreStash {
    fn default() -> Self {
        Self::new()
    }
}

/// A computed diff between pre and post package maps. The planner
/// consumes this to synthesize the inverse-op invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgDiff {
    /// Packages present in `post` but not in `pre`. Inverse: remove.
    pub installed: BTreeMap<String, String>,
    /// Packages present in `pre` but not in `post`. Inverse:
    /// reinstall at the prior version.
    pub removed: BTreeMap<String, String>,
    /// Packages whose version changed. Stored as `(pre_version,
    /// post_version)`. Inverse: install the pre version.
    pub changed: BTreeMap<String, (String, String)>,
}

/// Diff two name→version maps. Drops keys where the version is
/// identical in both.
pub fn diff_packages(pre: &BTreeMap<String, String>, post: &BTreeMap<String, String>) -> PkgDiff {
    let mut installed = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut changed = BTreeMap::new();
    for (name, v_post) in post {
        match pre.get(name) {
            None => {
                installed.insert(name.clone(), v_post.clone());
            }
            Some(v_pre) if v_pre != v_post => {
                changed.insert(name.clone(), (v_pre.clone(), v_post.clone()));
            }
            _ => {}
        }
    }
    for (name, v_pre) in pre {
        if !post.contains_key(name) {
            removed.insert(name.clone(), v_pre.clone());
        }
    }
    PkgDiff {
        installed,
        removed,
        changed,
    }
}

/// Handle one PkgEvent. Pre events go into the stash; Post events
/// pair with their Pre, compute a diff, attribute it to the active
/// command window via [`ActiveCommands::resolve_by_descendant`]
/// (DR-25), and write a [`CaptureEventKind::PackageOp`] to the
/// journal.
///
/// Returns the diff for tests / tracing. The journal write happens
/// as a side-effect on the Post path when an active command is
/// resolvable; orphan posts (no active command in the ancestor
/// chain) log a warning and skip the journal write.
pub fn handle(
    stash: &PkgPreStash,
    req: PkgEventReq,
    active: &ActiveCommands,
    index: &Index,
) -> Option<PkgDiff> {
    match req.phase {
        PkgPhase::Pre => {
            tracing::info!(
                manager = req.manager.as_str(),
                pid = req.pid,
                uid = req.uid,
                pkgs = req.packages.len(),
                "pkg-event Pre stashed"
            );
            stash.insert_pre(req);
            None
        }
        PkgPhase::Post => {
            let Some(pre) = stash.take_pre(req.pid) else {
                tracing::warn!(
                    manager = req.manager.as_str(),
                    pid = req.pid,
                    "pkg-event Post with no matching Pre; ignoring (orphan)"
                );
                return None;
            };
            if pre.manager != req.manager {
                tracing::warn!(
                    manager_pre = pre.manager.as_str(),
                    manager_post = req.manager.as_str(),
                    pid = req.pid,
                    "pkg-event Pre/Post manager mismatch; ignoring"
                );
                return None;
            }
            let diff = diff_packages(&pre.packages, &req.packages);
            // DR-25: attribute the event to the active command window.
            // Walk ancestors of the helper pid until we hit a tracked
            // shell. If the chain doesn't include one, the event is
            // an orphan (e.g., a pkg manager invoked outside a shell
            // hook, or after the originating shell exited); log and
            // drop.
            let Some(command) = active.resolve_by_descendant(req.pid) else {
                tracing::warn!(
                    manager = req.manager.as_str(),
                    pid = req.pid,
                    installed = diff.installed.len(),
                    removed = diff.removed.len(),
                    changed = diff.changed.len(),
                    "pkg-event Post not attributable to active command window; dropping"
                );
                return Some(diff);
            };
            let kind = CaptureEventKind::PackageOp {
                manager: wire_to_planner_manager(req.manager),
                op: classify_op(&req.op_hint, &diff),
                packages_before: pre.packages.clone(),
                packages_after: req.packages.clone(),
                repo_state_hint: req.extras.get("repo_state").cloned(),
            };
            let ev = CaptureEvent {
                id: EventId(0), // sqlite assigns
                command,
                ts: crate::server::next_ts(),
                partial: false,
                kind,
            };
            match index.put_event(&ev) {
                Ok(eid) => tracing::info!(
                    manager = req.manager.as_str(),
                    pid = req.pid,
                    session = %command.session,
                    seq = command.seq,
                    %eid,
                    installed = diff.installed.len(),
                    removed = diff.removed.len(),
                    changed = diff.changed.len(),
                    op_hint = ?req.op_hint,
                    "pkg-event Post journaled (DR-25)"
                ),
                Err(e) => tracing::warn!(
                    err = %e,
                    manager = req.manager.as_str(),
                    pid = req.pid,
                    "pkg-event journal write failed"
                ),
            }
            Some(diff)
        }
    }
}

/// Map shit-proto's dep-free wire enum to the planner's
/// [`PackageManager`]. Total — no fallback needed; both enums are
/// kept in lockstep.
fn wire_to_planner_manager(w: PkgManagerWire) -> PackageManager {
    match w {
        PkgManagerWire::Apt => PackageManager::Apt,
        PkgManagerWire::Dpkg => PackageManager::Dpkg,
        PkgManagerWire::Pacman => PackageManager::Pacman,
        PkgManagerWire::Dnf => PackageManager::Dnf,
        PkgManagerWire::Brew => PackageManager::Brew,
        PkgManagerWire::Pkg => PackageManager::Pkg,
    }
}

/// Classify the op from the hook's `op_hint` first, falling back to
/// the diff shape. apt sets `op_hint="install"`/`"remove"`/etc.;
/// pacman's hook doesn't always provide one, so the shape fallback
/// matters.
fn classify_op(op_hint: &Option<String>, diff: &PkgDiff) -> PackageOpKind {
    if let Some(s) = op_hint {
        match s.as_str() {
            "install" => return PackageOpKind::Install,
            "remove" => return PackageOpKind::Remove,
            "purge" => return PackageOpKind::Purge,
            "upgrade" => return PackageOpKind::Upgrade,
            "downgrade" => return PackageOpKind::Downgrade,
            "hold" => return PackageOpKind::Hold,
            "unhold" => return PackageOpKind::Unhold,
            _ => {} // unrecognised hint; fall through to diff shape
        }
    }
    // Diff-shape fallback. `changed` (different version pre vs post)
    // dominates because an upgrade often touches dependencies too;
    // if any version moved, treat as Upgrade. Otherwise install /
    // remove based on which side is empty.
    if !diff.changed.is_empty() {
        PackageOpKind::Upgrade
    } else if !diff.installed.is_empty() && diff.removed.is_empty() {
        PackageOpKind::Install
    } else if !diff.removed.is_empty() && diff.installed.is_empty() {
        PackageOpKind::Remove
    } else {
        // Both installed and removed in the same diff — `apt
        // replace-foo-with-bar` style. Calling it Install matches
        // user intent ("I added something"); Remove would be
        // confusing.
        PackageOpKind::Install
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::{CommandId, CommandRecord, PlannerStore, TimePoint};
    use uuid::Uuid;

    fn pkgs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    fn req(phase: PkgPhase, pid: u32, packages: BTreeMap<String, String>) -> PkgEventReq {
        PkgEventReq {
            manager: shit_proto::PkgManagerWire::Apt,
            phase,
            pid,
            uid: 1000,
            packages,
            op_hint: None,
            extras: BTreeMap::new(),
        }
    }

    /// Build a temp-dir Index + an ActiveCommands tracking the
    /// current pid (so resolve_by_descendant for `req.pid =
    /// std::process::id()` finds the entry).
    fn fixture() -> (tempfile::TempDir, Index, ActiveCommands, CommandId) {
        let tmp = tempfile::tempdir().unwrap();
        let idx = Index::open(tmp.path().join("index.sqlite")).unwrap();
        let session = Uuid::nil();
        idx.put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        let command = CommandId { session, seq: 1 };
        idx.put_command(&CommandRecord {
            command,
            cmd_string: None,
            cwd: std::path::PathBuf::from("/"),
            pid: std::process::id(),
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(0, 0),
            ended_at: None,
            exit_code: None,
            event_ids: vec![],
        })
        .unwrap();
        let active = ActiveCommands::new();
        active.insert(std::process::id(), command);
        (tmp, idx, active, command)
    }

    #[test]
    fn diff_install_only() {
        let pre = pkgs(&[("bash", "5.1")]);
        let post = pkgs(&[("bash", "5.1"), ("jq", "1.7")]);
        let d = diff_packages(&pre, &post);
        assert_eq!(d.installed.get("jq").map(String::as_str), Some("1.7"));
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
    }

    #[test]
    fn diff_remove_and_upgrade() {
        let pre = pkgs(&[("bash", "5.1"), ("nano", "6.2")]);
        let post = pkgs(&[("bash", "5.2")]);
        let d = diff_packages(&pre, &post);
        assert_eq!(d.removed.get("nano").map(String::as_str), Some("6.2"));
        assert_eq!(
            d.changed.get("bash"),
            Some(&("5.1".to_string(), "5.2".to_string()))
        );
        assert!(d.installed.is_empty());
    }

    #[test]
    fn handle_pairs_pre_and_post() {
        let (_tmp, idx, active, _) = fixture();
        let stash = PkgPreStash::new();
        let pre_pkgs = pkgs(&[("bash", "5.1")]);
        let post_pkgs = pkgs(&[("bash", "5.1"), ("jq", "1.7")]);
        let pid = std::process::id();
        assert!(handle(&stash, req(PkgPhase::Pre, pid, pre_pkgs), &active, &idx).is_none());
        assert_eq!(stash.len(), 1);
        let diff = handle(&stash, req(PkgPhase::Post, pid, post_pkgs), &active, &idx)
            .expect("post returns diff");
        assert_eq!(diff.installed.len(), 1);
        assert_eq!(stash.len(), 0, "Post drains the Pre stash");
    }

    #[test]
    fn handle_orphan_post_is_dropped() {
        let (_tmp, idx, active, _) = fixture();
        let stash = PkgPreStash::new();
        let post_pkgs = pkgs(&[("jq", "1.7")]);
        // No Pre with pid=99 in the stash.
        assert!(handle(&stash, req(PkgPhase::Post, 99, post_pkgs), &active, &idx).is_none());
    }

    #[test]
    fn handle_manager_mismatch_drops_post() {
        let (_tmp, idx, active, _) = fixture();
        let stash = PkgPreStash::new();
        let pid = std::process::id();
        stash.insert_pre(req(PkgPhase::Pre, pid, pkgs(&[("bash", "5.1")])));
        let mut bad_post = req(PkgPhase::Post, pid, pkgs(&[("bash", "5.2")]));
        bad_post.manager = shit_proto::PkgManagerWire::Pacman;
        assert!(handle(&stash, bad_post, &active, &idx).is_none());
    }

    /// DR-25: a Post that pairs with a Pre and resolves to an active
    /// command writes a CaptureEvent::PackageOp under the right
    /// (session, seq).
    #[test]
    fn handle_post_writes_package_op_under_active_command() {
        let (_tmp, idx, active, command) = fixture();
        let stash = PkgPreStash::new();
        let pid = std::process::id();
        // Pre.
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, pid, pkgs(&[("bash", "5.1")])),
            &active,
            &idx,
        );
        // Post — should journal a PackageOp.
        let mut post = req(PkgPhase::Post, pid, pkgs(&[("bash", "5.1"), ("jq", "1.7")]));
        post.op_hint = Some("install".to_string());
        let _ = handle(&stash, post, &active, &idx);
        let events = idx.events_for_command(command);
        assert_eq!(events.len(), 1, "exactly one PackageOp recorded");
        match &events[0].kind {
            CaptureEventKind::PackageOp {
                manager,
                op,
                packages_before,
                packages_after,
                ..
            } => {
                assert_eq!(*manager, PackageManager::Apt);
                assert_eq!(*op, PackageOpKind::Install);
                assert!(packages_before.contains_key("bash"));
                assert!(packages_after.contains_key("jq"));
            }
            other => panic!("expected PackageOp, got {other:?}"),
        }
    }

    /// Post with no active command in the ancestor chain logs and
    /// drops (no journal write).
    #[test]
    fn handle_post_drops_when_no_active_command_in_ancestors() {
        let (_tmp, idx, active, command) = fixture();
        let stash = PkgPreStash::new();
        // Use a pid that's definitely not in the ancestry of the
        // active map's tracked shell.
        let stranger_pid = u32::MAX - 1;
        let _ = handle(
            &stash,
            req(PkgPhase::Pre, stranger_pid, pkgs(&[("bash", "5.1")])),
            &active,
            &idx,
        );
        let _ = handle(
            &stash,
            req(PkgPhase::Post, stranger_pid, pkgs(&[("jq", "1.7")])),
            &active,
            &idx,
        );
        // No event should be journaled for our command.
        assert_eq!(idx.events_for_command(command).len(), 0);
    }

    #[test]
    fn classify_op_uses_hint_when_present() {
        let diff = PkgDiff {
            installed: pkgs(&[("jq", "1.7")]),
            removed: BTreeMap::new(),
            changed: BTreeMap::new(),
        };
        assert_eq!(
            classify_op(&Some("upgrade".into()), &diff),
            PackageOpKind::Upgrade
        );
        assert_eq!(
            classify_op(&Some("purge".into()), &diff),
            PackageOpKind::Purge
        );
    }

    #[test]
    fn classify_op_falls_back_to_diff_shape() {
        let install_only = PkgDiff {
            installed: pkgs(&[("jq", "1.7")]),
            removed: BTreeMap::new(),
            changed: BTreeMap::new(),
        };
        assert_eq!(classify_op(&None, &install_only), PackageOpKind::Install);
        let remove_only = PkgDiff {
            installed: BTreeMap::new(),
            removed: pkgs(&[("jq", "1.7")]),
            changed: BTreeMap::new(),
        };
        assert_eq!(classify_op(&None, &remove_only), PackageOpKind::Remove);
        let upgrade_only = PkgDiff {
            installed: BTreeMap::new(),
            removed: BTreeMap::new(),
            changed: [("bash".to_string(), ("5.1".to_string(), "5.2".to_string()))]
                .into_iter()
                .collect(),
        };
        assert_eq!(classify_op(&None, &upgrade_only), PackageOpKind::Upgrade);
    }

    #[test]
    fn classify_op_ignores_unknown_hint_and_falls_through() {
        let diff = PkgDiff {
            installed: pkgs(&[("jq", "1.7")]),
            removed: BTreeMap::new(),
            changed: BTreeMap::new(),
        };
        // "nonsense" not in the recognised list; classifier falls
        // back to diff shape, which says Install.
        assert_eq!(
            classify_op(&Some("nonsense".into()), &diff),
            PackageOpKind::Install
        );
    }
}
