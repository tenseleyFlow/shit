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

use shit_proto::{PkgEventReq, PkgPhase};

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
/// pair with their Pre, compute a diff, and (Stage 1) log it.
///
/// Returns the diff for the caller to inspect (currently for tests
/// + tracing; planner journal write is DR-25).
pub fn handle(stash: &PkgPreStash, req: PkgEventReq) -> Option<PkgDiff> {
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
            tracing::info!(
                manager = req.manager.as_str(),
                pid = req.pid,
                installed = diff.installed.len(),
                removed = diff.removed.len(),
                changed = diff.changed.len(),
                op_hint = ?req.op_hint,
                "pkg-event Post diff computed (DR-25 will journal this)"
            );
            Some(diff)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let stash = PkgPreStash::new();
        let pre_pkgs = pkgs(&[("bash", "5.1")]);
        let post_pkgs = pkgs(&[("bash", "5.1"), ("jq", "1.7")]);
        assert!(handle(&stash, req(PkgPhase::Pre, 42, pre_pkgs)).is_none());
        assert_eq!(stash.len(), 1);
        let diff = handle(&stash, req(PkgPhase::Post, 42, post_pkgs)).expect("post returns diff");
        assert_eq!(diff.installed.len(), 1);
        assert_eq!(stash.len(), 0, "Post drains the Pre stash");
    }

    #[test]
    fn handle_orphan_post_is_dropped() {
        let stash = PkgPreStash::new();
        let post_pkgs = pkgs(&[("jq", "1.7")]);
        // No Pre with pid=99 in the stash.
        assert!(handle(&stash, req(PkgPhase::Post, 99, post_pkgs)).is_none());
    }

    #[test]
    fn handle_manager_mismatch_drops_post() {
        let stash = PkgPreStash::new();
        stash.insert_pre(req(PkgPhase::Pre, 42, pkgs(&[("bash", "5.1")])));
        let mut bad_post = req(PkgPhase::Post, 42, pkgs(&[("bash", "5.2")]));
        bad_post.manager = shit_proto::PkgManagerWire::Pacman;
        assert!(handle(&stash, bad_post).is_none());
    }
}
