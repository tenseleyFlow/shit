// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tracked-tree bookkeeping for kqueue.
//!
//! On Linux the kernel knows about our tracked tree (the fanotify
//! marks are stored kernel-side). With kqueue every watched fd lives
//! userspace-side, so this struct owns the (dir-fd → watch-state)
//! mapping. Stage 1: minimal skeleton, no fd ownership yet.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::collections::HashMap;
use std::path::PathBuf;

/// Per-watch state. Stage 1: just the path. Stage 2 will add the
/// owned dir-fd, depth, and registration timestamp.
#[derive(Debug, Clone)]
pub struct WatchState {
    pub path: PathBuf,
    pub depth: u32,
}

/// In-memory map of watched paths. Mirrors `fanotify::tree::TreeMap`
/// but keyed by path (since kqueue is per-fd; we look up by path to
/// reuse the same dir-fd across watches).
#[derive(Debug, Default)]
pub struct TrackedTree {
    by_path: HashMap<PathBuf, WatchState>,
}

impl TrackedTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track(&mut self, path: PathBuf, depth: u32) {
        self.by_path
            .insert(path.clone(), WatchState { path, depth });
    }

    pub fn untrack(&mut self, path: &std::path::Path) -> bool {
        self.by_path.remove(path).is_some()
    }

    pub fn is_tracked(&self, path: &std::path::Path) -> bool {
        self.by_path.contains_key(path)
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_untrack_round_trip() {
        let mut t = TrackedTree::new();
        let p = PathBuf::from("/tmp/x");
        t.track(p.clone(), 0);
        assert!(t.is_tracked(&p));
        assert_eq!(t.len(), 1);
        assert!(t.untrack(&p));
        assert!(!t.is_tracked(&p));
    }
}
