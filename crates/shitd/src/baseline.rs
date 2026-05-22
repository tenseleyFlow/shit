// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live in-memory pre-image baseline for BSD capture (W02.B.live-baseline).
//!
//! ## Why this exists
//!
//! kqueue's `NOTE_WRITE` fires AFTER a write completes, which means
//! the existing pre-image reader (S24.4) reads post-write content
//! for any in-place write (vim's `O_WRONLY|O_CREAT` overwrite,
//! shell `echo >`, `dd of=`, ...). The "pre-image" stored in the
//! journal is then the modified bytes; `shit undo` becomes a no-op.
//!
//! This module holds a **content snapshot** of every regular file
//! in a watched cwd, populated once at first PreExec for that cwd
//! (or eagerly by a helper-side walker — wired in step 2). On
//! NOTE_WRITE for a tracked inode, the daemon promotes the cached
//! blob into a `FilePreImage` event for the current command. The
//! pre-image is now genuinely pre-write — because we captured it
//! BEFORE the command started.
//!
//! See `.docs/sprints/W/W02.B.live-baseline.md` for the full design,
//! including position in the 4-layer strategy (ZFS / live-baseline /
//! NOTE_WRITE / LD_PRELOAD) and the layer this fits into.
//!
//! ## Scope of this file
//!
//! Step 1 of the implementation plan: the in-memory state machine
//! and its invariants. No walker, no IPC wire, no integration with
//! the server's hook handlers yet. Subsequent steps plug those in
//! around this core.

// Step 1 lands the data structures + invariants in isolation.
// Step 3 (server.rs integration) and step 4 (PostExec re-baseline)
// will reference every item here. Remove this allow once those land.
#![allow(dead_code)]

use shit_planner::events::CommandId;
use shit_planner::inode::{BlobHash, InodeRef};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Lifecycle state of a cwd's baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkState {
    /// Walker hasn't reached this cwd yet, or is still scanning it.
    /// `promote()` calls on a Pending baseline must `wait_ready()`
    /// up to a bounded deadline before proceeding.
    Pending,
    /// Walker finished; the baseline is authoritative for the
    /// inodes it observed at session-open time.
    Ready,
    /// Walker failed (permission error, filesystem disappeared,
    /// size cap exceeded). The baseline is empty; pre-image
    /// capture falls back to layer 3 (S24.4 NOTE_WRITE read).
    Failed,
}

/// One entry per (cwd, inode) pair. Sized to be cheap to clone for
/// `promote()` since we hand its `blob` reference to the journal.
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub inode: InodeRef,
    /// Content hash of the file as observed at baseline time.
    pub blob: BlobHash,
    /// File size in bytes at baseline time. Used to detect rapid
    /// reuse (delete + recreate at same path with different
    /// content) — if the inode has the same number but size or
    /// blob differ at PostExec, we re-baseline.
    pub size: u64,
    /// True from the first `promote()` of this inode within a
    /// command's window until the next PostExec re-baseline. While
    /// stale the entry's `blob` is no longer the live pre-image
    /// — it's whatever the command wrote. The original blob is
    /// still in the blob store, referenced by the FilePreImage
    /// event emitted at promotion.
    pub stale: bool,
    /// Which command flipped this entry stale. Subsequent
    /// promotions within the same command are no-ops (we've
    /// already emitted FilePreImage for this inode this command).
    pub stale_for_command: Option<CommandId>,
}

impl BaselineEntry {
    pub fn new(inode: InodeRef, blob: BlobHash, size: u64) -> Self {
        Self {
            inode,
            blob,
            size,
            stale: false,
            stale_for_command: None,
        }
    }

    /// Mark stale on first promotion within a command. Returns the
    /// blob the caller should emit as FilePreImage. Returns `None`
    /// when already stale for this command (no double-emit).
    pub fn mark_stale(&mut self, command: CommandId) -> Option<BlobHash> {
        if self.stale && self.stale_for_command == Some(command) {
            return None;
        }
        let pre_image = self.blob;
        self.stale = true;
        self.stale_for_command = Some(command);
        Some(pre_image)
    }
}

/// Per-cwd baseline cache entry. Refcounted by sessions; the cache
/// is keyed by the cwd `PathBuf` in `LiveBaseline`.
pub struct BaselineCacheEntry {
    pub cwd: PathBuf,
    pub state: RwLock<WalkState>,
    /// Inode-keyed map. NOTE_WRITE arrives with a path; we look up
    /// the inode via `stat()` (cheap) and dispatch here.
    pub by_inode: RwLock<HashMap<InodeRef, BaselineEntry>>,
    /// Path-keyed secondary index. Pure optimization; `by_inode` is
    /// authoritative. Useful for NOTE_RENAME bookkeeping and for
    /// quick "is this path tracked?" probes.
    pub by_path: RwLock<HashMap<PathBuf, InodeRef>>,
}

impl BaselineCacheEntry {
    fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            state: RwLock::new(WalkState::Pending),
            by_inode: RwLock::new(HashMap::new()),
            by_path: RwLock::new(HashMap::new()),
        }
    }

    /// Insert (or refresh) a baseline entry for `path → inode`.
    /// Called by the walker (step 2) and by PostExec re-baseline
    /// (step 4).
    pub fn insert(&self, path: PathBuf, entry: BaselineEntry) {
        let inode = entry.inode;
        self.by_inode.write().unwrap().insert(inode, entry);
        self.by_path.write().unwrap().insert(path, inode);
    }

    /// Look up by inode. Returns a clone — callers don't hold the
    /// lock across the FilePreImage emit.
    pub fn get_inode(&self, inode: InodeRef) -> Option<BaselineEntry> {
        self.by_inode.read().unwrap().get(&inode).cloned()
    }

    /// Promote a baseline entry for the given inode into a pre-image
    /// for `command`. Returns the blob hash to emit, or `None` if
    /// the entry is missing OR already stale for this command.
    ///
    /// Caller is responsible for emitting the actual FilePreImage
    /// event; this method only flips the in-memory state.
    pub fn promote(&self, inode: InodeRef, command: CommandId) -> Option<BlobHash> {
        let mut map = self.by_inode.write().unwrap();
        let entry = map.get_mut(&inode)?;
        entry.mark_stale(command)
    }

    /// PostExec sweep: clear the stale flag on entries that flipped
    /// during `command`. The caller is responsible for re-reading
    /// the file content and `insert`ing a refreshed entry — that
    /// happens in step 4 once we have the walker primitives.
    /// Returns the list of inodes that need refresh.
    pub fn drain_stale_for(&self, command: CommandId) -> Vec<InodeRef> {
        let mut map = self.by_inode.write().unwrap();
        let mut needs_refresh = Vec::new();
        for (inode, entry) in map.iter_mut() {
            if entry.stale_for_command == Some(command) {
                needs_refresh.push(*inode);
                entry.stale = false;
                entry.stale_for_command = None;
                // Note: the entry's blob is still the OLD content
                // until the walker re-reads. The caller must call
                // `insert` to overwrite with fresh content before
                // any next PreExec writes can promote.
            }
        }
        needs_refresh
    }

    /// Mark the walker as finished. Future `promote()` calls don't
    /// need to wait.
    pub fn mark_ready(&self) {
        *self.state.write().unwrap() = WalkState::Ready;
    }

    /// Mark the walker as failed. Future `promote()` calls return
    /// `None` immediately (no baseline available; fall back to
    /// layer 3).
    pub fn mark_failed(&self) {
        *self.state.write().unwrap() = WalkState::Failed;
    }

    pub fn state(&self) -> WalkState {
        *self.state.read().unwrap()
    }

    pub fn entry_count(&self) -> usize {
        self.by_inode.read().unwrap().len()
    }
}

/// Daemon-wide live baseline state. One per shitd instance. Holds
/// per-cwd cache entries indexed by absolute path.
///
/// Cwd path is the natural key because PreExec's `WatchTree`
/// payload carries the cwd path (B05.10) and the walker scans
/// from there. Two sessions in the same cwd share the cache
/// entry (refcount); the walk runs once for both.
#[derive(Default)]
pub struct LiveBaseline {
    by_cwd: RwLock<HashMap<PathBuf, Arc<BaselineCacheEntry>>>,
}

impl LiveBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the cache entry for `cwd`. Newly-created
    /// entries are `Pending` — the caller (step 2 wiring) is
    /// expected to dispatch the walker.
    pub fn entry_for_cwd(&self, cwd: &Path) -> Arc<BaselineCacheEntry> {
        // Fast path: read-only lookup.
        if let Some(existing) = self.by_cwd.read().unwrap().get(cwd) {
            return Arc::clone(existing);
        }
        // Slow path: take the write lock and double-check.
        let mut map = self.by_cwd.write().unwrap();
        if let Some(existing) = map.get(cwd) {
            return Arc::clone(existing);
        }
        let new = Arc::new(BaselineCacheEntry::new(cwd.to_path_buf()));
        map.insert(cwd.to_path_buf(), Arc::clone(&new));
        new
    }

    /// Look up an existing cache entry without creating one.
    /// Returns `None` if no walker has been dispatched for this cwd
    /// yet. Used by the NOTE_WRITE handler — if no baseline exists
    /// for a path's cwd, capture falls back to layer 3.
    pub fn get_cwd(&self, cwd: &Path) -> Option<Arc<BaselineCacheEntry>> {
        self.by_cwd.read().unwrap().get(cwd).cloned()
    }

    /// Drop the cache entry for a cwd. Called when the last
    /// referencing session closes AND a memory-pressure policy
    /// decides to evict. Initial implementation never evicts;
    /// kept here so step 1 has the surface area in place.
    pub fn drop_cwd(&self, cwd: &Path) -> bool {
        self.by_cwd.write().unwrap().remove(cwd).is_some()
    }

    /// Find the cache entry (across all cwds) that owns a given
    /// `(dev, inode)` pair. The CapturedPreImage handler uses this
    /// to swap the helper's post-write blob for the baseline's
    /// genuine pre-write blob.
    ///
    /// O(N) over cached cwds × M entries per cwd. In practice N
    /// is small (1–2 active dirs per user session) and the by_inode
    /// HashMap is O(1) per cwd. Fine for v1; revisit if telemetry
    /// shows we routinely have dozens of cwds cached at once.
    pub fn get_cwd_for_inode(&self, dev: u64, inode: u64) -> Option<Arc<BaselineCacheEntry>> {
        let inode_ref = shit_planner::InodeRef::new(dev, inode);
        let map = self.by_cwd.read().unwrap();
        for entry in map.values() {
            if entry.by_inode.read().unwrap().contains_key(&inode_ref) {
                return Some(Arc::clone(entry));
            }
        }
        None
    }

    pub fn cached_cwd_count(&self) -> usize {
        self.by_cwd.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    fn entry(inode_num: u64, blob_byte: u8) -> BaselineEntry {
        BaselineEntry::new(
            InodeRef::new(1, inode_num),
            BlobHash::from_bytes([blob_byte; 32]),
            42,
        )
    }

    #[test]
    fn cache_entry_starts_pending_empty() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        assert_eq!(cache.state(), WalkState::Pending);
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn insert_then_lookup_by_inode() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        let e = entry(100, 0xAA);
        cache.insert(PathBuf::from("/tmp/x/foo"), e.clone());
        let got = cache.get_inode(InodeRef::new(1, 100)).unwrap();
        assert_eq!(got.blob, e.blob);
        assert!(!got.stale);
    }

    #[test]
    fn promote_returns_blob_first_time_only() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.insert(PathBuf::from("/tmp/x/foo"), entry(100, 0xAA));

        // First promote within the command: returns the blob.
        let blob1 = cache.promote(InodeRef::new(1, 100), cmd(1));
        assert!(blob1.is_some());
        assert_eq!(blob1.unwrap().0, [0xAA; 32]);

        // Same command, same inode: returns None (no double-emit).
        let blob2 = cache.promote(InodeRef::new(1, 100), cmd(1));
        assert!(blob2.is_none());
    }

    #[test]
    fn promote_for_unknown_inode_returns_none() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        // No insert.
        let blob = cache.promote(InodeRef::new(1, 100), cmd(1));
        assert!(blob.is_none());
    }

    #[test]
    fn drain_stale_for_command_clears_flag_and_lists_inodes() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.insert(PathBuf::from("/tmp/x/a"), entry(100, 0xAA));
        cache.insert(PathBuf::from("/tmp/x/b"), entry(200, 0xBB));
        cache.insert(PathBuf::from("/tmp/x/c"), entry(300, 0xCC));

        // Flip 100 and 300 stale for command 1; 200 stays clean.
        cache.promote(InodeRef::new(1, 100), cmd(1));
        cache.promote(InodeRef::new(1, 300), cmd(1));

        let mut got = cache.drain_stale_for(cmd(1));
        got.sort_by_key(|i| i.inode);
        assert_eq!(got, vec![InodeRef::new(1, 100), InodeRef::new(1, 300)]);

        // Stale flag cleared; the entries can be re-promoted by a
        // future command after re-baseline.
        let entry_a = cache.get_inode(InodeRef::new(1, 100)).unwrap();
        assert!(!entry_a.stale);
        assert_eq!(entry_a.stale_for_command, None);
    }

    #[test]
    fn drain_stale_only_returns_command_specific_entries() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.insert(PathBuf::from("/tmp/x/a"), entry(100, 0xAA));
        cache.insert(PathBuf::from("/tmp/x/b"), entry(200, 0xBB));

        cache.promote(InodeRef::new(1, 100), cmd(1));
        cache.promote(InodeRef::new(1, 200), cmd(2));

        let got_for_1 = cache.drain_stale_for(cmd(1));
        assert_eq!(got_for_1, vec![InodeRef::new(1, 100)]);

        // 200 still stale (under command 2).
        let entry_b = cache.get_inode(InodeRef::new(1, 200)).unwrap();
        assert!(entry_b.stale);
        assert_eq!(entry_b.stale_for_command, Some(cmd(2)));
    }

    #[test]
    fn second_command_can_repromote_after_drain() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.insert(PathBuf::from("/tmp/x/a"), entry(100, 0xAA));

        // Command 1 promotes.
        assert!(cache.promote(InodeRef::new(1, 100), cmd(1)).is_some());

        // Drain (simulating PostExec — but no re-baseline insert yet).
        cache.drain_stale_for(cmd(1));

        // Command 2 sees a clean entry, promotes the SAME OLD blob.
        // (In the real flow, PostExec re-baselines via insert() so
        // command 2 would see the post-command-1 content. Step 4
        // wires that in.)
        let blob2 = cache.promote(InodeRef::new(1, 100), cmd(2));
        assert!(blob2.is_some());
        assert_eq!(blob2.unwrap().0, [0xAA; 32]);
    }

    #[test]
    fn live_baseline_get_or_create_returns_same_arc() {
        let lb = LiveBaseline::new();
        let cwd = PathBuf::from("/tmp/repo");
        let a = lb.entry_for_cwd(&cwd);
        let b = lb.entry_for_cwd(&cwd);
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(lb.cached_cwd_count(), 1);
    }

    #[test]
    fn live_baseline_separate_cwds_separate_entries() {
        let lb = LiveBaseline::new();
        let a = lb.entry_for_cwd(Path::new("/tmp/repo"));
        let b = lb.entry_for_cwd(Path::new("/tmp/other"));
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(lb.cached_cwd_count(), 2);
    }

    #[test]
    fn get_cwd_returns_none_when_no_walker_started() {
        let lb = LiveBaseline::new();
        assert!(lb.get_cwd(Path::new("/tmp/never-walked")).is_none());
    }

    #[test]
    fn drop_cwd_removes_entry() {
        let lb = LiveBaseline::new();
        let cwd = PathBuf::from("/tmp/repo");
        lb.entry_for_cwd(&cwd);
        assert_eq!(lb.cached_cwd_count(), 1);
        assert!(lb.drop_cwd(&cwd));
        assert_eq!(lb.cached_cwd_count(), 0);
        assert!(!lb.drop_cwd(&cwd));
    }

    #[test]
    fn walker_state_transitions() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        assert_eq!(cache.state(), WalkState::Pending);
        cache.mark_ready();
        assert_eq!(cache.state(), WalkState::Ready);
        // Failed transition is allowed too (e.g., partial walk + error).
        cache.mark_failed();
        assert_eq!(cache.state(), WalkState::Failed);
    }
}
