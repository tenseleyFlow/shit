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
    /// size cap exceeded). The baseline is empty and must never be
    /// promoted: BSD NOTE_WRITE is post-mutation and cannot provide a
    /// safe fallback pre-image.
    Failed,
}

/// Complete pre-command state returned by an authoritative baseline
/// promotion. Keeping this tuple together prevents callers from accidentally
/// combining pre-command bytes with metadata read after a kqueue event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselinePreImage {
    pub blob: BlobHash,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_unix_nanos: i128,
    pub xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    pub flags: u32,
}

/// Result of asking a ready baseline to promote one inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselinePromotion {
    Promoted(BaselinePreImage),
    /// The command already promoted this inode. A repeated NOTE_WRITE is
    /// harmless and must not be mistaken for a missing baseline.
    AlreadyPromoted,
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
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_unix_nanos: i128,
    /// User-namespace extended attributes captured at baseline time
    /// (W09.21 capsicum fix). Captured here in the daemon because
    /// the helper runs under `cap_enter(2)` where `extattr_*_fd` is
    /// blocked at the syscall level. See `xattr.rs` for the why.
    pub xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    /// BSD `st_flags` captured before the command started.
    pub flags: u32,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inode: InodeRef,
        blob: BlobHash,
        size: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_unix_nanos: i128,
        xattrs: std::collections::BTreeMap<String, Vec<u8>>,
        flags: u32,
    ) -> Self {
        Self {
            inode,
            blob,
            size,
            mode,
            uid,
            gid,
            mtime_unix_nanos,
            xattrs,
            flags,
            stale: false,
            stale_for_command: None,
        }
    }

    /// Mark stale on first promotion within a command and return the complete
    /// pre-command state. A repeated event for the same command is distinct
    /// from a missing inode so the caller can drop it without refusing undo.
    pub fn mark_stale(&mut self, command: CommandId) -> BaselinePromotion {
        if self.stale && self.stale_for_command == Some(command) {
            return BaselinePromotion::AlreadyPromoted;
        }
        let pre_image = BaselinePreImage {
            blob: self.blob,
            size: self.size,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime_unix_nanos: self.mtime_unix_nanos,
            xattrs: self.xattrs.clone(),
            flags: self.flags,
        };
        self.stale = true;
        self.stale_for_command = Some(command);
        BaselinePromotion::Promoted(pre_image)
    }
}

/// Per-cwd baseline cache entry. Refcounted by sessions; the cache
/// is keyed by the cwd `PathBuf` in `LiveBaseline`.
pub struct BaselineCacheEntry {
    pub cwd: PathBuf,
    pub state: RwLock<WalkState>,
    /// Command whose baseline frames currently populate this cache. Prevents
    /// two interleaved WatchTree walks for one cwd from being merged into a
    /// falsely authoritative snapshot.
    walk_command: RwLock<Option<CommandId>>,
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
            walk_command: RwLock::new(None),
            by_inode: RwLock::new(HashMap::new()),
            by_path: RwLock::new(HashMap::new()),
        }
    }

    /// Start (or continue) the baseline generation for `command`. A new walk
    /// clears every entry from the previous generation, including paths that
    /// disappeared between commands. Interleaved pending walks are refused.
    pub fn begin_walk(&self, command: CommandId) -> Result<(), CommandId> {
        let mut state = self.state.write().unwrap();
        let mut active = self.walk_command.write().unwrap();
        if *active == Some(command) {
            return Ok(());
        }
        if *state == WalkState::Pending
            && let Some(other) = *active
        {
            return Err(other);
        }
        self.by_inode.write().unwrap().clear();
        self.by_path.write().unwrap().clear();
        *state = WalkState::Pending;
        *active = Some(command);
        Ok(())
    }

    pub fn is_walk_for(&self, command: CommandId) -> bool {
        *self.walk_command.read().unwrap() == Some(command)
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
    pub fn promote(&self, inode: InodeRef, command: CommandId) -> Option<BaselinePromotion> {
        if self.state() != WalkState::Ready {
            return None;
        }
        let mut map = self.by_inode.write().unwrap();
        let entry = map.get_mut(&inode)?;
        Some(entry.mark_stale(command))
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
        self.by_inode.write().unwrap().clear();
        self.by_path.write().unwrap().clear();
    }

    pub fn state(&self) -> WalkState {
        *self.state.read().unwrap()
    }

    /// Snapshot every (path, entry) pair currently cached. Used by
    /// the daemon's PostExec xattr sweep (W09.21.1) to diff each
    /// cached file's pre-command xattrs against the live FS without
    /// holding the locks across the read.
    pub fn snapshot_entries(&self) -> Vec<(PathBuf, BaselineEntry)> {
        let by_inode = self.by_inode.read().unwrap();
        let by_path = self.by_path.read().unwrap();
        by_path
            .iter()
            .filter_map(|(p, inode)| by_inode.get(inode).map(|e| (p.clone(), e.clone())))
            .collect()
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

    /// Find the most-specific watched cwd containing `path`. This is used for
    /// kqueue events whose inode was absent from a ready baseline (normally a
    /// file created during the current command), where inode lookup cannot
    /// identify the owning cache.
    pub fn get_cwd_for_path(&self, path: &Path) -> Option<Arc<BaselineCacheEntry>> {
        let map = self.by_cwd.read().unwrap();
        map.iter()
            .filter(|(cwd, cache)| {
                path.starts_with(cwd.as_path()) && cache.state() == WalkState::Ready
            })
            .max_by_key(|(cwd, _)| cwd.components().count())
            .map(|(_, cache)| Arc::clone(cache))
    }

    pub fn cached_cwd_count(&self) -> usize {
        self.by_cwd.read().unwrap().len()
    }

    /// W09.12 — return true if `path` is inside any actively-watched
    /// cwd subtree. Used by the shim_listener to skip its
    /// fresh-create journaling branch for paths that the in-watch
    /// kqueue tier will *also* report; without this the same Create
    /// gets journaled twice (once from the shim, once from the
    /// dir-diff), and undo emits N inverse unlinks → first one
    /// succeeds, the rest fail with ConflictMissing.
    ///
    /// `path` is expected to be absolute. Caller's responsibility.
    pub fn path_in_watched_subtree(&self, path: &Path) -> bool {
        let map = self.by_cwd.read().unwrap();
        map.iter()
            .any(|(cwd, cache)| cache.state() == WalkState::Ready && path.starts_with(cwd))
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
            0o100640,
            1001,
            1002,
            1_700_000_000_123_456_789,
            std::collections::BTreeMap::new(),
            0x2,
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
        cache.mark_ready();

        // First promote within the command returns the complete baseline.
        let promote1 = cache.promote(InodeRef::new(1, 100), cmd(1));
        let Some(BaselinePromotion::Promoted(pre)) = promote1 else {
            panic!("expected first promotion");
        };
        assert_eq!(pre.blob.0, [0xAA; 32]);
        assert_eq!(pre.mode, 0o100640);
        assert_eq!(pre.uid, 1001);
        assert_eq!(pre.gid, 1002);
        assert_eq!(pre.mtime_unix_nanos, 1_700_000_000_123_456_789);
        assert_eq!(pre.flags, 0x2);
        assert!(pre.xattrs.is_empty());

        // Same command, same inode is not confused with a cache miss.
        let blob2 = cache.promote(InodeRef::new(1, 100), cmd(1));
        assert_eq!(blob2, Some(BaselinePromotion::AlreadyPromoted));
    }

    #[test]
    fn promote_for_unknown_inode_returns_none() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.mark_ready();
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
        cache.mark_ready();

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
        cache.mark_ready();

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
        cache.mark_ready();

        // Command 1 promotes.
        assert!(cache.promote(InodeRef::new(1, 100), cmd(1)).is_some());

        // Drain (simulating PostExec — but no re-baseline insert yet).
        cache.drain_stale_for(cmd(1));

        // Command 2 sees a clean entry, promotes the SAME OLD blob.
        // (In the real flow, PostExec re-baselines via insert() so
        // command 2 would see the post-command-1 content. Step 4
        // wires that in.)
        let promote2 = cache.promote(InodeRef::new(1, 100), cmd(2));
        assert!(promote2.is_some());
        let Some(BaselinePromotion::Promoted(pre)) = promote2 else {
            panic!("expected second-command promotion");
        };
        assert_eq!(pre.blob.0, [0xAA; 32]);
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

    #[test]
    fn pending_or_failed_baseline_never_promotes_and_failure_discards_entries() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.insert(PathBuf::from("/tmp/x/a"), entry(100, 0xAA));
        assert_eq!(cache.promote(InodeRef::new(1, 100), cmd(1)), None);

        cache.mark_failed();
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.promote(InodeRef::new(1, 100), cmd(1)), None);
    }

    #[test]
    fn path_lookup_ignores_failed_cache_and_chooses_most_specific_ready_cwd() {
        let baselines = LiveBaseline::new();
        let outer = baselines.entry_for_cwd(Path::new("/tmp/work"));
        outer.mark_ready();
        let inner = baselines.entry_for_cwd(Path::new("/tmp/work/nested"));
        inner.mark_ready();
        let failed = baselines.entry_for_cwd(Path::new("/tmp/failed"));
        failed.mark_failed();

        let found = baselines
            .get_cwd_for_path(Path::new("/tmp/work/nested/file"))
            .expect("ready containing cwd");
        assert!(Arc::ptr_eq(&found, &inner));
        assert!(
            baselines
                .get_cwd_for_path(Path::new("/tmp/failed/file"))
                .is_none()
        );
    }

    #[test]
    fn new_walk_replaces_prior_generation_and_interleaved_walk_is_rejected() {
        let cache = BaselineCacheEntry::new(PathBuf::from("/tmp/x"));
        cache.begin_walk(cmd(1)).unwrap();
        cache.insert(PathBuf::from("/tmp/x/old"), entry(100, 0xAA));
        assert_eq!(cache.begin_walk(cmd(2)), Err(cmd(1)));
        cache.mark_ready();

        cache.begin_walk(cmd(2)).unwrap();
        assert_eq!(cache.state(), WalkState::Pending);
        assert_eq!(cache.entry_count(), 0);
        assert!(cache.get_inode(InodeRef::new(1, 100)).is_none());
    }
}
