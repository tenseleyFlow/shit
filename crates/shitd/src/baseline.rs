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
use shit_planner::time::TimePoint;
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
    /// User-namespace extended attributes captured at baseline time
    /// (W09.21 capsicum fix). Captured here in the daemon because
    /// the helper runs under `cap_enter(2)` where `extattr_*_fd` is
    /// blocked at the syscall level. See `xattr.rs` for the why.
    pub xattrs: std::collections::BTreeMap<String, Vec<u8>>,
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
    pub fn new(
        inode: InodeRef,
        blob: BlobHash,
        size: u64,
        xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            inode,
            blob,
            size,
            xattrs,
            stale: false,
            stale_for_command: None,
        }
    }

    /// Mark stale on first promotion within a command. Returns the
    /// blob + xattrs the caller should emit in the FilePreImage's
    /// FileMetadata. Returns `None` when already stale for this
    /// command (no double-emit).
    pub fn mark_stale(
        &mut self,
        command: CommandId,
    ) -> Option<(BlobHash, std::collections::BTreeMap<String, Vec<u8>>)> {
        if self.stale && self.stale_for_command == Some(command) {
            return None;
        }
        let pre_image = self.blob;
        let xattrs = self.xattrs.clone();
        self.stale = true;
        self.stale_for_command = Some(command);
        Some((pre_image, xattrs))
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
    pub fn promote(
        &self,
        inode: InodeRef,
        command: CommandId,
    ) -> Option<(BlobHash, std::collections::BTreeMap<String, Vec<u8>>)> {
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

/// L5: one command's kernel-tier watch, as the daemon requested it.
struct CommandWatch {
    root: PathBuf,
    /// The PostExec's timestamp, once it arrived.
    closed_at: Option<TimePoint>,
    /// When the helper confirmed the watch (WatchTreeReady routed).
    ready_at: Option<TimePoint>,
    /// The shim left at least one Create to the kernel tier.
    deferred: bool,
    /// When the daemon recorded it, for the age-out.
    recorded: std::time::Instant,
    /// When its PostExec (or the session's close) arrived, for the
    /// grace period below.
    closed_instant: Option<std::time::Instant>,
}

/// L5 (review of #232 medium review, items 2 and 3): a closed watch is
/// kept this long after its close. Shim notes stamped during the command
/// can be ingested late (the next PreExec may already have been
/// handled); they are judged by this watch, and a helper failure that
/// arrives late still finds the deferred-Create flag.
const CLOSED_WATCH_GRACE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// L5 (review of #232, item 8): a watch whose PostExec never arrived (a
/// shell killed mid-command) is dropped after this long.
const COMMAND_WATCH_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// At most this many command watches are kept; the oldest go first.
const COMMAND_WATCH_CAP: usize = 4096;

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
    /// L5 (review round 4, item 2): the watch root the daemon sent the
    /// helper in `WatchTree` for each command, on every platform, and the
    /// time its PostExec closed the watch. Dropped when the helper says it
    /// cannot watch that command, [`CLOSED_WATCH_GRACE`] after it closed
    /// (PostExec or session close), after [`COMMAND_WATCH_TTL`] unclosed,
    /// or past [`COMMAND_WATCH_CAP`].
    command_roots: RwLock<HashMap<CommandId, CommandWatch>>,
    /// R3 slice B — inodes whose BaselineCaptured the daemon could not
    /// ingest, per `(session, cwd)` of the walk that sent them. The
    /// helper already counts them as baselined, so a later write in that
    /// session has no pre-write content anywhere. Cleared when a command
    /// in that session and cwd closes; at most [`MAX_FAILED_INGESTS`]
    /// inodes are kept in all.
    ingest_failed: std::sync::Mutex<FailedIngests>,
}

/// Bound on inodes kept across every scope of [`LiveBaseline`]'s failed
/// ingests. Past it a scope is marked saturated instead of growing, and
/// every inode in it counts as failed until it is cleared.
pub const MAX_FAILED_INGESTS: usize = 4096;

#[derive(Default)]
pub struct FailedIngests {
    by_scope: HashMap<(uuid::Uuid, PathBuf), FailedScope>,
    total: usize,
}

#[derive(Default)]
struct FailedScope {
    inodes: std::collections::HashSet<(u64, u64)>,
    saturated: bool,
}

impl LiveBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the baseline for `(dev, inode)`, walked for
    /// `session` in `cwd`, was not ingested.
    pub fn mark_ingest_failed(&self, session: uuid::Uuid, cwd: &Path, dev: u64, inode: u64) {
        let mut f = self.ingest_failed.lock().unwrap_or_else(|e| e.into_inner());
        let full = f.total >= MAX_FAILED_INGESTS;
        let scope = f.by_scope.entry((session, cwd.to_path_buf())).or_default();
        if scope.saturated || scope.inodes.contains(&(dev, inode)) {
            return;
        }
        if full {
            scope.saturated = true;
            return;
        }
        scope.inodes.insert((dev, inode));
        f.total += 1;
    }

    /// A later baseline for `(dev, inode)` in this scope was ingested.
    pub fn clear_ingest_inode(&self, session: uuid::Uuid, cwd: &Path, dev: u64, inode: u64) {
        let mut f = self.ingest_failed.lock().unwrap_or_else(|e| e.into_inner());
        let removed = f
            .by_scope
            .get_mut(&(session, cwd.to_path_buf()))
            .is_some_and(|scope| scope.inodes.remove(&(dev, inode)));
        if removed {
            f.total -= 1;
        }
    }

    /// A command in `session` and `cwd` closed: its walk's failures are
    /// no longer anyone's pre-image.
    pub fn clear_ingest_failed_for(&self, session: uuid::Uuid, cwd: &Path) {
        let mut f = self.ingest_failed.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(scope) = f.by_scope.remove(&(session, cwd.to_path_buf())) {
            f.total -= scope.inodes.len();
        }
    }

    /// True when a walk for `session` failed to ingest `(dev, inode)`.
    pub fn ingest_failed(&self, session: uuid::Uuid, dev: u64, inode: u64) -> bool {
        let f = self.ingest_failed.lock().unwrap_or_else(|e| e.into_inner());
        f.by_scope.iter().any(|((s, _), scope)| {
            *s == session && (scope.saturated || scope.inodes.contains(&(dev, inode)))
        })
    }

    /// Inodes kept across every scope.
    pub fn failed_ingest_entries(&self) -> usize {
        self.ingest_failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .total
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
        map.keys().any(|cwd| path.starts_with(cwd))
    }

    /// L5: the daemon asked the helper to watch `command` under `root`.
    /// Watches closed more than [`CLOSED_WATCH_GRACE`] ago, unclosed ones
    /// past [`COMMAND_WATCH_TTL`], and the oldest past the cap are
    /// dropped. A closed watch is kept through the grace period even when
    /// the session has moved on, so a late note of the closed command is
    /// still judged by it.
    ///
    /// L5 (review of #232 round 2, item 1): the root is stored canonical.
    /// The hook sends the shell's logical `$PWD`, which may run through a
    /// symlink, while the shim keys every path canonically.
    pub fn record_command_watch(&self, command: CommandId, root: PathBuf) {
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        self.record_command_watch_at(command, root, std::time::Instant::now());
    }

    fn record_command_watch_at(&self, command: CommandId, root: PathBuf, now: std::time::Instant) {
        let mut map = self.command_roots.write().unwrap();
        map.retain(|_, w| match w.closed_instant {
            Some(closed) => now.saturating_duration_since(closed) < CLOSED_WATCH_GRACE,
            None => now.saturating_duration_since(w.recorded) < COMMAND_WATCH_TTL,
        });
        while map.len() >= COMMAND_WATCH_CAP {
            let Some(oldest) = map.iter().min_by_key(|(_, w)| w.recorded).map(|(c, _)| *c) else {
                break;
            };
            map.remove(&oldest);
        }
        map.insert(
            command,
            CommandWatch {
                root,
                closed_at: None,
                ready_at: None,
                deferred: false,
                recorded: now,
                closed_instant: None,
            },
        );
    }

    /// L5 (review of #232, item 8): the session closed at `at`. Its
    /// commands' watches close too and are dropped after the grace
    /// period, like any closed watch.
    pub fn close_session_watches(&self, session: uuid::Uuid, at: TimePoint) {
        let now = std::time::Instant::now();
        for (c, w) in self.command_roots.write().unwrap().iter_mut() {
            if c.session == session {
                w.closed_at.get_or_insert(at);
                w.closed_instant.get_or_insert(now);
            }
        }
    }

    /// L5 (review round 5, item 2): `command`'s PostExec at `at` closed
    /// its watch. The root is kept: a shim note the daemon timestamped
    /// before `at` was written while the kernel tier still watched.
    pub fn close_command_watch(&self, command: CommandId, at: TimePoint) {
        if let Some(w) = self.command_roots.write().unwrap().get_mut(&command) {
            w.closed_at.get_or_insert(at);
            w.closed_instant.get_or_insert_with(std::time::Instant::now);
        }
    }

    /// L5: `command` is not watched after all (the helper failed to
    /// attach, or has no capture tier, or the WatchTree send failed).
    ///
    /// Returns true when the shim had already left Creates to the kernel
    /// tier for this command: the caller must then say they may be lost.
    pub fn forget_command_watch(&self, command: CommandId) -> bool {
        self.command_roots
            .write()
            .unwrap()
            .remove(&command)
            .is_some_and(|w| w.deferred)
    }

    /// L5 (review of #232 round 2, item 2): the helper confirmed it
    /// watches `command` (WatchTreeReady routed at `at`).
    pub fn confirm_command_watch(&self, command: CommandId, at: TimePoint) {
        if let Some(w) = self.command_roots.write().unwrap().get_mut(&command) {
            w.ready_at.get_or_insert(at);
        }
    }

    /// L5 (review of #232 round 2, item 2): may the shim leave a Create at
    /// `path`, stamped `at`, to the kernel tier? Only when the helper
    /// confirmed the watch before `at` and the path is under its root.
    /// A yes is remembered, so a later failure of that watch can be
    /// reported (see [`Self::forget_command_watch`]).
    pub fn defer_create_to_kernel(&self, command: CommandId, path: &Path, at: TimePoint) -> bool {
        let mut map = self.command_roots.write().unwrap();
        let Some(w) = map.get_mut(&command) else {
            return false;
        };
        let ok = w.ready_at.is_some_and(|r| r <= at)
            && path.starts_with(&w.root)
            && w.closed_at.is_none_or(|c| at < c);
        w.deferred |= ok;
        ok
    }

    /// L5: `path` is under the tree a kernel tier watched for `command`
    /// when the daemon timestamped the note `at`.
    pub fn command_watches(&self, command: CommandId, path: &Path, at: TimePoint) -> bool {
        self.command_roots
            .read()
            .unwrap()
            .get(&command)
            .is_some_and(|w| path.starts_with(&w.root) && w.closed_at.is_none_or(|c| at < c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Review of #232 round 2, item 2: a Create is left to the kernel tier
    /// only once the helper confirmed the watch; a failure after that
    /// reports that deferred Creates may be lost.
    #[test]
    fn creates_defer_only_to_a_confirmed_watch() {
        let lb = LiveBaseline::new();
        let c = CommandId {
            session: Uuid::from_u128(5),
            seq: 1,
        };
        let f = Path::new("/w/f");
        lb.record_command_watch_at(c, PathBuf::from("/w"), std::time::Instant::now());
        assert!(
            !lb.defer_create_to_kernel(c, f, TimePoint::new(1, 0)),
            "not ready yet"
        );
        lb.confirm_command_watch(c, TimePoint::new(2, 0));
        assert!(
            !lb.defer_create_to_kernel(c, f, TimePoint::new(1, 0)),
            "stamped before ready"
        );
        assert!(lb.defer_create_to_kernel(c, f, TimePoint::new(3, 0)));
        assert!(!lb.defer_create_to_kernel(c, Path::new("/x/f"), TimePoint::new(3, 0)));
        assert!(lb.forget_command_watch(c), "a deferred Create is reported");
        assert!(!lb.defer_create_to_kernel(c, f, TimePoint::new(4, 0)));
        lb.record_command_watch_at(c, PathBuf::from("/w"), std::time::Instant::now());
        assert!(!lb.forget_command_watch(c), "nothing deferred");
    }

    /// Review of #232 medium review, item 2: PreExec N+1 is handled
    /// before N's open_create is ingested. The note was stamped during N,
    /// so it is still left to N's confirmed watch, not journaled.
    #[test]
    fn late_create_of_a_closed_command_still_defers() {
        let lb = LiveBaseline::new();
        let n = CommandId {
            session: Uuid::from_u128(8),
            seq: 1,
        };
        let f = Path::new("/w/venv/bin/python");
        lb.record_command_watch(n, PathBuf::from("/w"));
        lb.confirm_command_watch(n, TimePoint::new(2, 0));
        lb.close_command_watch(n, TimePoint::new(10, 0));
        lb.record_command_watch(CommandId { seq: 2, ..n }, PathBuf::from("/w"));
        assert!(lb.defer_create_to_kernel(n, f, TimePoint::new(9, 0)));
        assert!(lb.forget_command_watch(n), "the deferral is still known");
    }

    /// Review of #232 round 2, item 1: a shell whose `$PWD` runs through
    /// a symlink. The shim's canonical paths are under the recorded root.
    #[test]
    fn watch_root_under_a_symlinked_cwd_matches_canonical_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().canonicalize().unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let lb = LiveBaseline::new();
        let c = CommandId {
            session: Uuid::from_u128(4),
            seq: 1,
        };
        lb.record_command_watch(c, link);
        assert!(lb.command_watches(c, &real.join("venv/bin"), TimePoint::new(1, 0)));
    }

    /// Review of #232, item 8: a closed session drops its watches; an
    /// unclosed watch ages out; the map never grows past its cap.
    #[test]
    fn command_watches_are_pruned_by_session_close_age_and_cap() {
        use std::time::{Duration, Instant};
        let lb = LiveBaseline::new();
        let s1 = Uuid::from_u128(1);
        let s2 = Uuid::from_u128(2);
        let f = Path::new("/w/f");
        let at = TimePoint::new(1, 0);
        let c1 = CommandId {
            session: s1,
            seq: 1,
        };
        let c2 = CommandId {
            session: s2,
            seq: 1,
        };
        lb.record_command_watch(c1, PathBuf::from("/w"));
        lb.record_command_watch(c2, PathBuf::from("/w"));
        lb.close_session_watches(s1, TimePoint::new(5, 0));
        // Closed at 5: a note stamped before still counts, a later one not.
        assert!(lb.command_watches(c1, f, at));
        assert!(!lb.command_watches(c1, f, TimePoint::new(6, 0)));
        assert!(lb.command_watches(c2, f, at));
        // Past the grace period the closed watch is dropped.
        lb.record_command_watch_at(
            CommandId {
                session: s2,
                seq: 9,
            },
            PathBuf::from("/w"),
            Instant::now() + CLOSED_WATCH_GRACE + Duration::from_secs(1),
        );
        assert!(!lb.command_watches(c1, f, at));

        let t0 = Instant::now();
        let old = CommandId {
            session: s1,
            seq: 2,
        };
        lb.record_command_watch_at(old, PathBuf::from("/w"), t0);
        let later = t0 + COMMAND_WATCH_TTL + Duration::from_secs(1);
        let fresh = CommandId {
            session: s2,
            seq: 2,
        };
        lb.record_command_watch_at(fresh, PathBuf::from("/w"), later);
        assert!(!lb.command_watches(old, f, at), "unclosed watch aged out");
        assert!(lb.command_watches(fresh, f, at));

        for seq in 0..(COMMAND_WATCH_CAP as u64 + 10) {
            lb.record_command_watch_at(
                CommandId {
                    session: Uuid::from_u128(1000 + u128::from(seq)),
                    seq,
                },
                PathBuf::from("/w"),
                later + Duration::from_millis(seq),
            );
        }
        assert!(lb.command_roots.read().unwrap().len() <= COMMAND_WATCH_CAP);
    }

    /// Review round 5, item 2: a closed watch still covers notes the
    /// daemon timestamped before the PostExec, and no later ones.
    #[test]
    fn closed_command_watch_covers_only_notes_from_before_the_close() {
        let lb = LiveBaseline::new();
        let c = CommandId {
            session: Uuid::from_u128(9),
            seq: 1,
        };
        let f = Path::new("/w/f");
        lb.record_command_watch(c, PathBuf::from("/w"));
        lb.close_command_watch(c, TimePoint::new(10, 0));
        assert!(lb.command_watches(c, f, TimePoint::new(9, 0)));
        assert!(!lb.command_watches(c, f, TimePoint::new(11, 0)));
        assert!(!lb.command_watches(c, Path::new("/x/f"), TimePoint::new(9, 0)));
        // Review of #232 medium review, item 2: the session's next command
        // does not drop the closed one; a late note of `c` still counts.
        let next = CommandId { seq: 2, ..c };
        lb.record_command_watch(next, PathBuf::from("/w"));
        assert!(lb.command_watches(c, f, TimePoint::new(9, 0)));
        assert!(lb.command_watches(next, f, TimePoint::new(12, 0)));
    }

    #[test]
    fn failed_ingests_are_scoped_to_session_and_cleared_at_close() {
        let lb = LiveBaseline::new();
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let cwd = Path::new("/w");
        lb.mark_ingest_failed(a, cwd, 1, 7);
        assert!(lb.ingest_failed(a, 1, 7));
        assert!(!lb.ingest_failed(b, 1, 7), "another session");
        lb.clear_ingest_failed_for(b, cwd);
        assert!(lb.ingest_failed(a, 1, 7), "another session's close");
        lb.clear_ingest_failed_for(a, Path::new("/other"));
        assert!(lb.ingest_failed(a, 1, 7), "another cwd's close");
        lb.clear_ingest_failed_for(a, cwd);
        assert!(!lb.ingest_failed(a, 1, 7), "cleared at its command's close");
    }

    #[test]
    fn failed_ingests_past_the_cap_count_every_inode() {
        let lb = LiveBaseline::new();
        let a = Uuid::from_u128(3);
        let cwd = Path::new("/w");
        for i in 0..(MAX_FAILED_INGESTS as u64 + 1) {
            lb.mark_ingest_failed(a, cwd, 1, i);
        }
        assert!(
            lb.ingest_failed(a, 9, 999_999),
            "a saturated scope covers every inode"
        );
        assert!(lb.failed_ingest_entries() <= MAX_FAILED_INGESTS);
        lb.clear_ingest_failed_for(a, cwd);
        assert!(!lb.ingest_failed(a, 9, 999_999));
    }

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
            std::collections::BTreeMap::new(),
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

        // First promote within the command: returns (blob, xattrs).
        let promote1 = cache.promote(InodeRef::new(1, 100), cmd(1));
        assert!(promote1.is_some());
        let (blob1, xattrs1) = promote1.unwrap();
        assert_eq!(blob1.0, [0xAA; 32]);
        assert!(xattrs1.is_empty());

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
        let promote2 = cache.promote(InodeRef::new(1, 100), cmd(2));
        assert!(promote2.is_some());
        assert_eq!(promote2.unwrap().0.0, [0xAA; 32]);
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
