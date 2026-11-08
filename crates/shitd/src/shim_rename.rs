// SPDX-License-Identifier: AGPL-3.0-or-later

//! L5 — journaling for a directory rename's walk and for the shim's
//! post-syscall rename outcome.
//!
//! The walk's file pre-images are journaled as before
//! (`ShimRenameSubtree`), now with the xattrs the shim read before the
//! syscall. One [`CaptureEventKind::RenameWalk`] follows them. It is
//! marked complete only if the shim said so and every one of the walk's
//! pre-images was journaled, so the planner can treat a complete walk as
//! the whole subtree.

use shit_planner::events::{CaptureEvent, CaptureEventKind, CommandId, EventId, WalkEntry};
use shit_planner::inode::InodeRef;
use shit_planner::metadata::{FileKind, FileMetadata};
use shit_planner::time::TimePoint;
use shit_proto::{ShimNotification, ShimRenameOutcome, ShimWalkEntry};
use shit_store::{BlobStore, Index};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use tracing::{debug, warn};

fn entry_xattrs(e: &ShimWalkEntry) -> Option<BTreeMap<String, Vec<u8>>> {
    e.xattrs.as_ref().map(|v| v.iter().cloned().collect())
}

/// Review round 3, item 3: a walk file's xattrs come from the shim or not
/// at all. Its path was renamed away by the time the daemon runs, so the
/// daemon's own read would see nothing, or another file. When the shim
/// could not read them the set is left empty, and the walk entry's
/// `xattrs_read = false` tells the planner to say so.
fn walk_file_xattrs(entry: Option<&&ShimWalkEntry>) -> BTreeMap<String, Vec<u8>> {
    entry.and_then(|e| entry_xattrs(e)).unwrap_or_default()
}

fn walk_entry(e: &ShimWalkEntry, size: u64) -> Option<WalkEntry> {
    let kind = FileKind::from_mode(e.mode)?;
    Some(WalkEntry {
        path: PathBuf::from(&e.path),
        inode: InodeRef::new(e.dev, e.inode),
        kind,
        meta: FileMetadata {
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            size,
            mtime_unix_nanos: e.mtime_unix_nanos,
            xattrs: entry_xattrs(e).unwrap_or_default(),
            acl: None,
            flags: e.flags,
        },
        xattrs_read: e.xattrs.is_some(),
    })
}

/// Journal a rename notification's walk: its file pre-images, then its
/// [`CaptureEventKind::RenameWalk`].
pub(crate) fn ingest_walk(
    note: &ShimNotification,
    command: CommandId,
    ts: TimePoint,
    index: &Index,
    blob_store: &BlobStore,
) {
    let by_path: HashMap<&str, &ShimWalkEntry> = note
        .walk
        .iter()
        .flat_map(|w| w.entries.iter())
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut journaled = 0u64;
    let mut failed = 0u64;
    for pre in &note.extra_pre_images {
        let xattrs = Some(walk_file_xattrs(by_path.get(pre.path.as_str())));
        match crate::shim_listener::ingest_pre_image_full(
            command,
            pre,
            index,
            blob_store,
            shit_planner::FilePreImageSource::ShimRenameSubtree,
            ts,
            xattrs,
        ) {
            Ok(()) => journaled += 1,
            Err(e) => {
                failed += 1;
                warn!(err = %e, pid = note.pid, path = %pre.path, "shim notify: recursive pre-image ingest failed");
            }
        }
    }
    debug!(
        pid = note.pid,
        session = %command.session,
        seq = command.seq,
        n = note.extra_pre_images.len(),
        journaled,
        failed,
        "shim notify: recursive rename pre-images ingested (DR-CR-54)"
    );
    let Some(walk) = &note.walk else {
        return;
    };
    let Some((from, _)) = note.arg.split_once('\t') else {
        return;
    };
    let sizes: HashMap<&str, u64> = note
        .extra_pre_images
        .iter()
        .map(|p| (p.path.as_str(), p.size))
        .collect();
    let entries: Vec<WalkEntry> = walk
        .entries
        .iter()
        .filter_map(|e| walk_entry(e, sizes.get(e.path.as_str()).copied().unwrap_or(0)))
        .collect();
    // The proof of a whole subtree breaks as soon as one entry is
    // missing from the journal, whatever the shim saw.
    let complete = walk.complete
        && failed == 0
        && journaled == u64::from(walk.files)
        && entries.len() == walk.entries.len()
        && entries.first().is_some_and(|e| e.path.as_os_str() == from)
        // Review round 4, item 3: a pre-image with no entry has no shim-read
        // xattrs (its set is empty, not known), so the walk cannot be
        // rebuilt from as a whole.
        && note
            .extra_pre_images
            .iter()
            .all(|p| by_path.contains_key(p.path.as_str()));
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::RenameWalk {
            root: PathBuf::from(from),
            complete,
            files: walk.files,
            entries,
        },
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, pid = note.pid, "shim notify: RenameWalk journal failed");
    }
}

/// One rename-family call, by the shim's call id: registered before the
/// pre-syscall notification is acked, filled while it is ingested, and
/// done when that ingest returns.
struct Call {
    command: CommandId,
    rename: Option<EventId>,
    refusal: Option<EventId>,
    done: bool,
    registered: std::time::Instant,
}

/// An outcome that arrived for a call the daemon has no record of.
pub(crate) struct Parked {
    pub note: ShimNotification,
}

/// Done calls and parked outcomes older than this are dropped. A failed
/// call's outcome is sent right after the syscall returns, and a
/// directory rename's right after its ingest is done, so a minute is far
/// more than either needs. Pending calls never expire: their ingest is
/// still running.
const DONE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// Parked outcomes kept at most (oldest dropped first).
const MAX_PARKED: usize = 4096;

#[derive(Default)]
struct Registry {
    calls: HashMap<u64, Call>,
    /// Done calls by when they finished, oldest first: expiry pops the
    /// front, so a burst costs O(1) per call, not a scan of the map.
    done_order: std::collections::VecDeque<(std::time::Instant, u64)>,
    parked: HashMap<u64, Parked>,
    parked_order: std::collections::VecDeque<(std::time::Instant, u64)>,
}

impl Registry {
    fn expire(&mut self) {
        let now = std::time::Instant::now();
        while let Some((at, id)) = self.done_order.front().copied() {
            if now.duration_since(at) < DONE_TTL {
                break;
            }
            self.done_order.pop_front();
            if self.calls.get(&id).is_some_and(|c| c.done) {
                self.calls.remove(&id);
            }
        }
        while let Some((at, id)) = self.parked_order.front().copied() {
            if now.duration_since(at) < DONE_TTL && self.parked.len() <= MAX_PARKED {
                break;
            }
            self.parked_order.pop_front();
            self.parked.remove(&id);
        }
    }
}

fn registry() -> &'static std::sync::Mutex<Registry> {
    static REG: std::sync::OnceLock<std::sync::Mutex<Registry>> = std::sync::OnceLock::new();
    REG.get_or_init(Default::default)
}

fn lock() -> std::sync::MutexGuard<'static, Registry> {
    registry().lock().unwrap_or_else(|e| e.into_inner())
}

/// Wakes outcomes waiting on a call.
fn changed() -> &'static tokio::sync::Notify {
    static N: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

/// Review round 3, item 6: the shim's call id is unique only within its
/// process, and its pid only within its PID namespace. Scope it by the
/// connection's peer credentials as the daemon sees them (`SO_PEERCRED`:
/// uid and the pid in the daemon's namespace), so two processes in
/// different namespaces with the same pid and counter never share a call.
/// 0 stays 0 (not a rename call).
pub(crate) fn scoped_call_id(call_id: u64, peer_uid: Option<u32>, peer_pid: Option<i32>) -> u64 {
    use std::hash::{Hash, Hasher};
    if call_id == 0 {
        return 0;
    }
    // DefaultHasher::new() is SipHash with fixed keys: stable within the
    // daemon's lifetime, which is all the registry needs.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (call_id, peer_uid, peer_pid).hash(&mut h);
    h.finish().max(1)
}

/// Review round 2, item 1: register a rename-family call before its
/// pre-syscall notification is acked, so its outcome (sent only after the
/// syscall, so after the ack) always finds it.
pub(crate) fn register_call(call_id: u64, command: CommandId) {
    if call_id == 0 {
        return;
    }
    let mut reg = lock();
    reg.expire();
    reg.calls.insert(
        call_id,
        Call {
            command,
            rename: None,
            refusal: None,
            done: false,
            registered: std::time::Instant::now(),
        },
    );
}

/// The Rename the call's notification journaled.
pub(crate) fn record_rename(call_id: u64, id: EventId) {
    if let Some(c) = lock().calls.get_mut(&call_id) {
        c.rename = Some(id);
    }
}

/// The CaptureRefused the call's notification journaled.
pub(crate) fn record_refusal(call_id: u64, id: EventId) {
    if let Some(c) = lock().calls.get_mut(&call_id) {
        c.refusal = Some(id);
    }
}

/// The call's pre-syscall ingest returned, whatever it journaled. Wakes
/// its waiting outcome, and hands back one that was parked for it.
pub(crate) fn finish_call(call_id: u64) -> Option<Parked> {
    if call_id == 0 {
        return None;
    }
    let parked = {
        let mut reg = lock();
        if let Some(c) = reg.calls.get_mut(&call_id) {
            c.done = true;
            reg.done_order
                .push_back((std::time::Instant::now(), call_id));
        }
        reg.parked.remove(&call_id)
    };
    changed().notify_waiters();
    parked
}

/// What waiting on an outcome's call came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CallWait {
    /// The call's notification was ingested; the outcome belongs to this
    /// command.
    Ready(CommandId),
    /// No record of the call: the caller parks the outcome.
    Unknown,
    /// The call's command closed and its ingest never finished within
    /// `grace` of registering: the caller journals a capture gap.
    Abandoned(CommandId),
}

/// How long after its command closes a call may still be ingesting. A
/// 50 MiB walk ingests in seconds; pip can exit before its stash's walk
/// is journaled, so closing alone is not a reason to give up.
pub(crate) const PENDING_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// The command an outcome belongs to, once its call's pre-syscall ingest
/// is done (review item 9: no second ancestor walk). Waits as long as
/// that ingest runs, with no timeout of its own (review round 2, item 1),
/// until the call's command has closed and `grace` has passed since the
/// call was registered (review round 3, item 2).
pub(crate) async fn await_call(
    call_id: u64,
    is_open: impl Fn(CommandId) -> bool,
    grace: std::time::Duration,
) -> CallWait {
    loop {
        let wake = changed().notified();
        tokio::pin!(wake);
        // Arm before checking, so a finish between the check and the
        // wait is not missed.
        wake.as_mut().enable();
        {
            let mut reg = lock();
            match reg.calls.get(&call_id) {
                None => return CallWait::Unknown,
                Some(c) if c.done => return CallWait::Ready(c.command),
                Some(c) if !is_open(c.command) && c.registered.elapsed() >= grace => {
                    let command = c.command;
                    reg.calls.remove(&call_id);
                    return CallWait::Abandoned(command);
                }
                Some(_) => {}
            }
        }
        // Re-check now and then for the command closing; a finish wakes
        // this sooner.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), wake).await;
    }
}

/// Journal a capture gap for a rename call: what its notifications said
/// could not all be journaled.
pub(crate) fn journal_gap(index: &Index, command: CommandId, path: &str, detail: &str) {
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts: crate::server::next_ts(),
        partial: false,
        kind: CaptureEventKind::CaptureRefused {
            class: "capture-gap".to_string(),
            path: PathBuf::from(path),
            detail: detail.to_string(),
        },
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, path, "shim notify: rename capture-gap journal failed");
    }
}

/// Review round 3, item 2: finishes a registered call on every way out of
/// its ingest. Dropped without [`CallGuard::finish`] (the ingest
/// panicked, or the task was cancelled), it still wakes the waiting
/// outcome and journals a capture gap for the rename's source.
pub(crate) struct CallGuard {
    call_id: u64,
    command: CommandId,
    from: String,
    index: std::sync::Arc<Index>,
    armed: bool,
}

impl CallGuard {
    pub(crate) fn new(
        call_id: u64,
        command: CommandId,
        from: &str,
        index: std::sync::Arc<Index>,
    ) -> Self {
        Self {
            call_id,
            command,
            from: from.to_string(),
            index,
            armed: true,
        }
    }

    /// The ingest returned: mark the call done and take any outcome
    /// parked for it.
    pub(crate) fn finish(mut self) -> Option<Parked> {
        self.armed = false;
        finish_call(self.call_id)
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = finish_call(self.call_id);
        journal_gap(
            &self.index,
            self.command,
            &self.from,
            "the daemon failed partway through journaling this rename's notification; \
             its walk and outcome may be incomplete",
        );
    }
}

/// Keep an outcome whose call is not known yet; [`finish_call`] hands it
/// back if the call's notification is ingested later.
pub(crate) fn park(note: ShimNotification) {
    let mut reg = lock();
    reg.expire();
    let id = note.call_id;
    reg.parked_order.push_back((std::time::Instant::now(), id));
    reg.parked.insert(id, Parked { note });
}

/// Journal a rename's post-syscall outcome, naming the Rename and refusal
/// its call journaled.
pub(crate) fn ingest_outcome(
    note: &ShimNotification,
    outcome: &ShimRenameOutcome,
    command: CommandId,
    ts: TimePoint,
    index: &Index,
) {
    let call = lock().calls.remove(&note.call_id);
    let (rename, refusal) = call.map_or((None, None), |c| (c.rename, c.refusal));
    let Some((from, to)) = note.arg.split_once('\t') else {
        debug!(pid = note.pid, arg = %note.arg, "shim notify: rename outcome without from\\tto; dropping");
        return;
    };
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::RenameOutcome {
            from: PathBuf::from(from),
            to: PathBuf::from(to),
            errno: outcome.errno,
            source: InodeRef::new(outcome.source_dev, outcome.source_inode),
            dest: InodeRef::new(outcome.dest_dev, outcome.dest_inode),
            rename,
            refusal,
        },
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, pid = note.pid, "shim notify: RenameOutcome journal failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::LiveBaseline;
    use shit_planner::store::PlannerStore;
    use shit_proto::{ShimPreImage, ShimWalk};

    fn fixture() -> (tempfile::TempDir, Index, BlobStore, CommandId) {
        use shit_planner::events::CommandRecord;
        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let blob_store = BlobStore::open(tmp.path().join("blobs")).unwrap();
        let session = uuid::Uuid::nil();
        index
            .put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        let command = CommandId { session, seq: 1 };
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("mv d t".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        (tmp, index, blob_store, command)
    }

    fn entry(path: &str, mode: u32, inode: u64) -> ShimWalkEntry {
        ShimWalkEntry {
            path: path.into(),
            dev: 64,
            inode,
            mode,
            uid: 1000,
            gid: 1000,
            mtime_unix_nanos: 7,
            flags: 0,
            xattrs: Some(vec![("user.k".into(), b"v".to_vec())]),
        }
    }

    fn pre(path: &str, bytes: &[u8], inode: u64) -> ShimPreImage {
        ShimPreImage {
            path: path.into(),
            dev: 64,
            inode,
            mode: 0o100640,
            uid: 1000,
            gid: 1000,
            size: bytes.len() as u64,
            mtime_unix_nanos: 0,
            bytes: bytes.to_vec(),
            xattr: None,
            flags: 0,
        }
    }

    fn note(walk: Option<ShimWalk>, outcome: Option<ShimRenameOutcome>) -> ShimNotification {
        ShimNotification {
            pid: 4242,
            syscall: "rename".into(),
            arg: "/tmp/l5/d\t/tmp/l5/t".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: if outcome.is_some() {
                Vec::new()
            } else {
                vec![pre("/tmp/l5/d/f", b"f", 11)]
            },
            failure: None,
            walk,
            outcome,
            pre_stat: None,
            call_id: 0,
        }
    }

    fn ingest(n: &ShimNotification) -> Vec<CaptureEventKind> {
        let (_tmp, index, blobs, command) = fixture();
        crate::shim_listener::ingest_notification_for_test(
            n,
            Some(command),
            TimePoint::new(5, 0),
            &index,
            &blobs,
            &LiveBaseline::new(),
        );
        index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn complete_walk_journals_pre_images_walk_and_rename_in_order() {
        let walk = ShimWalk {
            complete: true,
            files: 1,
            entries: vec![
                entry("/tmp/l5/d", 0o040700, 10),
                entry("/tmp/l5/d/f", 0o100640, 11),
            ],
        };
        let kinds = ingest(&note(Some(walk), None));
        assert_eq!(kinds.len(), 3, "{kinds:#?}");
        match &kinds[0] {
            CaptureEventKind::FilePreImage { meta, .. } => {
                assert_eq!(
                    meta.xattrs.get("user.k").map(Vec::as_slice),
                    Some(&b"v"[..])
                );
            }
            k => panic!("{k:?}"),
        }
        match &kinds[1] {
            CaptureEventKind::RenameWalk {
                root,
                complete,
                files,
                entries,
            } => {
                assert_eq!(root, &PathBuf::from("/tmp/l5/d"));
                assert!(complete);
                assert_eq!(*files, 1);
                assert_eq!(entries[0].kind, FileKind::Directory);
                assert_eq!(entries[0].meta.mode, 0o040700);
                assert_eq!(entries[1].meta.size, 1);
            }
            k => panic!("{k:?}"),
        }
        assert!(matches!(
            &kinds[2],
            CaptureEventKind::TreeOp(shit_planner::TreeOp::Rename { .. })
        ));
    }

    #[test]
    fn walk_whose_count_does_not_match_is_journaled_incomplete() {
        let walk = ShimWalk {
            complete: true,
            files: 2,
            entries: vec![entry("/tmp/l5/d", 0o040700, 10)],
        };
        let kinds = ingest(&note(Some(walk), None));
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                CaptureEventKind::RenameWalk {
                    complete: false,
                    ..
                }
            )),
            "{kinds:#?}"
        );
    }

    #[test]
    fn outcome_names_the_rename_and_refusal_its_call_journaled() {
        // Review items 2 and 5: the pre-syscall note (with an AU10
        // marker) and its outcome share a call id; the outcome event names
        // both rows, and no pid resolution is needed for it.
        let (_tmp, index, blobs, command) = fixture();
        let mut pre = note(None, None);
        pre.extra_pre_images.clear();
        pre.call_id = 0x1234_0000_0001;
        register_call(pre.call_id, command);
        pre.failure = Some(shit_proto::ShimFailure::CanonicalizeFailed {
            which_arg: "to".into(),
            attempted_path: "/tmp/l5/t".into(),
            error_chain: "ENOENT".into(),
        });
        crate::shim_listener::ingest_notification_for_test(
            &pre,
            Some(command),
            TimePoint::new(5, 0),
            &index,
            &blobs,
            &LiveBaseline::new(),
        );
        assert!(finish_call(pre.call_id).is_none());
        let mut post = note(
            None,
            Some(ShimRenameOutcome {
                errno: libc::ENOENT,
                source_dev: 64,
                source_inode: 10,
                dest_dev: 0,
                dest_inode: 0,
            }),
        );
        post.call_id = pre.call_id;
        let resolved = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(await_call(post.call_id, |_| true, PENDING_GRACE));
        assert_eq!(resolved, CallWait::Ready(command));
        let resolved = Some(command);
        crate::shim_listener::ingest_notification_for_test(
            &post,
            resolved,
            TimePoint::new(6, 0),
            &index,
            &blobs,
            &LiveBaseline::new(),
        );
        let events = index.events_for_command(command);
        let id_of = |pred: &dyn Fn(&CaptureEventKind) -> bool| {
            events.iter().find(|e| pred(&e.kind)).map(|e| e.id)
        };
        let refusal = id_of(&|k| matches!(k, CaptureEventKind::CaptureRefused { .. }));
        let rename = id_of(&|k| {
            matches!(
                k,
                CaptureEventKind::TreeOp(shit_planner::TreeOp::Rename { .. })
            )
        });
        assert!(refusal.is_some() && rename.is_some(), "{events:#?}");
        let outcome = events
            .iter()
            .find_map(|e| match &e.kind {
                CaptureEventKind::RenameOutcome {
                    from,
                    to,
                    errno,
                    source,
                    dest,
                    rename,
                    refusal,
                } => Some((
                    from.clone(),
                    to.clone(),
                    *errno,
                    *source,
                    *dest,
                    *rename,
                    *refusal,
                )),
                _ => None,
            })
            .expect("outcome");
        assert_eq!(
            outcome,
            (
                PathBuf::from("/tmp/l5/d"),
                PathBuf::from("/tmp/l5/t"),
                libc::ENOENT,
                InodeRef::new(64, 10),
                InodeRef::new(0, 0),
                rename,
                refusal,
            )
        );
    }

    #[test]
    fn walk_chunks_journal_pre_images_and_no_rename() {
        let mut n = note(None, None);
        n.syscall = "rename_walk".into();
        let kinds = ingest(&n);
        assert!(
            matches!(
                kinds.as_slice(),
                [CaptureEventKind::FilePreImage {
                    source: shit_planner::FilePreImageSource::ShimRenameSubtree,
                    ..
                }]
            ),
            "{kinds:#?}"
        );
    }

    /// Review round 2, item 1: a pre-call note whose ingest (a big walk)
    /// takes longer than any fixed wait must not lose its outcome.
    #[test]
    fn outcome_waits_for_a_slow_pre_call_ingest() {
        let (_tmp, _index, _blobs, command) = fixture();
        let call_id = 0x5150_0000_0001;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let got = rt.block_on(async {
            // Registered before the ack; the ingest then takes 1.5 s.
            register_call(call_id, command);
            let slow = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                record_rename(call_id, EventId(9));
                finish_call(call_id);
            });
            let got = await_call(call_id, |_| true, PENDING_GRACE).await;
            slow.await.unwrap();
            got
        });
        assert_eq!(got, CallWait::Ready(command));
        assert_eq!(
            lock().calls.get(&call_id).and_then(|c| c.rename),
            Some(EventId(9))
        );
    }

    /// An outcome for a call with no record is parked, and handed back
    /// when that call's notification is ingested.
    #[test]
    fn outcome_for_an_unknown_call_is_parked_until_its_call_finishes() {
        let call_id = 0x5150_0000_0002;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        assert_eq!(
            rt.block_on(await_call(call_id, |_| true, PENDING_GRACE)),
            CallWait::Unknown
        );
        let mut n = note(None, None);
        n.call_id = call_id;
        park(n);
        let (_tmp, _index, _blobs, command) = fixture();
        register_call(call_id, command);
        let parked = finish_call(call_id).expect("parked outcome handed back");
        assert_eq!(parked.note.call_id, call_id);
    }

    /// Review round 3, item 6: the same shim call id from two processes
    /// (different PID namespaces, same pid and counter) is two calls.
    #[test]
    fn same_call_id_from_two_peers_is_two_calls() {
        let (_tmp, _index, _blobs, command) = fixture();
        let shim_id = 0x0000_0007_0000_0001;
        let a = scoped_call_id(shim_id, Some(1000), Some(4001));
        let b = scoped_call_id(shim_id, Some(1000), Some(4002));
        assert_ne!(a, b);
        assert_eq!(a, scoped_call_id(shim_id, Some(1000), Some(4001)));
        assert_eq!(scoped_call_id(0, Some(1000), Some(4001)), 0);
        register_call(a, command);
        register_call(b, command);
        record_rename(a, EventId(1));
        record_rename(b, EventId(2));
        let reg = lock();
        assert_eq!(reg.calls.get(&a).and_then(|c| c.rename), Some(EventId(1)));
        assert_eq!(reg.calls.get(&b).and_then(|c| c.rename), Some(EventId(2)));
    }

    /// Review round 3, item 1: an outcome that arrived before its call was
    /// registered is journaled after the call's Rename once applied.
    #[test]
    fn parked_outcome_is_stamped_after_its_rename() {
        let (_tmp, index, blobs, command) = fixture();
        let call_id = 0x5150_0000_0003;
        let mut out = note(
            None,
            Some(ShimRenameOutcome {
                errno: 0,
                source_dev: 64,
                source_inode: 10,
                dest_dev: 64,
                dest_inode: 10,
            }),
        );
        out.call_id = call_id;
        // Arrived first: its arrival time is the earliest of all.
        park(out);
        let mut pre = note(None, None);
        pre.call_id = call_id;
        register_call(call_id, command);
        crate::shim_listener::ingest_notification_for_test(
            &pre,
            Some(command),
            crate::server::next_ts(),
            &index,
            &blobs,
            &LiveBaseline::new(),
        );
        let parked = finish_call(call_id).expect("parked");
        crate::shim_listener::apply_parked(
            &parked,
            Some(command),
            &index,
            &blobs,
            &LiveBaseline::new(),
        );
        let events = index.events_for_command(command);
        let ts_of = |pred: &dyn Fn(&CaptureEventKind) -> bool| {
            events.iter().find(|e| pred(&e.kind)).map(|e| e.ts).unwrap()
        };
        let rename = ts_of(&|k| {
            matches!(
                k,
                CaptureEventKind::TreeOp(shit_planner::TreeOp::Rename { .. })
            )
        });
        let outcome = ts_of(&|k| matches!(k, CaptureEventKind::RenameOutcome { .. }));
        assert!(outcome > rename, "outcome {outcome:?} rename {rename:?}");
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            CaptureEventKind::RenameOutcome {
                rename: Some(_),
                ..
            }
        )));
    }

    /// Review round 3, item 2: an ingest that panics still finishes its
    /// call and leaves a capture gap; an outcome waiting on a call whose
    /// command closed without the ingest finishing gives up.
    #[test]
    fn panicked_ingest_finishes_its_call_and_journals_a_gap() {
        let (_tmp, index, _blobs, command) = fixture();
        let index = std::sync::Arc::new(index);
        let call_id = 0x5150_0000_0004;
        register_call(call_id, command);
        let idx = index.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = CallGuard::new(call_id, command, "/tmp/l5/d", idx);
            panic!("ingest blew up");
        }));
        assert!(r.is_err());
        assert!(lock().calls.get(&call_id).is_some_and(|c| c.done));
        let gaps: Vec<_> = index
            .events_for_command(command)
            .into_iter()
            .filter(|e| matches!(&e.kind, CaptureEventKind::CaptureRefused { class, .. } if class == "capture-gap"))
            .collect();
        assert_eq!(gaps.len(), 1, "{gaps:#?}");
    }

    #[test]
    fn outcome_for_a_call_whose_command_closed_is_abandoned() {
        let (_tmp, _index, _blobs, command) = fixture();
        let call_id = 0x5150_0000_0005;
        register_call(call_id, command);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let got = rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                await_call(call_id, |_| false, std::time::Duration::ZERO),
            )
            .await
        });
        assert_eq!(got.expect("gave up in time"), CallWait::Abandoned(command));
        assert!(!lock().calls.contains_key(&call_id));
    }

    /// Review round 3, item 3: unread xattrs stay empty rather than falling
    /// back to a read of the post-rename path.
    #[test]
    fn walk_file_xattrs_never_fall_back_to_the_daemons_read() {
        let mut e = entry("/tmp/l5/d/f", 0o100640, 11);
        assert_eq!(
            walk_file_xattrs(Some(&&e)).get("user.k").map(Vec::as_slice),
            Some(&b"v"[..])
        );
        e.xattrs = None;
        assert!(walk_file_xattrs(Some(&&e)).is_empty());
        assert!(walk_file_xattrs(None).is_empty());
    }

    /// Review round 4, item 3: a walk whose pre-image has no entry (so
    /// no xattrs the shim read) is not complete.
    #[test]
    fn walk_with_a_pre_image_missing_from_its_entries_is_incomplete() {
        let walk = ShimWalk {
            complete: true,
            files: 1,
            entries: vec![entry("/tmp/l5/d", 0o040700, 10)],
        };
        let kinds = ingest(&note(Some(walk), None));
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                CaptureEventKind::RenameWalk {
                    complete: false,
                    ..
                }
            )),
            "{kinds:#?}"
        );
    }
}
