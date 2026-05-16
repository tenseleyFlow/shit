// SPDX-License-Identifier: AGPL-3.0-or-later

//! `PlannerStore` — read-only API the planner uses to fetch captured state.
//!
//! `shit-store` (S04) implements this trait against its sqlite+blob backing.
//! Tests and tooling use the in-memory implementation in [`mock`].
//!
//! The trait is intentionally minimal: queries are by `CommandId`, by
//! `(SessionId, SeqRange)`, by `InodeRef`+time, or by `Path`+time. Anything
//! richer is the planner's job to compose.

use crate::events::{CaptureEvent, CommandId, CommandRecord, EventId};
use crate::inode::{BlobHash, InodeRef};
use crate::time::{SeqRange, TimePoint};
use std::path::Path;
use uuid::Uuid;

pub trait PlannerStore {
    /// All events that belong to one command, in `(ts, EventId)` order.
    fn events_for_command(&self, command: CommandId) -> Vec<CaptureEvent>;

    /// All events in a session within `seq_range`, ordered by `(seq, ts)`.
    fn events_for_session(&self, session: Uuid, seq_range: SeqRange) -> Vec<CaptureEvent>;

    /// Every event touching this inode since `since`. Used to answer
    /// "what touched /etc/foo recently?" by way of inode resolution.
    fn events_touching_inode(&self, inode: InodeRef, since: TimePoint) -> Vec<CaptureEvent>;

    /// Every event whose `path` field equals `path` at any time at-or-before
    /// `at`. The store resolves backward through any captured renames before
    /// returning, so a query for `/foo` at time T finds events for the
    /// pre-rename `/foo` even if it's been renamed to `/bar` since.
    fn events_touching_path(&self, path: &Path, at: TimePoint) -> Vec<CaptureEvent>;

    /// Wrap the most recent command in a `session` (by `seq`) — used by
    /// `shit undo` with no arguments.
    fn latest_command_for_session(&self, session: Uuid) -> Option<CommandRecord>;

    /// Fetch one command record.
    fn command_by_id(&self, id: CommandId) -> Option<CommandRecord>;

    /// One event by id.
    fn event_by_id(&self, id: EventId) -> Option<CaptureEvent>;

    /// Confirm a blob exists in the store. Returns its (uncompressed) byte
    /// length when present. The planner uses this to refuse `RestoreContent`
    /// ops for blobs that have been GC'd.
    fn blob_size_hint(&self, hash: BlobHash) -> Option<u64>;
}

/// In-memory implementation. Useful for property tests and the planner's
/// own examples. Production stores will be sqlite-backed (S04).
pub mod mock {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct InMemoryStore {
        pub events: Vec<CaptureEvent>,
        pub commands: BTreeMap<CommandId, CommandRecord>,
        pub blobs: BTreeMap<BlobHash, u64>,
    }

    impl InMemoryStore {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn put_event(&mut self, ev: CaptureEvent) {
            self.events.push(ev);
        }

        pub fn put_command(&mut self, cmd: CommandRecord) {
            self.commands.insert(cmd.command, cmd);
        }

        pub fn put_blob(&mut self, hash: BlobHash, len: u64) {
            self.blobs.insert(hash, len);
        }
    }

    impl PlannerStore for InMemoryStore {
        fn events_for_command(&self, command: CommandId) -> Vec<CaptureEvent> {
            let mut out: Vec<_> = self
                .events
                .iter()
                .filter(|e| e.command == command)
                .cloned()
                .collect();
            out.sort_by_key(|e| (e.ts, e.id));
            out
        }

        fn events_for_session(&self, session: Uuid, seq_range: SeqRange) -> Vec<CaptureEvent> {
            let mut out: Vec<_> = self
                .events
                .iter()
                .filter(|e| e.command.session == session && seq_range.contains(e.command.seq))
                .cloned()
                .collect();
            out.sort_by_key(|e| (e.command.seq, e.ts, e.id));
            out
        }

        fn events_touching_inode(&self, inode: InodeRef, since: TimePoint) -> Vec<CaptureEvent> {
            let mut out: Vec<_> = self
                .events
                .iter()
                .filter(|e| e.ts >= since && touches_inode(&e.kind, inode))
                .cloned()
                .collect();
            out.sort_by_key(|e| (e.ts, e.id));
            out
        }

        fn events_touching_path(&self, path: &Path, at: TimePoint) -> Vec<CaptureEvent> {
            let mut out: Vec<_> = self
                .events
                .iter()
                .filter(|e| e.ts <= at && touches_path(&e.kind, path))
                .cloned()
                .collect();
            out.sort_by_key(|e| (e.ts, e.id));
            out
        }

        fn latest_command_for_session(&self, session: Uuid) -> Option<CommandRecord> {
            self.commands
                .values()
                .filter(|c| c.command.session == session)
                .max_by_key(|c| c.command.seq)
                .cloned()
        }

        fn command_by_id(&self, id: CommandId) -> Option<CommandRecord> {
            self.commands.get(&id).cloned()
        }

        fn event_by_id(&self, id: EventId) -> Option<CaptureEvent> {
            self.events.iter().find(|e| e.id == id).cloned()
        }

        fn blob_size_hint(&self, hash: BlobHash) -> Option<u64> {
            self.blobs.get(&hash).copied()
        }
    }

    fn touches_inode(kind: &crate::events::CaptureEventKind, inode: InodeRef) -> bool {
        use crate::events::CaptureEventKind as K;
        use crate::events::TreeOp as T;
        match kind {
            K::FilePreImage { inode: i, .. } | K::MetadataChange { inode: i, .. } => *i == inode,
            K::TreeOp(T::Create { inode: i, .. })
            | K::TreeOp(T::Unlink { inode: i, .. })
            | K::TreeOp(T::Rename { inode: i, .. }) => *i == inode,
            K::TreeOp(T::Link { source, .. }) => *source == inode,
            _ => false,
        }
    }

    fn touches_path(kind: &crate::events::CaptureEventKind, path: &Path) -> bool {
        use crate::events::CaptureEventKind as K;
        use crate::events::TreeOp as T;
        match kind {
            K::FilePreImage { path: p, .. } | K::MetadataChange { path: p, .. } => p == path,
            K::TreeOp(T::Create { path: p, .. })
            | K::TreeOp(T::Unlink { path: p, .. })
            | K::TreeOp(T::Link { target: p, .. })
            | K::TreeOp(T::Symlink { path: p, .. }) => p == path,
            K::TreeOp(T::Rename { from, to, .. }) => from == path || to == path,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::InMemoryStore;
    use super::*;
    use crate::events::{CaptureEventKind, TreeOp};
    use crate::metadata::FileMetadata;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn empty_meta() -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
        }
    }

    #[test]
    fn round_trips_one_event() {
        let mut s = InMemoryStore::new();
        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        s.put_event(CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(1, 5),
                path: PathBuf::from("/tmp/x"),
            }),
        });
        let fetched = s.events_for_command(cmd);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, EventId(1));
    }

    #[test]
    fn events_for_session_filters_by_seq_range() {
        let mut s = InMemoryStore::new();
        let session = Uuid::nil();
        for seq in 1..=5 {
            s.put_event(CaptureEvent {
                id: EventId(seq),
                command: CommandId { session, seq },
                ts: TimePoint::new(seq, 0),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode: InodeRef::new(1, seq),
                    path: PathBuf::from(format!("/f{seq}")),
                    blob: BlobHash::from_bytes([seq as u8; 32]),
                    meta: empty_meta(),
                    post_content_hash: None,
                },
            });
        }
        let mid = s.events_for_session(session, SeqRange::new(2, 4));
        assert_eq!(mid.len(), 2);
        assert_eq!(mid[0].command.seq, 2);
        assert_eq!(mid[1].command.seq, 3);
    }

    #[test]
    fn events_touching_inode_is_inode_keyed() {
        let mut s = InMemoryStore::new();
        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let target = InodeRef::new(1, 42);
        let unrelated = InodeRef::new(1, 99);
        for (i, inode) in [target, unrelated, target].iter().enumerate() {
            s.put_event(CaptureEvent {
                id: EventId(i as u64),
                command: cmd,
                ts: TimePoint::new(i as u64 + 1, 0),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode: *inode,
                    path: PathBuf::from("/some/path"),
                    blob: BlobHash::from_bytes([0; 32]),
                    meta: empty_meta(),
                    post_content_hash: None,
                },
            });
        }
        let hits = s.events_touching_inode(target, TimePoint::min());
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn blob_size_hint_round_trips() {
        let mut s = InMemoryStore::new();
        let h = BlobHash::from_bytes([0xAA; 32]);
        s.put_blob(h, 12345);
        assert_eq!(s.blob_size_hint(h), Some(12345));
        assert!(s.blob_size_hint(BlobHash::from_bytes([0; 32])).is_none());
    }

    #[test]
    fn latest_command_for_session_picks_max_seq() {
        let mut s = InMemoryStore::new();
        let session = Uuid::nil();
        for seq in [3u64, 1, 2] {
            s.put_command(CommandRecord {
                command: CommandId { session, seq },
                cmd_string: None,
                cwd: PathBuf::from("/"),
                pid: 0,
                shell_kind: shit_proto::ShellKind::Unknown,
                started_at: TimePoint::new(seq, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            });
        }
        let latest = s.latest_command_for_session(session).unwrap();
        assert_eq!(latest.command.seq, 3);
    }
}
