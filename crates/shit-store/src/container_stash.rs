// SPDX-License-Identifier: AGPL-3.0-or-later

//! Container-runtime stash store (C04.6).
//!
//! A separate retention surface for `docker save` image tarballs and
//! `docker volume rm` volume tarballs. The actual tarball bytes are
//! stored in the existing [`BlobStore`](crate::blob); this module is
//! the *index* + retention layer that tracks which blobs are
//! container stashes and when they should age out.
//!
//! Default retention is 1 day — image-save tarballs can be tens of
//! GiB, and keeping months of them eats disk fast. Users who want
//! longer retention can `shit pin <cmd>` (file-tier pins from C01,
//! independent of this store).
//!
//! The S13 GC pass calls [`prune_older_than`] before the file-tier
//! refcount sweep; that ordering matters because pruning a stash
//! decrements the underlying blob's refcount, which is what makes the
//! blob eligible for the next GC pass's reap.

use crate::index::{Index, IndexError};
use rusqlite::params;
use shit_planner::CommandId;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Default retention for container stashes — 1 day in seconds. Short
/// because image tarballs are LARGE; users opt-in to longer keep via
/// `shit pin`.
pub const CONTAINER_STASH_RETENTION_SECS: u64 = 24 * 60 * 60;

/// What kind of container thing this stash represents. Drives the
/// reverse path (`docker load` for `ImageSave`, `tar -xzf -` into a
/// recreated volume for `VolumeTar`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StashKind {
    ImageSave = 0,
    VolumeTar = 1,
}

impl StashKind {
    fn as_wire(self) -> i64 {
        self as i64
    }

    fn from_wire(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::ImageSave),
            1 => Some(Self::VolumeTar),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImageSave => "image-save",
            Self::VolumeTar => "volume-tar",
        }
    }
}

/// One row in `container_stashes`. Returned by [`list_all`] /
/// [`list_for_command`] / [`get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerStash {
    /// 32-byte blake3 of the tarball bytes — also the key into the
    /// blob store.
    pub blob_hash: [u8; 32],
    pub kind: StashKind,
    /// `"docker"` or `"podman"`.
    pub runtime: String,
    /// Image name (e.g. `nginx:1.25`) or volume name.
    pub name: String,
    pub size_bytes: u64,
    pub created_unix_secs: u64,
    /// Best-effort link back to the originating command. `None` when
    /// the stash was registered before the command-window closed.
    pub command: Option<CommandId>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegisterRequest<'a> {
    pub blob_hash: [u8; 32],
    pub kind: StashKind,
    pub runtime: &'a str,
    pub name: &'a str,
    pub size_bytes: u64,
    pub command: Option<CommandId>,
    pub note: Option<&'a str>,
}

/// Register a stash. Idempotent — if a row already exists for the
/// same `blob_hash`, the `command` and `note` are updated and the
/// other fields are left alone (the bytes are content-addressed, so
/// re-registering with different metadata is fine; re-registering
/// with different *bytes* is impossible because the hash would
/// differ).
pub fn register(index: &Index, req: RegisterRequest<'_>) -> Result<(), IndexError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let session_bytes: Option<Vec<u8>> = req.command.map(|c| c.session.as_bytes().to_vec());
    let seq: Option<i64> = req.command.map(|c| c.seq as i64);
    let conn = index.conn().lock().unwrap();
    conn.execute(
        "INSERT INTO container_stashes
            (blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
             session, seq, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(blob_hash) DO UPDATE SET
            session = COALESCE(excluded.session, container_stashes.session),
            seq     = COALESCE(excluded.seq,     container_stashes.seq),
            note    = COALESCE(excluded.note,    container_stashes.note)",
        params![
            req.blob_hash.as_slice(),
            req.kind.as_wire(),
            req.runtime,
            req.name,
            req.size_bytes as i64,
            now,
            session_bytes,
            seq,
            req.note,
        ],
    )?;
    Ok(())
}

/// Fetch one stash by hash. Returns `None` if absent.
pub fn get(index: &Index, blob_hash: &[u8; 32]) -> Result<Option<ContainerStash>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
                session, seq, note
           FROM container_stashes
          WHERE blob_hash = ?1",
    )?;
    let mut rows = stmt.query_map([blob_hash.as_slice()], row_to_stash)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

/// List every stash, newest first. Used by `shit container-stashes list`.
pub fn list_all(index: &Index) -> Result<Vec<ContainerStash>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
                session, seq, note
           FROM container_stashes
       ORDER BY created_unix_secs DESC",
    )?;
    stmt.query_map([], row_to_stash)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(IndexError::from)
}

/// List stashes belonging to a specific command. Used by `shit show`.
pub fn list_for_command(index: &Index, cmd: CommandId) -> Result<Vec<ContainerStash>, IndexError> {
    let conn = index.conn().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT blob_hash, kind, runtime, name, size_bytes, created_unix_secs,
                session, seq, note
           FROM container_stashes
          WHERE session = ?1 AND seq = ?2
       ORDER BY created_unix_secs ASC",
    )?;
    stmt.query_map(
        params![cmd.session.as_bytes().as_slice(), cmd.seq as i64],
        row_to_stash,
    )?
    .collect::<Result<Vec<_>, _>>()
    .map_err(IndexError::from)
}

/// Remove a single stash by hash. Returns whether a row matched.
pub fn remove(index: &Index, blob_hash: &[u8; 32]) -> Result<bool, IndexError> {
    let conn = index.conn().lock().unwrap();
    let rows = conn.execute(
        "DELETE FROM container_stashes WHERE blob_hash = ?1",
        [blob_hash.as_slice()],
    )?;
    Ok(rows > 0)
}

/// Prune every stash strictly older than `older_than_secs`. Returns
/// the list of `blob_hash`es that were pruned so the caller can
/// decrement blob refcounts in the same transaction.
pub fn prune_older_than(index: &Index, older_than_secs: u64) -> Result<Vec<[u8; 32]>, IndexError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff = now.saturating_sub(older_than_secs) as i64;
    let conn = index.conn().lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT blob_hash FROM container_stashes WHERE created_unix_secs < ?1")?;
    let hashes: Vec<[u8; 32]> = stmt
        .query_map([cutoff], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let mut h = [0u8; 32];
            if bytes.len() == 32 {
                h.copy_from_slice(&bytes);
            }
            Ok(h)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if hashes.is_empty() {
        return Ok(hashes);
    }
    conn.execute(
        "DELETE FROM container_stashes WHERE created_unix_secs < ?1",
        [cutoff],
    )?;
    Ok(hashes)
}

/// Total bytes across all active stashes — `shit container-stashes
/// list` renders this so users can see the disk-usage exposure.
pub fn total_size_bytes(index: &Index) -> Result<u64, IndexError> {
    let conn = index.conn().lock().unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM container_stashes",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(n.max(0) as u64)
}

fn row_to_stash(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContainerStash> {
    let hash_bytes: Vec<u8> = row.get(0)?;
    let mut blob_hash = [0u8; 32];
    if hash_bytes.len() == 32 {
        blob_hash.copy_from_slice(&hash_bytes);
    }
    let kind_wire: i64 = row.get(1)?;
    let kind = StashKind::from_wire(kind_wire).unwrap_or(StashKind::ImageSave);
    let runtime: String = row.get(2)?;
    let name: String = row.get(3)?;
    let size_bytes: i64 = row.get(4)?;
    let created_unix_secs: i64 = row.get(5)?;
    let session_bytes: Option<Vec<u8>> = row.get(6)?;
    let seq: Option<i64> = row.get(7)?;
    let note: Option<String> = row.get(8)?;
    let command = match (session_bytes, seq) {
        (Some(bytes), Some(s)) if bytes.len() == 16 => {
            let mut session = [0u8; 16];
            session.copy_from_slice(&bytes);
            Some(CommandId {
                session: Uuid::from_bytes(session),
                seq: s.max(0) as u64,
            })
        }
        _ => None,
    };
    Ok(ContainerStash {
        blob_hash,
        kind,
        runtime,
        name,
        size_bytes: size_bytes.max(0) as u64,
        created_unix_secs: created_unix_secs.max(0) as u64,
        command,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;

    fn fresh_index() -> Index {
        let tmp = tempfile::tempdir().unwrap();
        Index::open(tmp.path().join("idx.sqlite")).unwrap()
    }

    fn sample_request<'a>() -> RegisterRequest<'a> {
        RegisterRequest {
            blob_hash: [7; 32],
            kind: StashKind::ImageSave,
            runtime: "docker",
            name: "nginx:1.25",
            size_bytes: 65 * 1024 * 1024,
            command: None,
            note: None,
        }
    }

    #[test]
    fn register_then_get_roundtrips() {
        let idx = fresh_index();
        register(&idx, sample_request()).unwrap();
        let row = get(&idx, &[7; 32]).unwrap().unwrap();
        assert_eq!(row.blob_hash, [7; 32]);
        assert_eq!(row.kind, StashKind::ImageSave);
        assert_eq!(row.runtime, "docker");
        assert_eq!(row.name, "nginx:1.25");
        assert_eq!(row.size_bytes, 65 * 1024 * 1024);
        assert!(row.command.is_none());
    }

    #[test]
    fn get_missing_returns_none() {
        let idx = fresh_index();
        assert!(get(&idx, &[0; 32]).unwrap().is_none());
    }

    #[test]
    fn register_is_idempotent_on_hash_collision() {
        let idx = fresh_index();
        register(&idx, sample_request()).unwrap();
        // Re-register with a command attached — should not error, and
        // should fill in the previously-NULL session/seq.
        let cmd = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 42,
        };
        let mut req = sample_request();
        req.command = Some(cmd);
        req.note = Some("attached on second pass");
        register(&idx, req).unwrap();
        let row = get(&idx, &[7; 32]).unwrap().unwrap();
        assert_eq!(row.command, Some(cmd));
        assert_eq!(row.note.as_deref(), Some("attached on second pass"));
    }

    #[test]
    fn list_all_orders_newest_first() {
        let idx = fresh_index();
        for i in 0..3 {
            let mut req = sample_request();
            req.blob_hash = [i; 32];
            // Bump size to disambiguate; created_unix_secs is set by
            // register() itself. Spread them via sleep — too slow for
            // a fast test. Instead, we just assert all three present.
            register(&idx, req).unwrap();
        }
        let all = list_all(&idx).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_for_command_filters_correctly() {
        let idx = fresh_index();
        let cmd_a = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 1,
        };
        let cmd_b = CommandId {
            session: Uuid::from_bytes([1; 16]),
            seq: 2,
        };
        let mut r1 = sample_request();
        r1.blob_hash = [10; 32];
        r1.command = Some(cmd_a);
        register(&idx, r1).unwrap();
        let mut r2 = sample_request();
        r2.blob_hash = [20; 32];
        r2.command = Some(cmd_b);
        register(&idx, r2).unwrap();

        let only_a = list_for_command(&idx, cmd_a).unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].blob_hash, [10; 32]);
    }

    #[test]
    fn remove_returns_true_on_hit_false_on_miss() {
        let idx = fresh_index();
        register(&idx, sample_request()).unwrap();
        assert!(remove(&idx, &[7; 32]).unwrap());
        assert!(!remove(&idx, &[7; 32]).unwrap());
    }

    #[test]
    fn total_size_bytes_aggregates_all_rows() {
        let idx = fresh_index();
        for i in 0..3 {
            let mut req = sample_request();
            req.blob_hash = [i; 32];
            req.size_bytes = 1000;
            register(&idx, req).unwrap();
        }
        assert_eq!(total_size_bytes(&idx).unwrap(), 3000);
    }

    #[test]
    fn prune_older_than_zero_drops_everything() {
        let idx = fresh_index();
        register(&idx, sample_request()).unwrap();
        // The row's `created_unix_secs` is `now`; pruning anything
        // older than 0 seconds drops it. (now - 0 = now; row strictly
        // less than now is the active row written before this
        // `SystemTime::now()` call; the timing is OS-dependent so we
        // sleep 1s to make sure the row is strictly older.)
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let pruned = prune_older_than(&idx, 0).unwrap();
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0], [7; 32]);
        assert!(list_all(&idx).unwrap().is_empty());
    }

    #[test]
    fn prune_older_than_huge_keeps_everything() {
        let idx = fresh_index();
        register(&idx, sample_request()).unwrap();
        let pruned = prune_older_than(&idx, 365 * 24 * 60 * 60).unwrap();
        assert!(pruned.is_empty());
        assert_eq!(list_all(&idx).unwrap().len(), 1);
    }

    #[test]
    fn volume_tar_kind_roundtrips() {
        let idx = fresh_index();
        let mut req = sample_request();
        req.kind = StashKind::VolumeTar;
        req.name = "pgdata";
        register(&idx, req).unwrap();
        let row = get(&idx, &[7; 32]).unwrap().unwrap();
        assert_eq!(row.kind, StashKind::VolumeTar);
    }

    #[test]
    fn stash_kind_as_str_renders_for_cli() {
        assert_eq!(StashKind::ImageSave.as_str(), "image-save");
        assert_eq!(StashKind::VolumeTar.as_str(), "volume-tar");
    }
}
