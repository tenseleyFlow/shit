// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR06.5 — synchronous pre-stash handler for shell stream redirects.
//!
//! The shell hook parses `cmd > file` / `tee file` / `dd of=file` via
//! [`shit_shell::redirect::parse_redirects`] BEFORE the shell performs
//! `open(O_TRUNC)`, and ships each destination as a
//! [`shit_proto::RedirectTargetWire`] inside a
//! [`shit_proto::CtlRequest::PreStashRedirects`]. We hash + stash the
//! file's bytes here, journal one
//! [`CaptureEventKind::FilePreImage`] per target keyed to the open
//! command window, then ack so the shell unblocks and lets the redirect
//! through. The planner picks up the `FilePreImage` event on undo and
//! emits `InverseOp::RestoreContent`, restoring the bytes that the
//! shell's truncation was about to discard.
//!
//! ## Append vs Truncate
//!
//! Truncate-class operators (`>`, `>|`, `2>`, `&>`, `tee` without
//! `-a`, `dd of=`) journal a [`CaptureEventKind::FilePreImage`] with
//! the file's full pre-content blob; inverse is `RestoreContent` via
//! tmpfile-rename.
//!
//! Append-class operators (`>>`, `tee -a`, `&>>`) journal a
//! [`CaptureEventKind::FileAppendPreStash`] with only the file's
//! pre-size (no blob — the bytes that need restoring are still on
//! disk in `[0..pre_size]`); inverse is `FileExtend { truncate_to:
//! pre_size }` via `ftruncate(2)`. AU27 / DR-CR-55 closed this.

use crate::active_commands::ActiveCommands;
use shit_planner::CommandId;
use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inode::InodeRef;
use shit_planner::metadata::FileMetadata;
use shit_proto::{
    CtlResponse, PreStashRedirectError, PreStashRedirectsResult, RedirectOpWire, RedirectTargetWire,
};
use shit_store::{BlobStore, Index};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::debug;
use uuid::Uuid;

/// Handle a `CtlRequest::PreStashRedirects`. Returns the wire response.
///
/// The handler is best-effort per target: a failure on one target
/// (file missing, permission denied, EISDIR, etc.) is recorded in
/// `errors` and the next target is still attempted. The shell ignores
/// per-target errors on purpose — a missed pre-stash falls back to
/// kernel-tier capture for the same path, which is acceptable
/// degradation. A torpedoing top-level `Error` would block the shell
/// instead.
pub fn handle(
    session: Uuid,
    command_seq: u64,
    targets: Vec<RedirectTargetWire>,
    active: &ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
) -> CtlResponse {
    let command = CommandId {
        session,
        seq: command_seq,
    };
    // We do NOT consult `active` for the lookup -- the shell hook
    // tells us the command directly. We DO use it as an attribution
    // sanity check (orphan PreStashRedirects with no matching active
    // command means the shell sent us this after PostExec; we
    // accept the journal but emit a debug breadcrumb).
    if active.tracked_shell_count() == 0 {
        debug!(
            session = %session,
            command_seq,
            "PreStashRedirects with no active commands; journaling anyway"
        );
    }

    let mut stashed: u32 = 0;
    let mut errors: Vec<PreStashRedirectError> = Vec::new();
    for target in targets {
        match stash_one(&target, command, index, blob_store) {
            Ok(StashOutcome::Stashed) => stashed += 1,
            Ok(StashOutcome::Skipped) => {} // fresh-create case; not an error, not a stash
            Err(reason) => errors.push(PreStashRedirectError {
                path: target.path.clone(),
                reason,
            }),
        }
    }
    CtlResponse::PreStashRedirectsAck(PreStashRedirectsResult { stashed, errors })
}

enum StashOutcome {
    Stashed,
    /// File didn't exist (fresh-create); nothing to pre-stash but
    /// not a failure either.
    Skipped,
}

fn stash_one(
    target: &RedirectTargetWire,
    command: CommandId,
    index: &Index,
    blob_store: &BlobStore,
) -> Result<StashOutcome, String> {
    match target.op {
        RedirectOpWire::Truncate | RedirectOpWire::TeeTruncate | RedirectOpWire::DdOf => {
            stash_truncate(target.path.as_str(), command, index, blob_store)
        }
        RedirectOpWire::Append | RedirectOpWire::TeeAppend => {
            // AU27 — Append/TeeAppend capture journals only the
            // pre-size (no blob); inverse is FileExtend which
            // truncates the file back at undo time. The bytes that
            // need restoring are still on disk in [0..pre_size]; the
            // appended bytes [pre_size..] get discarded by the
            // truncate.
            stash_append(target.path.as_str(), command, index)
        }
    }
}

fn stash_append(path_str: &str, command: CommandId, index: &Index) -> Result<StashOutcome, String> {
    let path = Path::new(path_str);
    // Fresh-file fast-path: `echo X >> /tmp/new.log` on a
    // non-existent target. There's no pre-state to truncate
    // back to. AR05.1-style fresh-create journaling could
    // emit a TreeOp::Create here; deferred to a sibling
    // sprint.
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "append target absent; nothing to pre-stash");
            return Ok(StashOutcome::Skipped);
        }
        Err(e) => return Err(format!("stat: {e}")),
    };
    // Same special-file defense as stash_truncate — only
    // regular files have a pre_size that means "truncate-back."
    if !meta.file_type().is_file() {
        return Err(format!("not a regular file ({:?})", meta.file_type()));
    }
    // Empty file fast-path: appending to a 0-byte file. Truncate
    // back would be a no-op (already 0 bytes after the inverse
    // runs IFF the truncate is the only inverse). Skip the
    // journal entry; no work, no event.
    if meta.size() == 0 {
        debug!(path = %path.display(), "append target empty; nothing to pre-stash");
        return Ok(StashOutcome::Skipped);
    }
    let ts = crate::server::next_ts();
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FileAppendPreStash {
            inode: InodeRef::new(meta.dev(), meta.ino()),
            path: PathBuf::from(path),
            pre_size: meta.size(),
        },
    };
    index
        .put_event(&event)
        .map_err(|e| format!("put_event: {e}"))?;
    debug!(
        path = %path.display(),
        pre_size = meta.size(),
        session = %command.session,
        seq = command.seq,
        "append pre-stashed"
    );
    Ok(StashOutcome::Stashed)
}

fn stash_truncate(
    path_str: &str,
    command: CommandId,
    index: &Index,
    blob_store: &BlobStore,
) -> Result<StashOutcome, String> {
    let path = Path::new(path_str);
    // If the file doesn't exist yet, there's nothing to pre-stash —
    // the redirect is a fresh-create. We could journal a Tree::Create
    // here so undo unlinks the newly-created file, but for AR06.5
    // we focus on the "clobber existing file" race. Fresh-create
    // covered by separate AR06.5 follow-up; today we just skip
    // cleanly (no error -- not a failure).
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "redirect target absent; nothing to pre-stash");
            return Ok(StashOutcome::Skipped);
        }
        Err(e) => return Err(format!("stat: {e}")),
    };
    // Refuse symlinks, FIFOs, sockets, devices — only regular files
    // have content worth restoring. Pre-stashing a /dev path was
    // already filtered at the shell-side parser (is_special_path),
    // but we defense-in-depth here too.
    if !meta.file_type().is_file() {
        return Err(format!("not a regular file ({:?})", meta.file_type()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let (blob_hash, stat) = blob_store
        .put(&bytes)
        .map_err(|e| format!("blob put: {e}"))?;
    let ts = crate::server::next_ts();
    index
        .put_blob_record(blob_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| format!("put_blob_record: {e}"))?;
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode: InodeRef::new(meta.dev(), meta.ino()),
            path: PathBuf::from(path),
            blob: blob_hash,
            meta: FileMetadata {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                size: meta.size(),
                mtime_unix_nanos: mtime_unix_nanos(&meta),
                xattrs: BTreeMap::new(),
                acl: None,
            },
            // post_content_hash is None — we run pre-syscall and don't
            // see what bytes the about-to-run command will write.
            // Matches the shim's pre-image journaling.
            post_content_hash: None,
            // AR06.5 shell pre-stash: bytes captured at PreExec time,
            // before the user's command ran. Same guarantee as
            // W02.B's LiveBaseline promote.
            source: shit_planner::FilePreImageSource::BaselineCachePromote,
        },
    };
    index
        .put_event(&event)
        .map_err(|e| format!("put_event: {e}"))?;
    debug!(
        path = %path.display(),
        size = meta.size(),
        session = %command.session,
        seq = command.seq,
        "redirect pre-stashed"
    );
    Ok(StashOutcome::Stashed)
}

fn mtime_unix_nanos(meta: &std::fs::Metadata) -> i128 {
    let secs = meta.mtime() as i128;
    let nanos = meta.mtime_nsec() as i128;
    secs * 1_000_000_000 + nanos
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::events::{CaptureEventKind, CommandRecord};
    use shit_planner::store::PlannerStore;
    use shit_planner::time::TimePoint;
    use std::io::Write;
    use tempfile::TempDir;

    fn fresh_session() -> Uuid {
        // The workspace uuid feature-set is v7 + serde (no v4). v7 is
        // monotonic + unique enough for test isolation.
        let ts = uuid::Timestamp::now(uuid::NoContext);
        Uuid::new_v7(ts)
    }

    fn fresh() -> (TempDir, BlobStore, Index, ActiveCommands) {
        let dir = TempDir::new().unwrap();
        let blob_store = BlobStore::open(dir.path().join("blobs")).unwrap();
        let index = Index::open(dir.path().join("db.sqlite")).unwrap();
        (dir, blob_store, index, ActiveCommands::new())
    }

    /// Register the (session, command) so FK constraints on `events`
    /// are satisfied — the real daemon does this via the PreExec
    /// hook path before any pre-stash arrives.
    fn register_command(index: &Index, cmd: CommandId) {
        index
            .put_session(cmd.session, "bash", 0, None, TimePoint::new(0, 0))
            .expect("put_session");
        index
            .put_command(&CommandRecord {
                command: cmd,
                cmd_string: Some("test".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .expect("put_command");
    }

    fn write_file(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[test]
    fn truncate_target_journaled_as_file_pre_image() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "probe.txt", b"original v1\n");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: path.to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 1, "expected 1 stashed, got {}", r.stashed);
                assert!(r.errors.is_empty(), "unexpected errors: {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        // Verify the FilePreImage event landed in the index keyed to
        // our command.
        let evs = index.events_for_command(cmd);
        assert_eq!(evs.len(), 1, "expected 1 event, got {}", evs.len());
        match &evs[0].kind {
            CaptureEventKind::FilePreImage { path: p, .. } => {
                assert_eq!(p, &path);
            }
            other => panic!("expected FilePreImage, got {other:?}"),
        }
    }

    #[test]
    fn missing_target_is_not_an_error() {
        let (dir, blob_store, index, active) = fresh();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: dir.path().join("nope.txt").to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                // Missing file is a no-op success (fresh-create case).
                // stashed=0 (nothing to capture) and errors empty.
                assert_eq!(r.stashed, 0);
                assert!(r.errors.is_empty(), "unexpected errors: {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// AU27 — Append targets are no longer deferred. The
    /// stash_append path journals a FileAppendPreStash event
    /// with the file's pre_size; the planner emits
    /// `InverseOp::FileExtend` from that event.
    #[test]
    fn append_target_stashes_pre_size() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "log.txt", b"old\n");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Append,
                path: path.to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 1, "stashed: got {}", r.stashed);
                assert!(
                    r.errors.is_empty(),
                    "no errors expected, got {:?}",
                    r.errors
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// AU27 — empty file fast-path: appending to a 0-byte
    /// target produces no journal entry (no inverse needed —
    /// truncate-to-0 of an already-0 file is a no-op).
    #[test]
    fn append_to_empty_file_skips_journal() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "empty.log", b"");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Append,
                path: path.to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 0, "empty file shouldn't stash");
                assert!(r.errors.is_empty(), "skip is not an error: {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn multiple_targets_partial_success() {
        let (dir, blob_store, index, active) = fresh();
        let good = write_file(dir.path(), "good.txt", b"keep me\n");
        let missing = dir.path().join("absent.txt");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        // AU27: Truncate(good) + Truncate(missing) + Append(good)
        // → Truncate(good) stashes, Truncate(missing) skips
        // cleanly (file absent), Append(good) stashes.
        // 2 stashed, 0 errors.
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![
                RedirectTargetWire {
                    op: RedirectOpWire::Truncate,
                    path: good.to_string_lossy().to_string(),
                },
                RedirectTargetWire {
                    op: RedirectOpWire::Truncate,
                    path: missing.to_string_lossy().to_string(),
                },
                RedirectTargetWire {
                    op: RedirectOpWire::Append,
                    path: good.to_string_lossy().to_string(),
                },
            ],
            &active,
            &index,
            &blob_store,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 2, "stashed: got {}", r.stashed);
                assert!(r.errors.is_empty(), "errors: got {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
