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
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
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
///
/// With `strict` set (`SHIT_STRICT_CAPTURE`), a per-target failure also
/// journals a `CaptureRefused` row for the path, so `shit undo` refuses
/// that command instead of silently restoring less than the shell
/// destroyed. The shell still gets its ack either way.
pub fn handle(
    session: Uuid,
    command_seq: u64,
    targets: Vec<RedirectTargetWire>,
    active: &ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
    strict: bool,
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
        match stash_one(&target, command, index, blob_store, strict) {
            Ok(StashOutcome::Stashed) => stashed += 1,
            Ok(StashOutcome::Skipped) => {} // fresh-create case; not an error, not a stash
            Err(reason) => {
                if strict {
                    let path = Path::new(target.path.as_str());
                    // A path the shell could not resolve is not a
                    // filesystem location; the refusal falls back to the
                    // command's cwd.
                    let refused_path = path.is_absolute().then(|| path.to_path_buf());
                    crate::helper_link::journal_capture_refused_or_log(
                        index,
                        command,
                        refused_path,
                        format!("redirect pre-stash failed for {}: {reason}", target.path),
                    );
                }
                errors.push(PreStashRedirectError {
                    path: target.path.clone(),
                    reason,
                });
            }
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
    strict: bool,
) -> Result<StashOutcome, String> {
    // The hook resolves relative targets against the shell's cwd before
    // sending. A path that is still relative (unexpanded `$VAR`, `~`, a
    // glob) would resolve against the daemon's cwd, which names the
    // wrong file, so it is never stat'd.
    //
    // Default mode keeps trunk's behavior (such targets were skipped, as
    // they named nothing the daemon could stat). Strict mode cannot tell
    // whether the command wrote a file it cannot attribute, so it refuses.
    if !Path::new(target.path.as_str()).is_absolute() {
        if strict {
            return Err(
                "redirect target is not an absolute path (shell expansion not resolved)".into(),
            );
        }
        debug!(path = %target.path, "unresolved redirect target; skipped");
        return Ok(StashOutcome::Skipped);
    }
    match target.op {
        RedirectOpWire::Truncate | RedirectOpWire::TeeTruncate | RedirectOpWire::DdOf => {
            stash_truncate(target.path.as_str(), command, index, blob_store, strict)
        }
        RedirectOpWire::Append | RedirectOpWire::TeeAppend => {
            // AU27 — Append/TeeAppend capture journals only the
            // pre-size (no blob); inverse is FileExtend which
            // truncates the file back at undo time. The bytes that
            // need restoring are still on disk in [0..pre_size]; the
            // appended bytes [pre_size..] get discarded by the
            // truncate.
            stash_append(target.path.as_str(), command, index, strict)
        }
    }
}

fn stash_append(
    path_str: &str,
    command: CommandId,
    index: &Index,
    strict: bool,
) -> Result<StashOutcome, String> {
    let path = Path::new(path_str);
    // Fresh-file fast-path: `echo X >> /tmp/new.log` on a
    // non-existent target. There's no pre-state to truncate
    // back to. AR05.1-style fresh-create journaling could
    // emit a TreeOp::Create here; deferred to a sibling
    // sprint.
    // Only the size is needed, so a write-only target (mode 0200) is
    // captured from its metadata when it cannot be opened for reading.
    let Some((_, meta)) = capture_regular(path, strict, false)? else {
        debug!(path = %path.display(), "append target absent; nothing to pre-stash");
        return Ok(StashOutcome::Skipped);
    };
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
    strict: bool,
) -> Result<StashOutcome, String> {
    let path = Path::new(path_str);
    // If the file doesn't exist yet, there's nothing to pre-stash —
    // the redirect is a fresh-create. We could journal a Tree::Create
    // here so undo unlinks the newly-created file, but for AR06.5
    // we focus on the "clobber existing file" race. Fresh-create
    // covered by separate AR06.5 follow-up; today we just skip
    // cleanly (no error -- not a failure).
    let Some((bytes, meta)) = capture_regular(path, strict, true)? else {
        debug!(path = %path.display(), "redirect target absent; nothing to pre-stash");
        return Ok(StashOutcome::Skipped);
    };
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
                // M03.x.SETATTR — redirect pre-stash path doesn't
                // pull st_flags (the C06 path is shell-redirect-
                // specific, not chflags). Default to 0; the inverse
                // for redirect-pre-stash is FileExtend / RestoreContent,
                // not flags-restore.
                flags: 0,
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

/// Why `open_regular_nofollow` failed. `denied` marks EACCES/EPERM so
/// callers that only need metadata can fall back to `lstat`.
struct OpenFail {
    msg: String,
    denied: bool,
}

impl From<OpenFail> for String {
    fn from(f: OpenFail) -> String {
        f.msg
    }
}

/// Open a regular file read-only, never opening anything else.
///
/// The final component is `lstat`ed first. Only a regular file is
/// opened: a symlink, FIFO, socket or device is rejected from the stat
/// alone, because opening a device or FIFO can block or have side effects
/// even with `O_NONBLOCK`. The open then uses `O_NOFOLLOW` and the
/// descriptor's `fstat` must name the same dev/ino, which catches a swap
/// between the stat and the open. `Ok(None)` means the path is absent.
/// No errno is interpreted to detect symlinks (ELOOP on Linux, EMLINK on
/// FreeBSD, and ELOOP can also mean a loop in a parent component).
fn open_regular_nofollow(path: &Path) -> Result<Option<(File, std::fs::Metadata)>, OpenFail> {
    let fail = |msg: String| OpenFail { msg, denied: false };
    let link = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(format!("stat: {e}"))),
    };
    if link.file_type().is_symlink() {
        return Err(fail("not a regular file (symlink)".to_string()));
    }
    if !link.file_type().is_file() {
        return Err(fail(format!("not a regular file ({:?})", link.file_type())));
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        // Removed between the stat and the open.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(OpenFail {
                msg: format!("open: {e}"),
                denied: e.kind() == std::io::ErrorKind::PermissionDenied,
            });
        }
    };
    let meta = file.metadata().map_err(|e| fail(format!("fstat: {e}")))?;
    if !meta.file_type().is_file() || meta.dev() != link.dev() || meta.ino() != link.ino() {
        return Err(fail(
            "target path was replaced between stat and open".to_string(),
        ));
    }
    Ok(Some((file, meta)))
}

/// Snapshot a regular file: its bytes (when `want_bytes`) and the metadata
/// the snapshot is consistent with. `Ok(None)` means the path is absent.
///
/// The read goes through one validated descriptor and is followed by a
/// check that the file did not change and that `path` still names it.
/// A mismatch is a torn or raced capture. Default mode keeps trunk's
/// best-effort behavior: log a warning and use what was read, because
/// dropping the pre-image would lose capture. Strict mode retries once,
/// then fails so the command is refused.
///
/// Without `want_bytes` (append targets), a file that cannot be opened
/// for reading is captured from its `lstat` metadata alone, as trunk did.
fn capture_regular(
    path: &Path,
    strict: bool,
    want_bytes: bool,
) -> Result<Option<(Vec<u8>, std::fs::Metadata)>, String> {
    capture_regular_with(path, strict, want_bytes, &mut |_| {})
}

/// `capture_regular` with a hook that runs after each attempt's read and
/// before its verification, given the attempt number. Tests use it to
/// change the file at exactly the racy moment.
fn capture_regular_with(
    path: &Path,
    strict: bool,
    want_bytes: bool,
    after_read: &mut dyn FnMut(u32),
) -> Result<Option<(Vec<u8>, std::fs::Metadata)>, String> {
    let attempts = if strict { 2 } else { 1 };
    let mut last_err = String::new();
    for attempt in 0..attempts {
        let (mut file, meta) = match open_regular_nofollow(path) {
            Ok(Some(opened)) => opened,
            Ok(None) => return Ok(None),
            Err(f) if f.denied && !want_bytes => {
                let meta = std::fs::symlink_metadata(path).map_err(|e| format!("stat: {e}"))?;
                if !meta.file_type().is_file() {
                    return Err(format!("not a regular file ({:?})", meta.file_type()));
                }
                return Ok(Some((Vec::new(), meta)));
            }
            Err(f) => return Err(f.msg),
        };
        let mut bytes = Vec::new();
        if want_bytes {
            // A huge or sparse file must not abort the daemon on
            // allocation failure; report it through the per-target path.
            let want = usize::try_from(meta.size()).unwrap_or(usize::MAX);
            bytes
                .try_reserve(want)
                .map_err(|e| format!("read: cannot reserve {want} bytes: {e}"))?;
            file.read_to_end(&mut bytes)
                .map_err(|e| format!("read: {e}"))?;
        }
        after_read(attempt);
        match verify_unchanged(path, &file, &meta) {
            Ok(()) => return Ok(Some((bytes, meta))),
            Err(e) if !strict => {
                tracing::warn!(path = %path.display(), reason = %e, "redirect pre-image may be torn; journaling best-effort bytes");
                return Ok(Some((bytes, meta)));
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Fail if the file changed while it was being captured, or if `path` no
/// longer names the inode we opened.
fn verify_unchanged(path: &Path, file: &File, before: &std::fs::Metadata) -> Result<(), String> {
    let after = file
        .metadata()
        .map_err(|e| format!("post-read fstat: {e}"))?;
    if !same_snapshot(before, &after) {
        return Err("target changed while its redirect pre-image was captured".to_string());
    }
    let bound = std::fs::symlink_metadata(path).map_err(|e| format!("post-read path stat: {e}"))?;
    if bound.file_type().is_symlink() || bound.dev() != before.dev() || bound.ino() != before.ino()
    {
        return Err(
            "target path was replaced while its redirect pre-image was captured".to_string(),
        );
    }
    Ok(())
}

fn same_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 2, "stashed: got {}", r.stashed);
                assert!(r.errors.is_empty(), "errors: got {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn one_target(path: &str, op: RedirectOpWire) -> Vec<RedirectTargetWire> {
        vec![RedirectTargetWire {
            op,
            path: path.to_string(),
        }]
    }

    fn ack(resp: CtlResponse) -> PreStashRedirectsResult {
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => r,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn refusals(index: &Index, cmd: CommandId) -> Vec<(PathBuf, String)> {
        index
            .events_for_command(cmd)
            .into_iter()
            .filter_map(|e| match e.kind {
                CaptureEventKind::CaptureRefused { path, detail, .. } => Some((path, detail)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn relative_target_is_skipped_by_default_refused_in_strict_never_statted() {
        for strict in [false, true] {
            let (_dir, blob_store, index, active) = fresh();
            let cmd = CommandId {
                session: fresh_session(),
                seq: 1,
            };
            register_command(&index, cmd);
            // Cargo.toml exists relative to the test's cwd; it must not be stashed.
            let r = ack(handle(
                cmd.session,
                cmd.seq,
                one_target("Cargo.toml", RedirectOpWire::Truncate),
                &active,
                &index,
                &blob_store,
                strict,
            ));
            assert_eq!(r.stashed, 0, "strict={strict}");
            assert!(
                index
                    .events_for_command(cmd)
                    .iter()
                    .all(|e| !matches!(e.kind, CaptureEventKind::FilePreImage { .. })),
                "strict={strict}: the daemon's cwd file was stashed"
            );
            if strict {
                assert_eq!(r.errors.len(), 1);
                assert!(
                    r.errors[0].reason.contains("not an absolute path"),
                    "{:?}",
                    r.errors
                );
                assert_eq!(refusals(&index, cmd).len(), 1);
            } else {
                assert!(r.errors.is_empty(), "default mode skips like trunk");
                assert!(refusals(&index, cmd).is_empty());
            }
        }
    }

    #[test]
    fn strict_unresolved_target_journals_refusal_default_does_not() {
        for strict in [false, true] {
            let (_dir, blob_store, index, active) = fresh();
            let cmd = CommandId {
                session: fresh_session(),
                seq: 1,
            };
            register_command(&index, cmd);
            let r = ack(handle(
                cmd.session,
                cmd.seq,
                one_target("$NOPE/out", RedirectOpWire::Truncate),
                &active,
                &index,
                &blob_store,
                strict,
            ));
            assert_eq!(r.errors.len(), usize::from(strict), "strict={strict}");
            let rows = refusals(&index, cmd);
            assert_eq!(rows.len(), usize::from(strict), "strict={strict}");
            if strict {
                assert_eq!(rows[0].0, PathBuf::from("/tmp"), "falls back to cwd");
                assert!(rows[0].1.contains("$NOPE/out"), "{}", rows[0].1);
            }
        }
    }

    #[test]
    fn symlink_target_is_refused_not_followed() {
        let (dir, blob_store, index, active) = fresh();
        let real = write_file(dir.path(), "real.txt", b"secret\n");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let r = ack(handle(
            cmd.session,
            cmd.seq,
            one_target(link.to_str().unwrap(), RedirectOpWire::Truncate),
            &active,
            &index,
            &blob_store,
            true,
        ));
        assert_eq!(r.stashed, 0);
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].reason.contains("(symlink)"), "{:?}", r.errors);
        let rows = refusals(&index, cmd);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, link);
    }

    #[test]
    fn fifo_target_does_not_block_the_daemon() {
        let (dir, blob_store, index, active) = fresh();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let r = ack(handle(
            cmd.session,
            cmd.seq,
            one_target(fifo.to_str().unwrap(), RedirectOpWire::Truncate),
            &active,
            &index,
            &blob_store,
            false,
        ));
        assert_eq!(r.stashed, 0);
        assert_eq!(r.errors.len(), 1);
    }

    #[test]
    fn verify_unchanged_catches_modification_and_replacement() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "f.txt", b"one\n");
        let (file, meta) = open_regular_nofollow(&path).ok().flatten().unwrap();
        verify_unchanged(&path, &file, &meta).expect("untouched file verifies");

        // Same inode, new bytes: the fd snapshot differs.
        std::fs::write(&path, b"two two\n").unwrap();
        assert!(verify_unchanged(&path, &file, &meta).is_err());

        // Path now names a different inode.
        let (file, meta) = open_regular_nofollow(&path).ok().flatten().unwrap();
        let other = write_file(dir.path(), "g.txt", b"swap\n");
        std::fs::rename(&other, &path).unwrap();
        let err = verify_unchanged(&path, &file, &meta).unwrap_err();
        assert!(err.contains("replaced") || err.contains("changed"), "{err}");
    }
    #[test]
    fn write_only_append_target_is_captured_from_metadata() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits
        }
        for strict in [false, true] {
            let (dir, blob_store, index, active) = fresh();
            let path = write_file(dir.path(), "wo.log", b"old\n");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();
            let cmd = CommandId {
                session: fresh_session(),
                seq: 1,
            };
            register_command(&index, cmd);
            let r = ack(handle(
                cmd.session,
                cmd.seq,
                one_target(path.to_str().unwrap(), RedirectOpWire::Append),
                &active,
                &index,
                &blob_store,
                strict,
            ));
            assert_eq!(r.stashed, 1, "strict={strict} {:?}", r.errors);
            assert!(matches!(
                index.events_for_command(cmd)[0].kind,
                CaptureEventKind::FileAppendPreStash { pre_size: 4, .. }
            ));
        }
    }

    #[test]
    fn torn_read_is_best_effort_by_default_and_retried_then_fatal_in_strict() {
        use std::io::Write as _;
        let append = |path: &Path| {
            let mut f = OpenOptions::new().append(true).open(path).unwrap();
            f.write_all(b"more\n").unwrap();
        };

        // Default: the file changes after the read; the bytes read are
        // journaled anyway, with one attempt only.
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "live.txt", b"abc\n");
        let mut calls = 0;
        let (bytes, _) = capture_regular_with(&path, false, true, &mut |_| {
            calls += 1;
            append(&path);
        })
        .unwrap()
        .unwrap();
        assert_eq!(bytes, b"abc\n");
        assert_eq!(calls, 1);

        // Strict, changes on every attempt: one retry, then an error.
        let path = write_file(dir.path(), "live2.txt", b"abc\n");
        let mut calls = 0;
        let err = capture_regular_with(&path, true, true, &mut |_| {
            calls += 1;
            append(&path);
        })
        .unwrap_err();
        assert!(err.contains("changed"), "{err}");
        assert_eq!(calls, 2);

        // Strict, changes only during the first attempt: the retry
        // reads the settled file and succeeds.
        let path = write_file(dir.path(), "live3.txt", b"abc\n");
        let mut calls = 0;
        let (bytes, _) = capture_regular_with(&path, true, true, &mut |attempt| {
            calls += 1;
            if attempt == 0 {
                append(&path);
            }
        })
        .unwrap()
        .unwrap();
        assert_eq!(bytes, b"abc\nmore\n");
        assert_eq!(calls, 2);
    }

    #[test]
    fn fifo_is_rejected_from_the_stat_without_opening() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // A reader open of a FIFO with no writer would block without
        // O_NONBLOCK, and any open of a device can have side effects. The
        // check must come from lstat, so it succeeds even with no
        // permission to open the node at all.
        std::fs::set_permissions(&fifo, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let err = open_regular_nofollow(&fifo).expect_err("rejected");
        assert!(err.msg.contains("not a regular file"), "{}", err.msg);
        assert!(!err.denied, "an open was attempted: {}", err.msg);
    }
}
