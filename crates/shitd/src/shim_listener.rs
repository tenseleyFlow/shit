// SPDX-License-Identifier: AGPL-3.0-or-later

//! S24.D.2 — accept loop for the LD_PRELOAD shim's per-process UDS.
//! W06.A.3 — route TreeOp notifications (unlink/rename) into journal.
//! W06.A.4 — route content notifications (open/openat/truncate with
//! attached pre-image bytes) into a `CaptureEventKind::FilePreImage`.
//!
//! The shim (`shit-preload-shim`) opens a short-lived connection to
//! `$XDG_RUNTIME_DIR/shit/shim.sock`, sends a [`ShimNotification`]
//! framed via `encode_frame` (or `encode_frame_large` when a
//! pre-image payload is attached), waits ≤50 ms for a [`ShimAck`],
//! and closes.
//!
//! Per-connection flow:
//! 1. Decode the notification (large-frame reader — accepts both
//!    small and large frames).
//! 2. Resolve `pid → CommandId` via `ActiveCommands::resolve_by_descendant`.
//!    If no active command owns the emitter, the event is orphan
//!    and dropped silently (the shim still gets an Allow ack — we
//!    never block a user command on an attribution miss).
//! 3. Send a best-effort `Allow` ack once the notification is decoded and
//!    attributed. A peer that times out/closes before reading it must not
//!    discard the already-received capture.
//! 4. Validate and classify:
//!    - `unlink`/`unlinkat`/`rmdir`/`remove` → `TreeOp::Unlink`
//!    - `rename`/`renameat` → `TreeOp::Rename`  (arg is `from\tto`)
//!    - `open`/`openat`/`truncate` with `pre_image=Some(_)` →
//!      `FilePreImage` (W06.A.4); without it, either a proven fresh
//!      `TreeOp::Create` or an explicit capture refusal.
//!    - `pwrite` / `ftruncate` / `mmap_shared_w` — logged but not
//!      journaled (fd-based — needs fd→path resolution; deferred).
//! 5. For content events: write blob bytes to the BlobStore, journal
//!    `FilePreImage`. For TreeOp events: journal directly.
//!
//! The locked design decision is **fan-in** (single daemon-side socket,
//! 100-conn pool) rather than fan-out per process.

use crate::active_commands::ActiveCommands;
use crate::baseline::LiveBaseline;
use crate::config::ResolvedConfig;
use shit_planner::TreeOp;
use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inode::InodeRef;
use shit_planner::metadata::{FileKind, FileMetadata};
use shit_proto::{
    ShimAck, ShimNotification, ShimPreImage, decode_shim_notification_frame_large, encode_frame,
};
use shit_store::{BlobStore, Index};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// Hard ceiling on per-connection allocation. Matches
/// [`shit_proto::MAX_LARGE_FRAME_SIZE`] so anything the wire encoder
/// will produce, the daemon can receive. Buffer is allocated
/// **dynamically** from the wire's u32 length prefix (W06.A.4.1)
/// — there's no fixed memory cost when most notifications are
/// small. Connections claiming a length above this ceiling are
/// rejected before allocation.
const SHIM_BUF_MAX: usize = shit_proto::MAX_LARGE_FRAME_SIZE;

/// Listen on the shim socket inside `$XDG_RUNTIME_DIR/shit/shim.sock`,
/// serving each accepted connection on its own tokio task. Returns when
/// `shutdown` fires.
pub async fn serve(
    cfg: &ResolvedConfig,
    shutdown: Arc<Notify>,
    index: Arc<Index>,
    blob_store: Arc<BlobStore>,
    active: Arc<ActiveCommands>,
    live_baseline: Arc<LiveBaseline>,
) -> anyhow::Result<()> {
    let sock_path = shim_socket_path(cfg);
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if Path::new(&sock_path).exists() {
        let _ = std::fs::remove_file(&sock_path);
    }
    let listener = UnixListener::bind(&sock_path)?;
    use std::os::unix::fs::PermissionsExt;
    // 0o600 — only the daemon's user (the only user that should be
    // running their LD_PRELOAD shim'd commands) can write here.
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    info!(path = %sock_path.display(), "shim listener listening");

    loop {
        tokio::select! {
            res = listener.accept() => match res {
                Ok((stream, _addr)) => {
                    let index = Arc::clone(&index);
                    let blob_store = Arc::clone(&blob_store);
                    let active = Arc::clone(&active);
                    let live_baseline = Arc::clone(&live_baseline);
                    tokio::spawn(async move {
                        if let Err(e) = handle_one(stream, index, blob_store, active, live_baseline).await {
                            debug!(err = %e, "shim client errored");
                        }
                    });
                }
                Err(e) => {
                    warn!(err = %e, "shim accept failed");
                }
            },
            _ = shutdown.notified() => {
                info!("shim listener shutting down");
                let _ = std::fs::remove_file(&sock_path);
                return Ok(());
            }
        }
    }
}

/// Per-connection handler. One notification → resolve/reserve order →
/// ack → best-effort ingest → close.
async fn handle_one(
    mut stream: UnixStream,
    index: Arc<Index>,
    blob_store: Arc<BlobStore>,
    active: Arc<ActiveCommands>,
    live_baseline: Arc<LiveBaseline>,
) -> anyhow::Result<()> {
    // W06.A.4.1: dynamic-allocation buffer. Read the 4-byte u32 BE
    // length prefix exactly, then allocate a buffer sized to the
    // declared frame and `read_exact` the body. Wire format:
    // `| u32 BE body_len | u8 version | postcard payload |`. This
    // lets us accept pre-images up to
    // `shit_proto::SHIM_INLINE_PREIMAGE_CAP` (32 MiB) without
    // pre-allocating per-connection — small notifications cost ~5
    // bytes of buffer, large ones get exactly what they need.
    //
    // `read_exact` (vs the previous read-in-loop) is the right
    // primitive once we know the target length: it blocks until the
    // full body arrives or peer closes mid-stream (clean error
    // signal), and we don't have to worry about per-read kernel
    // recvspace caps (typical FreeBSD UDS recvspace is 256 KiB,
    // which silently capped the previous loop at exactly that point).
    //
    // Reject early if the declared length exceeds `SHIM_BUF_MAX`
    // (= wire's `MAX_LARGE_FRAME_SIZE`) so a malicious peer can't
    // request unbounded allocation.
    // 10 s upper bound on the read side. The shim's
    // `set_write_timeout` is 5 s when carrying a pre-image; round-
    // trip overhead never legitimately exceeds 10 s. Bound here
    // protects against a malformed/malicious peer that opens a
    // connection, sends a partial frame, then idles — without this
    // bound, `read_exact` would park the daemon task indefinitely.
    let read_deadline = std::time::Duration::from_secs(10);
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(read_deadline, stream.read_exact(&mut len_buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            debug!(err = %e, "shim length-prefix read failed (peer hung up early?)");
            return Ok(());
        }
        Err(_elapsed) => {
            debug!("shim length-prefix read timed out after 10s");
            return Ok(());
        }
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;
    let frame_total = 4 + body_len;
    if frame_total > SHIM_BUF_MAX {
        warn!(
            declared = frame_total,
            max = SHIM_BUF_MAX,
            "shim notification declared length exceeds SHIM_BUF_MAX"
        );
        return Ok(());
    }
    let mut buf = vec![0u8; frame_total];
    buf[..4].copy_from_slice(&len_buf);
    match tokio::time::timeout(read_deadline, stream.read_exact(&mut buf[4..])).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(err = %e, declared = frame_total, "shim body read failed");
            return Ok(());
        }
        Err(_elapsed) => {
            warn!(declared = frame_total, "shim body read timed out after 10s");
            return Ok(());
        }
    }
    let total = frame_total;
    if total == 0 {
        return Ok(());
    }
    let note: ShimNotification = match decode_shim_notification_frame_large(&buf[..total]) {
        Ok(n) => n,
        Err(e) => {
            warn!(err = %e, "shim notification decode failed");
            return Ok(());
        }
    };
    debug!(
        pid = note.pid,
        syscall = %note.syscall,
        arg = %note.arg,
        has_pre_image = note.pre_image.is_some(),
        "shim pre-mutation"
    );

    // Resolve `pid → CommandId` BEFORE acking. The shim has already called
    // libc successfully, but it does not return to the mutating process until
    // notification delivery completes (or its read deadline expires). The
    // process (e.g. `install` invoked by `make`) can terminate within
    // milliseconds after that return. If we resolve after acking,
    // `ancestor_chain` can shell out to `ps -p <pid>`
    // for an already-dead pid and returns None — the notification
    // is then orphaned. Doing the resolution synchronously here
    // costs ~10ms (one ps invocation per ancestor level); we have
    // 40ms of headroom inside the shim's 50ms allow-on-timeout
    // budget.
    let resolved = active.resolve_by_descendant(note.pid);

    // Reserve this notification's daemon logical timestamp before the ACK.
    // Ingestion remains fail-open and happens after the ACK, but the event
    // keeps the order in which this listener accepted it.
    let ingest_ts = crate::server::next_ts();

    // Ack — never block the user's command on journaling. The shim's
    // read deadline is deliberately short, so a slow ancestry lookup can
    // leave us writing after the shim has already timed out and closed its
    // socket. ACK delivery is therefore best-effort: once a complete valid
    // notification has been decoded and attributed, an EPIPE must not throw
    // away its pre-image.
    let ack = ShimAck::Allow;
    let frame = encode_frame(&ack)?;
    if let Err(e) = stream.write_all(&frame).await {
        debug!(err = %e, pid = note.pid, syscall = %note.syscall, "shim ack write failed; ingesting notification anyway");
    }

    ingest_notification(
        &note,
        resolved,
        ingest_ts,
        &index,
        &blob_store,
        &live_baseline,
    );
    Ok(())
}

fn journal_capture_refused(
    index: &Index,
    command: shit_planner::events::CommandId,
    ts: shit_planner::time::TimePoint,
    path: PathBuf,
    detail: String,
) -> Result<(), shit_store::IndexError> {
    index
        .put_event(&CaptureEvent {
            id: EventId(0),
            command,
            ts,
            partial: false,
            kind: CaptureEventKind::CaptureRefused {
                class: "capture-incomplete".to_string(),
                path,
                detail,
            },
        })
        .map(|_| ())
}

/// Return the first path that is unsafe to turn into an inverse.
///
/// The shim protocol intentionally carries absolute replay identities. A
/// relative value cannot be repaired daemon-side because the emitter may have
/// changed cwd (or used a real `*at` dirfd) and the command record's cwd is not
/// authoritative for descendants.
fn unsafe_replay_path(note: &ShimNotification) -> Option<(PathBuf, String)> {
    use std::path::Component;

    let validate = |raw: &str, field: &str| -> Result<PathBuf, String> {
        if raw.as_bytes().contains(&0) {
            return Err(format!("shim supplied {field} with an embedded NUL byte"));
        }
        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(format!(
                "shim supplied relative {field}; refusing unsafe undo target"
            ));
        }
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::Normal(_) => {
                    normalized.push(component.as_os_str());
                }
                Component::CurDir => return Err(format!("shim supplied {field} containing `.`")),
                Component::ParentDir => {
                    return Err(format!("shim supplied {field} containing `..`"));
                }
                Component::Prefix(_) => {
                    return Err(format!("shim supplied {field} with a platform prefix"));
                }
            }
        }
        if normalized.to_str() != Some(raw) {
            return Err(format!(
                "shim supplied non-normalized {field}; refusing unsafe undo target"
            ));
        }
        Ok(normalized)
    };

    if let Some(pre) = &note.pre_image
        && let Err(detail) = validate(&pre.path, "pre-image path")
    {
        return Some((PathBuf::from(&pre.path), detail));
    }
    for pre in &note.extra_pre_images {
        if let Err(detail) = validate(&pre.path, "recursive pre-image path") {
            return Some((PathBuf::from(&pre.path), detail));
        }
    }

    let is_rename = matches!(note.syscall.as_str(), "rename" | "renameat" | "renameat2");
    if !is_rename && !note.extra_pre_images.is_empty() {
        return Some((
            PathBuf::from(&note.extra_pre_images[0].path),
            "shim supplied recursive pre-images for a non-rename operation".to_string(),
        ));
    }

    if matches!(
        note.syscall.as_str(),
        "unlink" | "unlinkat" | "rmdir" | "remove"
    ) {
        let Some(pre) = &note.pre_image else {
            return Some((
                PathBuf::from(&note.arg),
                "successful destructive notification carried no deletion pre-image or metadata marker"
                    .to_string(),
            ));
        };
        if pre.path != note.arg {
            return Some((
                PathBuf::from(&note.arg),
                format!(
                    "destructive notification path disagreed with its pre-image path {:?}",
                    pre.path
                ),
            ));
        }
    }

    match note.syscall.as_str() {
        "rename" | "renameat" | "renameat2" => {
            let Some((from, to)) = note.arg.split_once('\t') else {
                return Some((
                    PathBuf::from(&note.arg),
                    "shim supplied malformed rename operands; refusing unsafe undo target"
                        .to_string(),
                ));
            };
            if to.contains('\t') {
                return Some((
                    PathBuf::from(&note.arg),
                    "shim supplied ambiguous rename operands; refusing unsafe undo target"
                        .to_string(),
                ));
            }
            let from_path = match validate(from, "rename source") {
                Ok(path) => path,
                Err(detail) => return Some((PathBuf::from(from), detail)),
            };
            let to_path = match validate(to, "rename destination") {
                Ok(path) => path,
                Err(detail) => return Some((PathBuf::from(to), detail)),
            };
            if let Some(pre) = &note.pre_image
                && Path::new(&pre.path) != to_path
            {
                return Some((
                    PathBuf::from(&pre.path),
                    "rename destination pre-image is not bound to the rename destination"
                        .to_string(),
                ));
            }
            if let Some(pre) = note
                .extra_pre_images
                .iter()
                .find(|pre| !Path::new(&pre.path).starts_with(&from_path))
            {
                return Some((
                    PathBuf::from(&pre.path),
                    "recursive rename pre-image is outside the rename source subtree".to_string(),
                ));
            }
            None
        }
        "open" | "openat" | "truncate" | "unlink" | "unlinkat" | "rmdir" | "remove" | "mkfifo"
        | "mkfifoat" | "link" | "linkat" | "mkdir" | "mkdirat" | "chmod" | "fchmod"
        | "fchmodat" | "chown" | "fchown" | "lchown" | "fchownat" | "utimes" | "futimes"
        | "futimens" | "utimensat" | "setxattr" | "fsetxattr" | "removexattr" | "fremovexattr"
        | "chflags" | "fchflags" => {
            let arg_path = match validate(&note.arg, "path") {
                Ok(path) => path,
                Err(detail) => return Some((PathBuf::from(&note.arg), detail)),
            };
            if let Some(pre) = &note.pre_image
                && Path::new(&pre.path) != arg_path
            {
                return Some((
                    PathBuf::from(&pre.path),
                    "shim pre-image path is not bound to the syscall path".to_string(),
                ));
            }
            None
        }
        _ => None,
    }
}

/// Convert a shim notification into a `CaptureEvent` and journal it,
/// if the emitter's pid resolves to an active command. Errors are
/// logged but never propagated — the shim path is best-effort.
fn ingest_notification(
    note: &ShimNotification,
    resolved: Option<shit_planner::events::CommandId>,
    ingest_ts: shit_planner::time::TimePoint,
    index: &Index,
    blob_store: &BlobStore,
    live_baseline: &LiveBaseline,
) {
    let Some(command) = resolved else {
        // The shim is loaded into a process whose ancestor isn't a
        // tracked shell. Likely a background daemon / system service
        // that picked up LD_PRELOAD from a parent env, OR the pid
        // resolution raced the process's lifetime.
        debug!(pid = note.pid, syscall = %note.syscall, "shim notify: no active command for pid; dropping");
        return;
    };

    // AU10 — a structured resolution failure means the shim could not prove
    // a stable target identity. Journal one refusal and stop: the protocol's
    // contract is explicitly "refusal instead of an inverse op". Falling
    // through here used to pair the refusal with a best-effort relative
    // TreeOp, which could later be replayed from `shit undo`'s cwd.
    if let Some(failure) = &note.failure {
        let (primary_path, detail) = match failure {
            shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg,
                attempted_path,
                error_chain,
            } => (
                PathBuf::from(attempted_path),
                format!("shim canonicalize tripped on {which_arg} argument ({error_chain})"),
            ),
            shit_proto::ShimFailure::PreImageUnavailable {
                attempted_path,
                reason,
            } => (
                PathBuf::from(attempted_path),
                format!("shim could not capture the pre-image ({reason})"),
            ),
            shit_proto::ShimFailure::UnsupportedOperation {
                attempted_path,
                reason,
            } => (
                PathBuf::from(attempted_path),
                format!("shim cannot model this operation safely ({reason})"),
            ),
        };
        // The primary path matters for the user-visible refusal
        // text. We deliberately use the raw `attempted_path` here
        // (not a canonicalized form) because the failure mode IS
        // that canonicalize couldn't resolve it — surfacing the
        // raw input is the honest signal.
        if let Err(e) = journal_capture_refused(index, command, ingest_ts, primary_path, detail) {
            warn!(
                err = %e,
                pid = note.pid,
                syscall = %note.syscall,
                "shim notify: CaptureRefused journal failed"
            );
        } else {
            debug!(
                pid = note.pid,
                syscall = %note.syscall,
                session = %command.session,
                seq = command.seq,
                "shim notify: journaled CaptureRefused (AU10)"
            );
        }
        return;
    }

    // Defense in depth for older shims and malformed/corrupt frames. Every
    // filesystem operand that can become an inverse must already be absolute
    // when it reaches the daemon. Never reinterpret a captured path using the
    // daemon's cwd or the future undo caller's cwd.
    if let Some((path, detail)) = unsafe_replay_path(note) {
        if let Err(e) = journal_capture_refused(index, command, ingest_ts, path, detail) {
            warn!(
                err = %e,
                pid = note.pid,
                syscall = %note.syscall,
                "shim notify: unsafe-path CaptureRefused journal failed"
            );
        } else {
            warn!(
                pid = note.pid,
                syscall = %note.syscall,
                "shim notify: refused unsafe replay path"
            );
        }
        return;
    }

    // M07.B.5: metadata-mutation syscalls (chmod/chown/xattr and legacy
    // timestamp notifications). The shim's pre-image carries the OLD
    // mode/uid/gid/mtime; ingest as a FilePreImage event so the
    // event lands in the journal with the BEFORE metadata fields
    // populated. Current timestamp interposers send a structured refusal
    // instead because FileMetadata does not yet carry atime; keeping their
    // names here makes older compatible notifications explicit rather than
    // falling through and disappearing.
    //
    // Planner-side, the source discriminator below emits metadata-only
    // restoration: inline bytes are never treated as file content.
    //
    // Why not use the richer `MetadataChange { before, after }` event the ES
    // producer emits? The shim captures the pre-state before libc and sends it
    // only after libc succeeds; it intentionally carries no authoritative
    // post-state. Undo needs only the captured before-state, while redo reports
    // this limitation explicitly.
    if matches!(
        note.syscall.as_str(),
        "chmod"
            | "fchmod"
            | "fchmodat"
            | "chown"
            | "fchown"
            | "lchown"
            | "fchownat"
            | "utimes"
            | "futimes"
            | "futimens"
            | "utimensat"
            | "setxattr"
            | "fsetxattr"
            | "removexattr"
            | "fremovexattr"
            // B09 — chflags family. Pre-image carries the OLD st_flags;
            // the source discriminator makes the planner emit only a
            // RestoreFlags inverse rather than content + broad metadata.
            | "chflags"
            | "fchflags"
    ) {
        if let Some(pre) = &note.pre_image {
            let source = if matches!(note.syscall.as_str(), "chflags" | "fchflags") {
                shit_planner::FilePreImageSource::ShimFlagsPreMutation
            } else {
                shit_planner::FilePreImageSource::ShimMetadataPreMutation
            };
            if let Err(e) =
                ingest_pre_image_with_source(command, pre, index, blob_store, source, ingest_ts)
            {
                warn!(
                    err = %e,
                    pid = note.pid,
                    syscall = %note.syscall,
                    "shim notify: metadata pre-image ingest failed"
                );
                if let Err(journal_err) = journal_capture_refused(
                    index,
                    command,
                    ingest_ts,
                    PathBuf::from(&pre.path),
                    format!("metadata pre-image ingest failed: {e}"),
                ) {
                    warn!(err = %journal_err, pid = note.pid, syscall = %note.syscall, "shim notify: metadata-ingest CaptureRefused journal failed");
                }
            } else {
                debug!(
                    pid = note.pid,
                    syscall = %note.syscall,
                    arg = %note.arg,
                    "shim notify: metadata-mutation pre-image journaled (M07.B.5)"
                );
            }
        } else {
            if let Err(e) = journal_capture_refused(
                index,
                command,
                ingest_ts,
                PathBuf::from(&note.arg),
                "successful metadata mutation carried no pre-image".to_string(),
            ) {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: missing-metadata CaptureRefused journal failed");
            }
        }
        return;
    }

    // W06.A.4: content syscalls with attached pre-image take the
    // FilePreImage path.
    if matches!(note.syscall.as_str(), "open" | "openat" | "truncate") {
        if let Some(pre) = &note.pre_image {
            if let Err(e) = ingest_pre_image(command, pre, index, blob_store, ingest_ts) {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: pre-image ingest failed");
                if let Err(journal_err) = journal_capture_refused(
                    index,
                    command,
                    ingest_ts,
                    PathBuf::from(&pre.path),
                    format!("content pre-image ingest failed: {e}"),
                ) {
                    warn!(err = %journal_err, pid = note.pid, syscall = %note.syscall, "shim notify: content-ingest CaptureRefused journal failed");
                }
            }
            return;
        }
        // AR05.1: no pre-image means the file didn't exist when the
        // shim looked. On in-watch paths the dir-diff Create event
        // covers this; on OUT-OF-WATCH paths (e.g. `make install
        // PREFIX=/usr/local`) the kernel-capture tier doesn't see
        // the create at all — the shim is the only observation
        // channel. Journal a TreeOp::Create speculatively.
        //
        // W09.12: actually GATE on in-watch-ness. Pre-W09.12 we
        // journaled unconditionally, so bulk-creators in-watch
        // (e.g. `python3 -m venv`) produced N shim TreeOp::Create
        // events alongside N kqueue dir-diff Create events for the
        // same paths. Undo then emitted 2N inverse unlinks; the
        // second wave failed with ConflictMissing on every path,
        // surfacing "N conflicted" in the undo report. Check the
        // LiveBaseline's cached cwds and suppress when the wire arg
        // falls inside any of them — kqueue dir-diff is
        // authoritative there.
        if live_baseline.path_in_watched_subtree(Path::new(&note.arg)) {
            debug!(
                pid = note.pid,
                syscall = %note.syscall,
                arg = %note.arg,
                "shim notify: path is in-watch; defer to kqueue dir-diff"
            );
            return;
        }
        // Inode sentinel (0,0) matches the Unlink path's convention
        // (line 347) — the executor's TreeOp::Create reverse is just
        // `unlink <path>` which doesn't need accurate (dev,inode).
        // mode and kind default to (0o644, Regular) — best-effort
        // since the shim fires PRE-syscall (the file doesn't exist
        // yet to stat). For redo / metadata-accurate restore we'd
        // need a post-syscall notification path; v1 ships the
        // undo-direction load-bearing journal.
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: ingest_ts,
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(0, 0),
                path: PathBuf::from(&note.arg),
                kind: FileKind::Regular,
                mode: 0o644,
            }),
        };
        if let Err(e) = index.put_event(&event) {
            warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: TreeOp::Create journal failed");
        } else {
            debug!(
                pid = note.pid,
                syscall = %note.syscall,
                arg = %note.arg,
                "shim notify: journaled fresh-create as TreeOp::Create"
            );
        }
        return;
    }

    // W06.A.4: a rename notification with an attached pre-image is
    // an atomic-replace shape (e.g. `install` writes a tmpfile then
    // renames it over an existing dst). Journal BOTH the TreeOp::Rename
    // (so the planner knows the dst path's identity changed) AND the
    // FilePreImage of the dst (so RestoreContent can put the old
    // bytes back). The planner's classify_replace_paths recognizes
    // this Rename(to=P) + PreImage(P) shape as atomic_replace and
    // suppresses the ReverseRename inverse — RestoreContent on the
    // dst path is correct, while ReverseRename would leave dst
    // empty and the bytes stuck at the source tmpfile path.
    if matches!(note.syscall.as_str(), "rename" | "renameat" | "renameat2")
        && let Some(pre) = &note.pre_image
        && let Err(e) = ingest_pre_image(command, pre, index, blob_store, ingest_ts)
    {
        warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: rename pre-image ingest failed");
        if let Err(journal_err) = journal_capture_refused(
            index,
            command,
            ingest_ts,
            PathBuf::from(&pre.path),
            format!("rename destination pre-image ingest failed: {e}"),
        ) {
            warn!(err = %journal_err, pid = note.pid, syscall = %note.syscall, "shim notify: rename-ingest CaptureRefused journal failed");
        }
        return;
    }
    // DR-CR-54 — when the rename's source was a directory, the
    // shim captured per-file pre-images for every regular file in
    // the subtree (bounded; see RECURSIVE_MAX_* in the shim).
    // Each entry is keyed to its **original** absolute path, so
    // a plain `ingest_pre_image` call lands the right
    // FilePreImage event for the planner to plan a RestoreContent
    // against. Without this, pip-style installers that move the
    // whole site-packages tree out of the way before writing
    // fresh content lose all pre-state and undo can only emit a
    // refusal.
    if matches!(note.syscall.as_str(), "rename" | "renameat" | "renameat2")
        && !note.extra_pre_images.is_empty()
    {
        let mut journaled = 0u64;
        let mut failed = 0u64;
        for pre in &note.extra_pre_images {
            match ingest_pre_image(command, pre, index, blob_store, ingest_ts) {
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
        if failed > 0 {
            if let Err(e) = journal_capture_refused(
                index,
                command,
                ingest_ts,
                PathBuf::from(&note.arg),
                format!(
                    "{failed} of {} recursive rename pre-images failed to ingest",
                    note.extra_pre_images.len()
                ),
            ) {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: recursive-ingest CaptureRefused journal failed");
            }
            return;
        }
    }
    // Fall through to journal the TreeOp::Rename below.

    // W09.5: unlink notification with attached pre-image is the
    // "unlink-then-open(O_CREAT)" shape (tar/cpio/gzip). The shim
    // captured bytes BEFORE the unlink fired; if a subsequent open
    // recreates the path with new bytes, the planner classifies
    // Unlink + PreImage (no Create, no Rename) as atomic_replace
    // and uses the FilePreImage's RestoreContent inverse instead
    // of the Unlink's RecreatePath. Journal both events; the
    // planner picks the right shape.
    if matches!(note.syscall.as_str(), "unlink" | "unlinkat" | "remove")
        && let Some(pre) = &note.pre_image
        && matches!(FileKind::from_mode(pre.mode), Some(FileKind::Regular))
        && let Err(e) = ingest_pre_image(command, pre, index, blob_store, ingest_ts)
    {
        warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: unlink pre-image ingest failed");
        if let Err(journal_err) = journal_capture_refused(
            index,
            command,
            ingest_ts,
            PathBuf::from(&pre.path),
            format!("unlink pre-image ingest failed: {e}"),
        ) {
            warn!(err = %journal_err, pid = note.pid, syscall = %note.syscall, "shim notify: unlink-ingest CaptureRefused journal failed");
        }
        return;
    }
    // Fall through to journal the TreeOp::Unlink below.

    let Some(kind) = classify_tree_op(&note.syscall, &note.arg, note.pre_image.as_ref()) else {
        // Fd-based content syscalls (ftruncate, pwrite, mmap_shared_w)
        // have no path in the wire payload; they need fd→path resolution
        // which is FreeBSD-specific (procstat/kvm). Deferred.
        if matches!(
            note.syscall.as_str(),
            "ftruncate" | "pwrite" | "mmap_shared_w"
        ) {
            if let Err(e) = journal_capture_refused(
                index,
                command,
                ingest_ts,
                PathBuf::from(&note.arg),
                format!(
                    "successful fd-based {} mutation has no stable path or pre-image",
                    note.syscall
                ),
            ) {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: fd-mutation CaptureRefused journal failed");
            }
        } else {
            debug!(
                pid = note.pid,
                syscall = %note.syscall,
                arg = %note.arg,
                "shim notify: syscall not classifiable"
            );
        }
        return;
    };

    // M03.x.CREATE / M03.x.LINK: gate Create-style classifications
    // on out-of-watch, mirroring the speculative-Create gating above
    // for open/openat (W09.12). In-watch creates that ALSO fire on
    // kqueue NOTE_WRITE / FSEvents would produce duplicate Unlink
    // inverses if we journal them shim-side too.
    //
    // **mkfifo/mkfifoat are NOT gated** — per the W09.10.1 commit
    // comment, kqueue NOTE_WRITE on the parent dir doesn't fire for
    // FIFO / special-file creation. The shim is the ONLY observation
    // channel for mkfifo even in-watch. Gating it here would cause
    // the existing mkfifo-undo-fbsd smoke to lose its only signal.
    //
    // link/linkat + mkdir/mkdirat ARE gated — kqueue NOTE_WRITE on
    // the destination's parent fires when either creates a fresh
    // dirent, so in-watch mutations get dir-diff coverage and the
    // shim's notification would duplicate it.
    //
    // Unlink/Rename pass through (they describe in-place mutations,
    // not creates) — only the Create variants gate.
    if matches!(
        note.syscall.as_str(),
        "link" | "linkat" | "mkdir" | "mkdirat"
    ) && live_baseline.path_in_watched_subtree(Path::new(&note.arg))
    {
        debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            "shim notify: Create path is in-watch; defer to kqueue dir-diff"
        );
        return;
    }

    if let CaptureEventKind::TreeOp(tree_op) = kind {
        match crate::helper_link::journal_tree_op(
            index,
            command,
            ingest_ts,
            tree_op,
            crate::helper_link::TreeSignalSource::Shim,
            false,
        ) {
            Ok(crate::helper_link::TreeJournalOutcome::Journaled) => {}
            Ok(crate::helper_link::TreeJournalOutcome::Deduplicated) => {
                debug!(
                    pid = note.pid,
                    syscall = %note.syscall,
                    session = %command.session,
                    seq = command.seq,
                    "shim notify: equivalent helper TreeOp already journaled"
                );
                return;
            }
            Err(e) => {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: put_event failed");
                return;
            }
        }
    } else {
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: ingest_ts,
            partial: false,
            kind,
        };
        if let Err(e) = index.put_event(&event) {
            warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: put_event failed");
            return;
        }
    }
    debug!(
        pid = note.pid,
        syscall = %note.syscall,
        session = %command.session,
        seq = command.seq,
        "shim notify: journaled"
    );
}

/// W06.A.4 — write the shim's inline bytes into the BlobStore and
/// journal a `FilePreImage`. Mirrors helper_link::handle_captured_pre_image
/// but takes inline bytes rather than an SCM_RIGHTS staging fd.
fn ingest_pre_image(
    command: shit_planner::events::CommandId,
    pre: &ShimPreImage,
    index: &Index,
    blob_store: &BlobStore,
    ts: shit_planner::time::TimePoint,
) -> anyhow::Result<()> {
    ingest_pre_image_with_source(
        command,
        pre,
        index,
        blob_store,
        shit_planner::FilePreImageSource::Other,
        ts,
    )
}

/// Variant of [`ingest_pre_image`] that preserves why the shim captured
/// the snapshot. Metadata/chflags shims use this so the planner treats inline
/// bytes as a wire detail and never rewrites content for a metadata-only op.
fn ingest_pre_image_with_source(
    command: shit_planner::events::CommandId,
    pre: &ShimPreImage,
    index: &Index,
    blob_store: &BlobStore,
    source: shit_planner::FilePreImageSource,
    ts: shit_planner::time::TimePoint,
) -> anyhow::Result<()> {
    let (blob_hash, stat) = blob_store
        .put(&pre.bytes)
        .map_err(|e| anyhow::anyhow!("blob put: {e}"))?;
    index
        .put_blob_record(blob_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| anyhow::anyhow!("put_blob_record: {e}"))?;
    let inode = InodeRef::new(pre.dev, pre.inode);
    // Current shims capture the complete pre-mutation xattr set from the same
    // descriptor as content/metadata. A legacy payload has `xattrs=None`; it
    // may use the old strict pathname fallback only while that pathname still
    // exists. In particular, unlink ingestion never needs (or attempts) a
    // post-syscall lookup when the authoritative wire snapshot is present.
    let xattrs = resolve_xattrs_target(pre)?;
    let meta = FileMetadata {
        mode: pre.mode,
        uid: pre.uid,
        gid: pre.gid,
        size: pre.size,
        mtime_unix_nanos: pre.mtime_unix_nanos,
        xattrs,
        acl: None,
        flags: pre.flags,
    };
    let path = PathBuf::from(&pre.path);
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode,
            path,
            blob: blob_hash,
            meta,
            // post_content_hash is left None — the shim runs
            // pre-syscall; we don't know the post state at journal
            // time. The planner's post-mutation conflict detection
            // is best-effort for shim-captured events.
            post_content_hash: None,
            source,
        },
    };
    index
        .put_event(&event)
        .map_err(|e| anyhow::anyhow!("put_event: {e}"))?;
    Ok(())
}

/// Map a shim notification's `(syscall, arg)` to a `TreeOp` journal
/// event. Returns `None` for non-TreeOp syscalls — the caller routes
/// pre-image syscalls separately.
///
/// Inodes are best-effort: for `Rename` we stat the destination
/// (which is the inode-preserved post-state, so stat-after-syscall
/// works). For `Unlink`, a shim pre-image or metadata marker must supply the
/// original inode/kind/mode. Missing or malformed deletion evidence is a
/// refusal; it must never be guessed as an empty regular file.
fn classify_tree_op(
    syscall: &str,
    arg: &str,
    pre_image: Option<&ShimPreImage>,
) -> Option<CaptureEventKind> {
    match syscall {
        "unlink" | "unlinkat" | "rmdir" | "remove" => {
            let path = PathBuf::from(arg);
            let Some(pre) = pre_image else {
                return Some(CaptureEventKind::CaptureRefused {
                    class: "capture-incomplete".to_string(),
                    path,
                    detail: "shim supplied a destructive notification without deletion evidence"
                        .to_string(),
                });
            };
            let Some(kind) = FileKind::from_mode(pre.mode) else {
                return Some(CaptureEventKind::CaptureRefused {
                    class: "capture-incomplete".to_string(),
                    path,
                    detail: format!(
                        "shim supplied deletion evidence with unknown file mode {:#o}",
                        pre.mode
                    ),
                });
            };
            let inode = InodeRef::new(pre.dev, pre.inode);
            let mode = pre.mode;
            if kind == FileKind::Symlink {
                let Some(target) = String::from_utf8(pre.bytes.clone()).ok() else {
                    return Some(CaptureEventKind::CaptureRefused {
                        class: "capture-incomplete".to_string(),
                        path,
                        detail: "shim supplied a symlink marker without a UTF-8 target".to_string(),
                    });
                };
                return Some(CaptureEventKind::TreeOp(TreeOp::SymlinkRemovedIdentified {
                    inode,
                    target,
                    path,
                }));
            }
            if kind != FileKind::Regular {
                return Some(CaptureEventKind::CaptureRefused {
                    class: "capture-incomplete".to_string(),
                    path,
                    detail: format!(
                        "metadata-only deletion evidence cannot safely reconstruct {kind:?}"
                    ),
                });
            }
            Some(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path,
                kind,
                mode,
            }))
        }
        "rename" | "renameat" | "renameat2" => {
            // The shim packs `from\tto` into a single arg field
            // (see `crates/shit-preload-shim/src/lib.rs` rename
            // interposer).
            let (from, to) = arg.split_once('\t')?;
            let inode = inode_of(to).unwrap_or_else(|| InodeRef::new(0, 0));
            Some(CaptureEventKind::TreeOp(TreeOp::Rename {
                from: PathBuf::from(from),
                to: PathBuf::from(to),
                inode,
            }))
        }
        "mkfifo" | "mkfifoat" => {
            // W09.10.1 — FreeBSD kqueue NOTE_WRITE on the parent dir
            // doesn't fire for FIFO/special-file creation, so the
            // shim is the only observation channel for `mkfifo(1)`
            // and library callers of `mkfifo(3)`. Journal a fresh
            // TreeOp::Create whose executor inverse is `unlink`.
            //
            // The shim notifies pre-syscall, so the file may not yet
            // exist at ingest time → inode_of returns None → sentinel
            // (0,0). The executor's TreeOp::Create reverse only uses
            // the path, so the sentinel is fine.
            let path = PathBuf::from(arg);
            let inode = inode_of(arg).unwrap_or_else(|| InodeRef::new(0, 0));
            Some(CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path,
                kind: FileKind::Fifo,
                mode: 0o644,
            }))
        }
        "link" | "linkat" => {
            // M03.x.LINK — hardlink: dst is a NEW path aliasing src's
            // inode. The shim ships only dst (src is unchanged). Same
            // executor shape as mkfifo: TreeOp::Create → inverse
            // unlink(dst). The src remains a separate live path; we
            // never touch it. kind=Regular matches the typical
            // hardlink target (links to dirs are forbidden on
            // macOS unless via special privilege).
            let path = PathBuf::from(arg);
            let inode = inode_of(arg).unwrap_or_else(|| InodeRef::new(0, 0));
            Some(CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path,
                kind: FileKind::Regular,
                mode: 0o644,
            }))
        }
        "mkdir" | "mkdirat" => {
            // M03.x.CREATE — create notifications are emitted only
            // after mkdir succeeds. In particular, mkdir -p calls
            // that return EEXIST no longer fabricate Create events
            // for pre-existing parent directories. In-watch creates
            // are gated above; this classifies the out-of-watch path.
            let path = PathBuf::from(arg);
            let inode = inode_of(arg).unwrap_or_else(|| InodeRef::new(0, 0));
            Some(CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path,
                kind: FileKind::Directory,
                mode: 0o755,
            }))
        }
        _ => None,
    }
}

/// Best-effort stat of `path` to recover its `(dev, inode)`. Returns
/// `None` if the path doesn't exist (the post-syscall state may have
/// already moved it; the planner handles missing inodes gracefully).
fn inode_of(path: &str) -> Option<InodeRef> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some(InodeRef::new(meta.dev(), meta.ino()))
}

/// Resolve a pre-image's complete xattr target. New payloads carry the
/// authoritative map directly. Legacy payloads use a strict pathname read and
/// overlay the one old-style xattr pre-value; a missing/deleted path therefore
/// becomes an ingest error and a command-atomic CaptureRefused event.
///
/// This is what the planner's `restore_user_xattrs` converges to:
///   - target has key+value → setxattr to restore the value
///   - target lacks a key the current file has → removexattr
///
/// Daemon read happens shortly after shim notify; race window is
/// microseconds. Workloads that mutate xattrs concurrently from
/// multiple processes might lose attribution for non-primary
/// xattrs. Acceptable for v1.
fn resolve_xattrs_target(pre: &ShimPreImage) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    if let Some(target) = &pre.xattrs {
        if let Some(xpre) = &pre.xattr {
            let key = snapshot_xattr_name(&xpre.name);
            if target.get(key) != xpre.value.as_ref() {
                return Err(anyhow::anyhow!(
                    "wire xattr snapshot disagrees with legacy pre-value for {:?}",
                    xpre.name
                ));
            }
        }
        return Ok(target.clone());
    }

    let mut target = read_all_user_xattrs(&pre.path)?;
    if let Some(xpre) = &pre.xattr {
        let key = snapshot_xattr_name(&xpre.name);
        match &xpre.value {
            Some(v) => {
                // Pre-syscall the xattr existed with this value.
                // Overlay so target reflects pre-state, not the
                // (possibly post-mutation) value from the daemon's
                // own read.
                target.insert(key.to_string(), v.clone());
            }
            None => {
                // Pre-syscall the xattr did NOT exist. Drop it
                // from target so the restore loop's delete-orphans
                // path removes it.
                target.remove(key);
            }
        }
    }
    Ok(target)
}

#[cfg(target_os = "linux")]
fn snapshot_xattr_name(name: &str) -> &str {
    name.strip_prefix("user.").unwrap_or(name)
}

#[cfg(not(target_os = "linux"))]
fn snapshot_xattr_name(name: &str) -> &str {
    name
}

/// Read all user-namespace xattrs at `path`. macOS uses
/// `listxattr` + `getxattr`; FreeBSD reuses the existing
/// `crate::xattr::read_user_xattrs_at_path` helper; other
/// platforms return empty (the M07 shim is macOS-only and the
/// kqueue capture tier on FreeBSD doesn't go through this path).
#[cfg(target_os = "macos")]
fn read_all_user_xattrs(path: &str) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    use std::ffi::CString;
    const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;

    let c_path = CString::new(path).map_err(|e| anyhow::anyhow!("xattr path contains NUL: {e}"))?;
    // First call sizes the buffer. XATTR_NOFOLLOW so we operate on
    // the symlink itself if `path` is one (matches the shim's
    // capture site which uses symlink_metadata).
    let list_size = unsafe {
        libc::listxattr(
            c_path.as_ptr(),
            std::ptr::null_mut(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if list_size < 0 {
        return Err(anyhow::anyhow!(
            "listxattr size query failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if list_size == 0 {
        return Ok(BTreeMap::new());
    }
    let list_size = usize::try_from(list_size)
        .map_err(|_| anyhow::anyhow!("xattr name-list length does not fit usize"))?;
    if list_size > XATTR_CAPTURE_CAP {
        return Err(anyhow::anyhow!(
            "xattr name list is {list_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
        ));
    }
    let mut name_buf = vec![0u8; list_size];
    let n = unsafe {
        libc::listxattr(
            c_path.as_ptr(),
            name_buf.as_mut_ptr().cast(),
            name_buf.len(),
            libc::XATTR_NOFOLLOW,
        )
    };
    if n < 0 {
        return Err(anyhow::anyhow!(
            "listxattr read failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if n as usize != list_size {
        return Err(anyhow::anyhow!(
            "xattr name list changed during capture (expected {list_size}, read {n})"
        ));
    }
    let mut out = BTreeMap::new();
    let mut total = list_size;
    // listxattr returns NUL-separated name list.
    for raw in name_buf[..n as usize].split(|&b| b == 0) {
        if raw.is_empty() {
            continue;
        }
        let name = std::str::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("xattr name is not valid UTF-8"))?;
        // Keep capture filtering identical to the executor's centralized
        // denylist. Dropping every com.apple.* key here would make metadata
        // restore delete unrelated quarantine/FinderInfo attributes.
        if name == "com.apple.provenance" {
            continue;
        }
        let c_name =
            CString::new(name).map_err(|e| anyhow::anyhow!("xattr name contains NUL: {e}"))?;
        let val_size = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if val_size < 0 {
            return Err(anyhow::anyhow!(
                "getxattr size query for {name:?} failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let val_size = usize::try_from(val_size)
            .map_err(|_| anyhow::anyhow!("xattr {name:?} length does not fit usize"))?;
        if val_size > XATTR_CAPTURE_CAP {
            return Err(anyhow::anyhow!(
                "xattr {name:?} is {val_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
            ));
        }
        total = total
            .checked_add(val_size)
            .ok_or_else(|| anyhow::anyhow!("xattr capture length overflow"))?;
        if total > XATTR_CAPTURE_CAP {
            return Err(anyhow::anyhow!(
                "xattr capture exceeds the {XATTR_CAPTURE_CAP}-byte aggregate cap"
            ));
        }
        let mut val = vec![0u8; val_size];
        let got = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                val.as_mut_ptr().cast(),
                val.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if got < 0 {
            return Err(anyhow::anyhow!(
                "getxattr read for {name:?} failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if got as usize != val_size {
            return Err(anyhow::anyhow!(
                "xattr {name:?} changed during capture (expected {val_size}, read {got})"
            ));
        }
        out.insert(name.to_string(), val);
    }
    Ok(out)
}

#[cfg(target_os = "freebsd")]
fn read_all_user_xattrs(path: &str) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    crate::xattr::try_read_user_xattrs_at_path(std::path::Path::new(path))
        .map_err(|e| anyhow::anyhow!("strict FreeBSD xattr capture failed: {e}"))
}

#[cfg(target_os = "linux")]
fn read_all_user_xattrs(path: &str) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    use std::ffi::CString;
    const XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;

    let c_path = CString::new(path).map_err(|e| anyhow::anyhow!("xattr path contains NUL: {e}"))?;
    let list_size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if list_size < 0 {
        return Err(anyhow::anyhow!(
            "listxattr size query failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if list_size == 0 {
        return Ok(BTreeMap::new());
    }
    let list_size = usize::try_from(list_size)
        .map_err(|_| anyhow::anyhow!("xattr name-list length does not fit usize"))?;
    if list_size > XATTR_CAPTURE_CAP {
        return Err(anyhow::anyhow!(
            "xattr name list is {list_size} bytes, above the {XATTR_CAPTURE_CAP}-byte cap"
        ));
    }
    let mut names = vec![0 as libc::c_char; list_size];
    let got = unsafe { libc::listxattr(c_path.as_ptr(), names.as_mut_ptr(), names.len()) };
    if got < 0 || got as usize != list_size {
        return Err(anyhow::anyhow!(
            "xattr name list changed or failed during capture: {}",
            if got < 0 {
                std::io::Error::last_os_error().to_string()
            } else {
                format!("expected {list_size}, read {got}")
            }
        ));
    }
    let name_bytes =
        unsafe { std::slice::from_raw_parts(names.as_ptr().cast::<u8>(), names.len()) };
    let mut out = BTreeMap::new();
    let mut total = list_size;
    for raw in name_bytes
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let full = std::str::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("xattr name is not valid UTF-8"))?;
        let Some(name) = full.strip_prefix("user.") else {
            continue;
        };
        let c_name =
            CString::new(full).map_err(|e| anyhow::anyhow!("xattr name contains NUL: {e}"))?;
        let value_size =
            unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if value_size < 0 {
            return Err(anyhow::anyhow!(
                "getxattr size query for {full:?} failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let value_size = usize::try_from(value_size)
            .map_err(|_| anyhow::anyhow!("xattr {full:?} length does not fit usize"))?;
        total = total
            .checked_add(value_size)
            .ok_or_else(|| anyhow::anyhow!("xattr capture length overflow"))?;
        if total > XATTR_CAPTURE_CAP {
            return Err(anyhow::anyhow!(
                "xattr capture exceeds the {XATTR_CAPTURE_CAP}-byte aggregate cap"
            ));
        }
        let mut value = vec![0u8; value_size];
        let read = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if read < 0 || read as usize != value_size {
            return Err(anyhow::anyhow!(
                "xattr {full:?} changed or failed during capture: {}",
                if read < 0 {
                    std::io::Error::last_os_error().to_string()
                } else {
                    format!("expected {value_size}, read {read}")
                }
            ));
        }
        out.insert(name.to_string(), value);
    }
    Ok(out)
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "linux")))]
fn read_all_user_xattrs(_path: &str) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    Err(anyhow::anyhow!(
        "complete xattr capture is unsupported on this platform"
    ))
}

/// Resolve the shim socket path. Default is sibling to the hook socket
/// under `$XDG_RUNTIME_DIR`. Letting the path be derived (not a
/// separately configured field) means tests and production share one
/// source of truth.
pub fn shim_socket_path(cfg: &ResolvedConfig) -> std::path::PathBuf {
    // hook_socket_path is typically `${XDG_RUNTIME_DIR}/shit.sock`;
    // place the shim socket alongside it.
    let dir = cfg
        .hook_socket_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    dir.join("shit-shim.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::store::PlannerStore;
    use shit_proto::{decode_frame, encode_shim_notification_frame};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Duration;

    fn fresh_blob_store(tmp: &std::path::Path) -> Arc<BlobStore> {
        Arc::new(BlobStore::open(tmp.join("blobs")).unwrap())
    }

    fn note(syscall: &str, arg: &str) -> ShimNotification {
        ShimNotification {
            pid: 4242,
            syscall: syscall.to_string(),
            arg: arg.to_string(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
        }
    }

    #[test]
    fn mkdir_notifications_classify_as_directory_creates() {
        for syscall in ["mkdir", "mkdirat"] {
            let path = format!("/tmp/shit-{syscall}-does-not-exist");
            let event = classify_tree_op(syscall, &path, None).expect("mkdir must be classifiable");

            match event {
                CaptureEventKind::TreeOp(TreeOp::Create {
                    path: event_path,
                    kind,
                    mode,
                    ..
                }) => {
                    assert_eq!(event_path, PathBuf::from(&path));
                    assert_eq!(kind, FileKind::Directory);
                    assert_eq!(mode, 0o755);
                }
                other => panic!("unexpected mkdir classification: {other:?}"),
            }
        }
    }

    #[test]
    fn unlink_directory_marker_is_refused_as_lossy() {
        let pre = ShimPreImage {
            path: "/tmp/removed-dir".into(),
            dev: 7,
            inode: 9,
            mode: 0o040750,
            uid: 1000,
            gid: 1000,
            size: 64,
            mtime_unix_nanos: 0,
            bytes: Vec::new(),
            xattr: None,
            flags: 0,
            xattrs: Some(BTreeMap::new()),
        };
        for syscall in ["unlinkat", "rmdir", "remove"] {
            let event = classify_tree_op(syscall, &pre.path, Some(&pre)).unwrap();
            assert!(matches!(
                event,
                CaptureEventKind::CaptureRefused { ref path, ref detail, .. }
                    if path == Path::new("/tmp/removed-dir")
                        && detail.contains("cannot safely reconstruct Directory")
            ));
        }
    }

    #[test]
    fn unlink_symlink_marker_preserves_lexical_target() {
        let pre = ShimPreImage {
            path: "/tmp/removed-link".into(),
            dev: 7,
            inode: 10,
            mode: 0o120777,
            uid: 1000,
            gid: 1000,
            size: 9,
            mtime_unix_nanos: 0,
            bytes: b"../target".to_vec(),
            xattr: None,
            flags: 0,
            xattrs: Some(BTreeMap::new()),
        };
        let event = classify_tree_op("unlink", &pre.path, Some(&pre)).unwrap();
        assert!(matches!(
            event,
            CaptureEventKind::TreeOp(TreeOp::SymlinkRemovedIdentified {
                inode,
                target,
                path,
            }) if inode == InodeRef::new(7, 10)
                && target == "../target"
                && path == Path::new("/tmp/removed-link")
        ));
    }

    #[test]
    fn destructive_notification_without_preimage_is_refused() {
        for syscall in ["unlink", "unlinkat", "rmdir", "remove"] {
            let event = classify_tree_op(syscall, "/tmp/missing-evidence", None).unwrap();
            assert!(matches!(event, CaptureEventKind::CaptureRefused { .. }));

            let note = note(syscall, "/tmp/missing-evidence");
            assert!(unsafe_replay_path(&note).is_some());
        }
    }

    #[test]
    fn destructive_notification_rejects_disagreeing_preimage_path() {
        let mut note = note("unlink", "/tmp/claimed-target");
        note.pre_image = Some(ShimPreImage {
            path: "/tmp/different-target".into(),
            dev: 1,
            inode: 2,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            bytes: Vec::new(),
            xattr: None,
            flags: 0,
            xattrs: Some(BTreeMap::new()),
        });
        assert!(unsafe_replay_path(&note).is_some());
    }

    #[test]
    fn replay_path_validation_checks_all_mutable_operands() {
        assert!(unsafe_replay_path(&note("open", "relative.txt")).is_some());
        assert!(unsafe_replay_path(&note("rename", "/absolute/from\trelative-to")).is_some());
        assert!(unsafe_replay_path(&note("rename", "/missing-delimiter")).is_some());
        assert!(unsafe_replay_path(&note("rename", "/from\t/to")).is_none());
        assert!(unsafe_replay_path(&note("open", "/tmp/../unsafe")).is_some());
        assert!(unsafe_replay_path(&note("open", "/tmp//unsafe")).is_some());

        let mut primary = note("open", "/absolute/arg");
        primary.pre_image = Some(ShimPreImage {
            path: "relative-pre-image".into(),
            dev: 1,
            inode: 2,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            bytes: Vec::new(),
            xattr: None,
            flags: 0,
            xattrs: Some(BTreeMap::new()),
        });
        assert!(unsafe_replay_path(&primary).is_some());

        let mut recursive = note("rename", "/absolute/from\t/absolute/to");
        recursive.extra_pre_images = primary.pre_image.into_iter().collect();
        assert!(unsafe_replay_path(&recursive).is_some());

        let mut wrong_destination = note("rename", "/absolute/from\t/absolute/to");
        wrong_destination.pre_image = Some(ShimPreImage {
            path: "/absolute/not-to".into(),
            dev: 1,
            inode: 2,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            bytes: Vec::new(),
            xattr: None,
            flags: 0,
            xattrs: Some(BTreeMap::new()),
        });
        assert!(unsafe_replay_path(&wrong_destination).is_some());
    }

    #[test]
    fn relative_create_journals_only_capture_refused() {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;

        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let blob_store = BlobStore::open(tmp.path().join("blobs")).unwrap();
        let live_baseline = LiveBaseline::new();
        let session = uuid::Uuid::nil();
        let command = shit_planner::events::CommandId { session, seq: 1 };
        index
            .put_session(session, "bash", 4242, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("create relative.txt".into()),
                cwd: tmp.path().to_path_buf(),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();

        ingest_notification(
            &note("open", "relative.txt"),
            Some(command),
            TimePoint::new(1, 1),
            &index,
            &blob_store,
            &live_baseline,
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::CaptureRefused { .. }
        ));
    }

    /// Spawn a one-shot listener, connect a sync client, send a
    /// notification, read back the ack. End-to-end smoke for the
    /// shim wire. Uses sync std client to mirror the (real, non-tokio)
    /// shim's eventual call shape.
    #[tokio::test]
    async fn one_shot_notify_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("shim.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let idx_path = tmp.path().join("idx.sqlite");
        let index = Arc::new(Index::open(&idx_path).unwrap());
        let blob_store = fresh_blob_store(tmp.path());
        let active = Arc::new(ActiveCommands::new());
        let live_baseline = Arc::new(LiveBaseline::new());
        let _accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_one(stream, index, blob_store, active, live_baseline)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let sock_path = sock.clone();
        let client_result = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut s = StdUnixStream::connect(&sock_path).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let note = ShimNotification {
                pid: 4242,
                syscall: "unlink".into(),
                arg: "/tmp/probe".into(),
                ts_unix_nanos: 0,
                pre_image: None,
                extra_pre_images: Vec::new(),
                failure: None,
            };
            let frame = encode_shim_notification_frame(&note).unwrap();
            s.write_all(&frame).unwrap();
            let mut buf = vec![0u8; 64];
            let n = s.read(&mut buf).unwrap();
            let ack: ShimAck = decode_frame(&buf[..n]).unwrap();
            ack
        })
        .await
        .unwrap();
        assert_eq!(client_result, ShimAck::Allow);
    }

    /// A shim is allowed to stop waiting for the ACK after its short
    /// deadline. The daemon has already decoded and attributed the capture at
    /// that point, so a closed peer must not suppress journal ingestion.
    #[tokio::test]
    async fn closed_ack_peer_still_journals_pre_image() {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;
        use std::io::Write as _;
        use std::net::Shutdown;

        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("shim.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let index = Arc::new(Index::open(tmp.path().join("idx.sqlite")).unwrap());
        let blob_store = fresh_blob_store(tmp.path());
        let active = Arc::new(ActiveCommands::new());
        let live_baseline = Arc::new(LiveBaseline::new());

        let session = uuid::Uuid::nil();
        let command = shit_planner::events::CommandId { session, seq: 1 };
        let pid = std::process::id();
        index
            .put_session(session, "bash", pid, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("unlink then clonefile".into()),
                cwd: tmp.path().to_path_buf(),
                pid,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        active.insert(pid, command);

        let handler_index = Arc::clone(&index);
        let handler = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_one(stream, handler_index, blob_store, active, live_baseline).await
        });

        let note = ShimNotification {
            pid,
            syscall: "unlink".into(),
            arg: "/tmp/clone-destination".into(),
            ts_unix_nanos: 0,
            pre_image: Some(ShimPreImage {
                path: "/tmp/clone-destination".into(),
                dev: 64,
                inode: 7777,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                size: 3,
                mtime_unix_nanos: 0,
                bytes: b"old".to_vec(),
                xattr: None,
                flags: 0,
                xattrs: Some(BTreeMap::new()),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = shit_proto::encode_shim_notification_frame_large(&note).unwrap();
        let client_sock = sock.clone();
        tokio::task::spawn_blocking(move || {
            let mut stream = StdUnixStream::connect(client_sock).unwrap();
            stream.write_all(&frame).unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
        })
        .await
        .unwrap();

        handler.await.unwrap().unwrap();
        let events = index.events_for_command(command);
        assert_eq!(events.len(), 2, "unlink capture needs pre-image + tree op");
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, CaptureEventKind::FilePreImage { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, CaptureEventKind::TreeOp(TreeOp::Unlink { .. })))
        );
    }

    /// W06.A.4 — a content notification with an inline pre-image gets
    /// blob-stored AND journaled. Registers a session+command first
    /// so the put_event foreign-key constraint is satisfied; verifies
    /// the blob exists in the BlobStore at the canonical blake3 hash.
    #[test]
    fn pre_image_writes_blob_and_journals_event() {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;
        use std::path::PathBuf;

        let tmp = tempfile::tempdir().unwrap();
        let idx_path = tmp.path().join("idx.sqlite");
        let index = Index::open(&idx_path).unwrap();
        let blob_store = BlobStore::open(tmp.path().join("blobs")).unwrap();

        let session = uuid::Uuid::nil();
        index
            .put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .expect("put_session");
        let command = shit_planner::events::CommandId { session, seq: 1 };
        index
            .put_command(&CommandRecord {
                command,
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

        let deleted_path = tmp.path().join("deleted-before-ingest.txt");
        std::fs::write(&deleted_path, b"hello").unwrap();
        std::fs::remove_file(&deleted_path).unwrap();
        let pre = ShimPreImage {
            path: deleted_path.to_string_lossy().into_owned(),
            dev: 64,
            inode: 7777,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 5,
            mtime_unix_nanos: 1_700_000_000_000_000_000,
            bytes: b"hello".to_vec(),
            xattr: None,
            flags: 0,
            xattrs: Some(BTreeMap::from([(
                "user.shit.snapshot".to_string(),
                b"preserved".to_vec(),
            )])),
        };
        let reserved_ts = TimePoint::new(777, 42);
        ingest_pre_image(command, &pre, &index, &blob_store, reserved_ts).expect("ingest");

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ts, reserved_ts);
        assert!(matches!(
            &events[0].kind,
            CaptureEventKind::FilePreImage {
                source: shit_planner::FilePreImageSource::Other,
                meta,
                ..
            } if meta.xattrs.get("user.shit.snapshot").map(Vec::as_slice)
                == Some(b"preserved".as_slice())
        ));

        // Blob present at canonical hash. put() is content-addressed
        // and idempotent, so re-calling on the same bytes returns
        // the existing hash and round-trips identical content.
        let (blob_hash, _) = blob_store.put(b"hello").expect("put");
        let _ = blob_store
            .stat(&blob_hash)
            .expect("stat ok")
            .expect("blob present");
        let round_trip = blob_store.get(blob_hash).expect("get");
        assert_eq!(round_trip, b"hello");
    }

    #[test]
    fn legacy_pre_image_with_deleted_path_cannot_fabricate_empty_xattrs() {
        let missing = tempfile::tempdir()
            .unwrap()
            .path()
            .join("already-deleted")
            .to_string_lossy()
            .into_owned();
        let pre = ShimPreImage {
            path: missing,
            dev: 64,
            inode: 7777,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            bytes: Vec::new(),
            xattr: None,
            flags: 0,
            // This is how the dedicated decoder marks a legacy payload.
            xattrs: None,
        };
        assert!(
            resolve_xattrs_target(&pre).is_err(),
            "a missing legacy path must refuse instead of becoming authoritative empty"
        );
    }

    #[test]
    fn chflags_notification_uses_flags_source_and_reserved_timestamp() {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;
        use std::path::PathBuf;

        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let blob_store = BlobStore::open(tmp.path().join("blobs")).unwrap();
        let session = uuid::Uuid::nil();
        index
            .put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .expect("put_session");
        let command = shit_planner::events::CommandId { session, seq: 1 };
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("chflags hidden target".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .expect("put_command");
        let note = ShimNotification {
            pid: 4242,
            syscall: "chflags".into(),
            arg: "/tmp/flags-target".into(),
            ts_unix_nanos: 0,
            pre_image: Some(ShimPreImage {
                path: "/tmp/flags-target".into(),
                dev: 64,
                inode: 8888,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                size: 0,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                bytes: Vec::new(),
                xattr: None,
                flags: 7,
                xattrs: Some(BTreeMap::new()),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let reserved_ts = TimePoint::new(778, 43);

        ingest_notification(
            &note,
            Some(command),
            reserved_ts,
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ts, reserved_ts);
        assert!(matches!(
            &events[0].kind,
            CaptureEventKind::FilePreImage {
                source: shit_planner::FilePreImageSource::ShimFlagsPreMutation,
                meta,
                ..
            } if meta.flags == 7
        ));
    }

    #[test]
    fn chmod_notification_is_marked_metadata_only() {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;

        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let blob_store = BlobStore::open(tmp.path().join("blobs")).unwrap();
        let session = uuid::Uuid::nil();
        let command = shit_planner::events::CommandId { session, seq: 1 };
        index
            .put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("chmod 600 target".into()),
                cwd: "/tmp".into(),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        let note = ShimNotification {
            pid: 4242,
            syscall: "chmod".into(),
            arg: "/tmp/metadata-target".into(),
            ts_unix_nanos: 0,
            pre_image: Some(ShimPreImage {
                path: "/tmp/metadata-target".into(),
                dev: 64,
                inode: 9999,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                size: 12,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                // Metadata notifications may carry bytes because they reuse
                // ShimPreImage. Their source discriminator must keep those
                // bytes out of RestoreContent planning.
                bytes: b"must-not-restore-as-content".to_vec(),
                xattr: None,
                flags: 0,
                xattrs: Some(BTreeMap::new()),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };

        ingest_notification(
            &note,
            Some(command),
            TimePoint::new(779, 44),
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(matches!(
            &events[0].kind,
            CaptureEventKind::FilePreImage {
                source: shit_planner::FilePreImageSource::ShimMetadataPreMutation,
                ..
            }
        ));
    }
}
