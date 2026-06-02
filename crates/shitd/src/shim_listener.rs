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
//! 3. Classify:
//!    - `unlink`/`unlinkat` → `TreeOp::Unlink`
//!    - `rename`/`renameat` → `TreeOp::Rename`  (arg is `from\tto`)
//!    - `open`/`openat`/`truncate` with `pre_image=Some(_)` →
//!      `FilePreImage` (W06.A.4); without it, log + drop.
//!    - `pwrite` / `ftruncate` / `mmap_shared_w` — logged but not
//!      journaled (fd-based — needs fd→path resolution; deferred).
//! 4. For content events: write blob bytes to the BlobStore, journal
//!    `FilePreImage`. For TreeOp events: journal directly.
//! 5. Ack `Allow`.
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
use shit_proto::{ShimAck, ShimNotification, ShimPreImage, decode_frame_large, encode_frame};
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

/// Per-connection handler. One notification → ingest → ack → close.
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
    let note: ShimNotification = match decode_frame_large(&buf[..total]) {
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

    // Resolve `pid → CommandId` BEFORE acking. The shim returns to
    // the calling process immediately after we ack, the real
    // syscall fires, and the process (e.g. `install` invoked by
    // `make`) often terminates within milliseconds. If we resolve
    // after acking, `ancestor_chain` shells out to `ps -p <pid>`
    // for an already-dead pid and returns None — the notification
    // is then orphaned. Doing the resolution synchronously here
    // costs ~10ms (one ps invocation per ancestor level); we have
    // 40ms of headroom inside the shim's 50ms allow-on-timeout
    // budget.
    let resolved = active.resolve_by_descendant(note.pid);

    // Ack — never block the user's command on journaling. We're
    // fail-open by design: even if the journal write below errors,
    // the syscall proceeds.
    let ack = ShimAck::Allow;
    let frame = encode_frame(&ack)?;
    stream.write_all(&frame).await?;

    ingest_notification(&note, resolved, &index, &blob_store, &live_baseline);
    Ok(())
}

/// Convert a shim notification into a `CaptureEvent` and journal it,
/// if the emitter's pid resolves to an active command. Errors are
/// logged but never propagated — the shim path is best-effort.
fn ingest_notification(
    note: &ShimNotification,
    resolved: Option<shit_planner::events::CommandId>,
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

    // AU10 — when the shim reported a structured capture failure
    // (canonicalize_path tripping its load-bearing fallback is the
    // canonical example), journal a CaptureRefused event BEFORE the
    // rest of the syscall-specific handling. The downstream
    // pre-image/TreeOp ingest may still fire (we don't want to lose
    // the partial capture); the journaled refusal ensures the
    // planner surfaces the gap as an InverseOp::Refuse node at undo
    // time instead of silently mis-attributing.
    if let Some(failure) = &note.failure {
        let (class, primary_path, detail) = match failure {
            shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg,
                attempted_path,
                error_chain,
            } => (
                "capture-incomplete".to_string(),
                PathBuf::from(attempted_path),
                format!("shim canonicalize tripped on {which_arg} argument ({error_chain})"),
            ),
        };
        // The primary path matters for the user-visible refusal
        // text. We deliberately use the raw `attempted_path` here
        // (not a canonicalized form) because the failure mode IS
        // that canonicalize couldn't resolve it — surfacing the
        // raw input is the honest signal.
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: crate::server::next_ts(),
            partial: false,
            kind: CaptureEventKind::CaptureRefused {
                class,
                path: primary_path,
                detail,
            },
        };
        if let Err(e) = index.put_event(&event) {
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
        // Fall through — the syscall may have attached a partial
        // pre_image too (e.g., `from` canonicalized but `to`
        // didn't). Ingest what we can; the Refuse marker is
        // additive.
    }

    // M07.B.5: metadata-mutation syscalls (chmod / chown / utimes /
    // xattr families). The shim's pre-image carries the OLD
    // mode/uid/gid/mtime; ingest as a FilePreImage event so the
    // event lands in the journal with the BEFORE metadata fields
    // populated. Without this branch, fchmodat / fchownat /
    // utimensat etc. fall through to classify_tree_op (which
    // returns None for them) and the daemon drops the event —
    // undo has nothing to invert.
    //
    // Planner-side: synthesizing a metadata-restore inverse from
    // a FilePreImage that has no companion TreeOp is the M07.B.6
    // follow-up. This slice ships the journal correctness fix; the
    // planner gap is surfaced explicitly so undo reports "captured
    // but not yet restorable" rather than silently failing.
    //
    // Why not use the richer `MetadataChange { before, after }`
    // event the ES producer emits? Because the shim notifies
    // BEFORE the libc passthrough returns — a daemon-side stat to
    // capture `after` sees the unchanged BEFORE state (the chmod
    // hasn't fired yet on the file). Capturing `after` properly
    // would require either (a) shim sending a post-syscall
    // follow-up notification, or (b) the planner inferring after-
    // state from the syscall arg shape. Both are M07.B.6 scope.
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
            // M03.x.SETATTR — chflags family. Pre-image carries the
            // OLD st_flags via FileMetadataWire.flags; ingest_pre_image
            // routes through the same FilePreImage path as the chmod
            // family. Planner-side, the inverse is RestoreMetadata
            // (the executor's restore_flags_only call wraps chflags).
            | "chflags"
            | "fchflags"
    ) {
        if let Some(pre) = &note.pre_image {
            if let Err(e) = ingest_pre_image(command, pre, index, blob_store) {
                warn!(
                    err = %e,
                    pid = note.pid,
                    syscall = %note.syscall,
                    "shim notify: metadata pre-image ingest failed"
                );
            } else {
                debug!(
                    pid = note.pid,
                    syscall = %note.syscall,
                    arg = %note.arg,
                    "shim notify: metadata-mutation pre-image journaled (M07.B.5)"
                );
            }
        } else {
            // No pre-image — typical for xattr family (path-only
            // notify today) or fd-based variants where F_GETPATH
            // failed. Drop with a debug log; the lack of journal
            // entry surfaces at undo as a coverage gap.
            debug!(
                pid = note.pid,
                syscall = %note.syscall,
                arg = %note.arg,
                "shim notify: metadata-mutation without pre-image; dropping"
            );
        }
        return;
    }

    // W06.A.4: content syscalls with attached pre-image take the
    // FilePreImage path.
    if matches!(note.syscall.as_str(), "open" | "openat" | "truncate") {
        if let Some(pre) = &note.pre_image {
            if let Err(e) = ingest_pre_image(command, pre, index, blob_store) {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: pre-image ingest failed");
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
            ts: crate::server::next_ts(),
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
        && let Err(e) = ingest_pre_image(command, pre, index, blob_store)
    {
        warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: rename pre-image ingest failed");
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
            match ingest_pre_image(command, pre, index, blob_store) {
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
    if matches!(note.syscall.as_str(), "unlink" | "unlinkat")
        && let Some(pre) = &note.pre_image
        && let Err(e) = ingest_pre_image(command, pre, index, blob_store)
    {
        warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: unlink pre-image ingest failed");
    }
    // Fall through to journal the TreeOp::Unlink below.

    let Some(kind) = classify_tree_op(&note.syscall, &note.arg) else {
        // Fd-based content syscalls (ftruncate, pwrite, mmap_shared_w)
        // have no path in the wire payload; they need fd→path resolution
        // which is FreeBSD-specific (procstat/kvm). Deferred.
        debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            "shim notify: syscall not classifiable (fd-based content needs fd→path resolution)"
        );
        return;
    };

    let ts = crate::server::next_ts();
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind,
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: put_event failed");
        return;
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
) -> anyhow::Result<()> {
    let (blob_hash, stat) = blob_store
        .put(&pre.bytes)
        .map_err(|e| anyhow::anyhow!("blob put: {e}"))?;
    let ts = crate::server::next_ts();
    index
        .put_blob_record(blob_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| anyhow::anyhow!("put_blob_record: {e}"))?;
    let inode = InodeRef::new(pre.dev, pre.inode);
    // M03.x.XATTR-MUTATE — build the FULL captured xattrs target.
    // The shim only captures the ONE xattr being mutated (via
    // `pre.xattr`) — the file's other xattrs (com.apple.provenance,
    // user.*, etc.) aren't shipped on the wire. If we left them out
    // of target.xattrs, the planner's RestoreMetadata "delete
    // orphans" loop would remove every xattr not in target on undo.
    //
    // Strategy: read the file's CURRENT xattrs daemon-side, then
    // overlay the shim's pre-value for the specific xattr the
    // syscall is mutating. There's a small race (microseconds
    // between shim-notify and this read); workloads that mutate
    // multiple xattrs concurrently might lose attribution for
    // ones not the syscall's primary target. Acceptable for v1;
    // a future hardening could have the shim capture all xattrs.
    let xattrs = build_xattrs_target(&pre.path, pre.xattr.as_ref());
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
            source: shit_planner::FilePreImageSource::Other,
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
/// works). For `Unlink` the path is gone by ingest time so we use
/// `InodeRef::new(0, 0)` as a sentinel — the planner doesn't
/// require a valid inode for the Unlink-inverse-is-RecreatePath
/// path.
fn classify_tree_op(syscall: &str, arg: &str) -> Option<CaptureEventKind> {
    match syscall {
        "unlink" | "unlinkat" => {
            let path = PathBuf::from(arg);
            // G02: shim doesn't carry kind/mode in its notification
            // wire (the shim's notify happens pre-syscall and
            // doesn't fstat). Default to Regular/0o100644, matching
            // pre-G02 hard-coded behavior. The kernel-tier LSM
            // path (helper) DOES carry kind+mode and overrides this
            // when both tiers see the same unlink.
            Some(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(0, 0),
                path,
                kind: shit_planner::metadata::FileKind::Regular,
                mode: 0o100644,
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

/// M03.x.XATTR-MUTATE — build the target xattr map for a captured
/// shim pre-image. Reads the file's CURRENT xattrs daemon-side as
/// the baseline, then overlays the shim's captured pre-value for
/// the specific xattr being mutated (or removes it from the target
/// if `value: None` — i.e. xattr didn't exist pre-syscall).
///
/// This is what the planner's `restore_user_xattrs` converges to:
///   - target has key+value → setxattr to restore the value
///   - target lacks a key the current file has → removexattr
///
/// Daemon read happens shortly after shim notify; race window is
/// microseconds. Workloads that mutate xattrs concurrently from
/// multiple processes might lose attribution for non-primary
/// xattrs. Acceptable for v1.
fn build_xattrs_target(
    path: &str,
    xattr_pre: Option<&shit_proto::XattrPreImage>,
) -> BTreeMap<String, Vec<u8>> {
    let mut target = read_all_user_xattrs(path);
    if let Some(xpre) = xattr_pre {
        match &xpre.value {
            Some(v) => {
                // Pre-syscall the xattr existed with this value.
                // Overlay so target reflects pre-state, not the
                // (possibly post-mutation) value from the daemon's
                // own read.
                target.insert(xpre.name.clone(), v.clone());
            }
            None => {
                // Pre-syscall the xattr did NOT exist. Drop it
                // from target so the restore loop's delete-orphans
                // path removes it.
                target.remove(&xpre.name);
            }
        }
    }
    target
}

/// Read all user-namespace xattrs at `path`. macOS uses
/// `listxattr` + `getxattr`; FreeBSD reuses the existing
/// `crate::xattr::read_user_xattrs_at_path` helper; other
/// platforms return empty (the M07 shim is macOS-only and the
/// kqueue capture tier on FreeBSD doesn't go through this path).
#[cfg(target_os = "macos")]
fn read_all_user_xattrs(path: &str) -> BTreeMap<String, Vec<u8>> {
    use std::ffi::CString;
    let Ok(c_path) = CString::new(path) else {
        return BTreeMap::new();
    };
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
    if list_size <= 0 {
        return BTreeMap::new();
    }
    let mut name_buf = vec![0u8; list_size as usize];
    let n = unsafe {
        libc::listxattr(
            c_path.as_ptr(),
            name_buf.as_mut_ptr().cast(),
            name_buf.len(),
            libc::XATTR_NOFOLLOW,
        )
    };
    if n <= 0 {
        return BTreeMap::new();
    }
    let mut out = BTreeMap::new();
    // listxattr returns NUL-separated name list.
    for raw in name_buf[..n as usize].split(|&b| b == 0) {
        if raw.is_empty() {
            continue;
        }
        let Ok(name) = std::str::from_utf8(raw) else {
            continue;
        };
        // Skip system xattrs the planner shouldn't try to restore.
        // com.apple.* are kernel/Finder-managed; the user didn't
        // set them with `xattr -w`.
        if name.starts_with("com.apple.") {
            continue;
        }
        let Ok(c_name) = CString::new(name) else {
            continue;
        };
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
            continue;
        }
        let mut val = vec![0u8; val_size as usize];
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
            continue;
        }
        val.truncate(got as usize);
        out.insert(name.to_string(), val);
    }
    out
}

#[cfg(target_os = "freebsd")]
fn read_all_user_xattrs(path: &str) -> BTreeMap<String, Vec<u8>> {
    crate::xattr::read_user_xattrs_at_path(std::path::Path::new(path))
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
fn read_all_user_xattrs(_path: &str) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::new()
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
    use shit_proto::{decode_frame, encode_frame};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Duration;

    fn fresh_blob_store(tmp: &std::path::Path) -> Arc<BlobStore> {
        Arc::new(BlobStore::open(tmp.join("blobs")).unwrap())
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
            let frame = encode_frame(&note).unwrap();
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

        let pre = ShimPreImage {
            path: "/tmp/foo.txt".into(),
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
        };
        ingest_pre_image(command, &pre, &index, &blob_store).expect("ingest");

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
}
