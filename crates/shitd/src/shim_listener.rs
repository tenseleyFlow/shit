// SPDX-License-Identifier: AGPL-3.0-or-later

//! S24.D.2 — accept loop for the LD_PRELOAD shim's per-process UDS.
//! W06.A.3 — route notifications into journal events.
//!
//! The shim (`shit-preload-shim`) opens a short-lived connection to
//! `$XDG_RUNTIME_DIR/shit/shim.sock`, sends a [`ShimNotification`]
//! framed via `encode_frame`, waits ≤50 ms for a [`ShimAck`], and
//! closes.
//!
//! Per-connection flow (W06.A.3):
//! 1. Decode the notification.
//! 2. Resolve `pid → CommandId` via `ActiveCommands::resolve_by_descendant`.
//!    If no active command owns the emitter, the event is orphan
//!    and dropped silently (the shim still gets an Allow ack — we
//!    never block a user command on an attribution miss).
//! 3. Classify the `syscall` field into a `CaptureEvent`:
//!    - `unlink`/`unlinkat` → `TreeOp::Unlink`
//!    - `rename`/`renameat` → `TreeOp::Rename`  (arg is `from\tto`)
//!    - other syscalls (`open`, `truncate`, `pwrite`, `mmap`) are
//!      logged but not journaled — they need content pre-image
//!      capture which is W06.A.4 territory.
//! 4. Write the event via `Index::put_event`.
//! 5. Ack `Allow`.
//!
//! The locked design decision is **fan-in** (single daemon-side socket,
//! 100-conn pool) rather than fan-out per process.

use crate::active_commands::ActiveCommands;
use crate::config::ResolvedConfig;
use shit_planner::TreeOp;
use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inode::InodeRef;
use shit_proto::{ShimAck, ShimNotification, decode_frame, encode_frame};
use shit_store::Index;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// Buffer cap for a single notification frame. The shim only sends
/// path strings (bounded by PATH_MAX ~= 1k) plus a small header, so
/// 8 KiB is generous and avoids any malloc-per-read churn.
const SHIM_BUF: usize = 8 * 1024;

/// Listen on the shim socket inside `$XDG_RUNTIME_DIR/shit/shim.sock`,
/// serving each accepted connection on its own tokio task. Returns when
/// `shutdown` fires.
pub async fn serve(
    cfg: &ResolvedConfig,
    shutdown: Arc<Notify>,
    index: Arc<Index>,
    active: Arc<ActiveCommands>,
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
                    let active = Arc::clone(&active);
                    tokio::spawn(async move {
                        if let Err(e) = handle_one(stream, index, active).await {
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
    active: Arc<ActiveCommands>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; SHIM_BUF];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        // Peer hung up without sending anything. The shim's allow-
        // on-timeout path will already have moved on, so no ack
        // needed.
        return Ok(());
    }
    let note: ShimNotification = match decode_frame(&buf[..n]) {
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

    // W06.A.3: route into the journal. The path stat (for Rename
    // inode resolution) happens here, AFTER ack — that's fine
    // because the post-syscall path exists at the destination
    // (rename preserves inode), so stat after ack still works.
    ingest_notification(&note, resolved, &index);
    Ok(())
}

/// Convert a shim notification into a `CaptureEvent` and journal it,
/// if the emitter's pid resolves to an active command. Errors are
/// logged but never propagated — the shim path is best-effort.
fn ingest_notification(
    note: &ShimNotification,
    resolved: Option<shit_planner::events::CommandId>,
    index: &Index,
) {
    let Some(command) = resolved else {
        // The shim is loaded into a process whose ancestor isn't a
        // tracked shell. Likely a background daemon / system service
        // that picked up LD_PRELOAD from a parent env, OR the pid
        // resolution raced the process's lifetime (W06.A.4 will
        // address by carrying ancestry in the notification).
        debug!(pid = note.pid, syscall = %note.syscall, "shim notify: no active command for pid; dropping");
        return;
    };

    let Some(kind) = classify(&note.syscall, &note.arg) else {
        // Syscalls that don't yet have a TreeOp shape (open / truncate
        // / pwrite / mmap need pre-image capture before they're
        // useful — W06.A.4 territory). Log for visibility.
        debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            "shim notify: syscall not classifiable to TreeOp yet; W06.A.4 will cover content-changing kinds"
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

/// Map a shim notification's `(syscall, arg)` to a journal event.
///
/// W06.A.3 covers `unlink`/`unlinkat` and `rename`/`renameat`. Other
/// syscalls return `None` — they need wire-side flag/inode plumbing
/// or pre-image capture (W06.A.4).
///
/// Inodes are best-effort: for `Rename` we stat the destination
/// (which is the inode-preserved post-state, so stat-after-syscall
/// works). For `Unlink` the path is gone by ingest time so we use
/// `InodeRef::new(0, 0)` as a sentinel — the planner doesn't
/// require a valid inode for the Unlink-inverse-is-RecreatePath
/// path.
fn classify(syscall: &str, arg: &str) -> Option<CaptureEventKind> {
    match syscall {
        "unlink" | "unlinkat" => {
            let path = PathBuf::from(arg);
            Some(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(0, 0),
                path,
            }))
        }
        "rename" | "renameat" => {
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
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Duration;

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
        let active = Arc::new(ActiveCommands::new());
        let _accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_one(stream, index, active).await.unwrap();
        });

        // Give the listener a moment to be ready.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Sync client side (the shim won't use tokio).
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
}
