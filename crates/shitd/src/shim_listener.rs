// SPDX-License-Identifier: AGPL-3.0-or-later

//! S24.D.2 — accept loop for the LD_PRELOAD shim's per-process UDS.
//! W06.A.3 — route TreeOp notifications (unlink/rename) into journal.
//! W06.A.4 — route content notifications (open/openat/truncate with
//! attached pre-image bytes) into a `CaptureEventKind::FilePreImage`.
//!
//! The shim (`shit-preload-shim`) opens a short-lived connection to
//! `$XDG_RUNTIME_DIR/shit/shim.sock`, sends a [`ShimNotification`]
//! framed via `encode_shim_frame` (its own wire version, the large
//! cap), waits ≤50 ms for a [`ShimAck`], and closes.
//!
//! Per-connection flow:
//! 1. Decode the notification (`decode_shim_frame`; a frame from a
//!    shim built against another wire version is refused by name).
//! 2. Resolve the note's command ([`resolve_command`]): by the command
//!    key the shim read from the hook's environment (R8, #210), checked
//!    against the peer's uid and the daemon's known commands; else by
//!    `pid → CommandId` via `ActiveCommands::resolve_by_descendant`. A
//!    keyed note for a command that already closed journals a capture
//!    gap on it. An unattributable note is logged and dropped (the shim
//!    still gets an Allow ack: we never block a user command on an
//!    attribution miss).
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
use shit_proto::{ShimAck, ShimNotification, ShimPreImage, decode_shim_notification, encode_frame};
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
    let note: ShimNotification = match decode_shim_notification(&buf[..total]) {
        Ok(n) => n,
        // L5: a shell started before an upgrade still has the old shim
        // loaded. Say so by name; its notifications cannot be read.
        Err(shit_proto::DecodeError::UnsupportedVersion(got)) => {
            let peer_pid = peer_pid(&stream);
            warn!(
                got,
                expected = shit_proto::SHIM_WIRE_VERSION,
                peer_pid = ?peer_pid,
                "shim notification from a different shim version; restart that shell after upgrading"
            );
            // L5 (review of #232, item 4; #225): resolve the peer to its
            // command before acking (the caller may exit right after),
            // then ack Allow. Acks are version-1 frames, which every shim
            // reads, so the old shim does not wait out its timeout.
            let command = peer_pid.and_then(|p| active.resolve_by_descendant(p));
            if let Ok(frame) = encode_frame(&ShimAck::Allow) {
                let _ = stream.write_all(&frame).await;
            }
            if let Some(command) = command {
                journal_gap_once(&index, command, GapCause::OtherShimWire, || {
                    other_wire_gap_detail(got)
                });
            }
            return Ok(());
        }
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
        command_key = ?note.command_key,
        "shim pre-mutation"
    );

    // The shim notifies before the real unlink runs, so the path still
    // exists here. Stat it first: a slow `resolve_by_descendant` below
    // (a deep chain on a loaded host) can outlast the shim's 50 ms ack
    // timeout, after which the syscall has run and the path is gone. By
    // ingest time only the wire's Regular default would be left.
    let unlink_stat = pre_syscall_unlink_stat(&note);

    // Resolve the command BEFORE acking. The shim returns to the
    // calling process immediately after we ack, the real syscall
    // fires, and the process (e.g. `install` invoked by `make`) often
    // terminates within milliseconds. A note with a command key does
    // not need the sender alive (R8, #210). One without a key falls
    // back to the pid walk, which needs every ancestor alive, so it
    // runs here while the shim is still waiting for the ack.
    //
    // Reserve journal order before allowing the intercepted syscall to
    // run. Ingestion itself remains fail-open and happens after the ACK,
    // but later helper/shim events can no longer overtake this pre-
    // mutation snapshot in the planner's logical clock. L5 (review round
    // 5, item 2): reserved before the pid resolution. The watch check
    // compares it with the command's PostExec: a note stamped earlier was
    // sent while the kernel tier watched, however late it is ingested.
    let ingest_ts = crate::server::next_ts();
    let key = trusted_key(&note, &stream);
    // R8 review, item 6: the key check reads SQLite and the pid walk
    // reads /proc or libproc. Neither runs on a runtime worker.
    let resolution = {
        let (active, index, pid) = (Arc::clone(&active), Arc::clone(&index), note.pid);
        tokio::task::spawn_blocking(move || resolve_command(pid, key, &active, &index))
            .await
            .unwrap_or_else(|e| {
                warn!(err = %e, pid = note.pid, "shim note resolution task failed");
                Resolution::Unattributed
            })
    };

    // Ack — never block the user's command on journaling. We're
    // fail-open by design: even if the journal write below errors,
    // the syscall proceeds.
    let ack = ShimAck::Allow;
    let frame = encode_frame(&ack)?;
    // A write error here means the shim gave up waiting (50ms ack
    // timeout) and the caller already moved on, often exiting. The
    // notification was fully received, so journal it anyway; returning
    // early would silently drop the event (macOS create/overwrite
    // smokes regressed on this under slow pid resolution).
    if let Err(e) = stream.write_all(&frame).await {
        debug!(err = %e, pid = note.pid, "shim ack write failed; ingesting anyway");
    }

    match resolution {
        Resolution::Closed(command) => {
            ingest_late_note(&note, command, ingest_ts, &index, &live_baseline);
        }
        Resolution::Command(command) => ingest_notification(
            &note,
            Some(command),
            ingest_ts,
            unlink_stat,
            &index,
            &blob_store,
            &live_baseline,
        ),
        Resolution::Unattributed => ingest_notification(
            &note,
            None,
            ingest_ts,
            unlink_stat,
            &index,
            &blob_store,
            &live_baseline,
        ),
    }
    Ok(())
}

/// Where a shim note belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// Journal the note under this command.
    Command(shit_planner::events::CommandId),
    /// The note's key names this command, which had closed, or been
    /// superseded by a newer command of its session, when the note
    /// arrived. See [`ingest_late_note`].
    Closed(shit_planner::events::CommandId),
    /// Neither the key nor the pid ancestry names a command.
    Unattributed,
}

/// R8 review, item 4: how long after its command closed a keyed note
/// may still name it. Past this the key is ignored and the note falls
/// back to the pid walk. It is the kernel tier's closed-watch grace.
const LATE_KEY_WINDOW: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The note's command key, when the peer runs as the daemon's user.
fn trusted_key(
    note: &ShimNotification,
    stream: &UnixStream,
) -> Option<shit_planner::events::CommandId> {
    let key = note.command_key?;
    if !peer_is_daemon_user(stream) {
        warn!(
            pid = note.pid,
            "shim note carries a command key from a peer of another uid; ignoring the key"
        );
        return None;
    }
    Some(shit_planner::events::CommandId {
        session: key.session,
        seq: key.seq,
    })
}

/// R8 (#210, #251): the command a shim note from `pid` belongs to.
///
/// `key` is the note's [`shit_proto::ShimCommandKey`], already dropped
/// when the peer is not the daemon's user. A key needs no live sender,
/// so a sender that exits before the daemon reads its note is still
/// attributed. It is bounded (review item 4):
///
/// - It counts only for the most recent command of its session, while
///   that command is open and its shell is alive (see [`judge_key`]).
/// - A key for a command that closed, or that a newer command of its
///   session superseded, less than [`LATE_KEY_WINDOW`] ago is
///   [`Resolution::Closed`].
/// - Any other key (unknown, too old, a dead shell's open command) is
///   ignored and the note falls back to the pid walk.
/// - A live sender whose ancestry reaches another session's shell
///   (tmux started from a hooked shell, then used from another) goes to
///   that shell's command: the walk wins over the key.
pub(crate) fn resolve_command(
    pid: u32,
    key: Option<shit_planner::events::CommandId>,
    active: &ActiveCommands,
    index: &Index,
) -> Resolution {
    let walked = active.resolve_by_descendant(pid);
    let by_walk = || walked.map_or(Resolution::Unattributed, Resolution::Command);
    let Some(command) = key else {
        return by_walk();
    };
    if let Some(w) = walked
        && w.session != command.session
    {
        debug!(pid, %command, walked = %w, "shim note's sender runs under another session's shell");
        return Resolution::Command(w);
    }
    let now = std::time::SystemTime::now();
    let unusable = || {
        debug!(pid, %command, "shim note's command key is not usable; walking pid ancestry");
        by_walk()
    };
    // Review item 6: a command already judged late needs no lookup while
    // its key is inside the window. Past the window its key is stale like
    // any other (re-review of #259: a gap does not make it late forever).
    match closed_key_cached(command, now) {
        Some(true) => return Resolution::Closed(command),
        Some(false) => return unusable(),
        None => {}
    }
    match judge_key(command, active, index, now) {
        KeyState::Open => Resolution::Command(command),
        KeyState::RecentlyClosed(closed) => {
            if let Some(closed) = closed {
                cache_closed_key(command, closed);
            }
            Resolution::Closed(command)
        }
        KeyState::Unusable => unusable(),
    }
}

type ClosedKeys = std::collections::HashMap<shit_planner::events::CommandId, u64>;

/// When each command judged late closed (wall clock, Unix nanos). A
/// closed or superseded command does not reopen, so the time is final.
fn closed_keys() -> std::sync::MutexGuard<'static, ClosedKeys> {
    static KEYS: std::sync::OnceLock<std::sync::Mutex<ClosedKeys>> = std::sync::OnceLock::new();
    KEYS.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn cache_closed_key(command: shit_planner::events::CommandId, closed_unix_nanos: u64) {
    let mut keys = closed_keys();
    if keys.len() >= 4096 {
        keys.clear();
    }
    keys.insert(command, closed_unix_nanos);
}

/// `Some(true)`: `command` is cached as closed inside the window at
/// `now`. `Some(false)`: cached but past the window; the entry is
/// dropped. `None`: not cached.
fn closed_key_cached(
    command: shit_planner::events::CommandId,
    now: std::time::SystemTime,
) -> Option<bool> {
    let mut keys = closed_keys();
    let closed = *keys.get(&command)?;
    let inside = within_late_window(closed, now);
    if !inside {
        keys.remove(&command);
    }
    Some(inside)
}

/// Whether a close at `closed_unix_nanos` is less than
/// [`LATE_KEY_WINDOW`] before `now`.
fn within_late_window(closed_unix_nanos: u64, now: std::time::SystemTime) -> bool {
    let closed = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(closed_unix_nanos);
    !now.duration_since(closed)
        .is_ok_and(|age| age > LATE_KEY_WINDOW)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    /// The key's command is open: journal under it.
    Open,
    /// It closed, or was superseded, within [`LATE_KEY_WINDOW`], at
    /// this wall time when known.
    RecentlyClosed(Option<u64>),
    /// Unknown, closed too long ago, or open on a shell that is gone.
    Unusable,
}

/// What a trusted key for `command` is worth at `now`.
fn judge_key(
    command: shit_planner::events::CommandId,
    active: &ActiveCommands,
    index: &Index,
    now: std::time::SystemTime,
) -> KeyState {
    use shit_planner::PlannerStore;
    let Some(record) = index.command_by_id(command) else {
        return KeyState::Unusable;
    };
    let closed_recently = |closed_unix_nanos: u64| {
        if within_late_window(closed_unix_nanos, now) {
            KeyState::RecentlyClosed(Some(closed_unix_nanos))
        } else {
            KeyState::Unusable
        }
    };
    if let Some(ended) = record.ended_at {
        return closed_recently(ended.wallclock_unix_nanos);
    }
    // An open row the session has moved past: a command that never got
    // its PostExec (its shell exec'd or was killed mid-command).
    if let Some(latest) = index.latest_command_for_session(command.session)
        && latest.command.seq > command.seq
    {
        return closed_recently(latest.started_at.wallclock_unix_nanos);
    }
    // `exec` into another hooked shell: the same pid now runs another
    // session's command.
    if let Some(current) = active.foreground_of(record.pid)
        && current != command
    {
        return index
            .command_by_id(current)
            .map_or(KeyState::RecentlyClosed(None), |c| {
                closed_recently(c.started_at.wallclock_unix_nanos)
            });
    }
    if pid_alive(record.pid) {
        KeyState::Open
    } else {
        KeyState::Unusable
    }
}

/// Whether `pid` names a process (signal 0 sends nothing; EPERM means
/// it exists under another uid).
fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill with signal 0 only checks that the target exists.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Whether the peer of a shim connection runs as the daemon's user.
/// The socket is 0600, so only that user or root can connect; a root
/// peer's key is not trusted.
fn peer_is_daemon_user(stream: &UnixStream) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    stream.peer_cred().is_ok_and(|c| c.uid() == me)
}

/// R8 (D-35): a keyed note whose command had closed, or been
/// superseded, when it arrived. Its change cannot join the command's
/// journal.
///
/// - A rename-family outcome goes to the command its pre-call note was
///   journaled under, which was open then (review item 1).
/// - A Create the on-time path would have left to the kernel tier (the
///   path was under its watch) is left to it here too: the kernel record
///   is the record, and no gap is journaled (review item 2).
/// - Anything else had the shim as its only record. The command gets one
///   capture-gap refusal, so its undo refuses instead of passing over the
///   change.
pub(crate) fn ingest_late_note(
    note: &ShimNotification,
    command: shit_planner::events::CommandId,
    ingest_ts: shit_planner::time::TimePoint,
    index: &Index,
    live_baseline: &LiveBaseline,
) {
    if let Some(out) = note.outcome
        && let Some(call_command) = rename_call_command(note.pid, note.call_id)
    {
        journal_rename_outcome(note, out, call_command, ingest_ts, index);
        return;
    }
    if late_note_left_to_kernel(note, command, ingest_ts, live_baseline) {
        debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            %command,
            "late shim note: path was in the kernel tier's watch; no gap"
        );
        return;
    }
    let wrote = journal_gap_once(index, command, GapCause::LateNote, || {
        format!(
            "a process of this command reported {} on {} after the command finished; that \
             change was not captured",
            note.syscall, note.arg
        )
    });
    // Review item 5: once per command.
    if wrote {
        warn!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            %command,
            "shim note arrived after its command closed; journaled a capture gap"
        );
    }
}

/// The in-watch check of [`ingest_note`], for a late note: would the
/// on-time path have left this note's Create to the kernel tier? Only
/// Creates are left to it there, so every other note had the shim as its
/// only record. The Linux command watch is judged at the note's own
/// timestamp, so a note stamped after the watch closed is not covered.
fn late_note_left_to_kernel(
    note: &ShimNotification,
    command: shit_planner::events::CommandId,
    at: shit_planner::time::TimePoint,
    live_baseline: &LiveBaseline,
) -> bool {
    if note.failure.is_some() {
        return false;
    }
    let path = Path::new(&note.arg);
    if !path.is_absolute() {
        return false;
    }
    let create = matches!(note.syscall.as_str(), "open_create" | "mkdir" | "mkdirat");
    let link = matches!(note.syscall.as_str(), "link" | "linkat");
    if !create && !link {
        return false;
    }
    let in_command_watch = cfg!(target_os = "linux")
        && create
        && live_baseline.defer_create_to_kernel(command, path, at);
    in_command_watch || live_baseline.path_in_watched_subtree(path)
}

/// Why a command got a capture-gap refusal from this listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GapCause {
    /// A keyed note arrived after its command closed.
    LateNote,
    /// A shim of another wire version wrote for the command.
    OtherShimWire,
}

type GapSet = std::collections::HashSet<(shit_planner::events::CommandId, GapCause)>;

/// The gaps journaled (or being journaled) so far. A poisoned lock is
/// recovered: the set is only a dedupe.
fn journaled_gaps() -> std::sync::MutexGuard<'static, GapSet> {
    static GAPS: std::sync::OnceLock<std::sync::Mutex<GapSet>> = std::sync::OnceLock::new();
    GAPS.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Journal one capture-gap refusal per command and cause; returns
/// whether this call wrote it.
///
/// Review items 7 and 8: the claim is made under the lock and the write
/// happens outside it. A note racing this one sees the claim and writes
/// nothing; a failed write drops the claim, so the next note retries it
/// (review of #232 medium review, item 5).
fn journal_gap_once(
    index: &Index,
    command: shit_planner::events::CommandId,
    cause: GapCause,
    detail: impl FnOnce() -> String,
) -> bool {
    {
        let mut gaps = journaled_gaps();
        if gaps.contains(&(command, cause)) {
            return false;
        }
        if gaps.len() >= 4096 {
            gaps.clear();
        }
        gaps.insert((command, cause));
    }
    match crate::helper_link::journal_refusal(
        index,
        command,
        None,
        shit_planner::COMMAND_CAPTURE_GAP,
        detail(),
    ) {
        Ok(()) => true,
        Err(e) => {
            warn!(err = %e, %command, ?cause, "shim capture-gap journal failed");
            journaled_gaps().remove(&(command, cause));
            false
        }
    }
}

/// L5 (review of #232, item 4; #225): the refusal text for a command
/// whose shell loaded a shim of wire version `got`.
fn other_wire_gap_detail(got: u8) -> String {
    format!(
        "a shim from an older version (wire {got}, daemon expects {}) was loaded in this \
         command's shell; none of its changes were captured. Restart the shell to load the \
         current shim",
        shit_proto::SHIM_WIRE_VERSION
    )
}

/// Review item 5: a note with no command is logged at warn once per
/// sender pid; repeats are counted and summarized at most once a minute.
fn warn_unattributed(note: &ShimNotification) {
    #[derive(Default)]
    struct Log {
        pids: std::collections::HashSet<u32>,
        quiet: u64,
        last_summary: Option<std::time::Instant>,
    }
    const SUMMARY_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
    static LOG: std::sync::OnceLock<std::sync::Mutex<Log>> = std::sync::OnceLock::new();
    enum Say {
        First,
        Summary(u64),
        Nothing,
    }
    let say = {
        let mut log = LOG
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if log.pids.len() >= 4096 {
            log.pids.clear();
        }
        if log.pids.insert(note.pid) {
            log.last_summary.get_or_insert_with(std::time::Instant::now);
            Say::First
        } else {
            log.quiet += 1;
            if log
                .last_summary
                .is_none_or(|t| t.elapsed() >= SUMMARY_EVERY)
            {
                log.last_summary = Some(std::time::Instant::now());
                Say::Summary(std::mem::take(&mut log.quiet))
            } else {
                Say::Nothing
            }
        }
    };
    match say {
        Say::First => warn!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            has_key = note.command_key.is_some(),
            "shim notify: no command for this note; dropping"
        ),
        Say::Summary(count) => warn!(
            count,
            "shim notify: more notes with no command were dropped since the last report"
        ),
        Say::Nothing => debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            "shim notify: no command for this note; dropping"
        ),
    }
}

/// Kind, mode and identity of an unlink target, read before the syscall
/// runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnlinkStat {
    kind: FileKind,
    mode: u32,
    /// The removed entry's identity, when it is known: the shim's
    /// pre-call stat for a post-call removal (L5), `(st_dev, st_ino)` for
    /// a block/char node so the shim's report pairs with the helper's
    /// `DeviceNodeMeta` (L4b). `None` keeps the wire's `(0, 0)` sentinel.
    inode: Option<InodeRef>,
    /// The link's target when the entry is a symlink (L4b).
    link_target: Option<String>,
}

/// L5 — removals the shim reports after they succeeded: `rmdir` and
/// `unlinkat(AT_REMOVEDIR)`. Only ever directories, and gone by the time
/// the daemon reads the note.
fn is_post_call_removal(syscall: &str) -> bool {
    matches!(syscall, "rmdir" | "unlinkat_dir")
}

/// lstat the target of a shim `unlink`/`unlinkat` so the journaled
/// event carries the real kind and mode. Without it an
/// `unlinkat(AT_REMOVEDIR)` lands as a Regular unlink and undo's
/// RecreatePath makes a file where a directory was, which then breaks
/// every child restore under it (ENOTDIR). Directories, regular files,
/// fifos, sockets and block/char nodes are reported (the device number
/// comes from the helper's `DeviceNodeMeta`, not from here); a symlink
/// is reported with its target so undo recreates the link. The shim's
/// own pre-call lstat (`pre_stat`) is preferred; the daemon's lstat is
/// the fallback for a shim that did not send one.
fn pre_syscall_unlink_stat(note: &ShimNotification) -> Option<UnlinkStat> {
    use std::os::unix::fs::MetadataExt;
    if !matches!(note.syscall.as_str(), "unlink" | "unlinkat")
        && !is_post_call_removal(&note.syscall)
    {
        return None;
    }
    // L5: a removal reported after it succeeded carries the shim's own
    // stat from before the call. Never lstat it here (review round 3,
    // item 4): the directory is gone, or something new took its name.
    if is_post_call_removal(&note.syscall) {
        return note.pre_stat.as_ref().and_then(|s| {
            FileKind::from_mode(s.mode).map(|kind| UnlinkStat {
                kind,
                mode: s.mode,
                inode: Some(InodeRef::new(s.dev, s.inode)),
                link_target: None,
            })
        });
    }
    if !Path::new(&note.arg).is_absolute() {
        return None;
    }
    let (dev, ino, mode, shim_target) = match &note.pre_stat {
        Some(st) => (st.dev, st.inode, st.mode, st.link_target.clone()),
        None => match std::fs::symlink_metadata(&note.arg) {
            Ok(m) => (m.dev(), m.ino(), m.mode(), None),
            Err(e) => {
                debug!(err = %e, pid = note.pid, arg = %note.arg, "shim unlink: pre-syscall lstat failed; keeping default kind");
                return None;
            }
        },
    };
    let kind = FileKind::from_mode(mode)?;
    if kind == FileKind::Symlink {
        // The shim's target, read before the call; else the daemon's
        // read now. An empty target means unknown (no symlink can have
        // one): the planner then refuses rather than make a regular file.
        let target = shim_target
            .or_else(|| {
                std::fs::read_link(&note.arg)
                    .ok()
                    .map(|t| t.to_string_lossy().into_owned())
            })
            .unwrap_or_default();
        return Some(UnlinkStat {
            kind,
            mode,
            inode: None,
            link_target: Some(target),
        });
    }
    if !matches!(
        kind,
        FileKind::Directory
            | FileKind::Regular
            | FileKind::Fifo
            | FileKind::Socket
            | FileKind::BlockDevice
            | FileKind::CharDevice
    ) {
        return None;
    }
    let inode = matches!(kind, FileKind::BlockDevice | FileKind::CharDevice)
        .then(|| InodeRef::new(dev, ino));
    Some(UnlinkStat {
        kind,
        mode,
        inode,
        link_target: None,
    })
}

/// Overlay a pre-syscall lstat onto a classified shim Unlink. A removed
/// symlink becomes `SymlinkRemoved`, whose inverse recreates the link.
fn apply_unlink_stat(kind: CaptureEventKind, stat: Option<UnlinkStat>) -> CaptureEventKind {
    match (kind, stat) {
        (
            CaptureEventKind::TreeOp(TreeOp::Unlink { path, .. }),
            Some(UnlinkStat {
                link_target: Some(target),
                ..
            }),
        ) => CaptureEventKind::TreeOp(TreeOp::SymlinkRemoved { target, path }),
        (
            CaptureEventKind::TreeOp(TreeOp::Unlink { inode, path, .. }),
            Some(UnlinkStat {
                kind,
                mode,
                inode: shim_inode,
                ..
            }),
        ) => CaptureEventKind::TreeOp(TreeOp::Unlink {
            inode: shim_inode.unwrap_or(inode),
            path,
            kind,
            mode,
        }),
        (k, _) => k,
    }
}

/// The pid of the process on the other end of a shim connection.
///
/// tokio's `peer_cred` carries a pid on Linux and macOS but not on
/// FreeBSD, where it uses `getpeereid`. FreeBSD 13 and later report the
/// peer's pid in `LOCAL_PEERCRED`'s `xucred`, so read that there.
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    if let Some(pid) = stream.peer_cred().ok().and_then(|c| c.pid()) {
        return u32::try_from(pid).ok().filter(|p| *p > 0);
    }
    #[cfg(target_os = "freebsd")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: xucred is plain old data; zeroed is a valid value.
        let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        // SAFETY: a valid socket fd and a buffer of `len` bytes. Level 0
        // is SOL_LOCAL (sys/un.h), which libc does not export here.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                0,
                libc::LOCAL_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        if rc == 0 && cred.cr_version == libc::XUCRED_VERSION {
            // SAFETY: the kernel fills cr_pid for LOCAL_PEERCRED (13.0+).
            let pid = unsafe { cred.cr_pid__c_anonymous_union.cr_pid };
            return u32::try_from(pid).ok().filter(|p| *p > 0);
        }
    }
    None
}

/// Convert a shim notification into a `CaptureEvent` and journal it,
/// if the emitter's pid resolves to an active command. Errors are
/// logged but never propagated — the shim path is best-effort.
pub(crate) fn ingest_notification(
    note: &ShimNotification,
    resolved: Option<shit_planner::events::CommandId>,
    ingest_ts: shit_planner::time::TimePoint,
    unlink_stat: Option<UnlinkStat>,
    index: &Index,
    blob_store: &BlobStore,
    live_baseline: &LiveBaseline,
) {
    // L5 (PR B): the note a rename-family call sends after it returns.
    // Its command is the one the call's pre-call note was journaled for:
    // the outcome is not acked, and its sender may already have exited
    // (an EXDEV fallback copy, then exit), so a live pid lookup is only
    // the fallback.
    if let Some(out) = note.outcome {
        let command = rename_call_command(note.pid, note.call_id).or(resolved);
        match command {
            Some(command) => journal_rename_outcome(note, out, command, ingest_ts, index),
            None => debug!(
                pid = note.pid,
                call_id = note.call_id,
                "shim notify: rename outcome for an unknown call; dropping"
            ),
        }
        return;
    }
    let mut ids = Vec::new();
    ingest_note(
        note,
        resolved,
        ingest_ts,
        unlink_stat,
        index,
        blob_store,
        live_baseline,
        &mut ids,
    );
    // A pre-call note of a rename-family call: journal the rows it wrote
    // under the call's id.
    if note.call_id != 0
        && let Some(command) = resolved
        && !ids.is_empty()
    {
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: ingest_ts,
            partial: false,
            kind: CaptureEventKind::RenameCall {
                pid: note.pid,
                call_id: note.call_id,
                events: ids,
            },
        };
        match index.put_event(&event) {
            Ok(_) => remember_rename_call(note.pid, note.call_id, command),
            Err(e) => warn!(err = %e, pid = note.pid, "shim notify: RenameCall journal failed"),
        }
    }
}

/// L5 (PR B): the command each recent rename call's RenameCall was
/// journaled for, by `(pid, call_id)`, until its outcome arrives. Bounded:
/// past the cap the oldest go (their outcomes then fall back to a live
/// pid lookup).
fn rename_calls() -> &'static std::sync::Mutex<RenameCallMap> {
    static CALLS: std::sync::OnceLock<std::sync::Mutex<RenameCallMap>> = std::sync::OnceLock::new();
    CALLS.get_or_init(Default::default)
}

#[derive(Default)]
struct RenameCallMap {
    by_call: std::collections::HashMap<(u32, u64), shit_planner::events::CommandId>,
    order: std::collections::VecDeque<(u32, u64)>,
}

const RENAME_CALL_CAP: usize = 16_384;

fn remember_rename_call(pid: u32, call_id: u64, command: shit_planner::events::CommandId) {
    let mut m = rename_calls().lock().unwrap();
    if m.by_call.insert((pid, call_id), command).is_none() {
        m.order.push_back((pid, call_id));
    }
    while m.order.len() > RENAME_CALL_CAP {
        if let Some(old) = m.order.pop_front() {
            m.by_call.remove(&old);
        }
    }
}

fn rename_call_command(pid: u32, call_id: u64) -> Option<shit_planner::events::CommandId> {
    let mut m = rename_calls().lock().unwrap();
    let c = m.by_call.remove(&(pid, call_id))?;
    m.order.retain(|k| *k != (pid, call_id));
    Some(c)
}

/// Journal `event` and note its id among the rows this note wrote.
fn put(
    index: &Index,
    ids: &mut Vec<EventId>,
    event: &CaptureEvent,
) -> Result<EventId, shit_store::IndexError> {
    let id = index.put_event(event)?;
    ids.push(id);
    Ok(id)
}

/// L5 (PR B): journal what a rename-family call did.
fn journal_rename_outcome(
    note: &ShimNotification,
    out: shit_proto::ShimRenameOutcome,
    command: shit_planner::events::CommandId,
    ts: shit_planner::time::TimePoint,
    index: &Index,
) {
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::RenameOutcome {
            pid: note.pid,
            call_id: note.call_id,
            errno: out.errno,
            source: InodeRef::new(out.source_dev, out.source_inode),
        },
    };
    if let Err(e) = index.put_event(&event) {
        warn!(err = %e, pid = note.pid, "shim notify: RenameOutcome journal failed");
    }
}

/// [`ingest_notification`] for one note's own rows; `ids` collects the
/// id of every row it journals.
#[allow(clippy::too_many_arguments)]
fn ingest_note(
    note: &ShimNotification,
    resolved: Option<shit_planner::events::CommandId>,
    ingest_ts: shit_planner::time::TimePoint,
    unlink_stat: Option<UnlinkStat>,
    index: &Index,
    blob_store: &BlobStore,
    live_baseline: &LiveBaseline,
    ids: &mut Vec<EventId>,
) {
    let Some(command) = resolved else {
        // The shim is loaded into a process whose ancestor isn't a
        // tracked shell. Likely a background daemon / system service
        // that picked up LD_PRELOAD from a parent env, OR the pid
        // resolution raced the process's lifetime.
        // R8 (D-35): not silent. A note reaching this point carried no
        // usable command key, so it came from outside a hooked shell or
        // from a shim older than wire 5.
        warn_unattributed(note);
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
    // L5 (review of #232, item 2): the shim's gap marker is always
    // journaled. The planner drops it when another tier journaled a
    // pre-image of the same path in this command.
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
            // L5: an existing file was written without its bytes.
            shit_proto::ShimFailure::PreImageUncaptured { path, reason } => (
                "capture-gap".to_string(),
                PathBuf::from(path),
                format!("the file existed before the write, but its bytes {reason}"),
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
            ts: ingest_ts,
            partial: false,
            kind: CaptureEventKind::CaptureRefused {
                class,
                path: primary_path,
                detail,
            },
        };
        if let Err(e) = put(index, ids, &event) {
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
            // B09 — chflags family. Pre-image carries the OLD st_flags;
            // the source discriminator makes the planner emit only a
            // RestoreFlags inverse rather than content + broad metadata.
            | "chflags"
            | "fchflags"
    ) {
        if let Some(pre) = &note.pre_image {
            let source = metadata_pre_image_source(note.syscall.as_str());
            if let Err(e) = ingest_pre_image_with_source(
                command, pre, index, blob_store, source, ingest_ts, ids,
            ) {
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
            if let Err(e) = ingest_pre_image(command, pre, index, blob_store, ingest_ts, ids) {
                warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: pre-image ingest failed");
            }
        }
        // L5 (review item 1): no pre-image is not evidence the file was
        // new. The shim sends a capture-gap marker (journaled above as a
        // refusal) for an existing file it could not read, and an
        // `open_create` after a call that created its target.
        return;
    }
    // L5 (review round 5, item 1): on Linux the kernel tier journals
    // every create under the root the daemon asked it to watch for this
    // command, with the real inode. A shim Create there is a second
    // record of the same create, and undo would unlink the path twice
    // (the second one a conflict). Outside the root the shim is the only
    // record. The BSD baseline gate below is the same rule for kqueue.
    let create_in_command_watch = cfg!(target_os = "linux")
        && matches!(note.syscall.as_str(), "open_create" | "mkdir" | "mkdirat")
        && live_baseline.defer_create_to_kernel(command, Path::new(&note.arg), ingest_ts);
    if note.syscall == "open_create" {
        // AR05.1: the shim saw the path absent before an O_CREAT open
        // that then succeeded. On in-watch paths the dir-diff Create event
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
        if live_baseline.path_in_watched_subtree(Path::new(&note.arg)) || create_in_command_watch {
            debug!(
                pid = note.pid,
                syscall = %note.syscall,
                arg = %note.arg,
                "shim notify: path is in-watch; defer to the kernel tier"
            );
            return;
        }
        // A relative path would be resolved against the daemon's cwd at
        // undo time; the shim's CaptureRefused marker (if any) is the only
        // record we keep for it.
        if !Path::new(&note.arg).is_absolute() {
            debug!(pid = note.pid, arg = %note.arg, "shim notify: relative Create path; dropping");
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
        if let Err(e) = put(index, ids, &event) {
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
        && let Err(e) = ingest_pre_image(command, pre, index, blob_store, ingest_ts, ids)
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
            match ingest_pre_image_with_source(
                command,
                pre,
                index,
                blob_store,
                shit_planner::FilePreImageSource::ShimRenameSubtree,
                ingest_ts,
                ids,
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
    }
    // L5 (review of #232, item 3): the rename replaced a symlink at `to`.
    // Journal the link with its target before the Rename, so undo puts
    // the renamed entry back at `from` and then recreates the link.
    if matches!(note.syscall.as_str(), "rename" | "renameat" | "renameat2")
        && let Some(shit_proto::ShimStat {
            mode,
            link_target: Some(target),
            ..
        }) = &note.pre_stat
        && FileKind::from_mode(*mode) == Some(FileKind::Symlink)
        && let Some((_, to)) = note.arg.split_once('\t')
        && Path::new(to).is_absolute()
    {
        let event = CaptureEvent {
            id: EventId(0),
            command,
            ts: ingest_ts,
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::SymlinkRemoved {
                target: target.clone(),
                path: PathBuf::from(to),
            }),
        };
        if let Err(e) = put(index, ids, &event) {
            warn!(err = %e, pid = note.pid, "shim notify: replaced symlink journal failed");
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
    if matches!(note.syscall.as_str(), "unlink" | "unlinkat")
        && let Some(pre) = &note.pre_image
        && let Err(e) = ingest_pre_image(command, pre, index, blob_store, ingest_ts, ids)
    {
        warn!(err = %e, pid = note.pid, syscall = %note.syscall, "shim notify: unlink pre-image ingest failed");
    }
    // Fall through to journal the TreeOp::Unlink below.

    let Some(kind) =
        classify_tree_op(&note.syscall, &note.arg).map(|k| apply_unlink_stat(k, unlink_stat))
    else {
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

    // Never journal a tree op with a relative path: the undo executor
    // would resolve it against the daemon's cwd and act on the wrong
    // entry. L5 (review of #232, item 6): it is a refusal instead. The
    // shim attaches a marker when it could not make the path absolute
    // (journaled above); a relative path without one is refused here.
    if let Some(rel) = relative_tree_path(&kind) {
        debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            "shim notify: relative tree-op path; refusing"
        );
        if note.failure.is_none() {
            let event = CaptureEvent {
                id: EventId(0),
                command,
                ts: ingest_ts,
                partial: false,
                kind: CaptureEventKind::CaptureRefused {
                    class: "capture-incomplete".to_string(),
                    path: rel,
                    detail: format!(
                        "shim reported {} on a path it could not make absolute",
                        note.syscall
                    ),
                },
            };
            if let Err(e) = put(index, ids, &event) {
                warn!(err = %e, pid = note.pid, "shim notify: relative-path refusal journal failed");
            }
        }
        return;
    }

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
    ) && (live_baseline.path_in_watched_subtree(Path::new(&note.arg)) || create_in_command_watch)
    {
        debug!(
            pid = note.pid,
            syscall = %note.syscall,
            arg = %note.arg,
            "shim notify: Create path is in-watch; defer to the kernel tier"
        );
        return;
    }

    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts: ingest_ts,
        partial: false,
        kind,
    };
    if let Err(e) = put(index, ids, &event) {
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

/// The first relative path of a tree op, if it has one.
fn relative_tree_path(kind: &CaptureEventKind) -> Option<PathBuf> {
    let CaptureEventKind::TreeOp(op) = kind else {
        return None;
    };
    let paths: Vec<&Path> = match op {
        TreeOp::Create { path, .. }
        | TreeOp::Unlink { path, .. }
        | TreeOp::Symlink { path, .. }
        | TreeOp::SymlinkRemoved { path, .. } => vec![path],
        TreeOp::Rename { from, to, .. } => vec![from, to],
        TreeOp::Link { target, .. } => vec![target],
        TreeOp::DeviceNodeMeta { path, .. } => vec![path],
    };
    paths
        .into_iter()
        .find(|p| !p.is_absolute())
        .map(Path::to_path_buf)
}

/// Which `FilePreImageSource` a metadata-mutation syscall's pre-image is
/// journaled under. chflags and xattr records carry no file content, so
/// the planner must not restore bytes from them (#216).
fn metadata_pre_image_source(syscall: &str) -> shit_planner::FilePreImageSource {
    match syscall {
        "chflags" | "fchflags" => shit_planner::FilePreImageSource::ShimFlagsPreMutation,
        "setxattr" | "fsetxattr" | "removexattr" | "fremovexattr" => {
            shit_planner::FilePreImageSource::ShimXattrPreMutation
        }
        _ => shit_planner::FilePreImageSource::ShimPreMutation,
    }
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
    ids: &mut Vec<EventId>,
) -> anyhow::Result<()> {
    ingest_pre_image_with_source(
        command,
        pre,
        index,
        blob_store,
        shit_planner::FilePreImageSource::ShimPreMutation,
        ts,
        ids,
    )
}

/// Variant of [`ingest_pre_image`] that preserves why the shim captured
/// the snapshot. B09 uses this for chflags so the planner treats the
/// inline bytes as a wire detail and restores only `st_flags`.
fn ingest_pre_image_with_source(
    command: shit_planner::events::CommandId,
    pre: &ShimPreImage,
    index: &Index,
    blob_store: &BlobStore,
    source: shit_planner::FilePreImageSource,
    ts: shit_planner::time::TimePoint,
    ids: &mut Vec<EventId>,
) -> anyhow::Result<()> {
    let (blob_hash, stat) = blob_store
        .put(&pre.bytes)
        .map_err(|e| anyhow::anyhow!("blob put: {e}"))?;
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
            source,
        },
    };
    put(index, ids, &event).map_err(|e| anyhow::anyhow!("put_event: {e}"))?;
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
        "unlink" | "unlinkat" | "rmdir" | "unlinkat_dir" => {
            let path = PathBuf::from(arg);
            // G02: shim doesn't carry kind/mode in its notification
            // wire (the shim's notify happens pre-syscall and
            // doesn't fstat). Default to Regular/0o100644, matching
            // pre-G02 hard-coded behavior. The kernel-tier LSM
            // path (helper) DOES carry kind+mode and overrides this
            // when both tiers see the same unlink.
            // L5: rmdir(2) and unlinkat(AT_REMOVEDIR) only ever remove a
            // directory, whether or not the shim read its mode.
            let (kind, mode) = if is_post_call_removal(syscall) {
                (shit_planner::metadata::FileKind::Directory, 0o040755)
            } else {
                (shit_planner::metadata::FileKind::Regular, 0o100644)
            };
            Some(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(0, 0),
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
    use shit_planner::store::PlannerStore;
    use shit_proto::decode_frame;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Duration;

    fn fresh_blob_store(tmp: &std::path::Path) -> Arc<BlobStore> {
        Arc::new(BlobStore::open(tmp.join("blobs")).unwrap())
    }

    fn now_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    const MINUTE_NANOS: u64 = 60 * 1_000_000_000;

    /// R8: write `command`'s row, run on `shell_pid`, started at wall
    /// time `started`, and ended at `ended` when given.
    fn put_keyed_command(
        index: &Index,
        command: shit_planner::events::CommandId,
        shell_pid: u32,
        started: u64,
        ended: Option<u64>,
    ) {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("make_fifo".into()),
                cwd: PathBuf::from("/tmp"),
                pid: shell_pid,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(command.seq, started),
                ended_at: ended.map(|w| TimePoint::new(100 + command.seq, w)),
                exit_code: ended.map(|_| 0),
                event_ids: vec![],
            })
            .expect("put_command");
    }

    /// R8: an index holding one command (seq 3) of a fresh session, plus
    /// the command's id. Its shell is pid 1, which is always alive.
    /// `ended` finalizes it just now.
    fn keyed_fixture(
        ended: bool,
    ) -> (
        tempfile::TempDir,
        Arc<Index>,
        shit_planner::events::CommandId,
    ) {
        use shit_planner::time::TimePoint;
        let tmp = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(tmp.path().join("idx.sqlite")).unwrap());
        let session = uuid::Uuid::now_v7();
        index
            .put_session(session, "bash", 1, None, TimePoint::new(0, 0))
            .expect("put_session");
        let command = shit_planner::events::CommandId { session, seq: 3 };
        put_keyed_command(&index, command, 1, now_nanos(), ended.then(now_nanos));
        (tmp, index, command)
    }

    /// The pid of a process that has already exited and been reaped.
    fn exited_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    fn key_of(command: shit_planner::events::CommandId) -> shit_proto::ShimCommandKey {
        shit_proto::ShimCommandKey {
            session: command.session,
            seq: command.seq,
        }
    }

    fn mkfifo_note(pid: u32, path: &str) -> ShimNotification {
        note_of("mkfifo", pid, path)
    }

    fn note_of(syscall: &str, pid: u32, arg: &str) -> ShimNotification {
        ShimNotification {
            pid,
            syscall: syscall.into(),
            arg: arg.into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        }
    }

    fn kinds_of(index: &Index, command: shit_planner::events::CommandId) -> Vec<CaptureEventKind> {
        index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    fn has_gap(kinds: &[CaptureEventKind]) -> bool {
        kinds.iter().any(|k| {
            matches!(
                k,
                CaptureEventKind::CaptureRefused { class, .. }
                    if class == shit_planner::COMMAND_CAPTURE_GAP
            )
        })
    }

    /// Send `note` over a real socket to `handle_one` and wait until the
    /// daemon side has finished with it.
    async fn send_through_listener(
        note: ShimNotification,
        index: Arc<Index>,
        active: Arc<ActiveCommands>,
        dir: &std::path::Path,
    ) {
        let sock = dir.join("shim.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let blob_store = fresh_blob_store(dir);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_one(
                stream,
                index,
                blob_store,
                active,
                Arc::new(LiveBaseline::new()),
            )
            .await
            .unwrap();
        });
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut s = StdUnixStream::connect(&sock).unwrap();
            s.write_all(&shit_proto::encode_shim_frame(&note).unwrap())
                .unwrap();
            // Hang up without reading the ack, as an emitter that exits
            // right after its syscall does (#251).
        })
        .await
        .unwrap();
        server.await.unwrap();
    }

    /// R8 (#210, #251, D-35): a note from a process that has already
    /// exited, so no pid walk can reach its shell, is journaled under
    /// the command its key names. Another command active at the same
    /// time does not get it.
    #[tokio::test]
    async fn keyed_note_from_an_exited_sender_joins_its_command() {
        let (tmp, index, command) = keyed_fixture(false);
        let active = Arc::new(ActiveCommands::new());
        active.insert(1, command);
        let other = shit_planner::events::CommandId {
            session: uuid::Uuid::now_v7(),
            seq: 1,
        };
        active.insert(std::process::id(), other);
        let fifo = tmp.path().join("myfifo");
        let mut note = mkfifo_note(exited_pid(), fifo.to_str().unwrap());
        note.command_key = Some(key_of(command));

        send_through_listener(note, Arc::clone(&index), active, tmp.path()).await;

        let kinds = kinds_of(&index, command);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                CaptureEventKind::TreeOp(TreeOp::Create { path, .. }) if path == &fifo
            )),
            "the exited sender's mkfifo joins its command: {kinds:?}"
        );
    }

    /// The same note with no key (a version-4 shim, or a sender outside
    /// a hooked shell) still depends on the pid walk, which cannot reach
    /// a dead sender's shell.
    #[tokio::test]
    async fn unkeyed_note_from_an_exited_sender_is_unattributed() {
        let (tmp, index, command) = keyed_fixture(false);
        let active = Arc::new(ActiveCommands::new());
        active.insert(1, command);
        let note = mkfifo_note(exited_pid(), tmp.path().join("f").to_str().unwrap());
        assert_eq!(
            resolve_command(note.pid, None, &active, &index),
            Resolution::Unattributed
        );
        send_through_listener(note, Arc::clone(&index), active, tmp.path()).await;
        assert!(index.events_for_command(command).is_empty());
    }

    /// D-35: a keyed mkfifo for a command that was already finalized does
    /// not join it, and the command gets a capture-gap refusal instead.
    #[tokio::test]
    async fn keyed_note_after_its_command_closed_journals_a_capture_gap() {
        let (tmp, index, command) = keyed_fixture(true);
        let active = Arc::new(ActiveCommands::new());
        let fifo = tmp.path().join("late");
        let mut note = mkfifo_note(exited_pid(), fifo.to_str().unwrap());
        note.command_key = Some(key_of(command));
        assert_eq!(
            resolve_command(note.pid, Some(command), &active, &index),
            Resolution::Closed(command)
        );

        send_through_listener(note, Arc::clone(&index), active, tmp.path()).await;

        let kinds = kinds_of(&index, command);
        assert!(has_gap(&kinds), "{kinds:?}");
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, CaptureEventKind::TreeOp(_))),
            "{kinds:?}"
        );
    }

    /// A command whose PostExec arrived but whose close barrier is still
    /// pending is out of the active map with no `ended_at` yet: a keyed
    /// note still joins it.
    #[test]
    fn keyed_note_joins_a_command_that_is_still_closing() {
        let (_tmp, index, command) = keyed_fixture(false);
        assert_eq!(
            resolve_command(exited_pid(), Some(command), &ActiveCommands::new(), &index),
            Resolution::Command(command)
        );
    }

    /// A key the daemon does not know falls back to the pid walk.
    #[test]
    fn unknown_keys_fall_back_to_the_pid_walk() {
        let (_tmp, index, _command) = keyed_fixture(false);
        let active = ActiveCommands::new();
        let walked = shit_planner::events::CommandId {
            session: uuid::Uuid::now_v7(),
            seq: 8,
        };
        active.insert(std::process::id(), walked);
        let unknown = shit_planner::events::CommandId {
            session: uuid::Uuid::now_v7(),
            seq: 2,
        };
        assert_eq!(
            resolve_command(std::process::id(), Some(unknown), &active, &index),
            Resolution::Command(walked)
        );
        assert_eq!(
            resolve_command(exited_pid(), Some(unknown), &active, &index),
            Resolution::Unattributed
        );
    }

    /// R8 review, item 4 (tmux): a live sender whose ancestry reaches
    /// another session's shell goes to that shell's command, though its
    /// key names an open command of the session it inherited the key from.
    #[test]
    fn a_live_sender_under_another_sessions_shell_goes_to_that_shell() {
        let (_tmp, index, command) = keyed_fixture(false);
        let active = ActiveCommands::new();
        active.insert(1, command);
        let tmux_shell = shit_planner::events::CommandId {
            session: uuid::Uuid::now_v7(),
            seq: 1,
        };
        active.insert(std::process::id(), tmux_shell);
        assert_eq!(
            resolve_command(std::process::id(), Some(command), &active, &index),
            Resolution::Command(tmux_shell)
        );
        // The same key from a sender that already exited: the key holds.
        assert_eq!(
            resolve_command(exited_pid(), Some(command), &active, &index),
            Resolution::Command(command)
        );
    }

    /// R8 review, item 4: a command that never got its PostExec. Killed:
    /// its shell is gone, so its key is ignored. Exec'd into another
    /// hooked shell, or followed by a newer command of its session: it is
    /// treated as closed, and its notes are a capture gap.
    #[test]
    fn keys_of_commands_that_never_closed_are_bounded() {
        let (_tmp, index, command) = keyed_fixture(false);
        let now = now_nanos();

        // Killed shell.
        let killed = shit_planner::events::CommandId {
            session: uuid::Uuid::now_v7(),
            seq: 1,
        };
        put_keyed_command(&index, killed, exited_pid(), now, None);
        assert_eq!(
            resolve_command(exited_pid(), Some(killed), &ActiveCommands::new(), &index),
            Resolution::Unattributed
        );

        // `exec bash`: the same pid now runs another session's command.
        let active = ActiveCommands::new();
        active.insert(1, command);
        let next_shell = shit_planner::events::CommandId {
            session: uuid::Uuid::now_v7(),
            seq: 1,
        };
        put_keyed_command(&index, next_shell, 1, now, None);
        active.insert(1, next_shell);
        assert_eq!(
            resolve_command(exited_pid(), Some(command), &active, &index),
            Resolution::Closed(command)
        );

        // A newer PreExec of the same session.
        let (_tmp2, index2, command2) = keyed_fixture(false);
        put_keyed_command(
            &index2,
            shit_planner::events::CommandId {
                seq: command2.seq + 1,
                ..command2
            },
            1,
            now,
            None,
        );
        assert_eq!(
            resolve_command(
                exited_pid(),
                Some(command2),
                &ActiveCommands::new(),
                &index2
            ),
            Resolution::Closed(command2)
        );
    }

    /// R8 review, item 4: a key whose command closed, or was superseded,
    /// longer ago than the window is stale. It is ignored and the note
    /// falls back to the pid walk.
    #[test]
    fn stale_keys_fall_back_to_the_pid_walk() {
        use shit_planner::time::TimePoint;
        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let session = uuid::Uuid::now_v7();
        index
            .put_session(session, "bash", 1, None, TimePoint::new(0, 0))
            .unwrap();
        let long_ago = now_nanos() - 30 * MINUTE_NANOS;
        let closed = shit_planner::events::CommandId { session, seq: 1 };
        put_keyed_command(&index, closed, 1, long_ago, Some(long_ago));
        let superseded = shit_planner::events::CommandId { session, seq: 2 };
        put_keyed_command(&index, superseded, 1, long_ago, None);
        put_keyed_command(
            &index,
            shit_planner::events::CommandId { session, seq: 3 },
            1,
            long_ago,
            Some(long_ago),
        );
        let active = ActiveCommands::new();
        for key in [closed, superseded] {
            assert_eq!(
                resolve_command(exited_pid(), Some(key), &active, &index),
                Resolution::Unattributed,
                "{key}"
            );
        }
        // Within the window the same closed key is a late note.
        let recent = shit_planner::events::CommandId { session, seq: 4 };
        put_keyed_command(&index, recent, 1, now_nanos(), Some(now_nanos()));
        assert_eq!(
            resolve_command(exited_pid(), Some(recent), &active, &index),
            Resolution::Closed(recent)
        );
    }

    /// Re-review of #259: a command that already has its late-note gap
    /// and is cached as closed, whose key is now past the window. The key
    /// is stale: the note goes to the pid walk, which cannot reach a dead
    /// sender's shell.
    #[test]
    fn a_gapped_commands_key_past_the_window_goes_to_the_pid_walk() {
        let (_tmp, index, command) = keyed_fixture(true);
        let active = ActiveCommands::new();
        assert_eq!(
            resolve_command(exited_pid(), Some(command), &active, &index),
            Resolution::Closed(command)
        );
        assert!(journal_gap_once(
            &index,
            command,
            GapCause::LateNote,
            || { "late".into() }
        ));
        // The close is now long past.
        cache_closed_key(command, now_nanos() - 30 * MINUTE_NANOS);
        assert_eq!(
            resolve_command(exited_pid(), Some(command), &active, &index),
            Resolution::Unattributed
        );
    }

    /// R8 review, item 1: a rename call's pre-call note is journaled
    /// while its command is open; the command closes; the outcome note
    /// arrives late. It joins the call's command and leaves no gap.
    #[test]
    fn a_rename_outcome_after_its_command_closed_joins_the_call() {
        use shit_planner::time::TimePoint;
        let (_tmp, index, blob_store, command) = ingest_fixture("mv a b");
        let lb = LiveBaseline::new();
        let mut pre = open_note_arg("rename", "/tmp/r8-late/a\t/tmp/r8-late/b", None);
        pre.call_id = 0x5208;
        ingest_notification(
            &pre,
            Some(command),
            TimePoint::new(2, 0),
            None,
            &index,
            &blob_store,
            &lb,
        );
        let mut out = pre.clone();
        out.outcome = Some(shit_proto::ShimRenameOutcome {
            errno: 0,
            source_dev: 8,
            source_inode: 42,
        });
        ingest_late_note(&out, command, TimePoint::new(9, 0), &index, &lb);

        let kinds = kinds_of(&index, command);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                CaptureEventKind::RenameOutcome {
                    call_id: 0x5208,
                    ..
                }
            )),
            "{kinds:#?}"
        );
        assert!(!has_gap(&kinds), "{kinds:#?}");
        assert!(
            rename_call_command(pre.pid, pre.call_id).is_none(),
            "the call's map entry is taken, not leaked"
        );
    }

    /// R8 review, item 2: a late Create under a path the kernel tier
    /// watched is left to the kernel record, and journals no gap. A late
    /// Create outside any watch, and a late mkfifo (which the kernel tier
    /// cannot see on every platform), each journal one.
    #[test]
    fn late_notes_rely_on_the_kernel_tier_only_where_it_watched() {
        use shit_planner::time::TimePoint;
        let watched = tempfile::tempdir().unwrap();
        let watched_dir = watched.path().canonicalize().unwrap();
        let lb = LiveBaseline::new();
        lb.entry_for_cwd(&watched_dir);

        let (_tmp, index, covered) = keyed_fixture(false);
        let note = open_note_arg("open_create", watched_dir.join("x").to_str().unwrap(), None);
        ingest_late_note(&note, covered, TimePoint::new(9, 0), &index, &lb);
        assert!(kinds_of(&index, covered).is_empty(), "no gap in the watch");

        let (_tmp, index, outside) = keyed_fixture(false);
        let note = open_note_arg("open_create", "/r8-unwatched/y", None);
        ingest_late_note(&note, outside, TimePoint::new(9, 0), &index, &lb);
        assert!(has_gap(&kinds_of(&index, outside)));

        let (_tmp, index, fifo) = keyed_fixture(false);
        let note = note_of("mkfifo", 4242, watched_dir.join("p").to_str().unwrap());
        ingest_late_note(&note, fifo, TimePoint::new(9, 0), &index, &lb);
        ingest_late_note(&note, fifo, TimePoint::new(10, 0), &index, &lb);
        let kinds = kinds_of(&index, fifo);
        assert!(has_gap(&kinds));
        assert_eq!(kinds.len(), 1, "one gap per command: {kinds:?}");
    }

    /// On Linux the command's own kernel watch decides too: a late Create
    /// stamped while the watch was confirmed and open is covered; one
    /// stamped after the watch closed is a gap.
    #[cfg(target_os = "linux")]
    #[test]
    fn late_creates_are_judged_by_the_command_watch_at_their_stamp() {
        use shit_planner::time::TimePoint;
        let lb = LiveBaseline::new();
        let (_tmp, index, command) = keyed_fixture(false);
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        lb.record_command_watch(command, root.clone());
        lb.confirm_command_watch(command, TimePoint::new(2, 0));
        lb.close_command_watch(command, TimePoint::new(10, 0));
        let note = open_note_arg("mkdir", root.join("v").to_str().unwrap(), None);
        ingest_late_note(&note, command, TimePoint::new(9, 0), &index, &lb);
        assert!(kinds_of(&index, command).is_empty());
        ingest_late_note(&note, command, TimePoint::new(11, 0), &index, &lb);
        assert!(has_gap(&kinds_of(&index, command)));
    }

    /// R8 review, item 8: a poisoned gap lock does not panic the next
    /// note; the dedupe still works.
    #[test]
    fn a_poisoned_gap_lock_is_recovered() {
        let _ = std::panic::catch_unwind(|| {
            let _guard = journaled_gaps();
            panic!("poison the gap lock");
        });
        let (_tmp, index, command) = keyed_fixture(false);
        assert!(journal_gap_once(
            &index,
            command,
            GapCause::LateNote,
            || "d".into()
        ));
        assert!(!journal_gap_once(
            &index,
            command,
            GapCause::LateNote,
            || "d".into()
        ));
    }

    #[test]
    fn relative_create_paths_are_rejected() {
        for syscall in ["mkdir", "mkfifo", "link"] {
            let rel = classify_tree_op(syscall, "relative/child").expect("classifiable");
            assert!(
                relative_tree_path(&rel).is_some(),
                "{syscall} relative must be dropped"
            );
            let abs = classify_tree_op(syscall, "/tmp/shit-abs-child").expect("classifiable");
            assert!(
                relative_tree_path(&abs).is_none(),
                "{syscall} absolute must pass"
            );
        }
    }

    /// Review of #232, item 6: an Unlink or Rename with a relative path
    /// (macOS reports unresolved dirfd names raw) is never journaled as
    /// a tree op. It is a refusal: the shim's marker when it sent one,
    /// the daemon's own when it did not.
    #[test]
    fn relative_unlink_and_rename_are_refused_not_journaled() {
        for (syscall, arg) in [
            ("unlinkat", "name"),
            ("renameat", "a\t/tmp/abs-b"),
            ("renameat", "/tmp/abs-a\tb"),
        ] {
            let kinds = kinds_after(&open_note_arg(syscall, arg, None));
            assert!(
                matches!(
                    kinds.as_slice(),
                    [CaptureEventKind::CaptureRefused { class, .. }] if class == "capture-incomplete"
                ),
                "{syscall} {arg}: {kinds:#?}"
            );
            let marker = shit_proto::ShimFailure::CanonicalizeFailed {
                which_arg: "path".into(),
                attempted_path: arg.into(),
                error_chain: "F_GETPATH failed".into(),
            };
            let kinds = kinds_after(&open_note_arg(syscall, arg, Some(marker)));
            assert!(
                matches!(
                    kinds.as_slice(),
                    [CaptureEventKind::CaptureRefused { class, .. }] if class == "capture-incomplete"
                ),
                "{syscall} {arg} with marker: {kinds:#?}"
            );
        }
    }

    #[test]
    fn mkdir_notifications_classify_as_directory_creates() {
        for syscall in ["mkdir", "mkdirat"] {
            let path = format!("/tmp/shit-{syscall}-does-not-exist");
            let event = classify_tree_op(syscall, &path).expect("mkdir must be classifiable");

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
                pre_stat: None,
                call_id: 0,
                outcome: None,
                command_key: None,
            };
            let frame = shit_proto::encode_shim_frame(&note).unwrap();
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
        let reserved_ts = TimePoint::new(777, 42);
        ingest_pre_image(
            command,
            &pre,
            &index,
            &blob_store,
            reserved_ts,
            &mut Vec::new(),
        )
        .expect("ingest");

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ts, reserved_ts);
        assert!(matches!(
            &events[0].kind,
            CaptureEventKind::FilePreImage {
                source: shit_planner::FilePreImageSource::ShimPreMutation,
                ..
            }
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
            }),
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let reserved_ts = TimePoint::new(778, 43);

        ingest_notification(
            &note,
            Some(command),
            reserved_ts,
            None,
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

    fn ingest_fixture(
        cmd: &str,
    ) -> (
        tempfile::TempDir,
        Index,
        BlobStore,
        shit_planner::events::CommandId,
    ) {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;
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
                cmd_string: Some(cmd.into()),
                cwd: PathBuf::from("/tmp"),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .expect("put_command");
        (tmp, index, blob_store, command)
    }

    fn shim_pre(path: &str, bytes: &[u8]) -> ShimPreImage {
        ShimPreImage {
            path: path.into(),
            dev: 64,
            inode: 9000,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: bytes.len() as u64,
            mtime_unix_nanos: 0,
            bytes: bytes.to_vec(),
            xattr: None,
            flags: 0,
        }
    }

    /// The recursive dir-rename walk is tagged so the planner can tell
    /// it from in-command captures; the rename's own dst pre-image
    /// keeps the generic source.
    #[test]
    fn rename_walk_pre_images_carry_subtree_source() {
        use shit_planner::FilePreImageSource;
        use shit_planner::time::TimePoint;
        let (_tmp, index, blob_store, command) = ingest_fixture("mv d d.bak");
        let note = ShimNotification {
            pid: 4242,
            syscall: "rename".into(),
            arg: "/tmp/shit-walk/d\t/tmp/shit-walk/d.bak".into(),
            ts_unix_nanos: 0,
            pre_image: Some(shim_pre("/tmp/shit-walk/d.bak", b"old dst")),
            extra_pre_images: vec![
                shim_pre("/tmp/shit-walk/d/a", b"a"),
                shim_pre("/tmp/shit-walk/d/sub/b", b"b"),
            ],
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        ingest_notification(
            &note,
            Some(command),
            TimePoint::new(5, 0),
            None,
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );
        let mut sources: Vec<(PathBuf, FilePreImageSource)> = index
            .events_for_command(command)
            .into_iter()
            .filter_map(|e| match e.kind {
                CaptureEventKind::FilePreImage { path, source, .. } => Some((path, source)),
                _ => None,
            })
            .collect();
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            sources,
            vec![
                (
                    PathBuf::from("/tmp/shit-walk/d/a"),
                    FilePreImageSource::ShimRenameSubtree
                ),
                (
                    PathBuf::from("/tmp/shit-walk/d/sub/b"),
                    FilePreImageSource::ShimRenameSubtree
                ),
                (
                    PathBuf::from("/tmp/shit-walk/d.bak"),
                    FilePreImageSource::ShimPreMutation
                ),
            ]
        );
    }

    #[test]
    fn xattr_syscalls_journal_without_content_source() {
        use shit_planner::FilePreImageSource as S;
        for sc in ["setxattr", "fsetxattr", "removexattr", "fremovexattr"] {
            let src = metadata_pre_image_source(sc);
            assert_eq!(src, S::ShimXattrPreMutation, "{sc}");
            assert!(!src.has_content(), "{sc}");
        }
        assert_eq!(
            metadata_pre_image_source("chflags"),
            S::ShimFlagsPreMutation
        );
        assert_eq!(metadata_pre_image_source("fchmod"), S::ShimPreMutation);
    }

    #[test]
    fn pre_syscall_unlink_stat_reports_dir_and_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        let file = tmp.path().join("f");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = tmp.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let note = |syscall: &str, p: &Path| ShimNotification {
            pid: 1,
            syscall: syscall.into(),
            arg: p.to_str().unwrap().into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let fifo = tmp.path().join("p");
        let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o640) }, 0);
        let p = pre_syscall_unlink_stat(&note("unlink", &fifo)).expect("fifo stat");
        assert_eq!(p.kind, FileKind::Fifo);
        let d = pre_syscall_unlink_stat(&note("unlinkat", &dir)).expect("dir stat");
        assert_eq!(d.kind, FileKind::Directory);
        assert_eq!(d.mode & 0o170000, 0o040000);
        assert_eq!(d.mode & 0o7777, 0o711);
        let f = pre_syscall_unlink_stat(&note("unlink", &file)).expect("file stat");
        assert_eq!(f.kind, FileKind::Regular);
        assert_eq!(f.mode & 0o7777, 0o600);
        // A char node reports its kind (stat only; /dev/null is not
        // touched).
        let n = pre_syscall_unlink_stat(&note("unlink", Path::new("/dev/null")))
            .expect("char device stat");
        assert_eq!(n.kind, FileKind::CharDevice);
        // L4b: a symlink reports its target, and only device nodes
        // carry an identity.
        let l = pre_syscall_unlink_stat(&note("unlinkat", &link)).expect("symlink stat");
        assert_eq!(l.kind, FileKind::Symlink);
        assert_eq!(l.link_target.as_deref(), Some(file.to_str().unwrap()));
        assert_eq!(f.inode, None);
        assert!(n.inode.is_some_and(|i| i != InodeRef::new(0, 0)));
        assert_eq!(
            pre_syscall_unlink_stat(&note("unlinkat", &tmp.path().join("gone"))),
            None
        );
        assert_eq!(pre_syscall_unlink_stat(&note("rename", &dir)), None);
        assert_eq!(
            pre_syscall_unlink_stat(&note("unlinkat", Path::new("relative"))),
            None
        );
    }

    /// L4b: the shim's `unlink` of a symlink journals a
    /// `SymlinkRemoved` for the link's own path with its target, so
    /// undo recreates the link and leaves the target alone.
    #[test]
    fn unlink_of_a_symlink_journals_the_link_and_its_target() {
        use shit_planner::time::TimePoint;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let note = ShimNotification {
            pid: 4242,
            syscall: "unlinkat".into(),
            arg: link.to_str().unwrap().into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let stat = pre_syscall_unlink_stat(&note);
        let (_t, index, blob_store, command) = ingest_fixture("rm link");
        ingest_notification(
            &note,
            Some(command),
            TimePoint::new(6, 0),
            stat,
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );
        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        match &events[0].kind {
            CaptureEventKind::TreeOp(TreeOp::SymlinkRemoved { target: t, path }) => {
                assert_eq!(path, &link);
                assert_eq!(t, target.to_str().unwrap());
            }
            other => panic!("expected SymlinkRemoved, got {other:?}"),
        }
    }

    /// Review round 3, item 2: the symlink is gone by the time the daemon
    /// reads it. The shim's target is used; with none, the removal is
    /// still a SymlinkRemoved (target unknown), never a Regular Unlink.
    #[test]
    fn symlink_removal_uses_the_shim_target_when_the_link_is_gone() {
        let gone = "/nonexistent-shit-l4b/link";
        let note = |target: Option<&str>| ShimNotification {
            pid: 1,
            syscall: "unlinkat".into(),
            arg: gone.into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            call_id: 0,
            outcome: None,
            command_key: None,
            pre_stat: Some(shit_proto::ShimStat {
                dev: 1,
                inode: 2,
                mode: 0o120777,
                link_target: target.map(str::to_string),
            }),
        };
        let kind = |n: &ShimNotification| {
            apply_unlink_stat(
                classify_tree_op("unlinkat", gone).unwrap(),
                pre_syscall_unlink_stat(n),
            )
        };
        assert_eq!(
            kind(&note(Some("t"))),
            CaptureEventKind::TreeOp(TreeOp::SymlinkRemoved {
                target: "t".into(),
                path: PathBuf::from(gone),
            })
        );
        assert_eq!(
            kind(&note(None)),
            CaptureEventKind::TreeOp(TreeOp::SymlinkRemoved {
                target: String::new(),
                path: PathBuf::from(gone),
            })
        );
    }

    /// L4b: a shim `unlink` of a device node carries the shim's pre-call
    /// identity, so it pairs with the helper's `DeviceNodeMeta`.
    #[test]
    fn unlink_of_a_device_node_journals_the_shim_identity() {
        let note = ShimNotification {
            pid: 1,
            syscall: "unlink".into(),
            arg: "/w/null".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            call_id: 0,
            outcome: None,
            command_key: None,
            pre_stat: Some(shit_proto::ShimStat {
                dev: 0x803,
                inode: 77,
                mode: 0o020640,
                link_target: None,
            }),
        };
        let stat = pre_syscall_unlink_stat(&note).expect("stat from pre_stat");
        let kind = apply_unlink_stat(classify_tree_op("unlink", "/w/null").unwrap(), Some(stat));
        assert_eq!(
            kind,
            CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(0x803, 77),
                path: PathBuf::from("/w/null"),
                kind: FileKind::CharDevice,
                mode: 0o020640,
            })
        );
    }

    /// `unlinkat(AT_REMOVEDIR)` journals a Directory unlink with the
    /// mode read before the syscall, so undo recreates a directory.
    #[test]
    fn unlinkat_of_dir_journals_directory_kind() {
        use shit_planner::time::TimePoint;
        let note = ShimNotification {
            pid: 4242,
            syscall: "unlinkat".into(),
            arg: "/tmp/shit-unlink-dir/d".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let (_tmp, index, blob_store, command) = ingest_fixture("rm -rf d");
        ingest_notification(
            &note,
            Some(command),
            TimePoint::new(6, 0),
            Some(UnlinkStat {
                kind: FileKind::Directory,
                mode: 0o040750,
                inode: None,
                link_target: None,
            }),
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );
        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(
            matches!(
                &events[0].kind,
                CaptureEventKind::TreeOp(TreeOp::Unlink {
                    kind: FileKind::Directory,
                    mode: 0o040750,
                    ..
                })
            ),
            "{events:#?}"
        );

        // Without a stat (lstat lost the race) the wire default stays.
        let (_tmp2, index2, blob_store2, command2) = ingest_fixture("rm -rf d");
        ingest_notification(
            &note,
            Some(command2),
            TimePoint::new(7, 0),
            None,
            &index2,
            &blob_store2,
            &LiveBaseline::new(),
        );
        let events = index2.events_for_command(command2);
        assert!(
            matches!(
                &events[0].kind,
                CaptureEventKind::TreeOp(TreeOp::Unlink {
                    kind: FileKind::Regular,
                    mode: 0o100644,
                    ..
                })
            ),
            "{events:#?}"
        );
    }

    fn kinds_after(note: &ShimNotification) -> Vec<CaptureEventKind> {
        use shit_planner::time::TimePoint;
        let (_tmp, index, blob_store, command) = ingest_fixture("python3 save.py");
        ingest_notification(
            note,
            Some(command),
            TimePoint::new(6, 0),
            None,
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );
        index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    /// As `kinds_after`, with the daemon's own stat step as `handle_one`
    /// runs it.
    fn kinds_after_with_stat(note: &ShimNotification) -> Vec<CaptureEventKind> {
        use shit_planner::time::TimePoint;
        let (_tmp, index, blob_store, command) = ingest_fixture("rm -rf d");
        ingest_notification(
            note,
            Some(command),
            TimePoint::new(6, 0),
            pre_syscall_unlink_stat(note),
            &index,
            &blob_store,
            &LiveBaseline::new(),
        );
        index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    fn open_note_arg(
        syscall: &str,
        arg: &str,
        failure: Option<shit_proto::ShimFailure>,
    ) -> ShimNotification {
        ShimNotification {
            arg: arg.into(),
            ..open_note(syscall, failure)
        }
    }

    fn open_note(syscall: &str, failure: Option<shit_proto::ShimFailure>) -> ShimNotification {
        ShimNotification {
            pid: 4242,
            syscall: syscall.into(),
            arg: "/tmp/shit-open/existing".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        }
    }

    /// Review item 1: a write-open with no pre-image is never a Create.
    /// The file may have existed (over the cap, unreadable); unlinking it
    /// at undo would lose it.
    #[test]
    fn open_without_pre_image_never_journals_a_create() {
        for syscall in ["open", "openat", "truncate"] {
            let kinds = kinds_after(&open_note(syscall, None));
            assert!(
                !kinds
                    .iter()
                    .any(|k| matches!(k, CaptureEventKind::TreeOp(TreeOp::Create { .. }))),
                "{syscall}: {kinds:#?}"
            );
        }
    }

    #[test]
    fn uncaptured_existing_file_journals_a_refusal_only() {
        let failure = shit_proto::ShimFailure::PreImageUncaptured {
            path: "/tmp/shit-open/existing".into(),
            reason: "over the shim's inline pre-image cap".into(),
        };
        let kinds = kinds_after(&open_note("open", Some(failure)));
        assert_eq!(kinds.len(), 1, "{kinds:#?}");
        assert!(
            matches!(&kinds[0], CaptureEventKind::CaptureRefused { path, .. }
                if path == Path::new("/tmp/shit-open/existing")),
            "{kinds:#?}"
        );
    }

    /// Review of #232, item 2: the shim's gap marker is journaled in a
    /// watched tree too (BSD baseline or the command's watch root). The
    /// planner decides whether another tier covered it.
    #[test]
    fn uncaptured_file_in_a_watched_tree_still_journals_its_refusal() {
        use shit_planner::time::TimePoint;
        let failure = shit_proto::ShimFailure::PreImageUncaptured {
            path: "/tmp/shit-open/existing".into(),
            reason: "over the shim's inline pre-image cap".into(),
        };
        let note = open_note("open", Some(failure));
        let watched = LiveBaseline::new();
        watched.entry_for_cwd(Path::new("/tmp/shit-open"));
        let (_tmp, index, blob_store, command) = ingest_fixture("python3 save.py");
        watched.record_command_watch(command, PathBuf::from("/tmp/shit-open"));
        ingest_notification(
            &note,
            Some(command),
            TimePoint::new(6, 0),
            None,
            &index,
            &blob_store,
            &watched,
        );
        let kinds: Vec<_> = index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(
            matches!(
                kinds.as_slice(),
                [CaptureEventKind::CaptureRefused { class, .. }] if class == "capture-gap"
            ),
            "{kinds:#?}"
        );
    }

    /// Review round 5, item 1: `python3 -m venv` / `mkdir -p` under the
    /// command's watch root on Linux. The kernel tier journals each
    /// create with its inode; the shim's notes for the same paths are
    /// deferred, so each path has one Create and undo removes each once
    /// with no conflicts. Outside the root the shim's Create is kept.
    #[test]
    #[cfg(target_os = "linux")]
    fn shim_creates_in_the_commands_watch_root_defer_to_the_kernel_tier() {
        use shit_planner::time::TimePoint;
        use std::os::unix::fs::MetadataExt;
        let (tmp, index, blob_store, command) = ingest_fixture("python3 -m venv v");
        let root = tmp.path().canonicalize().unwrap().join("w");
        let out = tmp.path().canonicalize().unwrap().join("out");
        std::fs::create_dir_all(root.join("v/bin")).unwrap();
        std::fs::write(root.join("v/bin/activate"), b"x").unwrap();
        std::fs::create_dir(&out).unwrap();
        let lb = LiveBaseline::new();
        lb.record_command_watch(command, root.clone());
        lb.confirm_command_watch(command, TimePoint::new(1, 0));
        let mut t = 1;
        let mut ts = || {
            t += 1;
            TimePoint::new(t, 0)
        };
        for (rel, kind, shim) in [
            ("v", FileKind::Directory, "mkdir"),
            ("v/bin", FileKind::Directory, "mkdirat"),
            ("v/bin/activate", FileKind::Regular, "open_create"),
        ] {
            let p = root.join(rel);
            let m = std::fs::symlink_metadata(&p).unwrap();
            index
                .put_event(&CaptureEvent {
                    id: EventId(0),
                    command,
                    ts: ts(),
                    partial: false,
                    kind: CaptureEventKind::TreeOp(TreeOp::Create {
                        inode: InodeRef::new(m.dev(), m.ino()),
                        path: p.clone(),
                        kind,
                        mode: m.mode(),
                    }),
                })
                .unwrap();
            let mut note = open_note(shim, None);
            note.arg = p.to_str().unwrap().into();
            ingest_notification(&note, Some(command), ts(), None, &index, &blob_store, &lb);
        }
        let mut note = open_note("mkdir", None);
        note.arg = out.to_str().unwrap().into();
        ingest_notification(&note, Some(command), ts(), None, &index, &blob_store, &lb);
        let events = index.events_for_command(command);
        let mut creates: Vec<_> = events
            .iter()
            .filter_map(|e| match &e.kind {
                CaptureEventKind::TreeOp(TreeOp::Create { path, .. }) => Some(path.clone()),
                _ => None,
            })
            .collect();
        creates.sort();
        assert_eq!(
            creates,
            vec![
                out.clone(),
                root.join("v"),
                root.join("v/bin"),
                root.join("v/bin/activate")
            ]
        );
        let record = <Index as shit_planner::PlannerStore>::command_by_id(&index, command).unwrap();
        let plan = shit_planner::plan(
            record,
            &events,
            &shit_planner::LiveStateProbe::new(),
            &index,
        );
        assert!(
            plan.nodes.iter().all(|n| n.conflict.is_none()),
            "{:#?}",
            plan.nodes
        );
    }

    /// Review of #232, item 3: `mv new link` over a symlink. The daemon
    /// journals the replaced link, and undo puts `new` back and recreates
    /// the link with its target.
    #[test]
    fn rename_over_a_symlink_is_undone_by_recreating_the_link() {
        use shit_planner::time::TimePoint;
        let (tmp, index, blob_store, command) = ingest_fixture("mv new link");
        let dir = tmp.path().canonicalize().unwrap().join("w");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("target"), b"keep").unwrap();
        std::fs::write(dir.join("new"), b"new").unwrap();
        std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
        let mut note = open_note("rename", None);
        note.arg = format!(
            "{}\t{}",
            dir.join("new").display(),
            dir.join("link").display()
        );
        note.pre_stat = Some(shit_proto::ShimStat {
            dev: 1,
            inode: 2,
            mode: 0o120777,
            link_target: Some("target".into()),
        });
        let lb = LiveBaseline::new();
        ingest_notification(
            &note,
            Some(command),
            TimePoint::new(5, 0),
            None,
            &index,
            &blob_store,
            &lb,
        );
        std::fs::rename(dir.join("new"), dir.join("link")).unwrap();

        let events = index.events_for_command(command);
        assert!(
            events.iter().any(|e| matches!(
                &e.kind,
                CaptureEventKind::TreeOp(TreeOp::SymlinkRemoved { target, path })
                    if target == "target" && *path == dir.join("link")
            )),
            "{events:#?}"
        );
        let record = <Index as shit_planner::PlannerStore>::command_by_id(&index, command).unwrap();
        let probe = shit_planner::LiveStateProbe::new();
        let plan = shit_planner::plan(record, &events, &probe, &index);
        let blobs = shit_planner::InMemoryBlobReader::new();
        let exec = shit_planner::FileExecutor::new(&blobs);
        let report = shit_planner::Orchestrator::new(&exec, &probe).run(
            &plan,
            false,
            shit_planner::ConflictPolicy::Abort,
        );
        assert!(
            report
                .records
                .iter()
                .all(|r| r.outcome_kind == shit_planner::OutcomeKind::Applied),
            "{:#?}",
            report.records
        );
        assert_eq!(std::fs::read(dir.join("new")).unwrap(), b"new");
        assert_eq!(
            std::fs::read_link(dir.join("link")).unwrap(),
            PathBuf::from("target")
        );
    }

    /// Review of #232, item 4: a frame from an older shim (version 1, or
    /// version 2 from #223's shim) from a process running under a tracked
    /// command. The peer gets an Allow ack it can decode, and the command
    /// gets one capture-gap refusal.
    #[test]
    fn old_shim_frame_is_acked_and_journals_a_version_gap() {
        for version in [1u8, 2] {
            old_shim_frame_case(version);
        }
    }

    fn old_shim_frame_case(version: u8) {
        let (_tmp, index, blob_store, fixture) = ingest_fixture("python3 save.py");
        // One command per case: the refusal is journaled once per command.
        let command = shit_planner::events::CommandId {
            seq: 100 + u64::from(version),
            ..fixture
        };
        let mut record =
            <Index as shit_planner::PlannerStore>::command_by_id(&index, fixture).unwrap();
        record.command = command;
        index.put_command(&record).unwrap();
        let index = Arc::new(index);
        let active = Arc::new(ActiveCommands::default());
        active.insert(std::process::id(), command);
        let (ours, theirs) = StdUnixStream::pair().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let task = {
            let (index, active) = (index.clone(), active.clone());
            let blobs = Arc::new(blob_store);
            theirs.set_nonblocking(true).unwrap();
            let _guard = rt.enter();
            let theirs = UnixStream::from_std(theirs).unwrap();
            rt.spawn(handle_one(
                theirs,
                index,
                blobs,
                active,
                Arc::new(LiveBaseline::new()),
            ))
        };
        let mut ours = ours;
        // A frame as a shim from before the upgrade sends it: the
        // generic version-1 frame, or a current frame stamped 2.
        let old = if version == 1 {
            encode_frame(&open_note("open", None)).unwrap()
        } else {
            let mut f = shit_proto::encode_shim_frame(&open_note("open", None)).unwrap();
            f[4] = version;
            f
        };
        std::io::Write::write_all(&mut ours, &old).unwrap();
        ours.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut len = [0u8; 4];
        std::io::Read::read_exact(&mut ours, &mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        std::io::Read::read_exact(&mut ours, &mut body).unwrap();
        let mut frame = len.to_vec();
        frame.extend_from_slice(&body);
        let ack: ShimAck = decode_frame(&frame).unwrap();
        assert!(matches!(ack, ShimAck::Allow));
        rt.block_on(task).unwrap().unwrap();
        let kinds: Vec<_> = index
            .events_for_command(command)
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(
            matches!(
                kinds.as_slice(),
                [CaptureEventKind::CaptureRefused { class, detail, .. }]
                    if class == shit_planner::COMMAND_CAPTURE_GAP && detail.contains("Restart the shell")
            ),
            "{kinds:#?}"
        );
    }

    /// Review of #232 round 2, item 2: until the helper confirms the
    /// watch, the shim's Create is journaled; once it has, it is left to
    /// the kernel tier.
    #[test]
    #[cfg(target_os = "linux")]
    fn shim_create_before_the_watch_is_ready_is_journaled() {
        use shit_planner::time::TimePoint;
        let (_tmp, index, blob_store, command) = ingest_fixture("mkdir d");
        let lb = LiveBaseline::new();
        lb.record_command_watch(command, PathBuf::from("/tmp/shit-open"));
        let mut early = open_note("mkdir", None);
        early.arg = "/tmp/shit-open/early".into();
        ingest_notification(
            &early,
            Some(command),
            TimePoint::new(2, 0),
            None,
            &index,
            &blob_store,
            &lb,
        );
        lb.confirm_command_watch(command, TimePoint::new(3, 0));
        let mut late = open_note("mkdir", None);
        late.arg = "/tmp/shit-open/late".into();
        ingest_notification(
            &late,
            Some(command),
            TimePoint::new(4, 0),
            None,
            &index,
            &blob_store,
            &lb,
        );
        let creates: Vec<_> = index
            .events_for_command(command)
            .into_iter()
            .filter_map(|e| match e.kind {
                CaptureEventKind::TreeOp(TreeOp::Create { path, .. }) => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(creates, vec![PathBuf::from("/tmp/shit-open/early")]);
    }

    /// Review of #232 medium review, item 5: a version-gap refusal whose
    /// write failed (here the command row is not there yet) is written
    /// on the next note, not skipped as already seen.
    #[test]
    fn failed_version_gap_write_is_retried() {
        use shit_planner::events::CommandRecord;
        use shit_planner::time::TimePoint;
        let tmp = tempfile::tempdir().unwrap();
        let index = Index::open(tmp.path().join("idx.sqlite")).unwrap();
        let session = uuid::Uuid::from_u128(0x5eed);
        let command = shit_planner::events::CommandId { session, seq: 1 };
        journal_gap_once(&index, command, GapCause::OtherShimWire, || {
            other_wire_gap_detail(1)
        });
        assert!(index.events_for_command(command).is_empty());
        index
            .put_session(session, "bash", 0, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("python3 x.py".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 1,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        journal_gap_once(&index, command, GapCause::OtherShimWire, || {
            other_wire_gap_detail(1)
        });
        journal_gap_once(&index, command, GapCause::OtherShimWire, || {
            other_wire_gap_detail(1)
        });
        assert_eq!(index.events_for_command(command).len(), 1);
    }

    /// L5 PR B, through the ingest path: a rename call's pre-call note
    /// journals its Rename and a RenameCall listing it under the call id;
    /// the outcome note journals a RenameOutcome under the same id. A
    /// failed call (ENOTEMPTY, after the LSM hook fired) leaves no reverse rename in the plan, and the
    /// kernel tier's report of the same call (another path spelling, the
    /// source's inode) goes with it. The outcome is ingested after its
    /// sender exited (no live pid): its command comes from the call.
    #[test]
    fn a_failed_rename_call_is_joined_by_its_id_and_planned_away() {
        use shit_planner::time::TimePoint;
        let (_tmp, index, blob_store, command) = ingest_fixture("pip install");
        let lb = LiveBaseline::new();
        let mut pre = open_note_arg("rename", "/private/var/t/a\t/private/var/t/b", None);
        pre.call_id = 9;
        ingest_notification(
            &pre,
            Some(command),
            TimePoint::new(2, 0),
            None,
            &index,
            &blob_store,
            &lb,
        );
        // The kernel tier's report: same inode, other spelling.
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(3, 0),
                partial: false,
                kind: CaptureEventKind::TreeOp(TreeOp::Rename {
                    from: PathBuf::from("/var/t/a"),
                    to: PathBuf::from("/var/t/b"),
                    inode: InodeRef::new(8, 42),
                }),
            })
            .unwrap();
        let mut out = open_note_arg("rename", "/private/var/t/a\t/private/var/t/b", None);
        out.call_id = 9;
        out.outcome = Some(shit_proto::ShimRenameOutcome {
            errno: 39,
            source_dev: 8,
            source_inode: 42,
        });
        ingest_notification(
            &out,
            None, // Review item 1: the sender exited before its outcome was ingested.
            TimePoint::new(4, 0),
            None,
            &index,
            &blob_store,
            &lb,
        );

        let events = index.events_for_command(command);
        let rename_id = events
            .iter()
            .find(|e| {
                matches!(&e.kind, CaptureEventKind::TreeOp(TreeOp::Rename { from, .. })
                    if from == Path::new("/private/var/t/a"))
            })
            .map(|e| e.id)
            .expect("the shim's Rename");
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            CaptureEventKind::RenameCall { pid: 4242, call_id: 9, events } if events == &vec![rename_id]
        )), "{events:#?}");
        assert!(
            events.iter().any(|e| matches!(
                &e.kind,
                CaptureEventKind::RenameOutcome {
                    call_id: 9,
                    errno: 39,
                    ..
                }
            )),
            "{events:#?}"
        );
        // The outcome note is not a second Rename.
        let renames = events
            .iter()
            .filter(|e| matches!(&e.kind, CaptureEventKind::TreeOp(TreeOp::Rename { .. })))
            .count();
        assert_eq!(renames, 2, "the shim's and the kernel's");
        let record = <Index as shit_planner::PlannerStore>::command_by_id(&index, command).unwrap();
        let plan = shit_planner::plan(
            record,
            &events,
            &shit_planner::probe::mock::InMemoryProbe::new(),
            &index,
        );
        assert!(
            !plan
                .nodes
                .iter()
                .any(|n| matches!(n.op, shit_planner::InverseOp::Rename { .. })),
            "{:#?}",
            plan.nodes
        );
    }

    #[test]
    fn open_create_journals_a_create() {
        let kinds = kinds_after(&open_note("open_create", None));
        assert!(
            matches!(
                kinds.as_slice(),
                [CaptureEventKind::TreeOp(TreeOp::Create {
                    kind: FileKind::Regular,
                    ..
                })]
            ),
            "{kinds:#?}"
        );
    }

    /// L5: the Linux shim's rmdir interposer. With the stat its mode is
    /// journaled; without one it is still a directory.
    #[test]
    fn rmdir_takes_kind_and_mode_from_the_shims_pre_call_stat() {
        let mut note = open_note("rmdir", None);
        note.pre_stat = Some(shit_proto::ShimStat {
            dev: 1,
            inode: 2,
            mode: 0o040750,
            link_target: None,
        });
        let stat = pre_syscall_unlink_stat(&note);
        assert_eq!(
            stat,
            Some(UnlinkStat {
                kind: FileKind::Directory,
                mode: 0o040750,
                inode: Some(InodeRef::new(1, 2)),
                link_target: None,
            })
        );
    }

    /// Review round 3, items 4 and 5: an `unlinkat(AT_REMOVEDIR)` reported
    /// after success is a directory unlink with the shim's identity, and
    /// without a stat it is still a directory, never an lstat of whatever
    /// now has the name.
    #[test]
    fn post_call_removals_are_directories_with_the_shims_identity() {
        use std::os::unix::fs::PermissionsExt;
        let mut with_stat = open_note("unlinkat_dir", None);
        with_stat.pre_stat = Some(shit_proto::ShimStat {
            dev: 9,
            inode: 4242,
            mode: 0o040711,
            link_target: None,
        });
        let kinds = kinds_after_with_stat(&with_stat);
        assert!(
            matches!(
                kinds.as_slice(),
                [CaptureEventKind::TreeOp(TreeOp::Unlink {
                    kind: FileKind::Directory,
                    mode: 0o040711,
                    inode,
                    ..
                })] if *inode == InodeRef::new(9, 4242)
            ),
            "{kinds:#?}"
        );
        // Something new holds the name now; it must not be stat'ed.
        let tmp = tempfile::tempdir().unwrap();
        let reused = tmp.path().join("d");
        std::fs::create_dir(&reused).unwrap();
        std::fs::set_permissions(&reused, std::fs::Permissions::from_mode(0o700)).unwrap();
        for syscall in ["rmdir", "unlinkat_dir"] {
            let mut bare = open_note(syscall, None);
            bare.arg = reused.to_str().unwrap().into();
            let kinds = kinds_after_with_stat(&bare);
            assert!(
                matches!(
                    kinds.as_slice(),
                    [CaptureEventKind::TreeOp(TreeOp::Unlink {
                        kind: FileKind::Directory,
                        mode: 0o040755,
                        ..
                    })]
                ),
                "{syscall}: {kinds:#?}"
            );
        }
    }

    #[test]
    fn rmdir_journals_a_directory_unlink() {
        use shit_planner::time::TimePoint;
        let note = ShimNotification {
            pid: 4242,
            syscall: "rmdir".into(),
            arg: "/tmp/shit-rmdir/d".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        for (stat, want_mode) in [
            (
                Some(UnlinkStat {
                    kind: FileKind::Directory,
                    mode: 0o040700,
                    inode: None,
                    link_target: None,
                }),
                0o040700,
            ),
            (None, 0o040755),
        ] {
            let (_tmp, index, blob_store, command) = ingest_fixture("python3 -c rmtree");
            ingest_notification(
                &note,
                Some(command),
                TimePoint::new(6, 0),
                stat,
                &index,
                &blob_store,
                &LiveBaseline::new(),
            );
            let events = index.events_for_command(command);
            assert_eq!(events.len(), 1, "{events:#?}");
            assert!(
                matches!(
                    &events[0].kind,
                    CaptureEventKind::TreeOp(TreeOp::Unlink {
                        kind: FileKind::Directory,
                        mode,
                        ..
                    }) if *mode == want_mode
                ),
                "{events:#?}"
            );
        }
    }
}
