// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon side of the helper link. Spawns `shit-helper`, accepts its
//! connection, drives the handshake, and surfaces the connection +
//! granted capabilities to the rest of the daemon.
//!
//! Death detection: a 0-byte recv on the helper socket means the
//! helper exited. The reader task that gets there flips a flag the
//! daemon's stats path surfaces as "helper degraded / dead".

// S06.10 scaffold — the daemon main loop doesn't yet drive this; the
// integration test under crates/shitd/tests/helper_handshake.rs does.
// S07/S08/S09 wire this into the event loop.
#![allow(dead_code)]

use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, Shutdown, SockFlag, SockType, UnixAddr,
    bind, cmsg_space, listen, recvmsg, shutdown, socket,
};
use shit_planner::events::{CaptureEvent, CaptureEventKind, CommandId, EventId, TreeOp};
use shit_planner::inode::{BlobHash, InodeRef};
use shit_planner::metadata::FileMetadata;
use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse, decode_frame, encode_frame,
};
use shit_store::{BlobStore, Index};
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// W01.B.fix-framing: SEQPACKET on every platform that supports
// AF_UNIX+SOCK_SEQPACKET (Linux + all BSDs). macOS XNU is the only
// holdout — it falls back to STREAM. STREAM-on-BSD was a copy-paste
// from "macOS needs STREAM" and unintentionally pinned BSDs to a
// transport that coalesces messages, breaking high-rate capture
// (git commit, etc).
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const HELPER_SOCK_TYPE: SockType = SockType::SeqPacket;
#[cfg(target_os = "macos")]
const HELPER_SOCK_TYPE: SockType = SockType::Stream;

/// Keep synchronous hook-path writes bounded. Any timeout poisons the link
/// below because macOS's STREAM transport may already contain a frame prefix.
const SEND_TIMEOUT_SECS: libc::time_t = 1;

fn set_send_timeout(fd: RawFd) -> std::io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: SEND_TIMEOUT_SECS,
        tv_usec: 0,
    };
    // SAFETY: `timeout` is live for the call and `fd` remains owned by the
    // caller. The level/name pair requires exactly a `timeval` value.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn poison_after_send_failure(fd: RawFd) {
    let _ = shutdown(fd, Shutdown::Both);
}

#[derive(Debug, thiserror::Error)]
pub enum HelperLinkError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("encode: {0}")]
    Encode(#[from] shit_proto::EncodeError),
    #[error("decode: {0}")]
    Decode(#[from] shit_proto::DecodeError),
    #[error("helper exited before handshake")]
    HelperExited,
    #[error("first message from helper was not HandshakeAck")]
    NotHandshakeAck,
    #[error("protocol version mismatch: daemon {daemon}, helper {helper}")]
    VersionMismatch { daemon: u16, helper: u16 },
    #[error("helper binary not found; set SHIT_HELPER_BIN or install on PATH")]
    HelperNotFound,
    /// M07.C.3 — helper's `codesign --verify --strict --deep` against
    /// its own binary failed. The daemon refuses the helper to avoid
    /// accepting events from a process whose binary was tampered on
    /// disk between install and exec. Recovery is to re-install or
    /// re-codesign the helper (`shit setup-es-mode --apply` for the
    /// macOS power-user install path).
    #[error("helper self-verify failed: {0}")]
    SelfVerifyFailed(String),
}

/// AU28 — privileged-op waiters map shared between the dispatch
/// loop and the HelperLinkPrivilegedOpRouter. Keyed by the wire's
/// `(session, command_seq)`; the value is the sync sender the
/// dispatch loop fills when the helper's `PrivilegedOpResult`
/// arrives.
pub type PrivOpWaiters = std::sync::Arc<
    std::sync::Mutex<
        std::collections::HashMap<
            (uuid::Uuid, u64),
            std::sync::mpsc::SyncSender<shit_proto::PrivilegedOpOutcome>,
        >,
    >,
>;

/// Ordered `UnwatchTree` completion waiters shared by the hook server and the
/// helper-response dispatcher. The waiter is installed before the request is
/// written, so even a very fast helper cannot race its completion marker.
pub type UnwatchWaiters = std::sync::Arc<
    std::sync::Mutex<
        std::collections::HashMap<
            (uuid::Uuid, u64),
            tokio::sync::oneshot::Sender<Result<(), String>>,
        >,
    >,
>;

/// Capture responses are consumed before the helper's ordered unwatch
/// completion marker, but a response is not durable merely because it was
/// received.  This map remembers the rare case where both the primary
/// evidence write and the command-scoped `CaptureRefused` fallback failed.
/// The failure is sticky until the exact command's unwatch waiter consumes it.
#[derive(Debug, Default)]
pub(crate) struct IngestFailures {
    /// `None` means the command is initialized and has no known durability
    /// failure; `Some(detail)` is sticky until completion consumes the entry.
    inner: Mutex<HashMap<CommandId, Option<String>>>,
}

impl IngestFailures {
    fn begin_command(&self, command: CommandId) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(command)
            .or_insert(None);
    }

    fn mark(&self, command: CommandId, detail: String) {
        let mut failures = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = failures.entry(command).or_insert(None);
        if state.is_none() {
            *state = Some(detail);
        }
    }

    fn take(&self, command: CommandId) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&command)
            .flatten()
    }

    #[cfg(test)]
    fn contains(&self, command: CommandId) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&command)
            .is_some_and(Option::is_some)
    }

    #[cfg(test)]
    fn is_initialized(&self, command: CommandId) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&command)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UnwatchTreeError {
    #[error("unwatch request failed: {0}")]
    Send(#[from] HelperLinkError),
    #[error("an unwatch request is already pending for {session}/{command_seq}")]
    AlreadyPending {
        session: uuid::Uuid,
        command_seq: u64,
    },
    #[error("helper stopped before the unwatch barrier completed: {0}")]
    HelperStopped(String),
    #[error("unwatch completion channel closed")]
    CompletionChannelClosed,
    #[error("unwatch completion timed out after {0:?}")]
    Timeout(Duration),
}

/// Registered end-of-command barrier. Creation synchronously installs the
/// waiter and writes `UnwatchTree`; awaiting is deliberately separate so the
/// hook datagram loop can preserve wire order without stalling later PreExec
/// intake while the platform producer drains.
pub struct PendingUnwatch {
    key: (uuid::Uuid, u64),
    receiver: Option<tokio::sync::oneshot::Receiver<Result<(), String>>>,
    waiters: UnwatchWaiters,
    ingest_failures: Arc<IngestFailures>,
}

impl PendingUnwatch {
    pub async fn wait(mut self, timeout: Duration) -> Result<(), UnwatchTreeError> {
        let receiver = self
            .receiver
            .take()
            .expect("PendingUnwatch receiver is consumed exactly once");
        let result = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(detail))) => Err(UnwatchTreeError::HelperStopped(detail)),
            Ok(Err(_)) => Err(UnwatchTreeError::CompletionChannelClosed),
            Err(_) => Err(UnwatchTreeError::Timeout(timeout)),
        };
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
        result
    }
}

impl Drop for PendingUnwatch {
    fn drop(&mut self) {
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
        self.ingest_failures.take(CommandId {
            session: self.key.0,
            seq: self.key.1,
        });
    }
}

/// Outcome of a successful helper link.
#[derive(Debug)]
pub struct HelperLink {
    /// Connected SEQPACKET/STREAM fd to the running helper.
    pub conn_fd: OwnedFd,
    /// Serialize complete request frames. The server and privileged-op router
    /// can write through the same link concurrently, and macOS uses a byte
    /// stream where partial sends from two writers would otherwise interleave.
    send_lock: std::sync::Mutex<()>,
    /// Helper process handle. Wrapped in `Mutex<Option<Child>>` so
    /// `kill_helper(&self)` (called via `&Arc<HelperLink>`) can take +
    /// kill + reap without `&mut self`. `Drop` is a no-op when
    /// `kill_helper` has already consumed the child, which is the
    /// load-bearing path for AU09 graceful shutdown: tearing down the
    /// helper before the tokio runtime drop unblocks any
    /// `spawn_blocking` recv that the helper still holds open.
    child: std::sync::Mutex<Option<Child>>,
    pub helper_pid: u32,
    pub helper_uid: u32,
    pub granted: HelperCaps,
    /// Capture-tier classifier the helper reported in the handshake
    /// (DR-66). E.g. `"fanotify"`, `"bpf-lsm"`, `"endpoint-security"`,
    /// `"kqueue"`. Forwarded to `Stats::set_kernel_tier` after
    /// link-up so `shit metrics` and the structured log stream
    /// surface what's actually running.
    pub kernel_tier: String,
    /// M03.x.POWER-USER.3 — populated when `kernel_tier` is the
    /// fallback variant for a platform that has a higher tier
    /// available (e.g. `"fsevents-degraded"` on macOS when ES is
    /// the intended target). The string names the specific reason
    /// ES isn't running. `None` when the tier IS the intended one.
    /// Surfaced to the doctor + the structured log.
    pub degraded_reason: Option<String>,
    /// AU28 / DR-15 stage-1 — outstanding privileged-op requests
    /// keyed by `(session, command_seq)`. The router holds a
    /// `SyncSender` here, sends the request via `send_request`,
    /// then blocks on the matching `Receiver`. The dispatch loop
    /// peels `HelperResponse::PrivilegedOpResult` off the wire
    /// and forwards the outcome to the waiter (single-flight per
    /// key; the key is monotonic per router instance so collisions
    /// don't happen in practice).
    pub priv_op_waiters: PrivOpWaiters,
    /// Awaiters for the ordered end-of-command capture barrier. Kept separate
    /// from privileged-op replies because command ids are the real wire keys
    /// here and more than one command can be closing concurrently.
    unwatch_waiters: UnwatchWaiters,
    /// Sticky failures proving that a helper response could not be made
    /// durable, including failure of the refusal fallback itself.
    ingest_failures: Arc<IngestFailures>,
}

/// Reap a helper if handshake setup exits early through any `?` path. On a
/// successful handshake ownership is explicitly transferred into HelperLink.
struct SpawnedHelperGuard {
    child: Option<Child>,
}

impl SpawnedHelperGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn into_child(mut self) -> Child {
        self.child
            .take()
            .expect("spawned helper guard is consumed exactly once")
    }
}

impl Drop for SpawnedHelperGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl HelperLink {
    /// Send a request to the helper. STREAM-safe (relies on the
    /// length-prefix framing in `shit_proto::frame`).
    pub fn send_request(&self, msg: &HelperRequest) -> Result<(), HelperLinkError> {
        let _send_guard = self
            .send_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let HelperRequest::WatchTree {
            session,
            command_seq,
            ..
        } = msg
        {
            // Initialize before the first request byte is visible to the
            // helper, so a fast response cannot race command initialization.
            // Duplicate WatchTree requests never clear a sticky failure.
            self.ingest_failures.begin_command(CommandId {
                session: *session,
                seq: *command_seq,
            });
        }
        let frame = encode_frame(msg)?;
        send_frame_blocking(&self.conn_fd, &frame)
    }

    /// Receive one response frame from the helper.
    pub fn recv_response(&self) -> Result<HelperResponse, HelperLinkError> {
        let buf = recv_frame_blocking(self.conn_fd.as_raw_fd())?;
        Ok(decode_frame(&buf)?)
    }

    /// Receive one response frame plus an optional fd attached via
    /// `SCM_RIGHTS` (S24.A). Mirrors `Conn::recv_response_with_fd` on
    /// the helper side. On macOS STREAM sockets the cmsg rides with the
    /// first bytes, so we receive exactly the four-byte frame header with
    /// `recvmsg(2)` and then read the declared body. Limiting that first iov
    /// prevents it from consuming bytes belonging to a coalesced next frame.
    pub fn recv_response_with_fd(
        &self,
    ) -> Result<(HelperResponse, Option<OwnedFd>), HelperLinkError> {
        let (buf, fd) = recv_frame_with_fd_blocking(self.conn_fd.as_raw_fd())?;
        Ok((decode_frame(&buf)?, fd))
    }

    /// Register the completion waiter before synchronously writing
    /// `UnwatchTree`. Callers should do this in hook-arrival order, then await
    /// the returned barrier from a separate task.
    pub fn begin_unwatch_tree(
        &self,
        command: CommandId,
    ) -> Result<PendingUnwatch, UnwatchTreeError> {
        use std::collections::hash_map::Entry;

        let key = (command.session, command.seq);
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut waiters = self
                .unwatch_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match waiters.entry(key) {
                Entry::Vacant(slot) => {
                    slot.insert(tx);
                }
                Entry::Occupied(_) => {
                    return Err(UnwatchTreeError::AlreadyPending {
                        session: command.session,
                        command_seq: command.seq,
                    });
                }
            }
        }

        let request = HelperRequest::UnwatchTree {
            session: command.session,
            command_seq: command.seq,
        };
        if let Err(error) = self.send_request(&request) {
            self.unwatch_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
            self.ingest_failures.take(command);
            return Err(UnwatchTreeError::Send(error));
        }

        Ok(PendingUnwatch {
            key,
            receiver: Some(rx),
            waiters: Arc::clone(&self.unwatch_waiters),
            ingest_failures: Arc::clone(&self.ingest_failures),
        })
    }

    /// Convenience wrapper for callers that do not need to separate ordered
    /// request emission from the asynchronous wait.
    pub async fn unwatch_tree_and_wait(
        &self,
        command: CommandId,
        timeout: Duration,
    ) -> Result<(), UnwatchTreeError> {
        self.begin_unwatch_tree(command)?.wait(timeout).await
    }
}

/// Translate "peer is gone" errnos (ECONNRESET, EPIPE) into the
/// dispatch loop's clean-exit signal. The kernel can deliver these on
/// SEQPACKET/STREAM when the helper exits ungracefully (e.g. signaled)
/// instead of the EOF that orderly shutdown produces. Both mean the
/// same thing to us — there is no one to read from anymore.
fn map_peer_gone(e: nix::Error) -> HelperLinkError {
    match e {
        nix::Error::ECONNRESET | nix::Error::EPIPE => HelperLinkError::HelperExited,
        other => HelperLinkError::Nix(other),
    }
}

fn recv_frame_with_fd_blocking(
    fd: std::os::fd::RawFd,
) -> Result<(Vec<u8>, Option<OwnedFd>), HelperLinkError> {
    use std::os::fd::FromRawFd;

    // On macOS the transport is STREAM (XNU has no AF_UNIX
    // SOCK_SEQPACKET). recvmsg with a max-size iov can suck up MORE
    // bytes than one frame when the sender has multiple frames in
    // flight (helper emits CapturedPreImage immediately followed by
    // another frame). The excess bytes belong to the next frame and
    // can't be put back — so we cap the recvmsg iov at the header
    // size, then plain recv for the body. The SCM_RIGHTS cmsg rides
    // with the first chunk per Apple's UDS semantics, so the 4-byte
    // header recvmsg still picks up the fd.
    //
    // SEQPACKET (Linux/BSD) preserves boundaries; a single recvmsg
    // delivers exactly one frame, so the legacy MAX_FRAME_SIZE buffer
    // path applies there.
    #[cfg(target_os = "macos")]
    {
        let mut header = [0u8; 4];
        let mut iov = [std::io::IoSliceMut::new(&mut header)];
        let mut cmsg_buf: Vec<u8> = Vec::with_capacity(cmsg_space::<std::os::fd::RawFd>());
        let result = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
            .map_err(map_peer_gone)?;
        let n = result.bytes;
        if n == 0 {
            return Err(HelperLinkError::HelperExited);
        }
        let mut received_fd: Option<OwnedFd> = None;
        for cmsg in result.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg
                && let Some(raw) = fds.first()
            {
                // SAFETY: kernel handed us a fresh fd; ownership transfers.
                received_fd = Some(unsafe { OwnedFd::from_raw_fd(*raw) });
                for extra in fds.iter().skip(1) {
                    drop(unsafe { OwnedFd::from_raw_fd(*extra) });
                }
            }
        }
        // Complete short header read if recvmsg returned <4 bytes.
        let mut header_v = header[..n].to_vec();
        while header_v.len() < 4 {
            let mut chunk = [0u8; 4];
            let need = 4 - header_v.len();
            let m = nix::sys::socket::recv(fd, &mut chunk[..need], MsgFlags::empty())
                .map_err(map_peer_gone)?;
            if m == 0 {
                return Err(HelperLinkError::HelperExited);
            }
            header_v.extend_from_slice(&chunk[..m]);
        }
        let body_len =
            u32::from_be_bytes([header_v[0], header_v[1], header_v[2], header_v[3]]) as usize;
        let frame_len = 4 + body_len;
        if frame_len > shit_proto::MAX_HELPER_FRAME_SIZE {
            return Err(HelperLinkError::Decode(shit_proto::DecodeError::TooLarge(
                frame_len,
            )));
        }
        let mut buf = Vec::with_capacity(frame_len);
        buf.extend_from_slice(&header_v);
        buf.resize(frame_len, 0);
        recv_exact(fd, &mut buf[4..])?;
        Ok((buf, received_fd))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut buf = vec![0u8; shit_proto::MAX_HELPER_FRAME_SIZE];
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let mut cmsg_buf: Vec<u8> = Vec::with_capacity(cmsg_space::<std::os::fd::RawFd>());
        let result = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
            .map_err(map_peer_gone)?;
        let n = result.bytes;
        if n == 0 {
            return Err(HelperLinkError::HelperExited);
        }
        let mut received_fd: Option<OwnedFd> = None;
        for cmsg in result.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg
                && let Some(raw) = fds.first()
            {
                received_fd = Some(unsafe { OwnedFd::from_raw_fd(*raw) });
                for extra in fds.iter().skip(1) {
                    drop(unsafe { OwnedFd::from_raw_fd(*extra) });
                }
            }
        }
        buf.truncate(n);
        Ok((buf, received_fd))
    }
}

impl HelperLink {
    /// AU28 / DR-15 stage-1 — synchronous request/reply for a
    /// privileged op (chown, mknod). Registers a waiter keyed by
    /// `(session, command_seq)`, sends the request, blocks on the
    /// receiver up to `timeout`. The dispatch loop forwards the
    /// matching `PrivilegedOpResult` to the waiter.
    ///
    /// On timeout, ENXIO / EPIPE on send, or any other transport
    /// failure, returns `PrivilegedOpOutcome::Failed { err }`.
    /// Caller (the FileExecutor) treats Failed as a non-recoverable
    /// privileged-op error — same as the original EPERM that
    /// triggered the route.
    pub fn request_priv_op_blocking(
        &self,
        session: uuid::Uuid,
        command_seq: u64,
        req: shit_proto::HelperRequest,
        timeout: std::time::Duration,
    ) -> shit_proto::PrivilegedOpOutcome {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        {
            let mut waiters = self
                .priv_op_waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            waiters.insert((session, command_seq), tx);
        }
        if let Err(e) = self.send_request(&req) {
            // Clear our waiter; no reply will ever arrive.
            self.priv_op_waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&(session, command_seq));
            return shit_proto::PrivilegedOpOutcome::Failed {
                err: format!("send_request: {e}"),
            };
        }
        match rx.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.priv_op_waiters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&(session, command_seq));
                shit_proto::PrivilegedOpOutcome::Failed {
                    err: format!("priv-op timeout after {timeout:?}"),
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Sender dropped without sending; dispatch removed the
                // waiter (e.g. on helper exit) but didn't fill it.
                shit_proto::PrivilegedOpOutcome::Failed {
                    err: "priv-op response channel disconnected".into(),
                }
            }
        }
    }

    /// AU09 — terminate the helper child and reap it. Idempotent; safe
    /// to call multiple times or alongside `Drop` (the inner `Option`
    /// short-circuits the second pass). Required during graceful
    /// shutdown so the helper's blocking-recv thread unblocks before
    /// the daemon's tokio runtime tries to drop its `spawn_blocking`
    /// task pool.
    pub fn kill_helper(&self) {
        let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for HelperLink {
    fn drop(&mut self) {
        // Best-effort. If `kill_helper` already consumed the child the
        // lock holds None and this is a no-op.
        if let Ok(mut guard) = self.child.lock()
            && let Some(mut child) = guard.take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `shit-helper`, accept the connection, handshake, return the
/// link. `sock_path` is where the listening socket is bound; the path
/// is unlinked on drop of the listener.
pub fn spawn_and_handshake(
    helper_bin: &Path,
    sock_path: &Path,
    state_dir: &Path,
    caps_request: HelperCaps,
) -> Result<HelperLink, HelperLinkError> {
    if !helper_bin.exists() {
        return Err(HelperLinkError::HelperNotFound);
    }
    if sock_path.exists() {
        let _ = std::fs::remove_file(sock_path);
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(state_dir)?;

    // Listening socket.
    let listener = socket(
        AddressFamily::Unix,
        HELPER_SOCK_TYPE,
        SockFlag::empty(),
        None,
    )?;
    let addr = UnixAddr::new(sock_path)?;
    bind(listener.as_raw_fd(), &addr)?;
    listen(&listener, Backlog::new(1)?)?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;

    let daemon_pid = std::process::id();
    let daemon_uid = unsafe { libc::getuid() };

    let mut cmd = Command::new(helper_bin);
    cmd.arg("--daemon-sock")
        .arg(sock_path)
        .arg("--daemon-pid")
        .arg(daemon_pid.to_string())
        .arg("--daemon-uid")
        .arg(daemon_uid.to_string())
        .arg("--state-dir")
        .arg(state_dir)
        .stdin(Stdio::null());
    // LD_PRELOAD-stripping happens in the helper itself (TA-3); we
    // additionally clear it on the env we hand to the child so
    // `set_var` chicanery doesn't propagate.
    cmd.env_remove("LD_PRELOAD")
        .env_remove("DYLD_INSERT_LIBRARIES");

    let child = cmd.spawn().map_err(HelperLinkError::Io)?;
    let child = SpawnedHelperGuard::new(child);

    // Accept blocks until the helper connects. Tests timeout via
    // their own deadlines.
    let conn_raw = nix::sys::socket::accept(listener.as_raw_fd())?;
    // SAFETY: accept returned a fresh fd we own.
    let conn_fd: OwnedFd = unsafe { std::os::fd::FromRawFd::from_raw_fd(conn_raw) };
    if let Err(error) = set_send_timeout(conn_fd.as_raw_fd()) {
        drop(listener);
        let _ = std::fs::remove_file(sock_path);
        return Err(HelperLinkError::Io(error));
    }
    drop(listener);
    let _ = std::fs::remove_file(sock_path);

    // Handshake.
    let req = HelperRequest::Handshake {
        daemon_pid,
        daemon_uid,
        protocol_version: HELPER_PROTOCOL_VERSION,
        capability_request: caps_request,
    };
    send_frame_blocking(&conn_fd, &encode_frame(&req)?)?;
    let buf = recv_frame_blocking_owned(&conn_fd)?;
    let resp: HelperResponse = decode_frame(&buf)?;
    let HelperResponse::HandshakeAck {
        helper_pid,
        helper_uid,
        protocol_version,
        granted,
        helper_version: _,
        kernel_tier,
        degraded_reason,
        self_verify,
    } = resp
    else {
        return Err(HelperLinkError::NotHandshakeAck);
    };
    if protocol_version != HELPER_PROTOCOL_VERSION {
        return Err(HelperLinkError::VersionMismatch {
            daemon: HELPER_PROTOCOL_VERSION,
            helper: protocol_version,
        });
    }
    if let Some(reason) = degraded_reason.as_deref() {
        tracing::info!(
            kernel_tier = %kernel_tier,
            degraded_reason = %reason,
            "helper handshake: tier degraded — see `shit setup-es-mode --check` for remediation"
        );
    }
    // M07.C.3 — log the helper's self-verify outcome. On macOS,
    // a failed verify means the binary on disk has been tampered
    // (or has lost its signature); we refuse the helper rather
    // than accept events from a compromised process. Non-macOS
    // helpers ship `NotApplicable` and pass through.
    if !self_verify.ok {
        tracing::error!(
            reason = self_verify.reason.as_deref().unwrap_or("unknown"),
            "helper self-verify FAILED; refusing handshake"
        );
        return Err(HelperLinkError::SelfVerifyFailed(
            self_verify
                .reason
                .clone()
                .unwrap_or_else(|| "unspecified".into()),
        ));
    }
    tracing::info!(
        signature_kind = ?self_verify.signature_kind,
        team_id = self_verify.team_id.as_deref().unwrap_or(""),
        "helper self-verify ok"
    );

    Ok(HelperLink {
        conn_fd,
        send_lock: std::sync::Mutex::new(()),
        child: std::sync::Mutex::new(Some(child.into_child())),
        helper_pid,
        helper_uid,
        granted,
        kernel_tier,
        degraded_reason,
        priv_op_waiters: PrivOpWaiters::new(
            std::sync::Mutex::new(std::collections::HashMap::new()),
        ),
        unwatch_waiters: UnwatchWaiters::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        ingest_failures: Arc::new(IngestFailures::default()),
    })
}

/// Discover the helper binary. Order: `SHIT_HELPER_BIN` env > sibling
/// of the daemon's own exe > `PATH`. Tests set `SHIT_HELPER_BIN`
/// directly to `env!("CARGO_BIN_EXE_shit-helper")`.
pub fn discover_helper_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SHIT_HELPER_BIN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let candidate = parent.join("shit-helper");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    // PATH lookup
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("shit-helper");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn send_frame_blocking(fd: &OwnedFd, frame: &[u8]) -> Result<(), HelperLinkError> {
    let mut sent = 0;
    while sent < frame.len() {
        let n = match nix::sys::socket::send(
            fd.as_raw_fd(),
            &frame[sent..],
            nix::sys::socket::MsgFlags::empty(),
        ) {
            Ok(n) => n,
            Err(error) => {
                poison_after_send_failure(fd.as_raw_fd());
                return Err(error.into());
            }
        };
        if n == 0 {
            poison_after_send_failure(fd.as_raw_fd());
            return Err(HelperLinkError::HelperExited);
        }
        sent += n;
    }
    Ok(())
}

fn recv_frame_blocking(fd: std::os::fd::RawFd) -> Result<Vec<u8>, HelperLinkError> {
    // Transport-aware (see crates/shit-helper/src/ipc.rs for the same
    // pattern + rationale). SEQPACKET truncates short recvs to the
    // packet boundary, so we must recv into a full-size buffer. The
    // cfg gates MUST mirror the HELPER_SOCK_TYPE selection at the
    // top of this file.
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    {
        let mut buf = vec![0u8; shit_proto::MAX_HELPER_FRAME_SIZE];
        let n = nix::sys::socket::recv(fd, &mut buf, nix::sys::socket::MsgFlags::empty())?;
        if n == 0 {
            return Err(HelperLinkError::HelperExited);
        }
        buf.truncate(n);
        Ok(buf)
    }
    #[cfg(target_os = "macos")]
    {
        let mut header = [0u8; 4];
        recv_exact(fd, &mut header)?;
        let body_len = u32::from_be_bytes(header) as usize;
        if body_len > shit_proto::MAX_HELPER_FRAME_SIZE - 4 {
            return Err(HelperLinkError::Decode(shit_proto::DecodeError::TooLarge(
                body_len + 4,
            )));
        }
        let mut out = Vec::with_capacity(4 + body_len);
        out.extend_from_slice(&header);
        out.resize(4 + body_len, 0);
        recv_exact(fd, &mut out[4..])?;
        Ok(out)
    }
}

fn recv_frame_blocking_owned(fd: &OwnedFd) -> Result<Vec<u8>, HelperLinkError> {
    recv_frame_blocking(fd.as_raw_fd())
}

#[cfg(target_os = "macos")]
fn recv_exact(fd: std::os::fd::RawFd, buf: &mut [u8]) -> Result<(), HelperLinkError> {
    let mut got = 0;
    while got < buf.len() {
        let n = nix::sys::socket::recv(fd, &mut buf[got..], nix::sys::socket::MsgFlags::empty())?;
        if n == 0 {
            return Err(HelperLinkError::HelperExited);
        }
        got += n;
    }
    Ok(())
}

/// Pump helper responses to handlers (S24.A). Loops on
/// [`HelperLink::recv_response_with_fd`] inside `spawn_blocking`,
/// dispatches each response by variant. For `CapturedPreImage` the
/// handler verifies the helper's claimed blake3, ingests the bytes
/// into the canonical [`BlobStore`], and journals
/// `CaptureEvent::FilePreImage` (plus a paired `TreeOp::Unlink` when
/// `is_delete`).
///
/// Exits cleanly when the helper closes the connection
/// (`HelperLinkError::HelperExited`) or when `shutdown` is notified.
/// Per-event errors are logged but do NOT terminate the loop — the
/// project's hard-fail policy fires upstream at the helper, not at
/// the journal-ingest side.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_loop(
    link: Arc<HelperLink>,
    index: Arc<Index>,
    blob_store: Arc<BlobStore>,
    live_baseline: Arc<crate::baseline::LiveBaseline>,
    shutdown: Arc<tokio::sync::Notify>,
    watch_ready: Arc<crate::watch_ready::WatchReadyMap>,
    stats: Arc<crate::stats::Stats>,
    active: Arc<crate::active_commands::ActiveCommands>,
) -> Result<(), HelperLinkError> {
    tracing::info!("helper dispatch loop started");
    loop {
        let recv_task = {
            let link = Arc::clone(&link);
            tokio::task::spawn_blocking(move || link.recv_response_with_fd())
        };
        tokio::select! {
            r = recv_task => {
                match r {
                    Ok(Ok((resp, fd))) => {
                        dispatch_response(
                            resp,
                            fd,
                            &index,
                            &blob_store,
                            &watch_ready,
                            &live_baseline,
                            &link.kernel_tier,
                            &link.priv_op_waiters,
                            &link.unwatch_waiters,
                            &link.ingest_failures,
                        );
                    }
                    Ok(Err(HelperLinkError::HelperExited)) => {
                        tracing::warn!("helper exited; dispatch loop terminating");
                        // B03.A: flip the liveness signal so
                        // `shit doctor` and `shit metrics`
                        // surface the degraded state instead
                        // of trusting the sticky `kernel_tier`.
                        stats.note_helper_disconnected();
                        refuse_active_commands_after_helper_loss(
                            &active,
                            &index,
                            &watch_ready,
                            &link.ingest_failures,
                            "privileged capture helper exited while the command was running",
                        );
                        fail_pending_unwatch(
                            &link.unwatch_waiters,
                            "privileged capture helper exited during command close",
                        );
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "dispatch recv failed; loop terminating");
                        stats.note_helper_disconnected();
                        refuse_active_commands_after_helper_loss(
                            &active,
                            &index,
                            &watch_ready,
                            &link.ingest_failures,
                            &format!("privileged capture helper receive failed: {e}"),
                        );
                        fail_pending_unwatch(
                            &link.unwatch_waiters,
                            &format!("privileged capture helper receive failed: {e}"),
                        );
                        return Err(e);
                    }
                    Err(join_err) => {
                        tracing::error!(?join_err, "dispatch recv task panicked");
                        stats.note_helper_disconnected();
                        refuse_active_commands_after_helper_loss(
                            &active,
                            &index,
                            &watch_ready,
                            &link.ingest_failures,
                            &format!("privileged capture helper receive task failed: {join_err}"),
                        );
                        fail_pending_unwatch(
                            &link.unwatch_waiters,
                            &format!(
                                "privileged capture helper receive task failed: {join_err}"
                            ),
                        );
                        return Err(HelperLinkError::HelperExited);
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("helper dispatch loop received shutdown signal");
                fail_pending_unwatch(
                    &link.unwatch_waiters,
                    "daemon shutdown interrupted the capture completion barrier",
                );
                return Ok(());
            }
        }
    }
}

fn fail_pending_unwatch(waiters: &UnwatchWaiters, detail: &str) {
    let pending = {
        let mut waiters = waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        waiters
            .drain()
            .map(|(_, sender)| sender)
            .collect::<Vec<_>>()
    };
    for sender in pending {
        let _ = sender.send(Err(detail.to_string()));
    }
}

fn refuse_active_commands_after_helper_loss(
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
    watch_ready: &crate::watch_ready::WatchReadyMap,
    ingest_failures: &IngestFailures,
    detail: &str,
) {
    for command in active.snapshot() {
        watch_ready.mark_failed(command, detail.to_string());
        let path = <Index as shit_planner::PlannerStore>::command_by_id(index, command)
            .map(|record| record.cwd);
        let _ = persist_refusal_or_mark_ingest_failure(
            index,
            ingest_failures,
            command,
            path,
            detail.to_string(),
            "helper-loss CaptureRefused",
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_response(
    resp: HelperResponse,
    fd: Option<OwnedFd>,
    index: &Index,
    blob_store: &BlobStore,
    watch_ready: &crate::watch_ready::WatchReadyMap,
    live_baseline: &crate::baseline::LiveBaseline,
    kernel_tier: &str,
    priv_op_waiters: &PrivOpWaiters,
    unwatch_waiters: &UnwatchWaiters,
    ingest_failures: &IngestFailures,
) {
    match resp {
        HelperResponse::CapturedPreImage {
            session,
            seq,
            dev,
            inode,
            path,
            blob_hash,
            stored_bytes,
            post_content_hash,
            mode,
            uid,
            gid,
            mtime_unix_nanos,
            xattrs,
            is_delete,
            fd_sent_via_scm,
            flags,
        } => {
            let Some(staging) = fd else {
                let detail = format!(
                    "CapturedPreImage for ({dev}, {inode}) declared {stored_bytes} bytes but carried no SCM_RIGHTS fd"
                );
                let _ = persist_refusal_or_mark_ingest_failure(
                    index,
                    ingest_failures,
                    CommandId { session, seq },
                    path.map(PathBuf::from),
                    detail,
                    "missing-fd CapturedPreImage refusal",
                );
                return;
            };
            if !fd_sent_via_scm {
                let _ = persist_refusal_or_mark_ingest_failure(
                    index,
                    ingest_failures,
                    CommandId { session, seq },
                    path.map(PathBuf::from),
                    "CapturedPreImage carried an fd but declared fd_sent_via_scm=false".into(),
                    "invalid fd declaration refusal",
                );
                drop(staging);
                return;
            }
            let replay_path = match path.as_deref() {
                Some(raw) => match strict_absolute_replay_path(raw, "CapturedPreImage path") {
                    Ok(path) => path,
                    Err(detail) => {
                        let _ = persist_refusal_or_mark_ingest_failure(
                            index,
                            ingest_failures,
                            CommandId { session, seq },
                            Some(PathBuf::from(raw)),
                            detail,
                            "unsafe CapturedPreImage path refusal",
                        );
                        drop(staging);
                        return;
                    }
                },
                None => {
                    let _ = persist_refusal_or_mark_ingest_failure(
                        index,
                        ingest_failures,
                        CommandId { session, seq },
                        None,
                        "CapturedPreImage did not carry a replay path".into(),
                        "missing CapturedPreImage path refusal",
                    );
                    drop(staging);
                    return;
                }
            };
            // W02.B.live-baseline — if the LiveBaseline cache has a
            // clean (un-promoted) entry for this (dev, inode), the
            // baseline blob IS the genuine pre-image. The helper's
            // staging fd here carries POST-write content (NOTE_WRITE
            // fires after the write completes on BSD kqueue). We
            // take a separate code path that journals FilePreImage
            // with the baseline blob and discards the helper's
            // staging — the baseline IS the truth.
            //
            // Tradeoff: this path loses `post_content_hash` conflict
            // detection (which the standard path uses to refuse
            // restoring over the user's post-undo edits). Acceptable
            // for v1; baseline-promoted events are the correctness
            // path for in-place writes that the standard path
            // couldn't capture at all.
            let inode_ref = shit_planner::InodeRef::new(dev, inode);
            let cmd = shit_planner::events::CommandId { session, seq };
            if kernel_tier == "kqueue" {
                let baseline_cache = live_baseline
                    .get_cwd_for_inode(dev, inode)
                    .filter(|cache| cache.state() == crate::baseline::WalkState::Ready)
                    .or_else(|| live_baseline.get_cwd_for_path(&replay_path));

                if let Some(cache) = baseline_cache {
                    match cache.promote(inode_ref, cmd) {
                        Some(crate::baseline::BaselinePromotion::Promoted(pre_image)) => {
                            tracing::info!(
                                %session, seq, dev, inode,
                                xattr_count = pre_image.xattrs.len(),
                                "promoted complete pre-command baseline into FilePreImage"
                            );
                            if let Err(e) = handle_baseline_promoted_pre_image(
                                session,
                                seq,
                                dev,
                                inode,
                                path,
                                pre_image,
                                is_delete,
                                // The held fd is post-state for BSD
                                // Write/Extend, so only its hash is useful.
                                post_content_hash,
                                index,
                            ) {
                                tracing::error!(error = %e, %session, seq, "baseline-promoted FilePreImage journal failed");
                                let _ = persist_refusal_or_mark_ingest_failure(
                                    index,
                                    ingest_failures,
                                    CommandId { session, seq },
                                    Some(replay_path.clone()),
                                    format!("failed to ingest baseline-promoted pre-image: {e}"),
                                    "baseline-promoted pre-image ingest refusal",
                                );
                            }
                            drop(staging);
                            return;
                        }
                        Some(crate::baseline::BaselinePromotion::AlreadyPromoted) => {
                            // A repeated NOTE_WRITE for the same inode and
                            // command needs no second journal event.
                            drop(staging);
                            return;
                        }
                        None if !is_delete => {
                            // The cache is Ready, so an absent inode did not
                            // exist at command start. Its undo evidence is the
                            // directory Create observation, not post-write
                            // bytes mislabeled as a pre-image.
                            tracing::debug!(%session, seq, dev, inode, "discarding post-write bytes for inode absent from ready baseline");
                            drop(staging);
                            return;
                        }
                        None => {
                            // A held fd after unlink still contains genuine
                            // pre-delete bytes, so deletion may safely use the
                            // ordinary ingestion path below.
                        }
                    }
                } else if !is_delete {
                    let detail = "BSD kqueue write has no authoritative pre-command baseline; refusing post-write bytes as a pre-image";
                    refuse_baseline_command(
                        index,
                        watch_ready,
                        ingest_failures,
                        CommandId { session, seq },
                        Some(replay_path),
                        detail.into(),
                    );
                    drop(staging);
                    return;
                }
            }
            if let Err(e) = handle_captured_pre_image(
                CapturedPreImageArgs {
                    session,
                    seq,
                    dev,
                    inode,
                    path,
                    blob_hash,
                    stored_bytes,
                    post_content_hash,
                    mode,
                    uid,
                    gid,
                    mtime_unix_nanos,
                    xattrs,
                    flags,
                    is_delete,
                    staging,
                },
                index,
                blob_store,
                kernel_tier,
            ) {
                tracing::error!(error = %e, %session, seq, "failed to journal CapturedPreImage");
                let _ = persist_refusal_or_mark_ingest_failure(
                    index,
                    ingest_failures,
                    CommandId { session, seq },
                    Some(replay_path),
                    format!("failed to ingest captured pre-image: {e}"),
                    "captured pre-image ingest refusal",
                );
            }
        }
        HelperResponse::CapturedDeletionMarker {
            session,
            seq,
            dev,
            inode,
            path,
            metadata,
        } => {
            let command = CommandId { session, seq };
            let kind = kind_from_mode_bits(metadata.mode);
            let marker_path = PathBuf::from(&path);
            let detail = if fd.is_some() {
                "CapturedDeletionMarker unexpectedly carried an SCM_RIGHTS fd".to_string()
            } else if let Err(reason) = strict_absolute_replay_path(&path, "deletion marker path") {
                reason
            } else if kernel_tier == "bpf-lsm"
                && shit_planner::PlannerStore::events_for_command(index, command)
                    .iter()
                    .any(|event| {
                        matches!(
                            &event.kind,
                            CaptureEventKind::TreeOp(TreeOp::Create {
                                inode: created_inode,
                                path: created_path,
                                ..
                            }) if *created_inode == InodeRef::new(dev, inode)
                                && created_path == &marker_path
                        )
                    })
            {
                // The authoritative LSM create and this deletion marker name
                // the exact same inode at the exact same path.  The entry was
                // born and removed inside this command, so no pre-command
                // metadata exists to reconstruct.  Keep the Create event; the
                // planner's "created path is now gone" classifier makes it a
                // transient no-op.  Turning this marker into CaptureRefused
                // would make harmless pip-style scratch directories block the
                // command atomically.
                drop(fd);
                tracing::debug!(%session, seq, dev, inode, %path, "ignoring exact create-then-delete metadata marker");
                return;
            } else {
                format!(
                    "metadata-only deletion marker for {kind:?} cannot reconstruct complete metadata safely"
                )
            };
            drop(fd);
            let _ = persist_refusal_or_mark_ingest_failure(
                index,
                ingest_failures,
                command,
                Some(marker_path),
                detail,
                "deletion-marker refusal",
            );
        }
        HelperResponse::CaptureRefused {
            session,
            seq,
            path,
            detail,
        } => {
            drop(fd);
            let command = CommandId { session, seq };
            watch_ready.mark_failed(command, detail.clone());
            let _ = persist_refusal_or_mark_ingest_failure(
                index,
                ingest_failures,
                command,
                path.map(PathBuf::from),
                detail,
                "helper CaptureRefused",
            );
        }
        HelperResponse::BaselineCaptured {
            session,
            command_seq,
            cwd,
            dev,
            inode,
            path,
            blob_hash,
            stored_bytes,
            mode,
            uid,
            gid,
            mtime_unix_nanos,
            flags,
            xattrs: _,
            fd_sent_via_scm,
        } => {
            let command = CommandId {
                session,
                seq: command_seq,
            };
            let cwd_path = match strict_absolute_replay_path(&cwd, "BaselineCaptured cwd") {
                Ok(path) => path,
                Err(reason) => {
                    tracing::error!(%session, dev, inode, %reason, "rejecting unsafe BaselineCaptured cwd");
                    refuse_baseline_command(
                        index,
                        watch_ready,
                        ingest_failures,
                        command,
                        None,
                        format!("invalid baseline cwd: {reason}"),
                    );
                    drop(fd);
                    return;
                }
            };
            let cache = live_baseline.entry_for_cwd(&cwd_path);
            if let Err(other) = cache.begin_walk(command) {
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(cwd_path),
                    format!(
                        "baseline frames overlapped an active walk for command {}:{}",
                        other.session, other.seq
                    ),
                );
                drop(fd);
                return;
            }
            let Some(staging) = fd else {
                tracing::error!(%session, dev, inode, "BaselineCaptured missing SCM_RIGHTS fd");
                cache.mark_failed();
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(PathBuf::from(&path)),
                    "baseline content arrived without its staging fd".into(),
                );
                return;
            };
            if !fd_sent_via_scm {
                tracing::error!(%session, dev, inode, "BaselineCaptured carried fd with false fd_sent_via_scm");
                cache.mark_failed();
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(PathBuf::from(&path)),
                    "baseline staging-fd declaration was inconsistent".into(),
                );
                drop(staging);
                return;
            }
            let baseline_path = match strict_absolute_replay_path(&path, "BaselineCaptured path") {
                Ok(path) if path.starts_with(&cwd_path) => path,
                Ok(_) => {
                    tracing::error!(%session, dev, inode, %path, %cwd, "rejecting BaselineCaptured path outside its cwd");
                    cache.mark_failed();
                    refuse_baseline_command(
                        index,
                        watch_ready,
                        ingest_failures,
                        command,
                        Some(PathBuf::from(&path)),
                        "baseline path was outside its watched cwd".into(),
                    );
                    drop(staging);
                    return;
                }
                Err(reason) => {
                    tracing::error!(%session, dev, inode, %reason, "rejecting unsafe BaselineCaptured path");
                    cache.mark_failed();
                    refuse_baseline_command(
                        index,
                        watch_ready,
                        ingest_failures,
                        command,
                        Some(PathBuf::from(&path)),
                        format!("invalid baseline path: {reason}"),
                    );
                    drop(staging);
                    return;
                }
            };
            if let Err(e) = handle_baseline_captured(
                command,
                cwd_path,
                dev,
                inode,
                baseline_path,
                blob_hash,
                stored_bytes,
                mode,
                uid,
                gid,
                mtime_unix_nanos,
                flags,
                staging,
                blob_store,
                index,
                live_baseline,
            ) {
                tracing::error!(error = %e, %session, dev, inode, %path, "failed to ingest BaselineCaptured");
                cache.mark_failed();
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(PathBuf::from(path)),
                    format!("failed to ingest authoritative baseline: {e}"),
                );
            }
        }
        HelperResponse::BaselineWalkComplete {
            session,
            command_seq,
            cwd,
            file_count,
            partial,
        } => {
            let command = CommandId {
                session,
                seq: command_seq,
            };
            let cwd_path = match strict_absolute_replay_path(&cwd, "BaselineWalkComplete cwd") {
                Ok(path) => path,
                Err(reason) => {
                    tracing::error!(%session, %reason, "rejecting unsafe BaselineWalkComplete cwd");
                    refuse_baseline_command(
                        index,
                        watch_ready,
                        ingest_failures,
                        command,
                        None,
                        format!("invalid completed-baseline cwd: {reason}"),
                    );
                    return;
                }
            };
            // W09.12: empty-cwd case — the walk completed but no
            // entries arrived (cwd is empty pre-exec). Without an
            // entry in the LiveBaseline by-cwd map, the
            // shim_listener's `path_in_watched_subtree` check
            // returns false for paths under this cwd, so its
            // fresh-create branch fires alongside the kqueue
            // dir-diff and we get duplicate TreeOp::Create events.
            // Force-create the entry here so the cwd is registered
            // as watched even with zero baseline files.
            let cache = live_baseline.entry_for_cwd(&cwd_path);
            if let Err(other) = cache.begin_walk(command) {
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(cwd_path),
                    format!(
                        "baseline completion overlapped an active walk for command {}:{}",
                        other.session, other.seq
                    ),
                );
                return;
            }
            if partial {
                cache.mark_failed();
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(cwd_path),
                    "helper reported a partial pre-command baseline".into(),
                );
                tracing::warn!(
                    %session, cwd, file_count,
                    "partial live-baseline walk rejected; cache failed"
                );
            } else if cache.state() == crate::baseline::WalkState::Failed {
                refuse_baseline_command(
                    index,
                    watch_ready,
                    ingest_failures,
                    command,
                    Some(cwd_path),
                    "one or more authoritative baseline entries failed validation or ingest".into(),
                );
                tracing::warn!(
                    %session, cwd, file_count,
                    "live-baseline ingest failed before walk completion; cache remains failed"
                );
            } else {
                cache.mark_ready();
                tracing::info!(
                    %session, cwd, file_count, cached = cache.entry_count(),
                    "complete live-baseline walk accepted; cache ready"
                );
            }
        }
        HelperResponse::TreeMutation {
            session,
            seq,
            op,
            ts_unix_nanos,
            partial,
        } => {
            let fallback_path = Some(tree_mutation_path_hint(&op));
            if let Err(e) = handle_tree_mutation(session, seq, op, ts_unix_nanos, partial, index) {
                tracing::error!(error = %e, %session, seq, "failed to journal TreeMutation");
                let _ = persist_refusal_or_mark_ingest_failure(
                    index,
                    ingest_failures,
                    CommandId { session, seq },
                    fallback_path,
                    format!("failed to ingest TreeMutation: {e}"),
                    "TreeMutation ingest refusal",
                );
            }
        }
        HelperResponse::CapturedMetadataChange {
            session,
            seq,
            dev,
            inode,
            path,
            before,
            after,
            ts_unix_nanos,
        } => {
            let fallback_path = path.as_ref().map(PathBuf::from);
            if let Err(e) = handle_metadata_change(
                session,
                seq,
                dev,
                inode,
                path,
                before,
                after,
                ts_unix_nanos,
                index,
            ) {
                tracing::error!(
                    error = %e,
                    %session,
                    seq,
                    "failed to journal CapturedMetadataChange"
                );
                let _ = persist_refusal_or_mark_ingest_failure(
                    index,
                    ingest_failures,
                    CommandId { session, seq },
                    fallback_path,
                    format!("failed to ingest CapturedMetadataChange: {e}"),
                    "CapturedMetadataChange ingest refusal",
                );
            }
        }
        HelperResponse::WatchTreeReady {
            session,
            command_seq,
        } => {
            // AR00.5 / task #105 — release any shell hook waiting on
            // CtlRequest::WaitWatchReady for this command. Drains
            // pending oneshots and marks the entry Ready so late
            // waiters complete fast.
            let cmd = CommandId {
                session,
                seq: command_seq,
            };
            if watch_ready.mark_ready(cmd) {
                tracing::debug!(%session, command_seq, "WatchTreeReady routed");
            } else {
                tracing::warn!(
                    %session,
                    command_seq,
                    "ignoring WatchTreeReady after capture was already refused"
                );
            }
        }
        HelperResponse::UnwatchTreeFlushed {
            session,
            command_seq,
        } => {
            let command = CommandId {
                session,
                seq: command_seq,
            };
            let mut waiters = unwatch_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(sender) = waiters.remove(&(session, command_seq)) {
                let completion = ingest_failures.take(command).map_or(Ok(()), |detail| {
                    Err(format!(
                        "helper flush completed, but daemon capture ingest was not durable: {detail}"
                    ))
                });
                if sender.send(completion).is_err() {
                    tracing::warn!(
                        %session,
                        command_seq,
                        "unwatch waiter dropped before completion arrived"
                    );
                }
            } else {
                ingest_failures.take(command);
                tracing::warn!(
                    %session,
                    command_seq,
                    "UnwatchTreeFlushed arrived without a pending waiter"
                );
            }
        }
        HelperResponse::PrivilegedOpResult {
            session,
            command_seq,
            outcome,
        } => {
            // AU28 / DR-15 stage-1 — route to the waiter the
            // HelperLinkPrivilegedOpRouter registered before
            // sending the request. Drop on the floor if no waiter
            // (the request timed out and cleared its entry; the
            // helper's response is now late + irrelevant).
            let mut waiters = priv_op_waiters.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = waiters.remove(&(session, command_seq)) {
                if let Err(e) = tx.send(outcome.clone()) {
                    tracing::warn!(
                        %session,
                        command_seq,
                        err = %e,
                        "priv-op waiter receiver dropped before response arrived"
                    );
                }
            } else {
                tracing::warn!(
                    %session,
                    command_seq,
                    ?outcome,
                    "PrivilegedOpResult arrived but no waiter — likely a timeout race"
                );
            }
        }
        other => {
            tracing::trace!(
                ?other,
                "unhandled helper response (S24.A handles CapturedPreImage; S29.1 handles TreeMutation; AR00.5 handles WatchTreeReady)"
            );
        }
    }
}

/// Persist a command-atomic refusal whenever a capture tier cannot prove that
/// its evidence is complete.  This is shared by the helper response path and
/// the daemon's watch-readiness/dispatch failure paths: the shell hooks are
/// intentionally fail-open, so the journal entry (rather than withholding a
/// readiness notification) is the safety boundary for a later undo.
pub(crate) fn journal_helper_capture_refused(
    index: &Index,
    command: CommandId,
    path: Option<PathBuf>,
    detail: String,
) -> Result<(), shit_store::IndexError> {
    index
        .put_event(&CaptureEvent {
            id: EventId(0),
            command,
            ts: crate::server::next_ts(),
            partial: false,
            kind: CaptureEventKind::CaptureRefused {
                class: "capture-incomplete".to_string(),
                path: path.unwrap_or_else(|| PathBuf::from("<unrepresentable-helper-path>")),
                detail,
            },
        })
        .map(|_| ())
}

/// Persist the command-atomic fallback for an ingest or validation failure.
/// If the journal is unavailable even for the fallback, remember that fact in
/// memory so an ordered helper flush cannot be mistaken for durable ingest.
fn persist_refusal_or_mark_ingest_failure(
    index: &Index,
    ingest_failures: &IngestFailures,
    command: CommandId,
    path: Option<PathBuf>,
    detail: String,
    context: &str,
) -> Result<(), shit_store::IndexError> {
    match journal_helper_capture_refused(index, command, path, detail.clone()) {
        Ok(()) => Ok(()),
        Err(error) => {
            let sticky =
                format!("{context} was not durable: {error}; intended command refusal: {detail}");
            ingest_failures.mark(command, sticky);
            tracing::error!(%error, %command, %context, "CaptureRefused journal failed; command close will be rejected");
            Err(error)
        }
    }
}

/// Make a baseline failure sticky for readiness and durable for undo. Baseline
/// frames are ordered before WatchTreeReady on the helper connection; the
/// readiness map preserves this failure if that later frame still arrives.
fn refuse_baseline_command(
    index: &Index,
    watch_ready: &crate::watch_ready::WatchReadyMap,
    ingest_failures: &IngestFailures,
    command: CommandId,
    path: Option<PathBuf>,
    detail: String,
) {
    watch_ready.mark_failed(command, detail.clone());
    let _ = persist_refusal_or_mark_ingest_failure(
        index,
        ingest_failures,
        command,
        path,
        detail,
        "baseline CaptureRefused",
    );
}

/// Validate a path before it is allowed to become replay authority.
///
/// Helper messages are trusted for attribution, not for lexical path safety.
/// Requiring the exact normalized absolute spelling prevents a future undo
/// from reinterpreting `.`/`..`, repeated separators, trailing separators, or
/// an embedded NUL in a different process context.
fn strict_absolute_replay_path(raw: &str, field: &str) -> Result<PathBuf, String> {
    use std::path::Component;

    if raw.as_bytes().contains(&0) {
        return Err(format!("{field} contains an embedded NUL byte"));
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(format!("{field} is not absolute"));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => normalized.push(component.as_os_str()),
            Component::CurDir => return Err(format!("{field} contains `.`")),
            Component::ParentDir => return Err(format!("{field} contains `..`")),
            Component::Prefix(_) => return Err(format!("{field} contains a platform prefix")),
        }
    }
    if normalized.to_str() != Some(raw) {
        return Err(format!("{field} is not in normalized absolute form"));
    }
    Ok(normalized)
}

fn tree_mutation_path_hint(op: &shit_proto::TreeOpWire) -> PathBuf {
    use shit_proto::TreeOpWire;

    PathBuf::from(match op {
        TreeOpWire::Create { path, .. }
        | TreeOpWire::Unlink { path, .. }
        | TreeOpWire::Symlink { path, .. }
        | TreeOpWire::SymlinkRemoved { path, .. }
        | TreeOpWire::SymlinkRemovedIdentified { path, .. } => path,
        TreeOpWire::Rename { to, .. } => to,
        TreeOpWire::Link { target, .. } => target,
    })
}

/// S29.1 — convert a wire `TreeMutation` into a planner `CaptureEvent`
/// and journal it. Cheap; no blob round-trip needed.
fn handle_tree_mutation(
    session: uuid::Uuid,
    seq: u64,
    op: shit_proto::TreeOpWire,
    _ts_unix_nanos: u64,
    partial: bool,
    index: &Index,
) -> Result<(), HelperLinkError> {
    use shit_planner::TreeOp;
    use shit_planner::metadata::FileKind;
    use shit_proto::{FileKindWire, TreeOpWire};

    fn convert_kind(k: FileKindWire) -> FileKind {
        match k {
            FileKindWire::Regular => FileKind::Regular,
            FileKindWire::Directory => FileKind::Directory,
            FileKindWire::Symlink => FileKind::Symlink,
            FileKindWire::Fifo => FileKind::Fifo,
            FileKindWire::Socket => FileKind::Socket,
            FileKindWire::BlockDevice => FileKind::BlockDevice,
            FileKindWire::CharDevice => FileKind::CharDevice,
        }
    }

    let path_issue = match &op {
        TreeOpWire::Create { path, .. } => {
            strict_absolute_replay_path(path, "TreeMutation create path").err()
        }
        TreeOpWire::Unlink { path, .. } => {
            strict_absolute_replay_path(path, "TreeMutation unlink path").err()
        }
        TreeOpWire::Rename { from, to, .. } => {
            strict_absolute_replay_path(from, "TreeMutation rename source")
                .and_then(|_| strict_absolute_replay_path(to, "TreeMutation rename destination"))
                .err()
        }
        TreeOpWire::Link { target, .. } => {
            strict_absolute_replay_path(target, "TreeMutation link target").err()
        }
        TreeOpWire::Symlink { path, .. }
        | TreeOpWire::SymlinkRemoved { path, .. }
        | TreeOpWire::SymlinkRemovedIdentified { path, .. } => {
            strict_absolute_replay_path(path, "TreeMutation symlink path").err()
        }
    };
    if let Some(detail) = path_issue {
        let path = match &op {
            TreeOpWire::Create { path, .. }
            | TreeOpWire::Unlink { path, .. }
            | TreeOpWire::Symlink { path, .. }
            | TreeOpWire::SymlinkRemoved { path, .. }
            | TreeOpWire::SymlinkRemovedIdentified { path, .. } => PathBuf::from(path),
            TreeOpWire::Rename { to, .. } => PathBuf::from(to),
            TreeOpWire::Link { target, .. } => PathBuf::from(target),
        };
        journal_helper_capture_refused(index, CommandId { session, seq }, Some(path), detail)
            .map_err(|e| {
                HelperLinkError::Io(std::io::Error::other(format!(
                    "put_event (unsafe tree path refusal): {e}"
                )))
            })?;
        return Ok(());
    }

    let tree_op = match op {
        TreeOpWire::Create {
            dev,
            inode,
            path,
            kind,
            mode,
        } => TreeOp::Create {
            inode: InodeRef::new(dev, inode),
            path: std::path::PathBuf::from(path),
            kind: convert_kind(kind),
            mode,
        },
        TreeOpWire::Unlink {
            dev,
            inode,
            path,
            kind,
            mode,
        } => TreeOp::Unlink {
            inode: InodeRef::new(dev, inode),
            path: std::path::PathBuf::from(path),
            kind: convert_kind(kind),
            mode,
        },
        TreeOpWire::Rename {
            from,
            to,
            dev,
            inode,
        } => TreeOp::Rename {
            from: std::path::PathBuf::from(from),
            to: std::path::PathBuf::from(to),
            inode: InodeRef::new(dev, inode),
        },
        TreeOpWire::Link {
            source_dev,
            source_inode,
            target,
        } => TreeOp::Link {
            source: InodeRef::new(source_dev, source_inode),
            target: std::path::PathBuf::from(target),
        },
        TreeOpWire::Symlink { target, path } => TreeOp::Symlink {
            target,
            path: std::path::PathBuf::from(path),
        },
        TreeOpWire::SymlinkRemoved { target, path } => TreeOp::SymlinkRemoved {
            target,
            path: std::path::PathBuf::from(path),
        },
        TreeOpWire::SymlinkRemovedIdentified {
            dev,
            inode,
            target,
            path,
        } => TreeOp::SymlinkRemovedIdentified {
            inode: InodeRef::new(dev, inode),
            target,
            path: std::path::PathBuf::from(path),
        },
    };

    let ts = crate::server::next_ts();
    journal_tree_op(
        index,
        CommandId { session, seq },
        ts,
        tree_op,
        TreeSignalSource::HelperMutation,
        partial,
    )
    .map_err(|e| HelperLinkError::Io(std::io::Error::other(format!("put_event (tree): {e}"))))?;
    Ok(())
}

struct CapturedPreImageArgs {
    session: uuid::Uuid,
    seq: u64,
    dev: u64,
    inode: u64,
    path: Option<String>,
    blob_hash: [u8; 32],
    stored_bytes: u64,
    post_content_hash: Option<[u8; 32]>,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_unix_nanos: i128,
    xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    /// M03.x.SETATTR — BSD/macOS st_flags at capture time. 0 on
    /// Linux and on pre-M03.x.SETATTR captures.
    flags: u32,
    is_delete: bool,
    staging: OwnedFd,
}

/// S29.3 — convert a wire `CapturedMetadataChange` into a planner
/// `MetadataChange` capture event and journal it. Idempotence is not
/// needed here (no race-prone duplication path); a single NOTE_ATTRIB
/// produces a single emission on the helper side.
#[allow(clippy::too_many_arguments)]
fn handle_metadata_change(
    session: uuid::Uuid,
    seq: u64,
    dev: u64,
    inode: u64,
    path: Option<String>,
    before: shit_proto::FileMetadataWire,
    after: shit_proto::FileMetadataWire,
    _ts_unix_nanos: u64,
    index: &Index,
) -> Result<(), HelperLinkError> {
    use shit_planner::metadata::FileMetadata;
    fn convert(m: shit_proto::FileMetadataWire) -> FileMetadata {
        FileMetadata {
            mode: m.mode,
            uid: m.uid,
            gid: m.gid,
            size: m.size,
            mtime_unix_nanos: m.mtime_unix_nanos,
            xattrs: m.xattrs,
            acl: None,
            flags: m.flags,
        }
    }
    let command = CommandId { session, seq };
    let path_buf = match path.as_deref() {
        Some(raw) => match strict_absolute_replay_path(raw, "CapturedMetadataChange path") {
            Ok(path) => path,
            Err(detail) => {
                journal_helper_capture_refused(index, command, Some(PathBuf::from(raw)), detail)
                    .map_err(|e| {
                        HelperLinkError::Io(std::io::Error::other(format!(
                            "put_event (unsafe metadata path refusal): {e}"
                        )))
                    })?;
                return Ok(());
            }
        },
        None => {
            journal_helper_capture_refused(
                index,
                command,
                None,
                "CapturedMetadataChange did not carry a replay path".to_string(),
            )
            .map_err(|e| {
                HelperLinkError::Io(std::io::Error::other(format!(
                    "put_event (missing metadata path refusal): {e}"
                )))
            })?;
            return Ok(());
        }
    };
    let inode_ref = InodeRef::new(dev, inode);
    let ts = crate::server::next_ts();
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::MetadataChange {
            inode: inode_ref,
            path: path_buf,
            before: convert(before),
            after: convert(after),
        },
    };
    index.put_event(&event).map_err(|e| {
        HelperLinkError::Io(std::io::Error::other(format!("put_event (meta): {e}")))
    })?;
    Ok(())
}

fn handle_captured_pre_image(
    args: CapturedPreImageArgs,
    index: &Index,
    blob_store: &BlobStore,
    kernel_tier: &str,
) -> Result<(), HelperLinkError> {
    let raw_path = args.path.as_deref().ok_or_else(|| {
        HelperLinkError::Io(std::io::Error::other(
            "CapturedPreImage did not carry a replay path",
        ))
    })?;
    let path_buf = strict_absolute_replay_path(raw_path, "CapturedPreImage path")
        .map_err(|detail| HelperLinkError::Io(std::io::Error::other(detail)))?;
    let claimed = BlobHash(args.blob_hash);
    let mut staging_reader =
        PositionedStableFdReader::new(&args.staging, args.stored_bytes, MAX_CAPTURE_FD_BYTES)?;
    let publication = blob_store.shared_guard();
    let (canonical_hash, stat) = publication
        .put_verified_exact(
            &mut staging_reader,
            claimed,
            args.stored_bytes,
            MAX_CAPTURE_FD_BYTES,
        )
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!(
                "captured pre-image blob ingest: {e}"
            )))
        })?;
    staging_reader.finish()?;
    let ts = crate::server::next_ts();
    index
        .put_blob_record(canonical_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| HelperLinkError::Io(std::io::Error::other(format!("put_blob_record: {e}"))))?;

    let command = CommandId {
        session: args.session,
        seq: args.seq,
    };
    let inode_ref = InodeRef::new(args.dev, args.inode);
    let meta = FileMetadata {
        mode: args.mode,
        uid: args.uid,
        gid: args.gid,
        size: args.stored_bytes,
        mtime_unix_nanos: args.mtime_unix_nanos,
        xattrs: args.xattrs,
        acl: None,
        flags: args.flags,
    };
    // M03.x.OPEN-UNDO follow-up — tag the FilePreImage's source so
    // the planner can tell pre-mutation captures (macOS ES) from
    // post-mutation captures (BSD kqueue post-hoc, Linux LSM, shim).
    // The classifier's `spurious_creates_with_preimage` rule only
    // suppresses sibling Create-inverses when the source is
    // trusted-pre-mutation; otherwise legitimate `cp foo foo.bak`
    // patterns get their .bak left behind on undo.
    let source = if kernel_tier == "endpoint-security" {
        shit_planner::FilePreImageSource::EsAuthPreMutation
    } else {
        shit_planner::FilePreImageSource::Other
    };
    let pre_image = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode: inode_ref,
            path: path_buf.clone(),
            blob: canonical_hash,
            meta,
            post_content_hash: args.post_content_hash.map(BlobHash),
            source,
        },
    };
    index
        .put_event(&pre_image)
        .map_err(|e| HelperLinkError::Io(std::io::Error::other(format!("put_event: {e}"))))?;
    drop(publication);

    if args.is_delete {
        // G02: inherit kind+mode from the captured pre-image's
        // metadata. The mode bits carry the original perms; kind
        // is derived from S_IFMT.
        journal_tree_op(
            index,
            command,
            ts,
            TreeOp::Unlink {
                inode: inode_ref,
                path: path_buf,
                kind: kind_from_mode_bits(args.mode),
                mode: args.mode,
            },
            TreeSignalSource::HelperPreImage,
            false,
        )
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!("put_event (unlink): {e}")))
        })?;
    }
    Ok(())
}

/// G02 — derive `FileKind` from raw POSIX mode bits. The helper's
/// fstat-on-held-fd before unlink captures the full mode including
/// S_IFMT type bits; the planner needs a typed `FileKind` to emit
/// the right `RecreatePath` variant.
fn kind_from_mode_bits(mode: u32) -> shit_planner::metadata::FileKind {
    use shit_planner::metadata::FileKind;
    match mode & 0o170000 {
        0o040000 => FileKind::Directory,
        0o100000 => FileKind::Regular,
        0o120000 => FileKind::Symlink,
        // AU22 — Fifo + Socket map to their own kinds so
        // RecreatePath dispatches via PrivilegedOpRouter::mknod
        // through the helper (which holds CAP_MKNOD). Pre-AU22
        // these fell through to Regular and the planner emitted a
        // Regular-file inverse, which silently lost the kind.
        0o010000 => FileKind::Fifo,
        0o140000 => FileKind::Socket,
        // BlockDevice + CharDevice need CAP_SYS_ADMIN at the
        // helper (deferred to DR-15.2); recording the kind is
        // correct, the executor's recreate_path_inner returns the
        // DR-15.2 deferral message when it sees these.
        0o060000 => FileKind::BlockDevice,
        0o020000 => FileKind::CharDevice,
        // Unknown / no S_IF bits set — fall through to Regular as
        // the safest restore target. (mode=0 happens when the
        // helper lost the race to stat the unlinked inode.)
        _ => FileKind::Regular,
    }
}

/// Independent capture channels which can report the same namespace change.
///
/// `HelperPreImage` is deliberately distinct from `HelperMutation`: BSD can
/// surface one unlink through both its held-fd delete path and its directory
/// diff. Counting each channel separately lets us collapse those duplicates
/// without collapsing two real, identical operations observed twice by one
/// channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeSignalSource {
    HelperMutation,
    HelperPreImage,
    Shim,
}

impl TreeSignalSource {
    const fn slot(self) -> usize {
        match self {
            Self::HelperMutation => 0,
            Self::HelperPreImage => 1,
            Self::Shim => 2,
        }
    }
}

/// The exact semantic identity used to pair reports from independent tiers.
/// Metadata is part of an unlink's identity: if two tiers disagree about the
/// entry kind or mode, retaining both is safer than discarding the richer
/// reconstruction evidence. Target-less `Unlink(kind=Symlink)` likewise does
/// not match `SymlinkRemoved`, whose lexical target is load-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TreeMutationIdentity {
    Unlink {
        inode: InodeRef,
        path: PathBuf,
        kind: u8,
        mode: u32,
    },
    Rename {
        inode: InodeRef,
        from: PathBuf,
        to: PathBuf,
    },
    SymlinkRemoved {
        inode: InodeRef,
        target: String,
        path: PathBuf,
    },
}

impl TreeMutationIdentity {
    fn from_op(op: &TreeOp) -> Option<Self> {
        match op {
            TreeOp::Unlink {
                inode,
                path,
                kind,
                mode,
            } => Some(Self::Unlink {
                inode: *inode,
                path: path.clone(),
                kind: file_kind_tag(*kind),
                mode: *mode,
            }),
            TreeOp::Rename { from, to, inode } => Some(Self::Rename {
                inode: *inode,
                from: from.clone(),
                to: to.clone(),
            }),
            TreeOp::SymlinkRemovedIdentified {
                inode,
                target,
                path,
            } => Some(Self::SymlinkRemoved {
                inode: *inode,
                target: target.clone(),
                path: path.clone(),
            }),
            // The legacy target-bearing shape has no inode identity.  Never
            // infer that two path/target observations are the same removal.
            TreeOp::SymlinkRemoved { .. }
            | TreeOp::Create { .. }
            | TreeOp::Link { .. }
            | TreeOp::Symlink { .. } => None,
        }
    }

    /// Whether `op` proves that this exact namespace mutation can happen
    /// again.  Two identical unlinks/renames are physically impossible
    /// without an intervening transition that puts the same inode back at
    /// the source path.  That transition starts a new dedup generation.
    fn is_rearmed_by(&self, op: &TreeOp) -> bool {
        let inode_at = |candidate: InodeRef, candidate_path: &PathBuf| match op {
            TreeOp::Create { inode, path, .. } => inode == &candidate && path == candidate_path,
            TreeOp::Link { source, target } => source == &candidate && target == candidate_path,
            TreeOp::Rename { inode, to, .. } => inode == &candidate && to == candidate_path,
            TreeOp::Unlink { .. }
            | TreeOp::Symlink { .. }
            | TreeOp::SymlinkRemoved { .. }
            | TreeOp::SymlinkRemovedIdentified { .. } => false,
        };

        match self {
            Self::Unlink { inode, path, .. } | Self::SymlinkRemoved { inode, path, .. } => {
                inode_at(*inode, path)
            }
            Self::Rename { inode, from, .. } => inode_at(*inode, from),
        }
    }
}

const fn file_kind_tag(kind: shit_planner::metadata::FileKind) -> u8 {
    use shit_planner::metadata::FileKind;
    match kind {
        FileKind::Regular => 0,
        FileKind::Directory => 1,
        FileKind::Symlink => 2,
        FileKind::Fifo => 3,
        FileKind::Socket => 4,
        FileKind::BlockDevice => 5,
        FileKind::CharDevice => 6,
    }
}

#[derive(Debug)]
struct TreeObservationState {
    authoritative_sources: u8,
    partial_sources: u8,
    last_seen: Instant,
}

impl TreeObservationState {
    fn new(now: Instant) -> Self {
        Self {
            authoritative_sources: 0,
            partial_sources: 0,
            last_seen: now,
        }
    }
}

#[derive(Debug)]
struct TreeDedupLedger {
    entries: HashMap<(CommandId, TreeMutationIdentity), TreeObservationState>,
    last_prune: Instant,
}

impl TreeDedupLedger {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_prune: Instant::now(),
        }
    }

    fn prune(&mut self, now: Instant) {
        const ENTRY_TTL: Duration = Duration::from_secs(10);
        const PRUNE_INTERVAL: Duration = Duration::from_secs(1);
        const MAX_ENTRIES: usize = 8_192;

        if now.duration_since(self.last_prune) >= PRUNE_INTERVAL
            || self.entries.len() >= MAX_ENTRIES
        {
            self.entries
                .retain(|_, counts| now.duration_since(counts.last_seen) <= ENTRY_TTL);
            self.last_prune = now;
        }
        if self.entries.len() >= MAX_ENTRIES
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, counts)| counts.last_seen)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
    }

    fn rearm(&mut self, command: CommandId, op: &TreeOp) {
        self.entries.retain(|(entry_command, identity), _| {
            *entry_command != command || !identity.is_rearmed_by(op)
        });
    }
}

static TREE_DEDUP_LEDGER: OnceLock<Mutex<TreeDedupLedger>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeJournalOutcome {
    Journaled,
    Deduplicated,
}

/// Journal a namespace mutation while pairing equivalent observations from
/// independent capture channels.
///
/// For each exact `(command, operation identity, generation)`, at most one
/// authoritative event is journaled.  An exact unlink or rename cannot occur
/// twice until another namespace transition puts the same inode back at its
/// source path; observing that transition rearms the identity and begins a new
/// generation.  This avoids the unsafe old "maximum per-source count" rule,
/// which could pair two disjoint occurrences when different channels missed
/// opposite operations.  A partial event never establishes authoritative
/// coverage: if it arrives first it is retained as diagnostics and a later
/// authoritative event is also journaled; if an authoritative event already
/// exists for the generation, a partial duplicate is suppressed.
///
/// This ledger is intentionally bounded and process-local. Reports separated
/// by a daemon restart, by more than ten seconds, or by capacity eviction may
/// both be retained. That failure mode is a visible duplicate rather than the
/// unsafe alternative of suppressing a real mutation without provenance. The
/// current wires still carry no shared per-syscall operation id.  If a capture
/// tier loses the intervening same-inode rearm event, it has lost a
/// load-bearing namespace mutation and must report that loss separately; this
/// ledger never manufactures a cross-source ordinal match.
pub(crate) fn journal_tree_op(
    index: &Index,
    command: CommandId,
    ts: shit_planner::TimePoint,
    tree_op: TreeOp,
    source: TreeSignalSource,
    partial: bool,
) -> Result<TreeJournalOutcome, shit_store::IndexError> {
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial,
        kind: CaptureEventKind::TreeOp(tree_op.clone()),
    };

    let identity = TreeMutationIdentity::from_op(&tree_op);

    let now = Instant::now();
    let mut ledger = TREE_DEDUP_LEDGER
        .get_or_init(|| Mutex::new(TreeDedupLedger::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ledger.prune(now);

    // Rearm older identities before handling the current event.  An exact
    // duplicate cannot rearm itself: for Rename(A -> B), `to` differs from
    // the recorded source A; unlink/removal variants never enter this branch.
    ledger.rearm(command, &tree_op);

    let Some(identity) = identity else {
        drop(ledger);
        index.put_event(&event)?;
        return Ok(TreeJournalOutcome::Journaled);
    };

    let counts = ledger
        .entries
        .entry((command, identity))
        .or_insert_with(|| TreeObservationState::new(now));
    counts.last_seen = now;

    let source_bit = 1u8 << source.slot();
    let should_journal = if partial {
        if counts.authoritative_sources != 0 || counts.partial_sources != 0 {
            counts.partial_sources |= source_bit;
            false
        } else {
            index.put_event(&event)?;
            counts.partial_sources |= source_bit;
            true
        }
    } else {
        if counts.authoritative_sources != 0 {
            counts.authoritative_sources |= source_bit;
            false
        } else {
            index.put_event(&event)?;
            counts.authoritative_sources |= source_bit;
            true
        }
    };

    Ok(if should_journal {
        TreeJournalOutcome::Journaled
    } else {
        TreeJournalOutcome::Deduplicated
    })
}

#[cfg(test)]
mod tree_dedup_tests {
    use super::*;
    use shit_planner::events::CommandRecord;
    use shit_planner::metadata::FileKind;
    use shit_planner::{PlannerStore, TimePoint};
    use shit_proto::ShellKind;

    static NEXT_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    fn fixture(seq: u64) -> (tempfile::TempDir, Index, CommandId) {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path().join("index.sqlite")).unwrap();
        let discriminator = NEXT_SESSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
        let session =
            uuid::Uuid::from_u128(0xded0_0000_0000_4000_8000_0000_0000_0000 | discriminator);
        let command = CommandId { session, seq };
        index
            .put_session(session, "bash", 101, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("tree mutation".into()),
                cwd: "/tmp".into(),
                pid: 101,
                shell_kind: ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: Vec::new(),
            })
            .unwrap();
        (dir, index, command)
    }

    fn unlink() -> TreeOp {
        TreeOp::Unlink {
            inode: InodeRef::new(7, 11),
            path: "/tmp/removed".into(),
            kind: FileKind::Regular,
            mode: 0o100640,
        }
    }

    fn rename() -> TreeOp {
        TreeOp::Rename {
            inode: InodeRef::new(7, 12),
            from: "/tmp/from".into(),
            to: "/tmp/to".into(),
        }
    }

    fn symlink_removed() -> TreeOp {
        TreeOp::SymlinkRemovedIdentified {
            inode: InodeRef::new(7, 13),
            target: "../target".into(),
            path: "/tmp/link".into(),
        }
    }

    fn fsevents_placeholder_unlink() -> TreeOp {
        TreeOp::Unlink {
            inode: InodeRef::new(0, 0),
            path: "/tmp/link".into(),
            kind: FileKind::Regular,
            mode: 0o644,
        }
    }

    fn relink_removed_inode() -> TreeOp {
        TreeOp::Link {
            source: InodeRef::new(7, 11),
            target: "/tmp/removed".into(),
        }
    }

    fn assert_order(first: TreeSignalSource, second: TreeSignalSource) {
        let (_dir, index, command) = fixture(1);
        for (ordinal, op) in [unlink(), rename(), symlink_removed()]
            .into_iter()
            .enumerate()
        {
            let first_outcome = journal_tree_op(
                &index,
                command,
                TimePoint::new((ordinal * 2 + 1) as u64, 0),
                op.clone(),
                first,
                false,
            )
            .unwrap();
            let second_outcome = journal_tree_op(
                &index,
                command,
                TimePoint::new((ordinal * 2 + 2) as u64, 0),
                op,
                second,
                false,
            )
            .unwrap();
            assert_eq!(first_outcome, TreeJournalOutcome::Journaled);
            assert_eq!(second_outcome, TreeJournalOutcome::Deduplicated);
        }
        let events = index.events_for_command(command);
        assert_eq!(
            events.len(),
            3,
            "one event per semantic operation: {events:#?}"
        );
    }

    #[test]
    fn helper_then_shim_deduplicates_unlink_rename_and_symlink_removal() {
        assert_order(TreeSignalSource::HelperMutation, TreeSignalSource::Shim);
    }

    #[test]
    fn shim_then_helper_deduplicates_unlink_rename_and_symlink_removal() {
        assert_order(TreeSignalSource::Shim, TreeSignalSource::HelperMutation);
    }

    #[test]
    fn repeated_identical_operations_preserve_multiplicity() {
        let (_dir, index, command) = fixture(2);
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(1, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(2, 0),
                relink_removed_inode(),
                TreeSignalSource::HelperMutation,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(3, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );

        let events = index.events_for_command(command);
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    matches!(&event.kind, CaptureEventKind::TreeOp(TreeOp::Unlink { .. }))
                })
                .count(),
            2,
            "same identity was rearmed between real occurrences: {events:#?}"
        );
    }

    #[test]
    fn disjoint_cross_source_observations_do_not_collapse_across_rearm() {
        let (_dir, index, command) = fixture(5);
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(1, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
        journal_tree_op(
            &index,
            command,
            TimePoint::new(2, 0),
            relink_removed_inode(),
            TreeSignalSource::HelperMutation,
            false,
        )
        .unwrap();
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(3, 0),
                unlink(),
                TreeSignalSource::Shim,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
    }

    #[test]
    fn duplicate_from_same_source_without_rearm_is_suppressed() {
        let (_dir, index, command) = fixture(6);
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(1, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(2, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Deduplicated
        );
    }

    #[test]
    fn partial_first_does_not_suppress_authoritative_shim() {
        let (_dir, index, command) = fixture(3);
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(1, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                true,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(2, 0),
                unlink(),
                TreeSignalSource::Shim,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 2, "{events:#?}");
        assert_eq!(events.iter().filter(|event| !event.partial).count(), 1);
    }

    #[test]
    fn authoritative_shim_suppresses_later_partial_duplicate() {
        let (_dir, index, command) = fixture(4);
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(1, 0),
                unlink(),
                TreeSignalSource::Shim,
                false,
            )
            .unwrap(),
            TreeJournalOutcome::Journaled
        );
        assert_eq!(
            journal_tree_op(
                &index,
                command,
                TimePoint::new(2, 0),
                unlink(),
                TreeSignalSource::HelperMutation,
                true,
            )
            .unwrap(),
            TreeJournalOutcome::Deduplicated
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(!events[0].partial);
    }

    #[test]
    fn fsevents_placeholder_unlink_does_not_coalesce_with_rich_shim_symlink_removal() {
        for (seq, partial_first) in [(7, true), (8, false)] {
            let (_dir, index, command) = fixture(seq);
            let observations = if partial_first {
                [
                    (
                        fsevents_placeholder_unlink(),
                        TreeSignalSource::HelperMutation,
                        true,
                    ),
                    (symlink_removed(), TreeSignalSource::Shim, false),
                ]
            } else {
                [
                    (symlink_removed(), TreeSignalSource::Shim, false),
                    (
                        fsevents_placeholder_unlink(),
                        TreeSignalSource::HelperMutation,
                        true,
                    ),
                ]
            };

            for (ordinal, (op, source, partial)) in observations.into_iter().enumerate() {
                assert_eq!(
                    journal_tree_op(
                        &index,
                        command,
                        TimePoint::new(ordinal as u64 + 1, 0),
                        op,
                        source,
                        partial,
                    )
                    .unwrap(),
                    TreeJournalOutcome::Journaled
                );
            }

            let events = index.events_for_command(command);
            assert_eq!(events.len(), 2, "{events:#?}");
            assert_eq!(events.iter().filter(|event| event.partial).count(), 1);
            assert!(events.iter().any(|event| matches!(
                event.kind,
                CaptureEventKind::TreeOp(TreeOp::SymlinkRemovedIdentified { .. })
            )));
        }
    }
}

/// W02.B.live-baseline step 3 — ingest one BaselineCaptured message.
/// Reads the staging fd, verifies the blob hash, stores in the
/// canonical blob store, and inserts a `BaselineEntry` into the
/// per-cwd `LiveBaseline` cache. Does NOT journal anything — the
/// baseline is a content snapshot, not a command event. Promotion
/// to a real `FilePreImage` event happens later via
/// `CapturedPreImage`'s baseline-swap path.
#[allow(clippy::too_many_arguments)]
fn handle_baseline_captured(
    command: CommandId,
    cwd: std::path::PathBuf,
    dev: u64,
    inode: u64,
    path: std::path::PathBuf,
    blob_hash_claimed: [u8; 32],
    stored_bytes: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_unix_nanos: i128,
    flags: u32,
    staging: OwnedFd,
    blob_store: &BlobStore,
    index: &Index,
    live_baseline: &crate::baseline::LiveBaseline,
) -> Result<(), HelperLinkError> {
    let claimed = BlobHash(blob_hash_claimed);
    let mut staging_reader =
        PositionedStableFdReader::new(&staging, stored_bytes, MAX_CAPTURE_FD_BYTES)?;
    let publication = blob_store.shared_guard();
    let (canonical_hash, stat) = publication
        .put_verified_exact(
            &mut staging_reader,
            claimed,
            stored_bytes,
            MAX_CAPTURE_FD_BYTES,
        )
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!("baseline blob ingest: {e}")))
        })?;
    staging_reader.finish()?;
    // Register the blob in the index now, at capture time. When the
    // baseline cache later promotes this blob into a FilePreImage
    // event (via `handle_baseline_promoted_pre_image`), the planner's
    // `store.blob_size_hint(blob)` lookup must succeed — otherwise
    // plan.rs's "blob no longer in store" guard fires Conflict::Missing
    // even though the bytes are on disk, shadowing the post-hash drift
    // check (AU11 drift detection regression observed pre-fix).
    //
    // Idempotent via ON CONFLICT DO NOTHING; refcount stays 0 until a
    // FilePreImage event references it. A command-scoped lease protects that
    // zero-refcount interval. Promotion atomically bumps the refcount and
    // consumes this exact lease; successful command finish clears any
    // baseline leases that were never promoted.
    let ts = crate::server::next_ts();
    index
        .put_blob_record(canonical_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!(
                "baseline put_blob_record: {e}"
            )))
        })?;
    index
        .create_blob_lease(canonical_hash, command, ts)
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!(
                "baseline create_blob_lease: {e}"
            )))
        })?;
    drop(publication);
    let inode_ref = InodeRef::new(dev, inode);
    // W09.21 — read user-namespace xattrs here in the daemon (not
    // the helper) because the helper runs under cap_enter(2) where
    // extattr_*_fd is blocked unconditionally regardless of fd rights.
    // The daemon's read happens BEFORE the user's command runs (the
    // WatchTreeReady ack to PreExec waits for all BaselineCaptured to
    // flush), so we see the genuine pre-command state.
    let xattrs =
        crate::xattr::try_read_user_xattrs_at_path_for_inode(&path, dev, inode).map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!(
                "authoritative baseline xattr capture for {} failed: {e}",
                path.display()
            )))
        })?;
    let entry = crate::baseline::BaselineEntry::new(
        inode_ref,
        canonical_hash,
        stored_bytes,
        mode,
        uid,
        gid,
        mtime_unix_nanos,
        xattrs,
        flags,
    );
    let cache = live_baseline.entry_for_cwd(&cwd);
    cache.insert(path.clone(), entry);
    tracing::debug!(
        session = %command.session,
        seq = command.seq,
        dev,
        inode,
        path = %path.display(),
        cwd = %cwd.display(),
        bytes = stored_bytes,
        "baseline entry cached"
    );
    drop(staging);
    Ok(())
}

/// W02.B.live-baseline step 3b — journal a `FilePreImage` event
/// using a previously-cached baseline blob rather than the helper's
/// post-write content. Called from the CapturedPreImage handler
/// when the LiveBaseline cache had a clean entry for this inode.
#[allow(clippy::too_many_arguments)]
fn handle_baseline_promoted_pre_image(
    session: uuid::Uuid,
    seq: u64,
    dev: u64,
    inode: u64,
    path: Option<String>,
    baseline: crate::baseline::BaselinePreImage,
    is_delete: bool,
    post_content_hash: Option<[u8; 32]>,
    index: &Index,
) -> Result<(), HelperLinkError> {
    let command = CommandId { session, seq };
    let inode_ref = InodeRef::new(dev, inode);
    let meta = FileMetadata {
        mode: baseline.mode,
        uid: baseline.uid,
        gid: baseline.gid,
        size: baseline.size,
        mtime_unix_nanos: baseline.mtime_unix_nanos,
        // W09.21 — xattrs captured daemon-side at session-open (helper
        // can't because of cap_enter). Restore via planner's
        // restore_metadata_inner → restore_user_xattrs.
        xattrs: baseline.xattrs,
        acl: None,
        flags: baseline.flags,
    };
    let raw_path = path.as_deref().ok_or_else(|| {
        HelperLinkError::Io(std::io::Error::other(
            "baseline-promoted pre-image did not carry a replay path",
        ))
    })?;
    let path_buf = strict_absolute_replay_path(raw_path, "baseline-promoted pre-image path")
        .map_err(|detail| HelperLinkError::Io(std::io::Error::other(detail)))?;
    let ts = crate::server::next_ts();

    let pre_image = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode: inode_ref,
            path: path_buf.clone(),
            blob: baseline.blob,
            meta,
            // AU11 — the helper attached the held fd's
            // post-mutation content hash on BSD kqueue (post-hoc;
            // see capture/bsd.rs::handle_vnode). Plumbing it
            // through here restores drift detection on the
            // baseline-promoted path that pre-AU11 W02.B
            // explicitly traded off. Still None for Delete events
            // (no post-state) and None when the helper couldn't
            // hash for some reason.
            post_content_hash: post_content_hash.map(BlobHash),
            // G01.B.3 — load-bearing tag. The baseline cache is
            // populated at PreExec and promoted on first
            // modification, so by construction these bytes are
            // exactly the file's pre-command state. The planner
            // classifier uses this to override the line-256
            // transient safety-net for the Create+Unlink+PreImage
            // shape that BSD kqueue can emit (atomic-rename racing
            // dir-diff). See plan.rs::classify_replace_paths.
            source: shit_planner::FilePreImageSource::BaselineCachePromote,
        },
    };
    index
        .put_event(&pre_image)
        .map_err(|e| HelperLinkError::Io(std::io::Error::other(format!("put_event: {e}"))))?;

    if is_delete {
        journal_tree_op(
            index,
            command,
            ts,
            TreeOp::Unlink {
                inode: inode_ref,
                path: path_buf,
                kind: kind_from_mode_bits(baseline.mode),
                mode: baseline.mode,
            },
            TreeSignalSource::HelperPreImage,
            false,
        )
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!("put_event (unlink): {e}")))
        })?;
    }
    Ok(())
}

const MAX_CAPTURE_FD_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StagingFdIdentity {
    dev: u64,
    inode: u64,
    size: u64,
    file_type: libc::mode_t,
}

fn staging_fd_identity(fd: RawFd) -> std::io::Result<StagingFdIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is borrowed by the caller for this operation and `stat`
    // points at writable storage of the exact type required by fstat(2).
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let size = u64::try_from(stat.st_size).map_err(|_| {
        std::io::Error::other(format!(
            "captured SCM_RIGHTS fd reports a negative length ({})",
            stat.st_size
        ))
    })?;
    Ok(StagingFdIdentity {
        dev: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        size,
        file_type: stat.st_mode & libc::S_IFMT,
    })
}

/// Positioned, identity-checked view of an SCM_RIGHTS staging file.
///
/// `pread(2)` avoids trusting or mutating the sender's open-file-description
/// offset. Reaching EOF performs the post-read fstat before EOF is reported to
/// the blob store, so the store cannot publish bytes from an fd whose identity
/// or length changed during ingest.
struct PositionedStableFdReader<'a> {
    fd: &'a OwnedFd,
    before: StagingFdIdentity,
    expected_size: u64,
    offset: u64,
    post_read_verified: bool,
}

impl<'a> PositionedStableFdReader<'a> {
    fn new(fd: &'a OwnedFd, expected_size: u64, max_size: u64) -> std::io::Result<Self> {
        if expected_size > max_size {
            return Err(std::io::Error::other(format!(
                "captured fd declared {expected_size} bytes, above the {max_size}-byte ingest cap"
            )));
        }
        let before = staging_fd_identity(fd.as_raw_fd())?;
        if before.file_type != libc::S_IFREG {
            return Err(std::io::Error::other(
                "captured SCM_RIGHTS fd is not a regular staging file",
            ));
        }
        if before.size != expected_size {
            return Err(std::io::Error::other(format!(
                "captured fd length mismatch: wire declared {expected_size}, fd reports {}",
                before.size
            )));
        }
        Ok(Self {
            fd,
            before,
            expected_size,
            offset: 0,
            post_read_verified: false,
        })
    }

    fn verify_post_read_identity(&mut self) -> std::io::Result<()> {
        let after = staging_fd_identity(self.fd.as_raw_fd())?;
        if after.file_type != libc::S_IFREG || after != self.before {
            return Err(std::io::Error::other(
                "captured fd identity or length changed during ingest",
            ));
        }
        self.post_read_verified = true;
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<()> {
        if !self.post_read_verified {
            let mut probe = [0_u8; 1];
            if std::io::Read::read(&mut self, &mut probe)? != 0 {
                return Err(std::io::Error::other(format!(
                    "captured fd exceeded its declared {}-byte length",
                    self.expected_size
                )));
            }
        }
        if self.offset != self.expected_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "captured fd ended after {} bytes; wire declared {}",
                    self.offset, self.expected_size
                ),
            ));
        }
        Ok(())
    }
}

impl std::io::Read for PositionedStableFdReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.post_read_verified {
            return Ok(0);
        }
        let offset: libc::off_t = self.offset.try_into().map_err(|_| {
            std::io::Error::other("captured fd offset does not fit the platform's off_t")
        })?;
        loop {
            // SAFETY: `buffer` is valid writable memory for `buffer.len()`
            // bytes, `fd` remains owned for this call, and `offset` was
            // checked to fit off_t.
            let read = unsafe {
                libc::pread(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    offset,
                )
            };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if read == 0 {
                self.verify_post_read_identity()?;
                return Ok(0);
            }
            let read = read as usize;
            self.offset = self
                .offset
                .checked_add(read as u64)
                .ok_or_else(|| std::io::Error::other("captured fd offset overflow"))?;
            return Ok(read);
        }
    }
}

#[cfg(test)]
mod tests_kind_from_mode_bits {
    use super::*;
    use shit_planner::metadata::FileKind;

    #[test]
    fn directory_bits() {
        assert_eq!(kind_from_mode_bits(0o040755), FileKind::Directory);
    }
    #[test]
    fn regular_bits() {
        assert_eq!(kind_from_mode_bits(0o100644), FileKind::Regular);
    }
    #[test]
    fn symlink_bits() {
        assert_eq!(kind_from_mode_bits(0o120777), FileKind::Symlink);
    }
    #[test]
    fn fifo_bits_au22() {
        // AU22 — pre-AU22 this returned Regular; locks in the fix.
        assert_eq!(kind_from_mode_bits(0o010644), FileKind::Fifo);
    }
    #[test]
    fn socket_bits_au22() {
        assert_eq!(kind_from_mode_bits(0o140644), FileKind::Socket);
    }
    #[test]
    fn block_device_bits() {
        assert_eq!(kind_from_mode_bits(0o060644), FileKind::BlockDevice);
    }
    #[test]
    fn char_device_bits() {
        assert_eq!(kind_from_mode_bits(0o020644), FileKind::CharDevice);
    }
    #[test]
    fn unknown_falls_through_to_regular() {
        // mode=0 (helper lost race to stat the unlinked inode).
        assert_eq!(kind_from_mode_bits(0), FileKind::Regular);
    }
}

#[cfg(test)]
mod tests_dispatch {
    use super::*;
    use shit_planner::PlannerStore;
    use uuid::Uuid;

    fn test_helper_link() -> (Arc<HelperLink>, OwnedFd) {
        let (daemon, helper) = nix::sys::socket::socketpair(
            AddressFamily::Unix,
            HELPER_SOCK_TYPE,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        (
            Arc::new(HelperLink {
                conn_fd: daemon,
                send_lock: std::sync::Mutex::new(()),
                child: std::sync::Mutex::new(None),
                helper_pid: 0,
                helper_uid: 0,
                granted: HelperCaps::degraded(),
                kernel_tier: "test".into(),
                degraded_reason: None,
                priv_op_waiters: Default::default(),
                unwatch_waiters: Default::default(),
                ingest_failures: Arc::new(IngestFailures::default()),
            }),
            helper,
        )
    }

    fn tmp_staging_fd(content: &[u8]) -> OwnedFd {
        // Open a tempfile, write content, return the owned fd. The
        // file unlinks at tempdir drop — but the fd keeps it reachable.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staging");
        std::fs::write(&path, content).unwrap();
        let f = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        // Leak the tempdir to keep the file on disk for the fd's
        // lifetime. Test-only; OS reclaims on process exit.
        std::mem::forget(dir);
        f.into()
    }

    fn tmp_staging_rw_fd(content: &[u8]) -> OwnedFd {
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, content).unwrap();
        file.sync_all().unwrap();
        file.into()
    }

    fn register_test_command(index: &Index, session: Uuid, seq: u64, cwd: &str) -> CommandId {
        use shit_planner::{CommandRecord, TimePoint};

        index
            .put_session(
                session,
                "bash",
                1234,
                Some("/dev/null"),
                TimePoint::new(0, 0),
            )
            .unwrap();
        let command = CommandId { session, seq };
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("test mutation".into()),
                cwd: cwd.into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        command
    }

    #[tokio::test]
    async fn helper_loss_refuses_every_active_command_and_wakes_waiters() {
        let store_dir = tempfile::tempdir().unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0x1055);
        let first = register_test_command(&index, session, 1, "/tmp/first");
        let second = register_test_command(&index, session, 2, "/tmp/second");
        let inactive = register_test_command(&index, session, 3, "/tmp/inactive");
        let active = crate::active_commands::ActiveCommands::new();
        active.insert(1001, first);
        active.insert(1002, second);
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let first_wait = watch_ready.await_ready(first);
        let second_wait = watch_ready.await_ready(second);

        refuse_active_commands_after_helper_loss(
            &active,
            &index,
            &watch_ready,
            &IngestFailures::default(),
            "test helper disconnect",
        );

        assert_eq!(
            first_wait.await.unwrap().unwrap_err(),
            "test helper disconnect"
        );
        assert_eq!(
            second_wait.await.unwrap().unwrap_err(),
            "test helper disconnect"
        );
        for command in [first, second] {
            let events = index.events_for_command(command);
            assert!(matches!(
                &events[..],
                [CaptureEvent {
                    kind: CaptureEventKind::CaptureRefused { detail, .. },
                    ..
                }] if detail == "test helper disconnect"
            ));
        }
        assert!(index.events_for_command(inactive).is_empty());
    }

    #[tokio::test]
    async fn helper_loss_refusal_failure_is_sticky_for_the_command() {
        let store_dir = tempfile::tempdir().unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let command = CommandId {
            session: Uuid::from_u128(0x1056),
            seq: 1,
        };
        let active = crate::active_commands::ActiveCommands::new();
        active.insert(1001, command);
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let ready = watch_ready.await_ready(command);
        let ingest_failures = IngestFailures::default();

        // No command row: the helper-loss CaptureRefused cannot satisfy the
        // events foreign key and must poison later completion.
        refuse_active_commands_after_helper_loss(
            &active,
            &index,
            &watch_ready,
            &ingest_failures,
            "test helper disconnect",
        );

        assert_eq!(ready.await.unwrap().unwrap_err(), "test helper disconnect");
        assert!(ingest_failures.contains(command));
    }

    #[tokio::test]
    async fn unwatch_completion_routes_only_after_dispatch() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let unwatch_waiters: UnwatchWaiters = Default::default();
        let session = Uuid::from_u128(0xF105);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        unwatch_waiters
            .lock()
            .unwrap()
            .insert((session, 77), sender);

        dispatch_response(
            HelperResponse::UnwatchTreeFlushed {
                session,
                command_seq: 77,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &Default::default(),
        );

        assert_eq!(receiver.await.unwrap(), Ok(()));
        assert!(unwatch_waiters.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tree_ingest_and_refusal_failure_poison_exact_unwatch_completion() {
        use shit_proto::{FileKindWire, TreeOpWire};

        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let unwatch_waiters: UnwatchWaiters = Default::default();
        let ingest_failures = IngestFailures::default();
        let command = CommandId {
            session: Uuid::from_u128(0xF108),
            seq: 91,
        };

        // Intentionally do not register the command. Both the primary tree
        // event and its CaptureRefused fallback fail the events FK.
        dispatch_response(
            HelperResponse::TreeMutation {
                session: command.session,
                seq: command.seq,
                op: TreeOpWire::Create {
                    dev: 1,
                    inode: 2,
                    path: "/tmp/not-durable".into(),
                    kind: FileKindWire::Regular,
                    mode: 0o100644,
                },
                ts_unix_nanos: 1,
                partial: false,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &ingest_failures,
        );
        assert!(ingest_failures.contains(command));

        let (sender, receiver) = tokio::sync::oneshot::channel();
        unwatch_waiters
            .lock()
            .unwrap()
            .insert((command.session, command.seq), sender);
        dispatch_response(
            HelperResponse::UnwatchTreeFlushed {
                session: command.session,
                command_seq: command.seq,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &ingest_failures,
        );

        let detail = receiver.await.unwrap().unwrap_err();
        assert!(detail.contains("TreeMutation"), "{detail}");
        assert!(!ingest_failures.contains(command));
    }

    #[tokio::test]
    async fn metadata_journal_failure_uses_durable_refusal_without_poisoning_flush() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0xF109);
        let command = register_test_command(&index, session, 92, "/tmp");
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_metadata_ingest
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'MetadataChange'
                 BEGIN SELECT RAISE(FAIL, 'injected metadata journal failure'); END;",
            )
            .unwrap();
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let unwatch_waiters: UnwatchWaiters = Default::default();
        let ingest_failures = IngestFailures::default();
        let metadata = shit_proto::FileMetadataWire {
            mode: 0o100644,
            uid: 1,
            gid: 2,
            size: 3,
            mtime_unix_nanos: 4,
            xattrs: BTreeMap::new(),
            flags: 0,
        };

        dispatch_response(
            HelperResponse::CapturedMetadataChange {
                session,
                seq: command.seq,
                dev: 1,
                inode: 2,
                path: Some("/tmp/file".into()),
                before: metadata.clone(),
                after: metadata,
                ts_unix_nanos: 1,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &ingest_failures,
        );

        assert!(!ingest_failures.contains(command));
        assert!(matches!(
            &index.events_for_command(command)[..],
            [CaptureEvent {
                kind: CaptureEventKind::CaptureRefused { detail, .. },
                ..
            }] if detail.contains("CapturedMetadataChange")
        ));

        let (sender, receiver) = tokio::sync::oneshot::channel();
        unwatch_waiters
            .lock()
            .unwrap()
            .insert((session, command.seq), sender);
        dispatch_response(
            HelperResponse::UnwatchTreeFlushed {
                session,
                command_seq: command.seq,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &ingest_failures,
        );
        assert_eq!(receiver.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn undurable_helper_refusal_poison_exact_unwatch_completion() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let unwatch_waiters: UnwatchWaiters = Default::default();
        let ingest_failures = IngestFailures::default();
        let command = CommandId {
            session: Uuid::from_u128(0xF10A),
            seq: 93,
        };

        dispatch_response(
            HelperResponse::CaptureRefused {
                session: command.session,
                seq: command.seq,
                path: Some("/tmp/file".into()),
                detail: "helper detected loss".into(),
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &ingest_failures,
        );
        assert!(ingest_failures.contains(command));

        let (sender, receiver) = tokio::sync::oneshot::channel();
        unwatch_waiters
            .lock()
            .unwrap()
            .insert((command.session, command.seq), sender);
        dispatch_response(
            HelperResponse::UnwatchTreeFlushed {
                session: command.session,
                command_seq: command.seq,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "test",
            &Default::default(),
            &unwatch_waiters,
            &ingest_failures,
        );
        let detail = receiver.await.unwrap().unwrap_err();
        assert!(detail.contains("helper CaptureRefused"), "{detail}");
    }

    #[test]
    fn validation_refusal_failures_for_preimage_deletion_and_baseline_are_sticky() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let session = Uuid::from_u128(0xF10C);
        let metadata = shit_proto::FileMetadataWire {
            mode: 0o040700,
            uid: 1,
            gid: 2,
            size: 0,
            mtime_unix_nanos: 3,
            xattrs: BTreeMap::new(),
            flags: 0,
        };
        let responses = [
            HelperResponse::CapturedPreImage {
                session,
                seq: 1,
                dev: 1,
                inode: 2,
                path: Some("/tmp/preimage".into()),
                blob_hash: [0; 32],
                stored_bytes: 1,
                post_content_hash: None,
                mode: 0o100600,
                uid: 1,
                gid: 2,
                mtime_unix_nanos: 3,
                xattrs: BTreeMap::new(),
                is_delete: false,
                fd_sent_via_scm: false,
                flags: 0,
            },
            HelperResponse::CapturedDeletionMarker {
                session,
                seq: 2,
                dev: 1,
                inode: 3,
                path: "/tmp/deleted".into(),
                metadata,
            },
            HelperResponse::BaselineWalkComplete {
                session,
                command_seq: 3,
                cwd: "/tmp/baseline".into(),
                file_count: 1,
                partial: true,
            },
        ];

        for (offset, response) in responses.into_iter().enumerate() {
            let command = CommandId {
                session,
                seq: offset as u64 + 1,
            };
            let ingest_failures = IngestFailures::default();
            dispatch_response(
                response,
                None,
                &index,
                &blob_store,
                &watch_ready,
                &live_baseline,
                "test",
                &Default::default(),
                &Default::default(),
                &ingest_failures,
            );
            assert!(
                ingest_failures.contains(command),
                "validation failure for {command} was not sticky"
            );
        }
    }

    #[tokio::test]
    async fn helper_loss_wakes_every_unwatch_waiter() {
        let waiters: UnwatchWaiters = Default::default();
        let session = Uuid::from_u128(0xF106);
        let mut receivers = Vec::new();
        for seq in [1, 2] {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            waiters.lock().unwrap().insert((session, seq), sender);
            receivers.push(receiver);
        }

        fail_pending_unwatch(&waiters, "test helper loss");

        for receiver in receivers {
            assert_eq!(receiver.await.unwrap(), Err("test helper loss".into()));
        }
        assert!(waiters.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unwatch_timeout_removes_waiter_and_preserves_exact_request_identity() {
        let (link, helper_fd) = test_helper_link();
        let command = CommandId {
            session: Uuid::from_u128(0xF107),
            seq: 88,
        };

        let error = link
            .unwatch_tree_and_wait(command, Duration::from_millis(1))
            .await
            .unwrap_err();
        assert!(matches!(error, UnwatchTreeError::Timeout(_)));
        assert!(link.unwatch_waiters.lock().unwrap().is_empty());

        let frame = recv_frame_blocking_owned(&helper_fd).unwrap();
        let request: HelperRequest = decode_frame(&frame).unwrap();
        assert_eq!(
            request,
            HelperRequest::UnwatchTree {
                session: command.session,
                command_seq: command.seq,
            }
        );
    }

    #[test]
    fn watch_tree_initializes_ingest_state_without_clearing_duplicate_failure() {
        let (link, helper_fd) = test_helper_link();
        let command = CommandId {
            session: Uuid::from_u128(0xF10B),
            seq: 94,
        };
        let request = HelperRequest::WatchTree {
            root_pid: 123,
            descendants_too: true,
            session: command.session,
            command_seq: command.seq,
            shell_kind: shit_proto::ShellKind::Bash,
            cwd_path: "/tmp".into(),
        };
        link.send_request(&request).unwrap();
        assert!(link.ingest_failures.is_initialized(command));
        assert!(!link.ingest_failures.contains(command));

        link.ingest_failures
            .mark(command, "sticky ingest failure".into());
        link.send_request(&request).unwrap();

        assert!(link.ingest_failures.contains(command));
        for _ in 0..2 {
            let frame = recv_frame_blocking_owned(&helper_fd).unwrap();
            let decoded: HelperRequest = decode_frame(&frame).unwrap();
            assert_eq!(decoded, request);
        }
    }

    #[tokio::test]
    async fn partial_baseline_is_failed_refused_and_cannot_become_ready() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0xB501);
        let command = register_test_command(&index, session, 41, "/tmp/work");
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();

        dispatch_response(
            HelperResponse::BaselineWalkComplete {
                session,
                command_seq: command.seq,
                cwd: "/tmp/work".into(),
                file_count: 2,
                partial: true,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "kqueue",
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );
        dispatch_response(
            HelperResponse::WatchTreeReady {
                session,
                command_seq: command.seq,
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "kqueue",
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        assert_eq!(
            live_baseline
                .get_cwd(Path::new("/tmp/work"))
                .unwrap()
                .state(),
            crate::baseline::WalkState::Failed
        );
        assert!(watch_ready.await_ready(command).await.unwrap().is_err());
        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::CaptureRefused { .. }
        ));
    }

    #[tokio::test]
    async fn kqueue_baseline_miss_refuses_post_write_fd_instead_of_journaling_it() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0xB502);
        let command = register_test_command(&index, session, 42, "/tmp/work");
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let post_bytes = b"already modified";
        let (post_hash, _) = blob_store.put(post_bytes).unwrap();
        let claimed = *post_hash.as_bytes();

        dispatch_response(
            HelperResponse::CapturedPreImage {
                session,
                seq: command.seq,
                dev: 5,
                inode: 9,
                path: Some("/tmp/work/file".into()),
                blob_hash: claimed,
                stored_bytes: post_bytes.len() as u64,
                post_content_hash: Some(claimed),
                mode: 0o100600,
                uid: 9001,
                gid: 9002,
                mtime_unix_nanos: 99,
                xattrs: BTreeMap::new(),
                flags: 0,
                is_delete: false,
                fd_sent_via_scm: true,
            },
            Some(tmp_staging_fd(post_bytes)),
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "kqueue",
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        assert!(watch_ready.await_ready(command).await.unwrap().is_err());
        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::CaptureRefused { .. }
        ));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.kind, CaptureEventKind::FilePreImage { .. }))
        );
    }

    #[test]
    fn baseline_capture_lease_is_consumed_by_promotion_event() {
        use std::os::unix::fs::MetadataExt;

        let store_dir = tempfile::tempdir().unwrap();
        let cwd = store_dir.path().join("work");
        std::fs::create_dir(&cwd).unwrap();
        let path = cwd.join("file");
        let bytes = b"authoritative pre-command bytes";
        std::fs::write(&path, bytes).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();

        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0xB504);
        let command = register_test_command(&index, session, 44, cwd.to_str().unwrap());
        let live_baseline = crate::baseline::LiveBaseline::new();
        let cache = live_baseline.entry_for_cwd(&cwd);
        cache.begin_walk(command).unwrap();
        let blob = shit_planner::hash_file(&path).unwrap();

        handle_baseline_captured(
            command,
            cwd,
            metadata.dev(),
            metadata.ino(),
            path.clone(),
            *blob.as_bytes(),
            bytes.len() as u64,
            metadata.mode(),
            metadata.uid(),
            metadata.gid(),
            (metadata.mtime() as i128) * 1_000_000_000 + metadata.mtime_nsec() as i128,
            0,
            tmp_staging_fd(bytes),
            &blob_store,
            &index,
            &live_baseline,
        )
        .unwrap();

        assert!(index.has_blob_lease(blob, command).unwrap());
        let refcount_before: i64 = index
            .conn_for_test()
            .lock()
            .unwrap()
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                [blob.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount_before, 0);

        cache.mark_ready();
        let Some(crate::baseline::BaselinePromotion::Promoted(pre_image)) =
            cache.promote(InodeRef::new(metadata.dev(), metadata.ino()), command)
        else {
            panic!("ready baseline did not promote");
        };
        handle_baseline_promoted_pre_image(
            command.session,
            command.seq,
            metadata.dev(),
            metadata.ino(),
            Some(path.to_string_lossy().into_owned()),
            pre_image,
            false,
            None,
            &index,
        )
        .unwrap();

        assert!(!index.has_blob_lease(blob, command).unwrap());
        let refcount_after: i64 = index
            .conn_for_test()
            .lock()
            .unwrap()
            .query_row(
                "SELECT refcount FROM blobs WHERE hash = ?1",
                [blob.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount_after, 1);
        assert!(matches!(
            &index.events_for_command(command)[..],
            [CaptureEvent {
                kind: CaptureEventKind::FilePreImage { blob: event_blob, .. },
                ..
            }] if *event_blob == blob
        ));
    }

    #[test]
    fn baseline_promotion_uses_only_pre_command_metadata() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0xB503);
        let command = register_test_command(&index, session, 43, "/tmp/work");
        let (blob, stat) = blob_store.put(b"pre-command bytes").unwrap();
        index
            .put_blob_record(
                blob,
                stat.stored_bytes,
                stat.compressed,
                crate::server::next_ts(),
            )
            .unwrap();
        let mut xattrs = BTreeMap::new();
        xattrs.insert("user.test".into(), b"before".to_vec());
        let baseline = crate::baseline::BaselinePreImage {
            blob,
            size: 17,
            mode: 0o100640,
            uid: 1001,
            gid: 1002,
            mtime_unix_nanos: 1_700_000_000_123_456_789,
            xattrs: xattrs.clone(),
            flags: 0x2,
        };

        handle_baseline_promoted_pre_image(
            session,
            command.seq,
            5,
            9,
            Some("/tmp/work/file".into()),
            baseline,
            false,
            Some([0xCC; 32]),
            &index,
        )
        .unwrap();

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        let CaptureEventKind::FilePreImage {
            blob: actual_blob,
            meta,
            ..
        } = &events[0].kind
        else {
            panic!("expected baseline-promoted preimage: {events:#?}");
        };
        assert_eq!(*actual_blob, blob);
        assert_eq!(meta.mode, 0o100640);
        assert_eq!(meta.uid, 1001);
        assert_eq!(meta.gid, 1002);
        assert_eq!(meta.size, 17);
        assert_eq!(meta.mtime_unix_nanos, 1_700_000_000_123_456_789);
        assert_eq!(meta.xattrs, xattrs);
        assert_eq!(meta.flags, 0x2);
    }

    #[test]
    fn handle_captured_pre_image_journals_and_paired_unlink() {
        use shit_planner::{CommandRecord, TimePoint};
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();

        // Sessions + commands tables are FK targets for the events
        // table; set them up before journaling any event.
        let session = Uuid::nil();
        index
            .put_session(
                session,
                "bash",
                1234,
                Some("/dev/null"),
                TimePoint::new(0, 0),
            )
            .unwrap();
        index
            .put_command(&CommandRecord {
                command: CommandId { session, seq: 1 },
                cmd_string: Some("rm foo".into()),
                cwd: "/tmp".into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();

        let bytes = b"hello-pre-image-bytes";
        let fd = tmp_staging_fd(bytes);
        // Helper's claimed hash = whatever BlobStore would compute,
        // since BlobStore::put is content-addressed via the same
        // blake3 the helper uses. Pre-compute by ingesting once;
        // the handler's later ingest is idempotent on the hash.
        let (canonical, _) = blob_store.put(bytes).unwrap();
        let claimed: [u8; 32] = *canonical.as_bytes();

        let args = CapturedPreImageArgs {
            session,
            seq: 1,
            dev: 64,
            inode: 999,
            path: Some("/tmp/foo.txt".into()),
            blob_hash: claimed,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            mtime_unix_nanos: 0,
            xattrs: std::collections::BTreeMap::new(),
            flags: 0,
            is_delete: true,
            staging: fd,
        };
        handle_captured_pre_image(args, &index, &blob_store, "kqueue").expect("ingest");

        // Two events should be journaled: FilePreImage + paired
        // TreeOp::Unlink.
        let cmd = CommandId { session, seq: 1 };
        let events = index.events_for_command(cmd);
        assert_eq!(
            events.len(),
            2,
            "expected 2 events (FilePreImage + Unlink), got {events:#?}"
        );
        let has_pre_image = events
            .iter()
            .any(|e| matches!(e.kind, CaptureEventKind::FilePreImage { .. }));
        let has_unlink = events
            .iter()
            .any(|e| matches!(e.kind, CaptureEventKind::TreeOp(TreeOp::Unlink { .. })));
        assert!(has_pre_image, "missing FilePreImage event: {events:#?}");
        assert!(has_unlink, "missing paired Unlink event: {events:#?}");
    }

    /// A metadata-only directory marker cannot prove the complete state needed
    /// to reconstruct the entry, so it must journal a refusal rather than a
    /// lossy typed Unlink.
    #[test]
    fn marker_only_unlink_journals_refusal() {
        use shit_planner::{CommandRecord, TimePoint};
        let store_dir = tempfile::tempdir().unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();

        let session = Uuid::nil();
        index
            .put_session(
                session,
                "bash",
                1234,
                Some("/dev/null"),
                TimePoint::new(0, 0),
            )
            .unwrap();
        index
            .put_command(&CommandRecord {
                command: CommandId { session, seq: 1 },
                cmd_string: Some("rmdir cache".into()),
                cwd: "/tmp".into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();

        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let watch_ready = crate::watch_ready::WatchReadyMap::new();
        let live_baseline = crate::baseline::LiveBaseline::new();
        let waiters: PrivOpWaiters = Default::default();
        dispatch_response(
            HelperResponse::CapturedDeletionMarker {
                session,
                seq: 1,
                dev: 64,
                inode: 999,
                path: "/tmp/cache".into(),
                metadata: shit_proto::FileMetadataWire {
                    mode: 0o040700,
                    uid: 1000,
                    gid: 1000,
                    size: 0,
                    mtime_unix_nanos: 0,
                    xattrs: BTreeMap::new(),
                    flags: 0,
                },
            },
            None,
            &index,
            &blob_store,
            &watch_ready,
            &live_baseline,
            "bpf-lsm",
            &waiters,
            &Default::default(),
            &Default::default(),
        );

        let command = CommandId { session, seq: 1 };
        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "expected 1 refusal, got {events:#?}");
        assert!(
            matches!(events[0].kind, CaptureEventKind::CaptureRefused { .. }),
            "expected CaptureRefused, got {:#?}",
            events[0].kind
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.kind, CaptureEventKind::FilePreImage { .. })),
            "marker-only path must not journal FilePreImage: {events:#?}"
        );
        assert!(matches!(
            &events[0].kind,
            CaptureEventKind::CaptureRefused { path, detail, .. }
                if path == Path::new("/tmp/cache")
                    && detail.contains("cannot reconstruct complete metadata")
        ));
    }

    #[test]
    fn exact_lsm_create_then_deletion_marker_is_transient_not_refused() {
        use shit_planner::{CommandRecord, TimePoint};
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::from_u128(0xc0de);
        let command = CommandId { session, seq: 1 };
        index
            .put_session(
                session,
                "bash",
                1234,
                Some("/dev/null"),
                TimePoint::new(0, 0),
            )
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("mkdir cache && rmdir cache".into()),
                cwd: "/tmp".into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        let inode = InodeRef::new(64, 999);
        let path = PathBuf::from("/tmp/cache");
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command,
                ts: TimePoint::new(2, 0),
                partial: false,
                kind: CaptureEventKind::TreeOp(TreeOp::Create {
                    inode,
                    path: path.clone(),
                    kind: shit_planner::metadata::FileKind::Directory,
                    mode: 0o040700,
                }),
            })
            .unwrap();

        dispatch_response(
            HelperResponse::CapturedDeletionMarker {
                session,
                seq: command.seq,
                dev: inode.dev,
                inode: inode.inode,
                path: path.to_string_lossy().into_owned(),
                metadata: shit_proto::FileMetadataWire {
                    mode: 0o040700,
                    uid: 1000,
                    gid: 1000,
                    size: 0,
                    mtime_unix_nanos: 0,
                    xattrs: BTreeMap::new(),
                    flags: 0,
                },
            },
            None,
            &index,
            &blob_store,
            &crate::watch_ready::WatchReadyMap::new(),
            &crate::baseline::LiveBaseline::new(),
            "bpf-lsm",
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "marker should add no event: {events:#?}");
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::TreeOp(TreeOp::Create { inode: actual, .. }) if actual == inode
        ));
    }

    #[test]
    fn missing_regular_preimage_fd_journals_refusal_not_empty_recreate() {
        use shit_planner::{CommandRecord, TimePoint};
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::nil();
        let command = CommandId { session, seq: 9 };
        index
            .put_session(
                session,
                "bash",
                1234,
                Some("/dev/null"),
                TimePoint::new(0, 0),
            )
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("rm large.bin".into()),
                cwd: "/tmp".into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();

        dispatch_response(
            HelperResponse::CapturedPreImage {
                session,
                seq: command.seq,
                dev: 64,
                inode: 999,
                path: Some("/tmp/large.bin".into()),
                blob_hash: [0; 32],
                stored_bytes: 0,
                post_content_hash: None,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                mtime_unix_nanos: 0,
                xattrs: BTreeMap::new(),
                is_delete: true,
                fd_sent_via_scm: false,
                flags: 0,
            },
            None,
            &index,
            &blob_store,
            &crate::watch_ready::WatchReadyMap::new(),
            &crate::baseline::LiveBaseline::new(),
            "bpf-lsm",
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::CaptureRefused { .. }
        ));
        assert!(!events.iter().any(|event| matches!(
            event.kind,
            CaptureEventKind::TreeOp(TreeOp::Unlink { .. }) | CaptureEventKind::FilePreImage { .. }
        )));
    }

    #[test]
    fn degraded_tree_mutation_stays_partial_in_the_journal() {
        use shit_planner::{CommandRecord, TimePoint};
        use shit_proto::{FileKindWire, TreeOpWire};

        let store_dir = tempfile::tempdir().unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();
        let session = Uuid::nil();
        let command = CommandId { session, seq: 7 };
        index
            .put_session(
                session,
                "zsh",
                1234,
                Some("/dev/null"),
                TimePoint::new(0, 0),
            )
            .unwrap();
        index
            .put_command(&CommandRecord {
                command,
                cmd_string: Some("touch guessed-by-fsevents".into()),
                cwd: "/tmp".into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Zsh,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();

        handle_tree_mutation(
            session,
            command.seq,
            TreeOpWire::Create {
                dev: 1,
                inode: 2,
                path: "/tmp/guessed-by-fsevents".into(),
                kind: FileKindWire::Regular,
                mode: 0o100644,
            },
            0,
            true,
            &index,
        )
        .unwrap();

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "{events:#?}");
        assert!(events[0].partial, "degraded event became actionable");
        assert!(matches!(
            events[0].kind,
            CaptureEventKind::TreeOp(TreeOp::Create { .. })
        ));
    }

    #[test]
    fn handle_captured_pre_image_rejects_hash_mismatch() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let index = Index::open(store_dir.path().join("db.sqlite")).unwrap();

        let bytes = b"mismatch-payload";
        let fd = tmp_staging_fd(bytes);
        // Lie about the hash.
        let bogus_claim = [0xFF; 32];

        let args = CapturedPreImageArgs {
            session: Uuid::nil(),
            seq: 2,
            dev: 0,
            inode: 0,
            path: Some("/tmp/hash-mismatch".into()),
            blob_hash: bogus_claim,
            stored_bytes: bytes.len() as u64,
            post_content_hash: None,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            mtime_unix_nanos: 0,
            xattrs: std::collections::BTreeMap::new(),
            flags: 0,
            is_delete: false,
            staging: fd,
        };
        let err = handle_captured_pre_image(args, &index, &blob_store, "kqueue");
        assert!(err.is_err(), "expected hash-mismatch refusal");
        let actual = BlobHash(*blake3::hash(bytes).as_bytes());
        assert!(!blob_store.contains(&actual));
        assert!(!blob_store.contains(&BlobHash(bogus_claim)));
        assert_eq!(
            std::fs::read_dir(blob_store.root().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn positioned_staging_reader_preserves_sender_offset() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let payload = vec![b'P'; 3 * 64 * 1024 + 29];
        let hash = BlobHash(*blake3::hash(&payload).as_bytes());
        let fd = tmp_staging_rw_fd(&payload);
        // SAFETY: fd is live and 7 is within this regular staging file.
        assert_eq!(unsafe { libc::lseek(fd.as_raw_fd(), 7, libc::SEEK_SET) }, 7);

        let mut reader =
            PositionedStableFdReader::new(&fd, payload.len() as u64, MAX_CAPTURE_FD_BYTES).unwrap();
        let publication = blob_store.shared_guard();
        publication
            .put_verified_exact(
                &mut reader,
                hash,
                payload.len() as u64,
                MAX_CAPTURE_FD_BYTES,
            )
            .unwrap();
        reader.finish().unwrap();
        // SAFETY: querying a live fd's current offset has no side effects.
        assert_eq!(unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) }, 7);
        assert_eq!(publication.get(hash).unwrap(), payload);
    }

    #[test]
    fn positioned_staging_reader_rejects_initial_size_mismatch() {
        let payload = b"wire-size-mismatch";
        let fd = tmp_staging_rw_fd(payload);
        let error = match PositionedStableFdReader::new(
            &fd,
            payload.len() as u64 + 1,
            MAX_CAPTURE_FD_BYTES,
        ) {
            Ok(_) => panic!("mismatched staging length was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("length mismatch"), "{error}");
    }

    #[test]
    fn positioned_staging_reader_rejects_non_regular_fd() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd: OwnedFd = socket.into();
        let error = match PositionedStableFdReader::new(&fd, 0, MAX_CAPTURE_FD_BYTES) {
            Ok(_) => panic!("socket staging fd was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not a regular"), "{error}");
    }

    #[test]
    fn positioned_staging_reader_rejects_size_mutation_without_residue() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let payload = vec![b'M'; 128 * 1024 + 11];
        let hash = BlobHash(*blake3::hash(&payload).as_bytes());
        let fd = tmp_staging_rw_fd(&payload);
        let mut reader =
            PositionedStableFdReader::new(&fd, payload.len() as u64, MAX_CAPTURE_FD_BYTES).unwrap();
        // SAFETY: fd is a live writable regular tempfile.
        assert_eq!(unsafe { libc::ftruncate(fd.as_raw_fd(), 64 * 1024) }, 0);

        let publication = blob_store.shared_guard();
        assert!(
            publication
                .put_verified_exact(
                    &mut reader,
                    hash,
                    payload.len() as u64,
                    MAX_CAPTURE_FD_BYTES,
                )
                .is_err()
        );
        assert!(!publication.contains(&hash));
        assert_eq!(
            std::fs::read_dir(blob_store.root().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn positioned_staging_reader_rejects_identity_swap_without_residue() {
        let store_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(store_dir.path().join("blobs")).unwrap();
        let original_bytes = vec![b'A'; 96 * 1024 + 7];
        let replacement_bytes = vec![b'B'; original_bytes.len()];
        let original_hash = BlobHash(*blake3::hash(&original_bytes).as_bytes());
        let replacement_hash = BlobHash(*blake3::hash(&replacement_bytes).as_bytes());
        let fd = tmp_staging_rw_fd(&original_bytes);
        let replacement = tmp_staging_rw_fd(&replacement_bytes);
        let mut reader =
            PositionedStableFdReader::new(&fd, original_bytes.len() as u64, MAX_CAPTURE_FD_BYTES)
                .unwrap();
        // SAFETY: both descriptors are live. dup2 atomically replaces the
        // descriptor owned by `fd`; that OwnedFd remains its sole owner.
        assert_eq!(
            unsafe { libc::dup2(replacement.as_raw_fd(), fd.as_raw_fd()) },
            fd.as_raw_fd()
        );

        let publication = blob_store.shared_guard();
        assert!(
            publication
                .put_verified_exact(
                    &mut reader,
                    original_hash,
                    original_bytes.len() as u64,
                    MAX_CAPTURE_FD_BYTES,
                )
                .is_err()
        );
        assert!(!publication.contains(&original_hash));
        assert!(!publication.contains(&replacement_hash));
        assert_eq!(
            std::fs::read_dir(blob_store.root().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }
}
