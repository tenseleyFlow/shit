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
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr, bind,
    cmsg_space, listen, recvmsg, socket,
};
use shit_planner::events::{CaptureEvent, CaptureEventKind, CommandId, EventId, TreeOp};
use shit_planner::inode::{BlobHash, InodeRef};
use shit_planner::metadata::FileMetadata;
use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse, decode_frame, encode_frame,
};
use shit_store::{BlobStore, Index};
use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

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

/// Outcome of a successful helper link.
#[derive(Debug)]
pub struct HelperLink {
    /// Connected SEQPACKET/STREAM fd to the running helper.
    pub conn_fd: OwnedFd,
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
    /// (DR-66). E.g. `"fanotify"`, `"ebpf-lsm"`, `"endpoint-security"`,
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
    /// R3 close barrier: one waiter per command whose `UnwatchTree` was
    /// sent and whose `UnwatchTreeFlushed` has not arrived yet. The
    /// dispatch loop fires the waiter when the marker arrives and drops
    /// every waiter when the helper link goes away.
    pending_unwatch: UnwatchWaiters,
}

/// Close-barrier waiters. `closed` is set once the dispatch loop stops,
/// after which no marker can arrive.
#[derive(Debug, Default)]
struct UnwatchState {
    waiters: std::collections::HashMap<CommandId, tokio::sync::oneshot::Sender<()>>,
    closed: bool,
}

type UnwatchWaiters = std::sync::Mutex<UnwatchState>;

/// Why a command close could not prove the helper flushed its capture.
#[derive(Debug, thiserror::Error)]
pub enum UnwatchError {
    #[error("UnwatchTree could not be sent to the helper: {0}")]
    Send(String),
    #[error("helper link closed before UnwatchTreeFlushed arrived")]
    LinkClosed,
    #[error("UnwatchTreeFlushed did not arrive within {0:?}")]
    Timeout(std::time::Duration),
}

/// Receiver half of the close barrier for one command.
pub struct PendingUnwatch {
    rx: tokio::sync::oneshot::Receiver<()>,
}

impl PendingUnwatch {
    /// Wait for the helper's `UnwatchTreeFlushed` marker.
    pub async fn wait(self, timeout: std::time::Duration) -> Result<(), UnwatchError> {
        match tokio::time::timeout(timeout, self.rx).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(UnwatchError::LinkClosed),
            Err(_) => Err(UnwatchError::Timeout(timeout)),
        }
    }
}

impl HelperLink {
    /// Install the close-barrier waiter for `command`, then send
    /// `UnwatchTree`. The waiter goes in first so a fast helper's
    /// marker cannot arrive before anyone listens for it.
    pub fn begin_unwatch_tree(&self, command: CommandId) -> Result<PendingUnwatch, UnwatchError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut state = self
                .pending_unwatch
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state.closed {
                return Err(UnwatchError::LinkClosed);
            }
            state.waiters.insert(command, tx);
        }
        let req = HelperRequest::UnwatchTree {
            session: command.session,
            command_seq: command.seq,
        };
        if let Err(e) = self.send_request(&req) {
            self.pending_unwatch
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .waiters
                .remove(&command);
            return Err(UnwatchError::Send(e.to_string()));
        }
        Ok(PendingUnwatch { rx })
    }

    /// Wait for `command`'s marker. A timed-out waiter is removed so the
    /// map does not keep an entry for a command that already closed.
    pub async fn wait_unwatch(
        &self,
        command: CommandId,
        pending: PendingUnwatch,
        timeout: std::time::Duration,
    ) -> Result<(), UnwatchError> {
        let result = pending.wait(timeout).await;
        if matches!(result, Err(UnwatchError::Timeout(_))) {
            self.pending_unwatch
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .waiters
                .remove(&command);
        }
        result
    }

    /// A link with no helper process, over a socketpair. The peer end is
    /// returned so sends succeed for as long as the test holds it.
    #[cfg(test)]
    pub(crate) fn for_test() -> (Self, std::os::unix::net::UnixStream) {
        let (ours, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        (
            Self {
                conn_fd: ours.into(),
                child: std::sync::Mutex::new(None),
                helper_pid: 0,
                helper_uid: 0,
                granted: HelperCaps::default(),
                kernel_tier: String::new(),
                degraded_reason: None,
                priv_op_waiters: PrivOpWaiters::new(std::sync::Mutex::new(
                    std::collections::HashMap::new(),
                )),
                pending_unwatch: UnwatchWaiters::default(),
            },
            peer,
        )
    }

    fn complete_unwatch(&self, command: CommandId) {
        let waiter = self
            .pending_unwatch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .waiters
            .remove(&command);
        match waiter {
            Some(tx) => {
                let _ = tx.send(());
            }
            None => tracing::debug!(
                %command,
                "UnwatchTreeFlushed with no waiter (close already timed out)"
            ),
        }
    }

    /// Release every close-barrier waiter with an error. Called when the
    /// dispatch loop stops reading from the helper.
    fn fail_pending_unwatch(&self) {
        let mut state = self
            .pending_unwatch
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.waiters.clear();
    }

    /// Send a request to the helper. STREAM-safe (relies on the
    /// length-prefix framing in `shit_proto::frame`).
    pub fn send_request(&self, msg: &HelperRequest) -> Result<(), HelperLinkError> {
        let frame = encode_frame(msg)?;
        let mut sent = 0;
        while sent < frame.len() {
            let n = nix::sys::socket::send(
                self.conn_fd.as_raw_fd(),
                &frame[sent..],
                nix::sys::socket::MsgFlags::empty(),
            )?;
            if n == 0 {
                return Err(HelperLinkError::HelperExited);
            }
            sent += n;
        }
        Ok(())
    }

    /// Receive one response frame from the helper.
    pub fn recv_response(&self) -> Result<HelperResponse, HelperLinkError> {
        let buf = recv_frame_blocking(self.conn_fd.as_raw_fd())?;
        Ok(decode_frame(&buf)?)
    }

    /// Receive one response frame plus an optional fd attached via
    /// `SCM_RIGHTS` (S24.A). Mirrors `Conn::recv_response_with_fd` on
    /// the helper side. The cmsg always rides with the first chunk on
    /// STREAM transports; we issue one `recvmsg(2)` with a
    /// MAX_HELPER_FRAME_SIZE buffer and a cmsg space sized for one
    /// `RawFd`. On STREAM, if the kernel delivered fewer bytes than
    /// the frame's length-prefix demands, we complete the read via
    /// plain `recv(2)` (no cmsg expected for the tail).
    pub fn recv_response_with_fd(
        &self,
    ) -> Result<(HelperResponse, Option<OwnedFd>), HelperLinkError> {
        let (buf, fd) = recv_frame_with_fd_blocking(self.conn_fd.as_raw_fd())?;
        Ok((decode_frame(&buf)?, fd))
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

    // Accept blocks until the helper connects. Tests timeout via
    // their own deadlines.
    let conn_raw = nix::sys::socket::accept(listener.as_raw_fd())?;
    // SAFETY: accept returned a fresh fd we own.
    let conn_fd = unsafe { std::os::fd::FromRawFd::from_raw_fd(conn_raw) };
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
        child: std::sync::Mutex::new(Some(child)),
        helper_pid,
        helper_uid,
        granted,
        kernel_tier,
        degraded_reason,
        priv_op_waiters: PrivOpWaiters::new(
            std::sync::Mutex::new(std::collections::HashMap::new()),
        ),
        pending_unwatch: UnwatchWaiters::default(),
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
        let n = nix::sys::socket::send(
            fd.as_raw_fd(),
            &frame[sent..],
            nix::sys::socket::MsgFlags::empty(),
        )?;
        if n == 0 {
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
    strict_capture: bool,
) -> Result<(), HelperLinkError> {
    tracing::info!(strict_capture, "helper dispatch loop started");
    let result = dispatch_loop_inner(
        &link,
        index,
        blob_store,
        live_baseline,
        shutdown,
        watch_ready,
        stats,
        strict_capture,
    )
    .await;
    link.fail_pending_unwatch();
    result
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_loop_inner(
    link: &Arc<HelperLink>,
    index: Arc<Index>,
    blob_store: Arc<BlobStore>,
    live_baseline: Arc<crate::baseline::LiveBaseline>,
    shutdown: Arc<tokio::sync::Notify>,
    watch_ready: Arc<crate::watch_ready::WatchReadyMap>,
    stats: Arc<crate::stats::Stats>,
    strict_capture: bool,
) -> Result<(), HelperLinkError> {
    loop {
        let recv_task = {
            let link = Arc::clone(link);
            tokio::task::spawn_blocking(move || link.recv_response_with_fd())
        };
        tokio::select! {
            r = recv_task => {
                match r {
                    Ok(Ok((resp, fd))) => {
                        if let HelperResponse::UnwatchTreeFlushed { session, command_seq } = &resp {
                            link.complete_unwatch(CommandId {
                                session: *session,
                                seq: *command_seq,
                            });
                            continue;
                        }
                        dispatch_response(
                            resp,
                            fd,
                            &index,
                            &blob_store,
                            &watch_ready,
                            &live_baseline,
                            &link.kernel_tier,
                            &link.priv_op_waiters,
                            strict_capture,
                        );
                    }
                    Ok(Err(HelperLinkError::HelperExited)) => {
                        tracing::warn!("helper exited; dispatch loop terminating");
                        // B03.A: flip the liveness signal so
                        // `shit doctor` and `shit metrics`
                        // surface the degraded state instead
                        // of trusting the sticky `kernel_tier`.
                        stats.note_helper_disconnected();
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "dispatch recv failed; loop terminating");
                        stats.note_helper_disconnected();
                        return Err(e);
                    }
                    Err(join_err) => {
                        tracing::error!(?join_err, "dispatch recv task panicked");
                        stats.note_helper_disconnected();
                        return Err(HelperLinkError::HelperExited);
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("helper dispatch loop received shutdown signal");
                return Ok(());
            }
        }
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
    strict_capture: bool,
) {
    match resp {
        HelperResponse::SnapshotPreImage {
            session,
            seq,
            dev,
            inode,
            path,
            post_content_hash,
            xattrs,
            is_delete,
        } => {
            let command = CommandId { session, seq };
            let path_buf: PathBuf = shit_proto::wire_path::decode(&path);
            let ev = crate::zfs_snap::SnapshotPreImage {
                command,
                dev,
                inode,
                path: path_buf.clone(),
                post_content_hash,
                xattrs,
            };
            // The helper sends these only for regular files.
            let mut mode = 0o100644;
            match crate::zfs_snap::journal_pre_image(&ev, index, blob_store) {
                Ok(m) => mode = m,
                Err(why) => {
                    tracing::warn!(%session, seq, %why, "zfs snapshot pre-image unavailable");
                    // The helper read nothing itself: without the snapshot's
                    // bytes this change has no pre-image at all.
                    let detail = format!(
                        "the pre-image of {} could not be read from the command's zfs snapshot: {why}",
                        path_buf.display()
                    );
                    if let Err(e) = journal_refusal(
                        index,
                        command,
                        Some(path_buf.clone()),
                        "capture-incomplete",
                        detail,
                    ) {
                        tracing::error!(error = %e, %session, seq, "snapshot pre-image refusal journal failed");
                    }
                }
            }
            if is_delete {
                if let Err(e) = journal_unlink_idempotent(
                    index,
                    command,
                    crate::server::next_ts(),
                    InodeRef::new(dev, inode),
                    path_buf,
                    kind_from_mode_bits(mode),
                    mode,
                ) {
                    tracing::error!(error = %e, %session, seq, "snapshot delete Unlink journal failed");
                    note_ingest_failure(
                        strict_capture,
                        index,
                        command,
                        format!("a deletion could not be journaled: {e}"),
                    );
                }
            }
        }
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
            fd_sent_via_scm: _,
            flags,
            rdev,
            device_token,
            device_untrusted,
        } => {
            let Some(staging) = fd else {
                // AR01.1.fix-marker-only — when the helper lost the
                // race to read pre-image bytes (typical for atomic
                // unlinks like .git/index.lock), it emits a marker
                // CapturedPreImage with stored_bytes=0, is_delete=true,
                // and no SCM_RIGHTS fd. The intended semantics (per
                // capture/linux.rs::handle_lsm_unlink doc): journal the
                // TreeOp::Unlink only -- the planner falls back to any
                // prior FilePreImage for the same (dev, inode), and if
                // none exists treats the shape as a transient lock-file
                // (W01.B classifier).
                if stored_bytes == 0 && is_delete {
                    let command = CommandId { session, seq };
                    let inode_ref = InodeRef::new(dev, inode);
                    let path_buf: PathBuf =
                        shit_proto::wire_path::decode(path.as_deref().unwrap_or_default());
                    let ts = crate::server::next_ts();
                    // G02: derive kind from mode bits (S_IFMT). The
                    // marker-only path is the canonical route for
                    // dir-removal via LSM's inode_unlink because the
                    // helper's fstat returns FileType::Directory and
                    // the pre-image-bytes capture is skipped (dirs
                    // have no content). With kind+mode plumbed here,
                    // the planner emits RecreatePath{Directory} so
                    // `git clean -fd` undo restores the dir as a
                    // dir, not a regular file.
                    let kind = kind_from_mode_bits(mode);
                    let device =
                        device_capture(kind, rdev, mode, uid, gid, device_token, device_untrusted);
                    if let Err(e) = journal_unlink_with_device(
                        index, command, ts, inode_ref, path_buf, kind, mode, device,
                    ) {
                        tracing::error!(error = %e, %session, seq, "marker-only Unlink journal failed");
                        note_ingest_failure(
                            strict_capture,
                            index,
                            command,
                            format!("a deletion could not be journaled: {e}"),
                        );
                    }
                    return;
                }
                tracing::error!(%session, seq, dev, inode, "CapturedPreImage missing SCM_RIGHTS fd");
                note_ingest_failure(
                    strict_capture,
                    index,
                    CommandId { session, seq },
                    "a pre-image arrived without its staging fd".to_string(),
                );
                return;
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
            let baseline_promote = live_baseline
                .get_cwd_for_inode(dev, inode)
                .and_then(|cache| cache.promote(inode_ref, cmd));
            if let Some((blob, baseline_xattrs)) = baseline_promote {
                tracing::info!(
                    %session, seq, dev, inode,
                    xattr_count = baseline_xattrs.len(),
                    "promoted live-baseline blob into FilePreImage (pre-write content captured at session-open)"
                );
                if let Err(e) = handle_baseline_promoted_pre_image(
                    session,
                    seq,
                    dev,
                    inode,
                    path,
                    blob,
                    stored_bytes,
                    mode,
                    uid,
                    gid,
                    mtime_unix_nanos,
                    baseline_xattrs,
                    flags,
                    is_delete,
                    // AU11 — the helper's `post_content_hash` (which
                    // on BSD post-hoc kqueue is the held-fd's
                    // CURRENT content hash) is genuinely post-state.
                    // Carry it through so the planner's drift
                    // detection still fires for baseline-promoted
                    // captures (previously the W02.B path discarded
                    // it as a v1 tradeoff).
                    post_content_hash,
                    index,
                ) {
                    tracing::error!(error = %e, %session, seq, "baseline-promoted FilePreImage journal failed");
                    note_ingest_failure(
                        strict_capture,
                        index,
                        cmd,
                        format!("a baseline pre-image could not be journaled: {e}"),
                    );
                }
                drop(staging); // close helper's post-write fd; we don't need it
                return;
            }
            // R3 slice B — kqueue captures after the write, and the
            // baseline that held the pre-write bytes never made it into
            // the store. The journaled bytes below are post-write.
            if !is_delete && live_baseline.ingest_failed(session, dev, inode) {
                note_ingest_failure(
                    strict_capture,
                    index,
                    cmd,
                    format!(
                        "the baseline pre-image of {} could not be ingested before it was written",
                        path.as_deref().unwrap_or("a file")
                    ),
                );
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
                note_ingest_failure(
                    strict_capture,
                    index,
                    cmd,
                    format!("a pre-image could not be journaled: {e}"),
                );
            }
        }
        HelperResponse::BaselineCaptured {
            session,
            cwd,
            dev,
            inode,
            path,
            blob_hash,
            stored_bytes,
            mode: _,
            uid: _,
            gid: _,
            mtime_unix_nanos: _,
            xattrs: _,
            fd_sent_via_scm: _,
        } => {
            let Some(staging) = fd else {
                tracing::error!(%session, dev, inode, "BaselineCaptured missing SCM_RIGHTS fd");
                live_baseline.mark_ingest_failed(
                    session,
                    &shit_proto::wire_path::decode(&cwd),
                    dev,
                    inode,
                );
                return;
            };
            let ingested = handle_baseline_captured(
                session,
                shit_proto::wire_path::decode(&cwd),
                dev,
                inode,
                shit_proto::wire_path::decode(&path),
                blob_hash,
                stored_bytes,
                staging,
                blob_store,
                index,
                live_baseline,
            );
            match ingested {
                Ok(_) => live_baseline.clear_ingest_inode(
                    session,
                    &shit_proto::wire_path::decode(&cwd),
                    dev,
                    inode,
                ),
                Err(e) => {
                    tracing::error!(error = %e, %session, dev, inode, %path, "failed to ingest BaselineCaptured");
                    live_baseline.mark_ingest_failed(
                        session,
                        &shit_proto::wire_path::decode(&cwd),
                        dev,
                        inode,
                    );
                }
            }
        }
        HelperResponse::BaselineWalkComplete {
            session,
            cwd,
            file_count,
            partial,
        } => {
            let cwd_path = shit_proto::wire_path::decode(&cwd);
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
            cache.mark_ready();
            tracing::info!(
                %session, cwd, file_count, partial, cached = cache.entry_count(),
                "live-baseline walk complete; cache ready"
            );
        }
        HelperResponse::TreeMutation {
            session,
            seq,
            op,
            ts_unix_nanos,
        } => {
            if let Err(e) = handle_tree_mutation(session, seq, op, ts_unix_nanos, index) {
                tracing::error!(error = %e, %session, seq, "failed to journal TreeMutation");
                note_ingest_failure(
                    strict_capture,
                    index,
                    CommandId { session, seq },
                    format!("a tree change could not be journaled: {e}"),
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
                note_ingest_failure(
                    strict_capture,
                    index,
                    CommandId { session, seq },
                    format!("a metadata change could not be journaled: {e}"),
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
            watch_ready.mark_ready(cmd);
            // L5: from now on the shim may leave Creates to the kernel tier.
            live_baseline.confirm_command_watch(cmd, crate::server::next_ts());
            tracing::debug!(%session, command_seq, "WatchTreeReady routed");
        }
        HelperResponse::WatchTreeFailed {
            session,
            command_seq,
            reason,
        } => {
            let cmd = CommandId {
                session,
                seq: command_seq,
            };
            watch_ready.mark_failed(cmd, reason.clone());
            // L5: not watched, so the shim's Creates there are journaled.
            if live_baseline.forget_command_watch(cmd) {
                journal_lost_deferred_creates(index, cmd);
            }
            tracing::warn!(%session, command_seq, %reason, "helper reported watch attach failure");
            if strict_capture {
                journal_capture_refused_or_log(
                    index,
                    cmd,
                    None,
                    format!("capture attach failed: {reason}"),
                );
            }
        }
        HelperResponse::CaptureRefused {
            session,
            seq,
            path,
            detail,
        } => {
            // An observation, not a readiness verdict: it must never touch
            // the WatchReadyMap. Default mode logs it; strict mode journals
            // it so the planner refuses the command's undo.
            let cmd = CommandId { session, seq };
            // L5: a whole-command observation (no capture tier, or the
            // attach failed) means nothing watches it: the shim's Creates
            // there are journaled.
            if path.is_none() && live_baseline.forget_command_watch(cmd) {
                journal_lost_deferred_creates(index, cmd);
            }
            if strict_capture {
                tracing::warn!(%session, seq, ?path, %detail, "helper capture refusal (strict; journaling)");
                journal_capture_refused_or_log(
                    index,
                    cmd,
                    path.as_deref().map(shit_proto::wire_path::decode),
                    detail,
                );
            } else {
                tracing::info!(%session, seq, ?path, %detail, "helper capture observation (best-effort mode; not journaled)");
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

/// Journal a strict-mode `CaptureRefused` row for `command`. A missing
/// `path` (command-scoped refusal) uses the command's cwd so the user
/// sees a real directory in the refusal line.
pub(crate) fn journal_capture_refused(
    index: &Index,
    command: CommandId,
    path: Option<PathBuf>,
    detail: String,
) -> Result<(), shit_store::IndexError> {
    journal_refusal(index, command, path, "capture-incomplete", detail)
}

/// [`journal_capture_refused`] with an explicit refusal class. A missing
/// `path` (command-scoped refusal) uses the command's cwd.
pub(crate) fn journal_refusal(
    index: &Index,
    command: CommandId,
    path: Option<PathBuf>,
    class: &str,
    detail: String,
) -> Result<(), shit_store::IndexError> {
    let path = path
        .or_else(|| {
            <Index as shit_planner::PlannerStore>::command_by_id(index, command)
                .map(|record| record.cwd)
        })
        .unwrap_or_default();
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts: crate::server::next_ts(),
        partial: false,
        kind: CaptureEventKind::CaptureRefused {
            class: class.to_string(),
            path,
            detail,
        },
    };
    index.put_event(&event).map(|_| ())
}

/// L5 (review of #232 round 2, item 2): the shim left Creates to the
/// kernel tier for `command`, then the helper said it cannot watch it.
/// Those notes are gone and the kernel tier may not have the Creates
/// either, so the command gets a loud capture-gap refusal in every mode.
fn journal_lost_deferred_creates(index: &Index, command: CommandId) {
    if let Err(e) = journal_refusal(
        index,
        command,
        None,
        shit_planner::COMMAND_CAPTURE_GAP,
        "the shim left file creations to the kernel tier, which then stopped watching this \
         command; some files it created may not be removed by undo"
            .to_string(),
    ) {
        tracing::error!(error = %e, %command, "lost-deferred-creates refusal journal failed");
    }
}

/// R3 slice B — the daemon received a capture event and could not
/// journal it, so the command's capture is incomplete. Strict mode
/// journals a command-scoped refusal; default mode has already logged
/// the error.
fn note_ingest_failure(strict_capture: bool, index: &Index, command: CommandId, detail: String) {
    if strict_capture {
        journal_capture_refused_or_log(index, command, None, detail);
    }
}

pub(crate) fn journal_capture_refused_or_log(
    index: &Index,
    command: CommandId,
    path: Option<PathBuf>,
    detail: String,
) {
    if let Err(e) = journal_capture_refused(index, command, path, detail.clone()) {
        tracing::error!(error = %e, %command, %detail, "strict CaptureRefused journal failed");
    }
}

/// S29.1 — convert a wire `TreeMutation` into a planner `CaptureEvent`
/// and journal it. Cheap; no blob round-trip needed.
fn handle_tree_mutation(
    session: uuid::Uuid,
    seq: u64,
    op: shit_proto::TreeOpWire,
    _ts_unix_nanos: u64,
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

    // Unlink is dedupe-sensitive: the dir-diff and the per-file Delete
    // both surface Unlink for the same removal. Route through
    // `journal_unlink_idempotent` and return early.
    if let TreeOpWire::Unlink {
        dev,
        inode,
        path,
        kind,
        mode,
    } = &op
    {
        let ts = crate::server::next_ts();
        return journal_unlink_idempotent(
            index,
            CommandId { session, seq },
            ts,
            InodeRef::new(*dev, *inode),
            shit_proto::wire_path::decode(path),
            convert_kind(*kind),
            *mode,
        );
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
            path: shit_proto::wire_path::decode(&path),
            kind: convert_kind(kind),
            mode,
        },
        TreeOpWire::Unlink { .. } => unreachable!("handled above"),
        TreeOpWire::Rename {
            from,
            to,
            dev,
            inode,
        } => TreeOp::Rename {
            from: shit_proto::wire_path::decode(&from),
            to: shit_proto::wire_path::decode(&to),
            inode: InodeRef::new(dev, inode),
        },
        TreeOpWire::Link {
            source_dev,
            source_inode,
            target,
        } => TreeOp::Link {
            source: InodeRef::new(source_dev, source_inode),
            target: shit_proto::wire_path::decode(&target),
        },
        TreeOpWire::Symlink { target, path } => TreeOp::Symlink {
            target,
            path: shit_proto::wire_path::decode(&path),
        },
        TreeOpWire::SymlinkRemoved { target, path } => TreeOp::SymlinkRemoved {
            target,
            path: shit_proto::wire_path::decode(&path),
        },
    };

    let ts = crate::server::next_ts();
    let event = CaptureEvent {
        id: EventId(0),
        command: CommandId { session, seq },
        ts,
        partial: false,
        kind: CaptureEventKind::TreeOp(tree_op),
    };
    index.put_event(&event).map_err(|e| {
        HelperLinkError::Io(std::io::Error::other(format!("put_event (tree): {e}")))
    })?;
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
    let inode_ref = InodeRef::new(dev, inode);
    let path_buf: std::path::PathBuf =
        shit_proto::wire_path::decode(path.as_deref().unwrap_or_default());
    let ts = crate::server::next_ts();
    let event = CaptureEvent {
        id: EventId(0),
        command: CommandId { session, seq },
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
    let bytes = read_all_from_fd(&args.staging, args.stored_bytes as usize)?;
    let (canonical_hash, stat) = blob_store
        .put(&bytes)
        .map_err(|e| HelperLinkError::Io(std::io::Error::other(format!("blob put: {e}"))))?;
    let claimed = BlobHash(args.blob_hash);
    if canonical_hash != claimed {
        return Err(HelperLinkError::Io(std::io::Error::other(format!(
            "captured pre-image hash mismatch: helper claimed {claimed}, daemon computed {canonical_hash}"
        ))));
    }
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
    let path_buf: PathBuf = shit_proto::wire_path::decode(args.path.as_deref().unwrap_or_default());

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

    if args.is_delete {
        // G02: inherit kind+mode from the captured pre-image's
        // metadata. The mode bits carry the original perms; kind
        // is derived from S_IFMT.
        journal_unlink_idempotent(
            index,
            command,
            ts,
            inode_ref,
            path_buf,
            kind_from_mode_bits(args.mode),
            args.mode,
        )?;
    }
    Ok(())
}

/// Journal a `TreeOp::Unlink` exactly once per `(command, inode, path)`.
/// Both the CapturedPreImage(is_delete=true) handler AND the dir-diff
/// path on the helper side can produce an Unlink for the same target;
/// kqueue's per-event delivery order isn't deterministic enough to
/// dedupe on the helper. Dedupe here so the planner sees one Unlink
/// per logical mutation — otherwise plan() emits two RecreatePath
/// nodes and the second hits ConflictPhantom at undo time (the smoke
/// regression surfaced this).
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
        // BlockDevice + CharDevice restore through the helper's
        // mknod once the journal row also carries the captured rdev
        // (L4); a row without one is refused at undo.
        0o060000 => FileKind::BlockDevice,
        0o020000 => FileKind::CharDevice,
        // Unknown / no S_IF bits set — fall through to Regular as
        // the safest restore target. (mode=0 happens when the
        // helper lost the race to stat the unlinked inode.)
        _ => FileKind::Regular,
    }
}

#[allow(clippy::too_many_arguments)]
fn journal_unlink_idempotent(
    index: &Index,
    command: CommandId,
    ts: shit_planner::TimePoint,
    inode_ref: InodeRef,
    path: std::path::PathBuf,
    kind: shit_planner::metadata::FileKind,
    mode: u32,
) -> Result<(), HelperLinkError> {
    journal_unlink_with_device(index, command, ts, inode_ref, path, kind, mode, None)
}

/// L4b - what the daemon journals beside a device `Unlink`: a device
/// number with the helper's token, or with none when the source
/// filesystem was `nodev` (undo then refuses with that reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceCapture {
    rdev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    token: Option<shit_planner::CaptureToken>,
    untrusted: Option<shit_planner::UntrustedSource>,
}

/// L4 / L4b ruling 6 - a `DeviceNodeMeta` is journaled only for a node
/// the mode bits say is a device, with a nonzero rdev, and either the
/// helper's token or the helper's word that the source was `nodev`.
/// Anything less is no capture at all: the `Unlink` alone is journaled,
/// and undo gives the "no device number captured" refusal.
fn device_capture(
    kind: shit_planner::metadata::FileKind,
    rdev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    token: Option<shit_proto::CaptureToken>,
    untrusted: Option<shit_proto::UntrustedSource>,
) -> Option<DeviceCapture> {
    use shit_planner::metadata::FileKind;
    if !matches!(kind, FileKind::BlockDevice | FileKind::CharDevice) || rdev == 0 {
        return None;
    }
    if token.is_none() && untrusted.is_none() {
        return None;
    }
    Some(DeviceCapture {
        rdev,
        mode,
        uid,
        gid,
        token: token.map(|t| shit_planner::CaptureToken {
            helper: t.helper,
            mac: t.mac,
        }),
        untrusted: untrusted.map(|u| match u {
            shit_proto::UntrustedSource::Nodev => shit_planner::UntrustedSource::Nodev,
            shit_proto::UntrustedSource::Unknown => shit_planner::UntrustedSource::Unknown,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn journal_unlink_with_device(
    index: &Index,
    command: CommandId,
    ts: shit_planner::TimePoint,
    inode_ref: InodeRef,
    path: std::path::PathBuf,
    kind: shit_planner::metadata::FileKind,
    mode: u32,
    device: Option<DeviceCapture>,
) -> Result<(), HelperLinkError> {
    let events = index.events_for_command_at_path(command, &path);
    let already = if device.is_some() {
        // L4b - only the latest Unlink at this path counts, and only if
        // no DeviceNodeMeta follows it yet: after inode reuse an earlier
        // removal's Unlink is not this one.
        latest_unclaimed_unlink(&events, &path) == Some(inode_ref)
    } else {
        events.iter().any(|e| {
            matches!(
                &e.kind,
                CaptureEventKind::TreeOp(TreeOp::Unlink { inode, path: existing_path, .. })
                    if *inode == inode_ref && existing_path == &path
            )
        })
    };
    // L4b - the shim may already have journaled this removal with the
    // same identity (its pre-call lstat). The Unlink is then not repeated,
    // but the device capture is still journaled, after it, so the two
    // pair.
    if already && device.is_none() {
        return Ok(());
    }
    if !already {
        put_unlink(index, command, ts, inode_ref, path.clone(), kind, mode)?;
    }
    if let Some(d) = device {
        let meta_ev = CaptureEvent {
            id: EventId(0),
            command,
            ts,
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::DeviceNodeMeta {
                inode: inode_ref,
                path,
                rdev: d.rdev,
                mode: d.mode,
                uid: d.uid,
                gid: d.gid,
                token: d.token,
                untrusted: d.untrusted,
            }),
        };
        index.put_event(&meta_ev).map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!(
                "put_event (device meta): {e}"
            )))
        })?;
    }
    Ok(())
}

/// The inode of the latest `Unlink` at `path` in journal order, when no
/// `DeviceNodeMeta` for that path follows it.
fn latest_unclaimed_unlink(events: &[CaptureEvent], path: &std::path::Path) -> Option<InodeRef> {
    let mut ordered: Vec<&CaptureEvent> = events.iter().collect();
    ordered.sort_by_key(|e| (e.ts, e.id));
    let mut latest = None;
    for e in ordered {
        match &e.kind {
            CaptureEventKind::TreeOp(TreeOp::Unlink { inode, path: p, .. }) if p == path => {
                latest = Some(*inode);
            }
            CaptureEventKind::TreeOp(TreeOp::DeviceNodeMeta { path: p, .. }) if p == path => {
                latest = None;
            }
            _ => {}
        }
    }
    latest
}

fn put_unlink(
    index: &Index,
    command: CommandId,
    ts: shit_planner::TimePoint,
    inode_ref: InodeRef,
    path: std::path::PathBuf,
    kind: shit_planner::metadata::FileKind,
    mode: u32,
) -> Result<(), HelperLinkError> {
    let unlink_ev = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
            inode: inode_ref,
            path,
            kind,
            mode,
        }),
    };
    index.put_event(&unlink_ev).map_err(|e| {
        HelperLinkError::Io(std::io::Error::other(format!("put_event (unlink): {e}")))
    })?;
    Ok(())
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
    session: uuid::Uuid,
    cwd: std::path::PathBuf,
    dev: u64,
    inode: u64,
    path: std::path::PathBuf,
    blob_hash_claimed: [u8; 32],
    stored_bytes: u64,
    staging: OwnedFd,
    blob_store: &BlobStore,
    index: &Index,
    live_baseline: &crate::baseline::LiveBaseline,
) -> Result<(), HelperLinkError> {
    let bytes = read_all_from_fd(&staging, stored_bytes as usize)?;
    let (canonical_hash, stat) = blob_store
        .put(&bytes)
        .map_err(|e| HelperLinkError::Io(std::io::Error::other(format!("blob put: {e}"))))?;
    let claimed = BlobHash(blob_hash_claimed);
    if canonical_hash != claimed {
        return Err(HelperLinkError::Io(std::io::Error::other(format!(
            "baseline blob hash mismatch: helper claimed {claimed}, daemon computed {canonical_hash}"
        ))));
    }
    // Register the blob in the index now, at capture time. When the
    // baseline cache later promotes this blob into a FilePreImage
    // event (via `handle_baseline_promoted_pre_image`), the planner's
    // `store.blob_size_hint(blob)` lookup must succeed — otherwise
    // plan.rs's "blob no longer in store" guard fires Conflict::Missing
    // even though the bytes are on disk, shadowing the post-hash drift
    // check (AU11 drift detection regression observed pre-fix).
    //
    // Idempotent via ON CONFLICT DO NOTHING; refcount stays 0 until a
    // FilePreImage event references it, at which point put_event bumps
    // it. Unpromoted baseline blobs end up refcount=0 and get GC'd.
    let ts = crate::server::next_ts();
    index
        .put_blob_record(canonical_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| {
            HelperLinkError::Io(std::io::Error::other(format!(
                "baseline put_blob_record: {e}"
            )))
        })?;
    let inode_ref = InodeRef::new(dev, inode);
    // W09.21 — read user-namespace xattrs here in the daemon (not
    // the helper) because the helper runs under cap_enter(2) where
    // extattr_*_fd is blocked unconditionally regardless of fd rights.
    // The daemon's read happens BEFORE the user's command runs (the
    // WatchTreeReady ack to PreExec waits for all BaselineCaptured to
    // flush), so we see the genuine pre-command state.
    let xattrs = crate::xattr::read_user_xattrs_at_path(&path);
    let entry =
        crate::baseline::BaselineEntry::new(inode_ref, canonical_hash, stored_bytes, xattrs);
    let cache = live_baseline.entry_for_cwd(&cwd);
    cache.insert(path.clone(), entry);
    tracing::debug!(
        %session,
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
    blob: BlobHash,
    stored_bytes: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_unix_nanos: i128,
    xattrs: BTreeMap<String, Vec<u8>>,
    flags: u32,
    is_delete: bool,
    post_content_hash: Option<[u8; 32]>,
    index: &Index,
) -> Result<(), HelperLinkError> {
    let command = CommandId { session, seq };
    let inode_ref = InodeRef::new(dev, inode);
    let meta = FileMetadata {
        mode,
        uid,
        gid,
        size: stored_bytes,
        mtime_unix_nanos,
        // W09.21 — xattrs captured daemon-side at session-open (helper
        // can't because of cap_enter). Restore via planner's
        // restore_metadata_inner → restore_user_xattrs.
        xattrs,
        acl: None,
        flags,
    };
    let path_buf: PathBuf = shit_proto::wire_path::decode(path.as_deref().unwrap_or_default());
    let ts = crate::server::next_ts();

    let pre_image = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode: inode_ref,
            path: path_buf.clone(),
            blob,
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
        journal_unlink_idempotent(
            index,
            command,
            ts,
            inode_ref,
            path_buf,
            kind_from_mode_bits(mode),
            mode,
        )?;
    }
    Ok(())
}

fn read_all_from_fd(fd: &OwnedFd, expected_size: usize) -> Result<Vec<u8>, HelperLinkError> {
    let mut buf = vec![0u8; expected_size];
    let mut offset: usize = 0;
    while offset < expected_size {
        // SAFETY: buf is a valid writable slice; fd is owned for the
        // call duration.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buf[offset..].as_mut_ptr().cast(),
                expected_size - offset,
                offset as i64,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(HelperLinkError::Io(err));
        }
        if n == 0 {
            buf.truncate(offset);
            return Ok(buf);
        }
        offset += n as usize;
    }
    Ok(buf)
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

    /// L4b ruling 6: no meta row without a device kind, a nonzero rdev
    /// and the helper's token.
    #[test]
    fn device_capture_needs_kind_rdev_and_token() {
        let t = Some(shit_proto::CaptureToken {
            helper: [1; 16],
            mac: [2; 32],
        });
        let chr = FileKind::CharDevice;
        assert_eq!(device_capture(chr, 0, 0o020600, 1, 1, t, None), None);
        assert_eq!(device_capture(chr, 0x103, 0o020600, 1, 1, None, None), None);
        // Review round 2, item 1: a nodev source journals the meta with
        // no token, so undo can say why it refuses.
        let nodev = device_capture(
            chr,
            0x103,
            0o020600,
            1,
            1,
            None,
            Some(shit_proto::UntrustedSource::Nodev),
        )
        .unwrap();
        assert!(nodev.token.is_none());
        assert_eq!(nodev.untrusted, Some(shit_planner::UntrustedSource::Nodev));
        assert_eq!(
            device_capture(FileKind::Fifo, 0x103, 0o010600, 1, 1, t, None),
            None
        );
        let got = device_capture(FileKind::BlockDevice, 0x803, 0o060600, 1, 2, t, None).unwrap();
        assert_eq!(
            (got.rdev, got.mode, got.uid, got.gid),
            (0x803, 0o060600, 1, 2)
        );
        assert_eq!(got.token.unwrap().mac, [2; 32]);
    }
}

#[cfg(test)]
mod tests_dispatch {
    use super::*;
    use shit_planner::PlannerStore;
    use uuid::Uuid;

    #[tokio::test]
    async fn unwatch_timeout_removes_the_waiter() {
        let (link, _peer) = HelperLink::for_test();
        let command = CommandId {
            session: Uuid::from_u128(40),
            seq: 1,
        };
        let pending = link.begin_unwatch_tree(command).unwrap();
        assert_eq!(link.pending_unwatch.lock().unwrap().waiters.len(), 1);
        let result = link
            .wait_unwatch(command, pending, std::time::Duration::from_millis(5))
            .await;
        assert!(matches!(result, Err(UnwatchError::Timeout(_))));
        assert!(link.pending_unwatch.lock().unwrap().waiters.is_empty());
    }

    #[tokio::test]
    async fn close_after_the_link_stopped_fails_at_once() {
        let (link, _peer) = HelperLink::for_test();
        let waiting = CommandId {
            session: Uuid::from_u128(41),
            seq: 1,
        };
        let pending = link.begin_unwatch_tree(waiting).unwrap();
        link.fail_pending_unwatch();
        let started = std::time::Instant::now();
        assert!(matches!(
            link.wait_unwatch(waiting, pending, std::time::Duration::from_secs(5))
                .await,
            Err(UnwatchError::LinkClosed)
        ));
        let later = CommandId {
            session: Uuid::from_u128(41),
            seq: 2,
        };
        assert!(matches!(
            link.begin_unwatch_tree(later),
            Err(UnwatchError::LinkClosed)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// L4b: when the shim journaled the removal first with the same
    /// identity, the helper's capture adds the DeviceNodeMeta after it and
    /// no second Unlink.
    #[test]
    fn device_meta_follows_a_shim_unlink_of_the_same_node() {
        use shit_planner::PlannerStore;
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(5),
            seq: 1,
        };
        let index = index_with_command(dir.path(), cmd);
        let inode = InodeRef::new(0x803, 77);
        let path = PathBuf::from("/w/null");
        let kind = shit_planner::metadata::FileKind::CharDevice;
        put_unlink(
            &index,
            cmd,
            shit_planner::TimePoint::new(2, 0),
            inode,
            path.clone(),
            kind,
            0o020640,
        )
        .unwrap();
        let device = DeviceCapture {
            rdev: 0x103,
            mode: 0o020640,
            uid: 1,
            gid: 1,
            token: Some(shit_planner::CaptureToken {
                helper: [1; 16],
                mac: [2; 32],
            }),
            untrusted: None,
        };
        journal_unlink_with_device(
            &index,
            cmd,
            shit_planner::TimePoint::new(3, 0),
            inode,
            path,
            kind,
            0o020640,
            Some(device),
        )
        .unwrap();
        let events = index.events_for_command(cmd);
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| match &e.kind {
                CaptureEventKind::TreeOp(TreeOp::Unlink { .. }) => "unlink",
                CaptureEventKind::TreeOp(TreeOp::DeviceNodeMeta { .. }) => "meta",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["unlink", "meta"], "{events:#?}");
    }

    /// Review item 5: the node is removed, a new one gets the same inode
    /// number, and it is removed too. The second removal's Unlink must be
    /// journaled before its meta, not skipped because of the first.
    #[test]
    fn second_removal_after_inode_reuse_journals_its_own_unlink() {
        use shit_planner::PlannerStore;
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(6),
            seq: 1,
        };
        let index = index_with_command(dir.path(), cmd);
        let inode = InodeRef::new(0x803, 77);
        let path = PathBuf::from("/w/null");
        let kind = shit_planner::metadata::FileKind::CharDevice;
        let device = |rdev| DeviceCapture {
            rdev,
            mode: 0o020640,
            uid: 1,
            gid: 1,
            token: Some(shit_planner::CaptureToken {
                helper: [1; 16],
                mac: [2; 32],
            }),
            untrusted: None,
        };
        for (t, rdev) in [(2, 0x103), (3, 0x105)] {
            journal_unlink_with_device(
                &index,
                cmd,
                shit_planner::TimePoint::new(t, 0),
                inode,
                path.clone(),
                kind,
                0o020640,
                Some(device(rdev)),
            )
            .unwrap();
        }
        let kinds: Vec<&str> = index
            .events_for_command(cmd)
            .iter()
            .map(|e| match &e.kind {
                CaptureEventKind::TreeOp(TreeOp::Unlink { .. }) => "unlink",
                CaptureEventKind::TreeOp(TreeOp::DeviceNodeMeta { .. }) => "meta",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["unlink", "meta", "unlink", "meta"]);
    }

    fn index_with_command(dir: &Path, cmd: CommandId) -> Index {
        use shit_planner::{CommandRecord, TimePoint};
        let index = Index::open(dir.join("db.sqlite")).unwrap();
        index
            .put_session(cmd.session, "bash", 1, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command: cmd,
                cmd_string: Some("true".into()),
                cwd: "/tmp/watched".into(),
                pid: 2,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        index
    }

    fn dispatch(
        resp: HelperResponse,
        index: &Index,
        blob_store: &BlobStore,
        watch_ready: &crate::watch_ready::WatchReadyMap,
        strict: bool,
    ) {
        let waiters = PrivOpWaiters::default();
        dispatch_response(
            resp,
            None,
            index,
            blob_store,
            watch_ready,
            &crate::baseline::LiveBaseline::new(),
            "bpf-lsm",
            &waiters,
            strict,
        );
    }

    fn refusal_details(index: &Index, cmd: CommandId) -> Vec<(PathBuf, String)> {
        index
            .events_for_command(cmd)
            .into_iter()
            .filter_map(|ev| match ev.kind {
                CaptureEventKind::CaptureRefused { path, detail, .. } => Some((path, detail)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn capture_refused_is_journaled_only_in_strict_mode() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(1),
            seq: 1,
        };
        let index = index_with_command(dir.path(), cmd);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let map = crate::watch_ready::WatchReadyMap::new();
        let refused = || HelperResponse::CaptureRefused {
            session: cmd.session,
            seq: cmd.seq,
            path: None,
            detail: "no Linux capture tier is active".into(),
        };

        dispatch(refused(), &index, &blobs, &map, false);
        assert!(refusal_details(&index, cmd).is_empty());

        dispatch(refused(), &index, &blobs, &map, true);
        let rows = refusal_details(&index, cmd);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, PathBuf::from("/tmp/watched"));
        assert!(rows[0].1.contains("no Linux capture tier"));
    }

    /// L5 (review round 4, item 2): a command the helper cannot watch
    /// (attach failed, or no capture tier) is not watched, so the shim's
    /// Creates there are journaled; a per-path observation changes
    /// nothing.
    #[test]
    fn unwatchable_command_drops_its_watch_root() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(5),
            seq: 2,
        };
        let index = index_with_command(dir.path(), cmd);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let map = crate::watch_ready::WatchReadyMap::new();
        let waiters = PrivOpWaiters::default();
        let lb = crate::baseline::LiveBaseline::new();
        let f = std::path::Path::new("/tmp/watched/f");
        let send = |resp| {
            dispatch_response(
                resp, None, &index, &blobs, &map, &lb, "bpf-lsm", &waiters, false,
            )
        };
        lb.record_command_watch(cmd, PathBuf::from("/tmp/watched"));
        send(HelperResponse::CaptureRefused {
            session: cmd.session,
            seq: cmd.seq,
            path: Some("/tmp/watched/f".into()),
            detail: "one path".into(),
        });
        assert!(lb.command_watches(cmd, f, shit_planner::time::TimePoint::new(1, 0)));
        send(HelperResponse::WatchTreeFailed {
            session: cmd.session,
            command_seq: cmd.seq,
            reason: "attach failed".into(),
        });
        assert!(!lb.command_watches(cmd, f, shit_planner::time::TimePoint::new(1, 0)));
        lb.record_command_watch(cmd, PathBuf::from("/tmp/watched"));
        send(HelperResponse::CaptureRefused {
            session: cmd.session,
            seq: cmd.seq,
            path: None,
            detail: "no Linux capture tier is active".into(),
        });
        assert!(!lb.command_watches(cmd, f, shit_planner::time::TimePoint::new(1, 0)));
    }

    /// Review of #232 round 2, item 2: the shim left a Create to the
    /// kernel tier, then the helper failed the watch. In default mode the
    /// command still gets a loud capture-gap refusal.
    #[test]
    fn watch_failure_after_a_deferred_create_journals_a_capture_gap() {
        for failure in [
            HelperResponse::WatchTreeFailed {
                session: Uuid::from_u128(6),
                command_seq: 1,
                reason: "lost the mark".into(),
            },
            HelperResponse::CaptureRefused {
                session: Uuid::from_u128(6),
                seq: 1,
                path: None,
                detail: "no Linux capture tier is active".into(),
            },
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cmd = CommandId {
                session: Uuid::from_u128(6),
                seq: 1,
            };
            let index = index_with_command(dir.path(), cmd);
            let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
            let map = crate::watch_ready::WatchReadyMap::new();
            let waiters = PrivOpWaiters::default();
            let lb = crate::baseline::LiveBaseline::new();
            lb.record_command_watch(cmd, PathBuf::from("/tmp/watched"));
            dispatch_response(
                HelperResponse::WatchTreeReady {
                    session: cmd.session,
                    command_seq: cmd.seq,
                },
                None,
                &index,
                &blobs,
                &map,
                &lb,
                "bpf-lsm",
                &waiters,
                false,
            );
            assert!(lb.defer_create_to_kernel(
                cmd,
                std::path::Path::new("/tmp/watched/new"),
                crate::server::next_ts()
            ));
            dispatch_response(
                failure, None, &index, &blobs, &map, &lb, "bpf-lsm", &waiters, false,
            );
            let kinds: Vec<_> = index
                .events_for_command(cmd)
                .into_iter()
                .map(|e| e.kind)
                .collect();
            assert!(
                matches!(
                    kinds.as_slice(),
                    [CaptureEventKind::CaptureRefused { class, .. }] if class == shit_planner::COMMAND_CAPTURE_GAP
                ),
                "{kinds:#?}"
            );
        }
    }

    /// Review of #232 medium review, item 3: the helper's failure for N
    /// arrives after the session moved on to N+1. N's watch is still
    /// known, so the deferred Creates are reported, not lost silently.
    #[test]
    fn late_watch_failure_after_the_next_command_still_journals_the_gap() {
        let dir = tempfile::tempdir().unwrap();
        let n = CommandId {
            session: Uuid::from_u128(12),
            seq: 1,
        };
        let index = index_with_command(dir.path(), n);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let map = crate::watch_ready::WatchReadyMap::new();
        let waiters = PrivOpWaiters::default();
        let lb = crate::baseline::LiveBaseline::new();
        lb.record_command_watch(n, PathBuf::from("/tmp/watched"));
        lb.confirm_command_watch(n, shit_planner::time::TimePoint::new(1, 0));
        assert!(lb.defer_create_to_kernel(
            n,
            std::path::Path::new("/tmp/watched/new"),
            shit_planner::time::TimePoint::new(2, 0)
        ));
        lb.close_command_watch(n, shit_planner::time::TimePoint::new(3, 0));
        lb.record_command_watch(CommandId { seq: 2, ..n }, PathBuf::from("/tmp/watched"));
        dispatch_response(
            HelperResponse::WatchTreeFailed {
                session: n.session,
                command_seq: n.seq,
                reason: "late".into(),
            },
            None,
            &index,
            &blobs,
            &map,
            &lb,
            "bpf-lsm",
            &waiters,
            false,
        );
        assert!(
            index
                .events_for_command(n)
                .iter()
                .any(|e| matches!(&e.kind, CaptureEventKind::CaptureRefused { .. })),
            "deferred Creates must be reported"
        );
    }

    #[tokio::test]
    async fn capture_refused_does_not_change_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(2),
            seq: 4,
        };
        let index = index_with_command(dir.path(), cmd);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let map = crate::watch_ready::WatchReadyMap::new();
        map.mark_ready(cmd);
        dispatch(
            HelperResponse::CaptureRefused {
                session: cmd.session,
                seq: cmd.seq,
                path: Some("/tmp/watched/f".into()),
                detail: "observation".into(),
            },
            &index,
            &blobs,
            &map,
            true,
        );
        assert!(map.failure_reason(cmd).is_none());
        map.await_ready(cmd).await.expect("still ready");
    }

    #[test]
    fn watch_tree_failed_refuses_only_in_strict_mode() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(3),
            seq: 9,
        };
        let index = index_with_command(dir.path(), cmd);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let failed = || HelperResponse::WatchTreeFailed {
            session: cmd.session,
            command_seq: cmd.seq,
            reason: "watch cwd metadata unavailable".into(),
        };

        let map = crate::watch_ready::WatchReadyMap::new();
        dispatch(failed(), &index, &blobs, &map, false);
        assert!(refusal_details(&index, cmd).is_empty());
        assert!(map.failure_reason(cmd).is_some());

        let map = crate::watch_ready::WatchReadyMap::new();
        dispatch(failed(), &index, &blobs, &map, true);
        let rows = refusal_details(&index, cmd);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].1.starts_with("capture attach failed: "));
    }

    #[test]
    fn unjournaled_capture_refuses_only_in_strict_mode() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = CommandId {
            session: Uuid::from_u128(4),
            seq: 2,
        };
        let index = index_with_command(dir.path(), cmd);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let map = crate::watch_ready::WatchReadyMap::new();
        // A content pre-image whose staging fd never arrived: the bytes
        // are gone, so the command's capture is incomplete.
        let no_fd = || HelperResponse::CapturedPreImage {
            session: cmd.session,
            seq: cmd.seq,
            dev: 1,
            inode: 2,
            path: Some("/tmp/watched/f".into()),
            blob_hash: [0u8; 32],
            stored_bytes: 5,
            post_content_hash: None,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            flags: 0,
            rdev: 0,
            device_token: None,
            device_untrusted: None,
            is_delete: false,
            fd_sent_via_scm: true,
        };

        dispatch(no_fd(), &index, &blobs, &map, false);
        assert!(refusal_details(&index, cmd).is_empty());

        dispatch(no_fd(), &index, &blobs, &map, true);
        let rows = refusal_details(&index, cmd);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].1.contains("without its staging fd"), "{rows:?}");
    }

    /// Review round 2, item 2: the BSD helper counts a file as baselined
    /// once its BaselineCaptured is sent. If the daemon then fails to
    /// ingest it, the write that follows has no pre-write content, and
    /// strict mode must refuse the writing command.
    #[test]
    fn failed_baseline_ingest_refuses_the_write_only_in_strict_mode() {
        for strict in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cmd = CommandId {
                session: Uuid::from_u128(5),
                seq: 3,
            };
            let index = index_with_command(dir.path(), cmd);
            let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
            let map = crate::watch_ready::WatchReadyMap::new();
            let baseline = crate::baseline::LiveBaseline::new();
            let waiters = PrivOpWaiters::default();
            let send = |resp: HelperResponse, fd: Option<OwnedFd>| {
                dispatch_response(
                    resp, fd, &index, &blobs, &map, &baseline, "kqueue", &waiters, strict,
                );
            };
            // BaselineCaptured without its fd: not ingested.
            send(
                HelperResponse::BaselineCaptured {
                    session: cmd.session,
                    cwd: "/tmp/watched".into(),
                    dev: 1,
                    inode: 7,
                    path: "/tmp/watched/f".into(),
                    blob_hash: [0u8; 32],
                    stored_bytes: 3,
                    mode: 0o100644,
                    uid: 0,
                    gid: 0,
                    mtime_unix_nanos: 0,
                    xattrs: Default::default(),
                    fd_sent_via_scm: true,
                },
                None,
            );
            let post = b"new";
            let claimed: [u8; 32] = *blobs.put(post).unwrap().0.as_bytes();
            send(
                HelperResponse::CapturedPreImage {
                    session: cmd.session,
                    seq: cmd.seq,
                    dev: 1,
                    inode: 7,
                    path: Some("/tmp/watched/f".into()),
                    blob_hash: claimed,
                    stored_bytes: post.len() as u64,
                    post_content_hash: Some(claimed),
                    mode: 0o100644,
                    uid: 0,
                    gid: 0,
                    mtime_unix_nanos: 0,
                    xattrs: Default::default(),
                    flags: 0,
                    rdev: 0,
                    device_token: None,
                    device_untrusted: None,
                    is_delete: false,
                    fd_sent_via_scm: true,
                },
                Some(tmp_staging_fd(post)),
            );
            let rows = refusal_details(&index, cmd);
            if strict {
                assert_eq!(rows.len(), 1, "{rows:?}");
                assert!(rows[0].1.contains("baseline"), "{rows:?}");
            } else {
                assert!(rows.is_empty(), "{rows:?}");
            }
        }
    }

    /// Review round 3, item 2: a failed baseline in one session says
    /// nothing about the same inode number written in another session.
    #[test]
    fn failed_baseline_ingest_in_another_session_refuses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let other = Uuid::from_u128(6);
        let cmd = CommandId {
            session: Uuid::from_u128(7),
            seq: 1,
        };
        let index = index_with_command(dir.path(), cmd);
        let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
        let map = crate::watch_ready::WatchReadyMap::new();
        let baseline = crate::baseline::LiveBaseline::new();
        let waiters = PrivOpWaiters::default();
        let send = |resp: HelperResponse, fd: Option<OwnedFd>| {
            dispatch_response(
                resp, fd, &index, &blobs, &map, &baseline, "kqueue", &waiters, true,
            );
        };
        send(
            HelperResponse::BaselineCaptured {
                session: other,
                cwd: "/tmp/elsewhere".into(),
                dev: 1,
                inode: 7,
                path: "/tmp/elsewhere/g".into(),
                blob_hash: [0u8; 32],
                stored_bytes: 3,
                mode: 0o100644,
                uid: 0,
                gid: 0,
                mtime_unix_nanos: 0,
                xattrs: Default::default(),
                fd_sent_via_scm: true,
            },
            None,
        );
        let post = b"new";
        let claimed: [u8; 32] = *blobs.put(post).unwrap().0.as_bytes();
        send(
            HelperResponse::CapturedPreImage {
                session: cmd.session,
                seq: cmd.seq,
                dev: 1,
                inode: 7,
                path: Some("/tmp/watched/f".into()),
                blob_hash: claimed,
                stored_bytes: post.len() as u64,
                post_content_hash: Some(claimed),
                mode: 0o100644,
                uid: 0,
                gid: 0,
                mtime_unix_nanos: 0,
                xattrs: Default::default(),
                flags: 0,
                rdev: 0,
                device_token: None,
                device_untrusted: None,
                is_delete: false,
                fd_sent_via_scm: true,
            },
            Some(tmp_staging_fd(post)),
        );
        assert!(refusal_details(&index, cmd).is_empty());
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

    /// Review of #232 medium review, item 1, through the real ingest
    /// paths and clock. The shim's gap note for an open is stamped first
    /// (before the write runs); the kernel tier's capture of the same open
    /// is stamped on receipt, after it. A capture of the file as it was
    /// before the command (old mtime) covers the gap. A capture taken
    /// after the gapped write (fresh mtime) does not.
    #[test]
    fn kernel_capture_of_the_same_open_covers_the_shims_gap() {
        use std::os::unix::fs::MetadataExt;
        for (age_secs, want_refusals) in [(3600u64, 0usize), (0, 1)] {
            let dir = tempfile::tempdir().unwrap();
            let cmd = CommandId {
                session: Uuid::from_u128(77),
                seq: 1,
            };
            let index = index_with_command(dir.path(), cmd);
            let blobs = BlobStore::open(dir.path().join("blobs")).unwrap();
            let big = dir.path().canonicalize().unwrap().join("big.bin");
            let bytes = b"bytes the kernel tier captured";
            std::fs::write(&big, bytes).unwrap();
            let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
            std::fs::File::options()
                .write(true)
                .open(&big)
                .unwrap()
                .set_modified(when)
                .unwrap();
            let m = std::fs::metadata(&big).unwrap();

            let gap = shit_proto::ShimNotification {
                pid: 1,
                syscall: "open".into(),
                arg: big.to_str().unwrap().into(),
                ts_unix_nanos: 0,
                pre_image: None,
                extra_pre_images: Vec::new(),
                failure: Some(shit_proto::ShimFailure::PreImageUncaptured {
                    path: big.to_str().unwrap().into(),
                    reason: "over the shim's inline pre-image cap".into(),
                }),
                pre_stat: None,
                call_id: 0,
                outcome: None,
                command_key: None,
            };
            crate::shim_listener::ingest_notification(
                &gap,
                Some(cmd),
                crate::server::next_ts(),
                None,
                &index,
                &blobs,
                &crate::baseline::LiveBaseline::new(),
            );
            let (canonical, _) = blobs.put(bytes).unwrap();
            handle_captured_pre_image(
                CapturedPreImageArgs {
                    session: cmd.session,
                    seq: cmd.seq,
                    dev: m.dev(),
                    inode: m.ino(),
                    path: Some(big.to_str().unwrap().into()),
                    blob_hash: *canonical.as_bytes(),
                    stored_bytes: bytes.len() as u64,
                    post_content_hash: None,
                    mode: m.mode(),
                    uid: m.uid(),
                    gid: m.gid(),
                    mtime_unix_nanos: i128::from(m.mtime()) * 1_000_000_000
                        + i128::from(m.mtime_nsec()),
                    xattrs: std::collections::BTreeMap::new(),
                    flags: 0,
                    is_delete: false,
                    staging: tmp_staging_fd(bytes),
                },
                &index,
                &blobs,
                "bpf-lsm",
            )
            .unwrap();
            let events = index.events_for_command(cmd);
            let record = <Index as shit_planner::PlannerStore>::command_by_id(&index, cmd).unwrap();
            let plan = shit_planner::plan(
                record,
                &events,
                &shit_planner::LiveStateProbe::new(),
                &index,
            );
            let refusals = plan
                .nodes
                .iter()
                .filter(|n| {
                    matches!(&n.op, shit_planner::InverseOp::Refuse { class, .. } if class == "capture-gap")
                })
                .count();
            assert_eq!(
                refusals, want_refusals,
                "age {age_secs}s: {:#?}",
                plan.nodes
            );
        }
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

    /// AR01.1.fix-marker-only — when the helper sends `CapturedPreImage`
    /// with `stored_bytes=0`, `is_delete=true`, and no SCM_RIGHTS fd
    /// (the unlink-race-lost path used for atomic lock files like
    /// `.git/index.lock`), the daemon must journal a `TreeOp::Unlink`
    /// only -- NO `FilePreImage`. Pre-AR01.1 the daemon rejected these
    /// outright with `CapturedPreImage missing SCM_RIGHTS fd` and the
    /// unlink never reached the journal, leaving the planner blind to
    /// the delete.
    #[test]
    fn marker_only_unlink_journals_just_treeop() {
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
                cmd_string: Some("git commit".into()),
                cwd: "/tmp".into(),
                pid: 5678,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();

        let command = CommandId { session, seq: 1 };
        let inode_ref = InodeRef::new(64, 999);
        let path_buf: PathBuf = "/tmp/.git/index.lock".into();
        let ts = crate::server::next_ts();
        journal_unlink_idempotent(
            &index,
            command,
            ts,
            inode_ref,
            path_buf,
            shit_planner::metadata::FileKind::Regular,
            0o100644,
        )
        .expect("marker-only journal");

        let events = index.events_for_command(command);
        assert_eq!(events.len(), 1, "expected 1 Unlink, got {events:#?}");
        assert!(
            matches!(
                events[0].kind,
                CaptureEventKind::TreeOp(TreeOp::Unlink { .. })
            ),
            "expected TreeOp::Unlink, got {:#?}",
            events[0].kind
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.kind, CaptureEventKind::FilePreImage { .. })),
            "marker-only path must not journal FilePreImage: {events:#?}"
        );
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
            path: None,
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
    }
}
