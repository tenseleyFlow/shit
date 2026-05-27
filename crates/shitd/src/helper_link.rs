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
}

/// Outcome of a successful helper link.
#[derive(Debug)]
pub struct HelperLink {
    /// Connected SEQPACKET/STREAM fd to the running helper.
    pub conn_fd: OwnedFd,
    /// Helper process handle. Drop kills the helper.
    pub child: Child,
    pub helper_pid: u32,
    pub helper_uid: u32,
    pub granted: HelperCaps,
    /// Capture-tier classifier the helper reported in the handshake
    /// (DR-66). E.g. `"fanotify"`, `"bpf-lsm"`, `"endpoint-security"`,
    /// `"kqueue"`. Forwarded to `Stats::set_kernel_tier` after
    /// link-up so `shit metrics` and the structured log stream
    /// surface what's actually running.
    pub kernel_tier: String,
}

impl HelperLink {
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

impl Drop for HelperLink {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

    Ok(HelperLink {
        conn_fd,
        child,
        helper_pid,
        helper_uid,
        granted,
        kernel_tier,
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

fn dispatch_response(
    resp: HelperResponse,
    fd: Option<OwnedFd>,
    index: &Index,
    blob_store: &BlobStore,
    watch_ready: &crate::watch_ready::WatchReadyMap,
    live_baseline: &crate::baseline::LiveBaseline,
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
            fd_sent_via_scm: _,
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
                    let path_buf: PathBuf = path.unwrap_or_default().into();
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
                    if let Err(e) = journal_unlink_idempotent(
                        index,
                        command,
                        ts,
                        inode_ref,
                        path_buf,
                        kind_from_mode_bits(mode),
                        mode,
                    ) {
                        tracing::error!(error = %e, %session, seq, "marker-only Unlink journal failed");
                    }
                    return;
                }
                tracing::error!(%session, seq, dev, inode, "CapturedPreImage missing SCM_RIGHTS fd");
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
                    is_delete,
                    index,
                ) {
                    tracing::error!(error = %e, %session, seq, "baseline-promoted FilePreImage journal failed");
                }
                drop(staging); // close helper's post-write fd; we don't need it
                return;
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
                    is_delete,
                    staging,
                },
                index,
                blob_store,
            ) {
                tracing::error!(error = %e, %session, seq, "failed to journal CapturedPreImage");
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
                return;
            };
            if let Err(e) = handle_baseline_captured(
                session,
                std::path::PathBuf::from(&cwd),
                dev,
                inode,
                std::path::PathBuf::from(&path),
                blob_hash,
                stored_bytes,
                staging,
                blob_store,
                live_baseline,
            ) {
                tracing::error!(error = %e, %session, dev, inode, %path, "failed to ingest BaselineCaptured");
            }
        }
        HelperResponse::BaselineWalkComplete {
            session,
            cwd,
            file_count,
            partial,
        } => {
            let cwd_path = std::path::PathBuf::from(&cwd);
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
            tracing::debug!(%session, command_seq, "WatchTreeReady routed");
        }
        other => {
            tracing::trace!(
                ?other,
                "unhandled helper response (S24.A handles CapturedPreImage; S29.1 handles TreeMutation; AR00.5 handles WatchTreeReady)"
            );
        }
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
            std::path::PathBuf::from(path),
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
            path: std::path::PathBuf::from(path),
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
        }
    }
    let inode_ref = InodeRef::new(dev, inode);
    let path_buf: std::path::PathBuf = path.unwrap_or_default().into();
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
    };
    let path_buf: PathBuf = args.path.clone().unwrap_or_default().into();

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
            source: shit_planner::FilePreImageSource::Other,
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
        // FIFO / Socket / Block / Char devices — uncommon at unlink
        // time; fall through to Regular so the planner's
        // RecreatePath emits a regular-file inverse. The unit test
        // suite's directory restore is the load-bearing case.
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
    use shit_planner::PlannerStore;
    let already = index.events_for_command(command).into_iter().any(|e| {
        matches!(
            &e.kind,
            CaptureEventKind::TreeOp(TreeOp::Unlink { inode, path: existing_path, .. })
                if *inode == inode_ref && existing_path == &path
        )
    });
    if already {
        return Ok(());
    }
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
    // The blob is already content-addressed in the store. Baseline
    // blobs don't need an index record because they aren't refed by
    // journal events directly — they're refed by LiveBaseline cache
    // entries, which manage their own lifecycle. When the cache is
    // promoted into a FilePreImage, that event's
    // `handle_captured_pre_image` path records the blob normally.
    let _ = stat;
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
    is_delete: bool,
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
    };
    let path_buf: PathBuf = path.clone().unwrap_or_default().into();
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
            // No post-content hash on the baseline-promoted path —
            // we discarded the helper's staging fd. Conflict
            // detection for "user modified after our capture"
            // doesn't fire for in-place writes promoted from
            // baseline. Acceptable v1 tradeoff documented in
            // .docs/sprints/W/W02.B.live-baseline.md.
            post_content_hash: None,
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
mod tests_dispatch {
    use super::*;
    use shit_planner::PlannerStore;
    use uuid::Uuid;

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
            is_delete: true,
            staging: fd,
        };
        handle_captured_pre_image(args, &index, &blob_store).expect("ingest");

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
            is_delete: false,
            staging: fd,
        };
        let err = handle_captured_pre_image(args, &index, &blob_store);
        assert!(err.is_err(), "expected hash-mismatch refusal");
    }
}
