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
    AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
};
use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse, decode_frame, encode_frame,
};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[cfg(target_os = "linux")]
const HELPER_SOCK_TYPE: SockType = SockType::SeqPacket;
#[cfg(not(target_os = "linux"))]
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

fn recv_frame_blocking_owned(fd: &OwnedFd) -> Result<Vec<u8>, HelperLinkError> {
    recv_frame_blocking(fd.as_raw_fd())
}

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
