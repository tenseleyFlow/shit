// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side IPC: SOCK_SEQPACKET UDS to the daemon, framed with
//! `shit_proto::frame`. Synchronous send/recv on the underlying raw fd
//! via `nix` — we don't need async during the handshake, and per-event
//! processing in S07/8/9 runs on the helper's own event loop.

use nix::sys::socket::{
    AddressFamily, Shutdown, SockFlag, SockType, UnixAddr, recv, send, shutdown, socket,
};

/// Transport choice. macOS XNU does not support `AF_UNIX + SOCK_SEQPACKET`
/// (only Linux and modern BSD do). We use STREAM everywhere; our
/// length-prefixed framing in `shit_proto::frame` provides message
/// boundaries portably, and `SCM_RIGHTS` works on STREAM sockets just
/// the same. See `.docs/audits/helper-protocol.md` HP-13 for the
/// rationale tracking.
#[cfg(target_os = "linux")]
const HELPER_SOCK_TYPE: SockType = SockType::SeqPacket;
#[cfg(not(target_os = "linux"))]
const HELPER_SOCK_TYPE: SockType = SockType::Stream;
use shit_proto::{
    HelperRequest, HelperResponse, MAX_HELPER_FRAME_SIZE, decode_frame, encode_frame,
};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("encode: {0}")]
    Encode(#[from] shit_proto::EncodeError),
    #[error("decode: {0}")]
    Decode(#[from] shit_proto::DecodeError),
    #[error("daemon socket missing at {0}")]
    Missing(String),
    #[error("peer closed the connection")]
    PeerClosed,
}

/// Helper-owned IPC connection to the daemon.
#[derive(Debug)]
pub struct Conn {
    fd: OwnedFd,
}

impl Conn {
    /// Underlying fd, for sandbox bookkeeping and SCM_RIGHTS plumbing.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Send a `HelperResponse` to the daemon.
    pub fn send_response(&self, msg: &HelperResponse) -> Result<(), ConnError> {
        let frame = encode_frame(msg)?;
        let mut sent = 0;
        while sent < frame.len() {
            let n = send(self.fd.as_raw_fd(), &frame[sent..], nix::sys::socket::MsgFlags::empty())?;
            if n == 0 {
                return Err(ConnError::PeerClosed);
            }
            sent += n;
        }
        Ok(())
    }

    /// Send a `HelperRequest` (used by tests + the daemon-side stub).
    pub fn send_request(&self, msg: &HelperRequest) -> Result<(), ConnError> {
        let frame = encode_frame(msg)?;
        let mut sent = 0;
        while sent < frame.len() {
            let n = send(self.fd.as_raw_fd(), &frame[sent..], nix::sys::socket::MsgFlags::empty())?;
            if n == 0 {
                return Err(ConnError::PeerClosed);
            }
            sent += n;
        }
        Ok(())
    }

    /// Receive one `HelperRequest` frame. SEQPACKET preserves boundaries
    /// natively; on STREAM transports we reassemble via the length prefix.
    pub fn recv_request(&self) -> Result<HelperRequest, ConnError> {
        let buf = self.recv_frame()?;
        Ok(decode_frame(&buf)?)
    }

    /// Receive one `HelperResponse` frame.
    pub fn recv_response(&self) -> Result<HelperResponse, ConnError> {
        let buf = self.recv_frame()?;
        Ok(decode_frame(&buf)?)
    }

    fn recv_frame(&self) -> Result<Vec<u8>, ConnError> {
        // Read the 4-byte BE length prefix, then read exactly that many
        // payload bytes. SEQPACKET would let us read one packet at a
        // time, but the framing handles either case so we use the same
        // path everywhere.
        let mut header = [0u8; 4];
        self.recv_exact(&mut header)?;
        let body_len = u32::from_be_bytes(header) as usize;
        if body_len > MAX_HELPER_FRAME_SIZE - 4 {
            return Err(ConnError::Decode(shit_proto::DecodeError::TooLarge(
                body_len + 4,
            )));
        }
        let mut out = Vec::with_capacity(4 + body_len);
        out.extend_from_slice(&header);
        out.resize(4 + body_len, 0);
        self.recv_exact(&mut out[4..])?;
        Ok(out)
    }

    fn recv_exact(&self, buf: &mut [u8]) -> Result<(), ConnError> {
        let mut got = 0;
        while got < buf.len() {
            let n = recv(
                self.fd.as_raw_fd(),
                &mut buf[got..],
                nix::sys::socket::MsgFlags::empty(),
            )?;
            if n == 0 {
                return Err(ConnError::PeerClosed);
            }
            got += n;
        }
        Ok(())
    }

    /// Close the IPC half of the connection (write end). Useful when
    /// the helper is shutting down after sending its final
    /// `HelperResponse::ShutdownAck`.
    pub fn shutdown_write(&self) -> Result<(), ConnError> {
        shutdown(self.fd.as_raw_fd(), Shutdown::Write)?;
        Ok(())
    }

    /// Take ownership of the fd. Caller is then responsible for closing.
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// Wrap an existing fd. Used by tests and by the daemon side that
    /// already has an accepted SEQPACKET fd from `accept(2)`.
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }
}

/// Connect to the daemon's SEQPACKET listening socket at `path`.
pub async fn connect_seqpacket(path: &Path) -> Result<Conn, ConnError> {
    if !path.exists() {
        return Err(ConnError::Missing(path.display().to_string()));
    }
    let fd = socket(
        AddressFamily::Unix,
        HELPER_SOCK_TYPE,
        SockFlag::empty(),
        None,
    )?;
    let addr = UnixAddr::new(path)?;
    nix::sys::socket::connect(fd.as_raw_fd(), &addr)?;
    Ok(Conn { fd })
}

/// Back-compat alias for the S06.3 stub.
pub async fn connect(path: &Path) -> Result<Conn, ConnError> {
    connect_seqpacket(path).await
}

/// Helper for tests: create a connected SEQPACKET pair. Returns
/// `(client, server)` fds wrapped as `Conn`. Useful for round-tripping
/// without involving the filesystem.
pub fn socketpair() -> Result<(Conn, Conn), ConnError> {
    let (a, b) = nix::sys::socket::socketpair(
        AddressFamily::Unix,
        HELPER_SOCK_TYPE,
        None,
        SockFlag::empty(),
    )?;
    Ok((Conn { fd: a }, Conn { fd: b }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_proto::{HelperCaps, HELPER_PROTOCOL_VERSION};

    #[test]
    fn socketpair_round_trip_request() {
        let (a, b) = socketpair().unwrap();
        let req = HelperRequest::Handshake {
            daemon_pid: 1234,
            daemon_uid: 1000,
            protocol_version: HELPER_PROTOCOL_VERSION,
            capability_request: HelperCaps::full(),
        };
        a.send_request(&req).unwrap();
        let got = b.recv_request().unwrap();
        assert_eq!(got, req);
    }

    #[test]
    fn socketpair_round_trip_response() {
        let (a, b) = socketpair().unwrap();
        let resp = HelperResponse::Pong { nonce: 42 };
        b.send_response(&resp).unwrap();
        let got = a.recv_response().unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn peer_closed_surfaces_when_other_end_drops() {
        let (a, b) = socketpair().unwrap();
        drop(b);
        let res = a.recv_request();
        assert!(matches!(res, Err(ConnError::PeerClosed)));
    }
}
