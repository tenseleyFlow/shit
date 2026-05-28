// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side IPC: SOCK_SEQPACKET UDS to the daemon, framed with
//! `shit_proto::frame`. Synchronous send/recv on the underlying raw fd
//! via `nix` — we don't need async during the handshake, and per-event
//! processing in S07/8/9 runs on the helper's own event loop.

use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, Shutdown, SockFlag, SockType,
    UnixAddr, cmsg_space, recv, recvmsg, send, sendmsg, shutdown, socket,
};

/// Transport choice. macOS XNU does not support `AF_UNIX + SOCK_SEQPACKET`;
/// Linux and the BSDs do. The original "STREAM everywhere" choice
/// (HP-13) was wrong for BSDs: a high-rate burst of `sendmsg`s
/// coalesces into one daemon-side `recvmsg`, and the per-call
/// decoder reads only the first frame (lossy). W01 (`git commit
/// undo`) exposed it. SEQPACKET preserves message boundaries
/// kernel-side. macOS keeps STREAM and accepts the throughput
/// limit until S08 adds EndpointSecurity (where the macOS helper
/// stops needing high-rate captures over the IPC anyway).
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
use shit_proto::{
    HelperRequest, HelperResponse, MAX_HELPER_FRAME_SIZE, decode_frame, encode_frame,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
            let n = send(self.fd.as_raw_fd(), &frame[sent..], MsgFlags::empty())?;
            if n == 0 {
                return Err(ConnError::PeerClosed);
            }
            sent += n;
        }
        Ok(())
    }

    /// Send a `HelperResponse` with a single `RawFd` attached via
    /// `SCM_RIGHTS` (S24.A). The receiver must call
    /// [`Conn::recv_response_with_fd`] (or the daemon-side analog) with
    /// a cmsg buffer to extract the fd.
    ///
    /// On STREAM transports the kernel may split a large send into
    /// multiple internal chunks; the cmsg always rides with the first
    /// chunk. We assume the frame fits in a single `sendmsg(2)` because
    /// `MAX_HELPER_FRAME_SIZE` is well under any plausible kernel
    /// send-buffer limit. If `sendmsg` returns short, the rest is
    /// completed with plain `send(2)` (the cmsg was already delivered).
    pub fn send_response_with_fd(
        &self,
        msg: &HelperResponse,
        attach: RawFd,
    ) -> Result<(), ConnError> {
        let frame = encode_frame(msg)?;
        let iov = [std::io::IoSlice::new(&frame)];
        let fds = [attach];
        let cmsgs = [ControlMessage::ScmRights(&fds)];
        // SAFETY (the nix wrapper): iov + cmsgs outlive the call; fd is
        // owned by us; we don't take an address (None).
        let n = sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)?;
        if n == 0 {
            return Err(ConnError::PeerClosed);
        }
        let mut sent = n;
        while sent < frame.len() {
            let m = send(self.fd.as_raw_fd(), &frame[sent..], MsgFlags::empty())?;
            if m == 0 {
                return Err(ConnError::PeerClosed);
            }
            sent += m;
        }
        Ok(())
    }

    /// Send a `HelperRequest` (used by tests + the daemon-side stub).
    #[allow(dead_code)]
    pub fn send_request(&self, msg: &HelperRequest) -> Result<(), ConnError> {
        let frame = encode_frame(msg)?;
        let mut sent = 0;
        while sent < frame.len() {
            let n = send(
                self.fd.as_raw_fd(),
                &frame[sent..],
                nix::sys::socket::MsgFlags::empty(),
            )?;
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
    #[allow(dead_code)]
    pub fn recv_response(&self) -> Result<HelperResponse, ConnError> {
        let buf = self.recv_frame()?;
        Ok(decode_frame(&buf)?)
    }

    /// Receive one `HelperResponse` frame plus an optional fd attached
    /// via `SCM_RIGHTS` (S24.A). Returns `(message, Some(fd))` when the
    /// peer attached one; `(message, None)` otherwise.
    ///
    /// The cmsg always arrives with the first chunk of a STREAM
    /// recvmsg, so we issue one recvmsg sized to `MAX_HELPER_FRAME_SIZE`;
    /// on the rare case where the kernel delivers fewer bytes than the
    /// frame's length-prefix demands (only possible on STREAM), we
    /// complete via plain `recv(2)` for the tail.
    #[allow(dead_code)]
    pub fn recv_response_with_fd(&self) -> Result<(HelperResponse, Option<OwnedFd>), ConnError> {
        let (buf, fd) = self.recv_frame_with_fd()?;
        Ok((decode_frame(&buf)?, fd))
    }

    fn recv_frame_with_fd(&self) -> Result<(Vec<u8>, Option<OwnedFd>), ConnError> {
        let mut buf = vec![0u8; MAX_HELPER_FRAME_SIZE];
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let mut cmsg_buf: Vec<u8> = Vec::with_capacity(cmsg_space::<RawFd>());
        let result = recvmsg::<()>(
            self.fd.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )?;
        let n = result.bytes;
        if n == 0 {
            return Err(ConnError::PeerClosed);
        }
        let mut received_fd: Option<OwnedFd> = None;
        for cmsg in result.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg
                && let Some(raw) = fds.first()
            {
                // SAFETY: the kernel just handed us a fresh fd via
                // SCM_RIGHTS; ownership transfers to us. Multiple fds
                // in one cmsg would be unusual; we take the first and
                // close any others below.
                received_fd = Some(unsafe { OwnedFd::from_raw_fd(*raw) });
                for extra in fds.iter().skip(1) {
                    // SAFETY: same — we own these but won't use them.
                    drop(unsafe { OwnedFd::from_raw_fd(*extra) });
                }
            }
        }
        buf.truncate(n);
        // STREAM transports may deliver the cmsg with a short read;
        // SEQPACKET delivers the whole packet atomically. For STREAM
        // (macOS only after W01.B.fix-framing), parse the length
        // prefix and complete the read if needed.
        #[cfg(target_os = "macos")]
        {
            if buf.len() >= 4 {
                let body_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let frame_len = 4 + body_len;
                if frame_len > MAX_HELPER_FRAME_SIZE {
                    return Err(ConnError::Decode(shit_proto::DecodeError::TooLarge(
                        frame_len,
                    )));
                }
                while buf.len() < frame_len {
                    let needed = frame_len - buf.len();
                    let mut chunk = vec![0u8; needed];
                    let m = recv(self.fd.as_raw_fd(), &mut chunk, MsgFlags::empty())?;
                    if m == 0 {
                        return Err(ConnError::PeerClosed);
                    }
                    chunk.truncate(m);
                    buf.extend_from_slice(&chunk);
                }
            }
        }
        Ok((buf, received_fd))
    }

    fn recv_frame(&self) -> Result<Vec<u8>, ConnError> {
        // Transport-aware:
        //   - SEQPACKET (Linux + all BSDs): one `recv()` returns the
        //     full packet atomically. Issuing a short recv would
        //     TRUNCATE the rest of the kernel packet, so we must
        //     read into a full-size buffer up-front.
        //   - STREAM (macOS): byte stream; we read the 4-byte length
        //     header first, then the declared body. Partial reads OK.
        // The cfg gates MUST mirror the HELPER_SOCK_TYPE selection
        // exactly — W01.B.fix-framing earlier mis-gated this on
        // `target_os = "linux"` while the socket type was on
        // `target_os = "macos"`, which deadlocked FreeBSD handshakes
        // (SEQPACKET socket + STREAM reader → second recv hangs).
        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        ))]
        {
            let mut buf = vec![0u8; MAX_HELPER_FRAME_SIZE];
            let n = recv(
                self.fd.as_raw_fd(),
                &mut buf,
                nix::sys::socket::MsgFlags::empty(),
            )?;
            if n == 0 {
                return Err(ConnError::PeerClosed);
            }
            buf.truncate(n);
            Ok(buf)
        }

        #[cfg(target_os = "macos")]
        {
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
    }

    #[cfg(target_os = "macos")]
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
    #[allow(dead_code)]
    pub fn shutdown_write(&self) -> Result<(), ConnError> {
        shutdown(self.fd.as_raw_fd(), Shutdown::Write)?;
        Ok(())
    }

    /// Take ownership of the fd. Caller is then responsible for closing.
    #[allow(dead_code)]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// Wrap an existing fd. Used by tests and by the daemon side that
    /// already has an accepted SEQPACKET fd from `accept(2)`.
    #[allow(dead_code)]
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
#[allow(dead_code)]
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
    use shit_proto::{HELPER_PROTOCOL_VERSION, HelperCaps};

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

    #[test]
    fn scm_rights_round_trip_via_socketpair() {
        // Sender attaches a memfd-style temp file containing known
        // bytes; receiver extracts the fd from the cmsg and reads
        // back the bytes via pread. Validates the SCM_RIGHTS path
        // end-to-end against our own IPC layer.
        use shit_proto::HelperResponse;
        use uuid::Uuid;
        let (a, b) = socketpair().unwrap();
        // Stage a payload in a temp file.
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("payload");
        std::fs::write(&staging, b"scm-rights-payload").unwrap();
        let staging_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(&staging)
            .unwrap();
        let resp = HelperResponse::CapturedPreImage {
            session: Uuid::nil(),
            seq: 1,
            dev: 0,
            inode: 0,
            path: None,
            blob_hash: [0xAB; 32],
            stored_bytes: 18,
            post_content_hash: None,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            mtime_unix_nanos: 0,
            xattrs: std::collections::BTreeMap::new(),
            is_delete: false,
            fd_sent_via_scm: true,
        };
        a.send_response_with_fd(&resp, staging_fd.as_raw_fd())
            .unwrap();
        drop(staging_fd);
        let (got_msg, got_fd) = b.recv_response_with_fd().unwrap();
        assert_eq!(got_msg, resp);
        let owned_fd = got_fd.expect("expected attached fd");
        // Read bytes back via the received fd.
        let mut buf = [0u8; 32];
        // SAFETY: owned_fd is a valid open RawFd we just received.
        let n = unsafe { libc::pread(owned_fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert!(n > 0);
        assert_eq!(&buf[..n as usize], b"scm-rights-payload");
    }
}
