// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end: spawn the real `shit-helper` binary, accept its
//! connection, complete the handshake, verify granted capabilities,
//! then cleanly shut it down.

use shit_proto::HelperCaps;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shit-helper"))
}

// The helper_link module is internal to shitd's binary; cargo doesn't
// expose it to integration tests directly. We re-declare the smallest
// path through it via the same helpers (everything is portable through
// the public shit-proto surface).

use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
};
use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse, decode_frame, encode_frame,
};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

// W01.B.fix-framing: match shit-helper/src/ipc.rs and
// shitd/src/helper_link.rs — SEQPACKET on every supported platform
// except macOS.
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

#[test]
fn spawn_helper_and_complete_handshake() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("helper.sock");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let listener = socket(
        AddressFamily::Unix,
        HELPER_SOCK_TYPE,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    let addr = UnixAddr::new(&sock_path).unwrap();
    bind(listener.as_raw_fd(), &addr).unwrap();
    listen(&listener, Backlog::new(1).unwrap()).unwrap();

    let daemon_pid = std::process::id();
    let daemon_uid = unsafe { libc::getuid() };

    let mut child = Command::new(helper_bin())
        .arg("--daemon-sock")
        .arg(&sock_path)
        .arg("--daemon-pid")
        .arg(daemon_pid.to_string())
        .arg("--daemon-uid")
        .arg(daemon_uid.to_string())
        .arg("--state-dir")
        .arg(&state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove("LD_PRELOAD")
        .env_remove("DYLD_INSERT_LIBRARIES")
        .spawn()
        .expect("spawn helper");

    let deadline = Instant::now() + Duration::from_secs(10);
    let conn_fd = loop {
        if Instant::now() > deadline {
            // Capture helper stderr for context.
            let _ = child.kill();
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                use std::io::Read;
                let _ = s.read_to_string(&mut stderr);
            }
            panic!("helper did not connect in time\n--- helper stderr ---\n{stderr}");
        }
        match nix::sys::socket::accept(listener.as_raw_fd()) {
            Ok(raw) => {
                use std::os::fd::FromRawFd;
                break unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
            Err(e) => panic!("accept failed: {e}"),
        }
    };

    let req = HelperRequest::Handshake {
        daemon_pid,
        daemon_uid,
        protocol_version: HELPER_PROTOCOL_VERSION,
        capability_request: HelperCaps::full(),
    };
    send_frame(&conn_fd, &encode_frame(&req).unwrap());
    let resp_bytes = recv_frame(&conn_fd);
    let resp: HelperResponse = decode_frame(&resp_bytes).unwrap();
    match resp {
        HelperResponse::HandshakeAck {
            helper_pid: _,
            helper_uid,
            protocol_version,
            granted,
            helper_version,
            kernel_tier,
        } => {
            assert_eq!(protocol_version, HELPER_PROTOCOL_VERSION);
            assert_eq!(helper_uid, daemon_uid);
            // S06 helper advertises watch_tree only (no real ES/fanotify yet).
            assert!(granted.watch_tree);
            assert!(!helper_version.is_empty());
            // DR-66: per-OS classifier; non-empty + finite vocab.
            assert!(matches!(
                kernel_tier.as_str(),
                "fanotify"
                    | "bpf-lsm"
                    | "endpoint-security"
                    | "kqueue"
                    | "preload-shim"
                    | "degraded"
                    | "unsupported"
            ));
        }
        other => panic!("expected HandshakeAck, got {other:?}"),
    }

    // Clean shutdown.
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn helper_refuses_wrong_daemon_pid() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("helper.sock");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let listener = socket(
        AddressFamily::Unix,
        HELPER_SOCK_TYPE,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    let addr = UnixAddr::new(&sock_path).unwrap();
    bind(listener.as_raw_fd(), &addr).unwrap();
    listen(&listener, Backlog::new(1).unwrap()).unwrap();

    let real_pid = std::process::id();
    let wrong_pid = real_pid.wrapping_add(12345);
    let daemon_uid = unsafe { libc::getuid() };

    let mut child = Command::new(helper_bin())
        .arg("--daemon-sock")
        .arg(&sock_path)
        .arg("--daemon-pid")
        .arg(wrong_pid.to_string()) // lie about our pid
        .arg("--daemon-uid")
        .arg(daemon_uid.to_string())
        .arg("--state-dir")
        .arg(&state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_remove("LD_PRELOAD")
        .spawn()
        .expect("spawn helper");

    let deadline = Instant::now() + Duration::from_secs(10);
    let _conn = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("helper did not connect");
        }
        match nix::sys::socket::accept(listener.as_raw_fd()) {
            Ok(raw) => {
                use std::os::fd::FromRawFd;
                break unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
            Err(e) => panic!("accept: {e}"),
        }
    };

    // Helper should exit non-zero from the pid-mismatch error before
    // we even try to handshake. Give it a moment.
    let status = wait_with_timeout(&mut child, Duration::from_secs(10));
    let status = status.expect("helper should exit on pid mismatch");
    assert!(
        !status.success(),
        "helper exited 0 despite wrong daemon-pid"
    );
}

#[test]
fn daemon_sees_eof_when_helper_is_killed() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("helper.sock");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let listener = socket(
        AddressFamily::Unix,
        HELPER_SOCK_TYPE,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    let addr = UnixAddr::new(&sock_path).unwrap();
    bind(listener.as_raw_fd(), &addr).unwrap();
    listen(&listener, Backlog::new(1).unwrap()).unwrap();

    let daemon_pid = std::process::id();
    let daemon_uid = unsafe { libc::getuid() };

    let mut child = Command::new(helper_bin())
        .arg("--daemon-sock")
        .arg(&sock_path)
        .arg("--daemon-pid")
        .arg(daemon_pid.to_string())
        .arg("--daemon-uid")
        .arg(daemon_uid.to_string())
        .arg("--state-dir")
        .arg(&state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_remove("LD_PRELOAD")
        .spawn()
        .expect("spawn helper");

    let deadline = Instant::now() + Duration::from_secs(10);
    let conn_fd = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("helper did not connect");
        }
        match nix::sys::socket::accept(listener.as_raw_fd()) {
            Ok(raw) => {
                use std::os::fd::FromRawFd;
                break unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
            Err(e) => panic!("accept: {e}"),
        }
    };

    // Complete the handshake so we know the helper is past startup.
    let req = HelperRequest::Handshake {
        daemon_pid,
        daemon_uid,
        protocol_version: HELPER_PROTOCOL_VERSION,
        capability_request: HelperCaps::full(),
    };
    send_frame(&conn_fd, &encode_frame(&req).unwrap());
    let _ack: HelperResponse = decode_frame(&recv_frame(&conn_fd)).unwrap();

    // Kill -9. Helper has no chance to send a ShutdownAck.
    let _ = child.kill();
    let _ = child.wait();

    // A subsequent recv must return 0 bytes (EOF) within a reasonable
    // window. We deliberately don't set SO_RCVTIMEO; SEQPACKET/STREAM
    // both report EOF as a 0-byte recv once the peer fd is closed.
    let mut buf = [0u8; 8];
    let n = nix::sys::socket::recv(
        conn_fd.as_raw_fd(),
        &mut buf,
        nix::sys::socket::MsgFlags::empty(),
    )
    .expect("recv after kill");
    assert_eq!(n, 0, "expected EOF after SIGKILL; got {n} bytes");
}

fn send_frame(fd: &std::os::fd::OwnedFd, frame: &[u8]) {
    let mut sent = 0;
    while sent < frame.len() {
        let n = nix::sys::socket::send(
            fd.as_raw_fd(),
            &frame[sent..],
            nix::sys::socket::MsgFlags::empty(),
        )
        .expect("send");
        if n == 0 {
            panic!("peer closed");
        }
        sent += n;
    }
}

fn recv_frame(fd: &std::os::fd::OwnedFd) -> Vec<u8> {
    // SEQPACKET (Linux) requires a single full-size recv to avoid
    // truncating the packet. STREAM (macOS/BSD) allows incremental
    // reads via the length-prefix header.
    #[cfg(target_os = "linux")]
    {
        let mut buf = vec![0u8; shit_proto::MAX_HELPER_FRAME_SIZE];
        let n = nix::sys::socket::recv(
            fd.as_raw_fd(),
            &mut buf,
            nix::sys::socket::MsgFlags::empty(),
        )
        .expect("recv");
        if n == 0 {
            panic!("peer closed");
        }
        buf.truncate(n);
        buf
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut header = [0u8; 4];
        recv_exact(fd, &mut header);
        let body_len = u32::from_be_bytes(header) as usize;
        let mut out = vec![0u8; 4 + body_len];
        out[..4].copy_from_slice(&header);
        recv_exact(fd, &mut out[4..]);
        out
    }
}

#[cfg(not(target_os = "linux"))]
fn recv_exact(fd: &std::os::fd::OwnedFd, buf: &mut [u8]) {
    let mut got = 0;
    while got < buf.len() {
        let n = nix::sys::socket::recv(
            fd.as_raw_fd(),
            &mut buf[got..],
            nix::sys::socket::MsgFlags::empty(),
        )
        .expect("recv");
        if n == 0 {
            panic!("peer closed mid-frame");
        }
        got += n;
    }
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}
