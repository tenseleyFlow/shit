// SPDX-License-Identifier: AGPL-3.0-or-later

//! M01.A integration test — end-to-end FSEvents capture pipeline.
//!
//! Spawns the real `shit-helper` binary as a subprocess, completes
//! the handshake, sends a `WatchTree` for a tempdir, then mutates
//! the tempdir from this test process and asserts that
//! `HelperResponse::TreeMutation` events arrive over the daemon-side
//! socket for the expected `(CommandId, path, op)` tuples.
//!
//! Why this lives as an integration test: the helper holds a real
//! FSEvents subscription that runs on a CoreFoundation runloop in a
//! worker thread. Exercising it inside a `#[test]` in the bin crate
//! would either monopolize the test process's runloop or share it
//! with the FSEvents callback in surprising ways. Subprocess spawn
//! is the same pattern `helper_handshake.rs` uses.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
};
use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse, ShellKind, TreeOpWire,
    decode_frame, encode_frame,
};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use uuid::Uuid;

// macOS uses SOCK_STREAM (XNU has no AF_UNIX SEQPACKET).
const HELPER_SOCK_TYPE: SockType = SockType::Stream;

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shit-helper"))
}

#[test]
fn fsevents_capture_create_and_unlink_through_helper() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("helper.sock");
    let state_dir = tmp.path().join("state");
    let watch_root = tmp.path().join("watched");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::create_dir_all(&watch_root).unwrap();
    // FSEvents reports realpath-resolved paths; canonicalize the
    // watch root so our `starts_with` checks line up with what
    // arrives in the TreeMutation events.
    let watch_root = std::fs::canonicalize(&watch_root).unwrap();

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

    let conn_fd = accept_with_timeout(&listener, &mut child, Duration::from_secs(10));

    // 1. Handshake.
    let req = HelperRequest::Handshake {
        daemon_pid,
        daemon_uid,
        protocol_version: HELPER_PROTOCOL_VERSION,
        capability_request: HelperCaps::full(),
    };
    send_frame(&conn_fd, &encode_frame(&req).unwrap());
    let resp: HelperResponse = decode_frame(&recv_frame(&conn_fd)).unwrap();
    let kernel_tier = match resp {
        HelperResponse::HandshakeAck { kernel_tier, .. } => kernel_tier,
        other => {
            kill_and_dump_stderr(&mut child);
            panic!("expected HandshakeAck, got {other:?}");
        }
    };
    assert_eq!(
        kernel_tier, "fsevents-degraded",
        "M01 baseline expects FSEvents-degraded tier on macOS"
    );

    // 2. WatchTree → fsevents producer registers the tempdir.
    // Deterministic test session id — workspace `uuid` has `v7` only.
    let session = Uuid::from_u128(0xDEAD_BEEF_CAFE_F00D_0000_0000_0000_0001);
    let command_seq: u64 = 1;
    let watch_req = HelperRequest::WatchTree {
        root_pid: std::process::id(),
        descendants_too: true,
        session,
        command_seq,
        shell_kind: ShellKind::Bash,
        cwd_path: watch_root.to_string_lossy().into_owned(),
    };
    send_frame(&conn_fd, &encode_frame(&watch_req).unwrap());

    // 3. Drain until we see WatchTreeReady. The helper may emit other
    // responses interleaved (none expected here, but we tolerate them).
    drain_until(&conn_fd, Duration::from_secs(5), |r| {
        matches!(
            r,
            HelperResponse::WatchTreeReady {
                session: s,
                command_seq: cs,
            } if *s == session && *cs == command_seq
        )
    })
    .unwrap_or_else(|| {
        kill_and_dump_stderr(&mut child);
        panic!("WatchTreeReady never arrived within 5s");
    });

    // 4. Small settle — FSEvents needs the kernel to attach the
    //    stream before the first event reliably fires (M01.7 tests
    //    use the same 200ms heuristic).
    std::thread::sleep(Duration::from_millis(300));

    // 5. Touch a file inside the watched dir.
    let target = watch_root.join("hello.txt");
    std::fs::write(&target, b"hi").expect("write");

    // 6. Drain TreeMutation events. FSEvents may coalesce Create +
    //    Modify into a single event with multiple flag bits; either
    //    Create or Touch shape is acceptable as long as the path
    //    matches and we observe SOMETHING for the file.
    let create_event = drain_until(&conn_fd, Duration::from_secs(5), |r| {
        matches!(
            r,
            HelperResponse::TreeMutation {
                session: s,
                seq: cs,
                op: TreeOpWire::Create { path, .. },
                ..
            } if *s == session && *cs == command_seq && path.as_str() == target.to_string_lossy()
        )
    });
    if create_event.is_none() {
        kill_and_dump_stderr(&mut child);
        panic!("no Create TreeMutation for {target:?} within 5s");
    }

    // 7. Unlink the file; expect a TreeOpWire::Unlink.
    std::fs::remove_file(&target).expect("remove");
    let unlink_event = drain_until(&conn_fd, Duration::from_secs(5), |r| {
        matches!(
            r,
            HelperResponse::TreeMutation {
                session: s,
                seq: cs,
                op: TreeOpWire::Unlink { path, .. },
                ..
            } if *s == session && *cs == command_seq && path.as_str() == target.to_string_lossy()
        )
    });
    if unlink_event.is_none() {
        kill_and_dump_stderr(&mut child);
        panic!("no Unlink TreeMutation for {target:?} within 5s");
    }

    // 8. UnwatchTree teardown (best-effort; the test passes either way).
    let unwatch_req = HelperRequest::UnwatchTree {
        session,
        command_seq,
    };
    let _ = send_frame_nonblocking(&conn_fd, &encode_frame(&unwatch_req).unwrap());

    let _ = child.kill();
    let _ = child.wait();
}

// ─────────────────────────────────────────────────────────────────────
// Helpers (subset of helper_handshake.rs; macOS-only — Stream socket
// with 4-byte length-prefixed framing)
// ─────────────────────────────────────────────────────────────────────

fn accept_with_timeout(
    listener: &std::os::fd::OwnedFd,
    child: &mut std::process::Child,
    timeout: Duration,
) -> std::os::fd::OwnedFd {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            kill_and_dump_stderr(child);
            panic!("helper did not connect in time");
        }
        match nix::sys::socket::accept(listener.as_raw_fd()) {
            Ok(raw) => {
                use std::os::fd::FromRawFd;
                let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
                set_recv_timeout(&fd, Duration::from_secs(1));
                return fd;
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
            Err(e) => panic!("accept failed: {e}"),
        }
    }
}

fn set_recv_timeout(fd: &std::os::fd::OwnedFd, dur: Duration) {
    let tv = libc::timeval {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_usec: dur.subsec_micros() as libc::suseconds_t,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "SO_RCVTIMEO setsockopt failed");
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

/// Best-effort send for the teardown path; ignores failures.
fn send_frame_nonblocking(fd: &std::os::fd::OwnedFd, frame: &[u8]) -> Result<(), ()> {
    let mut sent = 0;
    while sent < frame.len() {
        match nix::sys::socket::send(
            fd.as_raw_fd(),
            &frame[sent..],
            nix::sys::socket::MsgFlags::empty(),
        ) {
            Ok(0) => return Err(()),
            Ok(n) => sent += n,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame off a SOCK_STREAM. Blocks up to the
/// fd's `SO_RCVTIMEO`.
fn recv_frame(fd: &std::os::fd::OwnedFd) -> Vec<u8> {
    let mut header = [0u8; 4];
    recv_exact(fd, &mut header);
    let body_len = u32::from_be_bytes(header) as usize;
    let mut out = vec![0u8; 4 + body_len];
    out[..4].copy_from_slice(&header);
    recv_exact(fd, &mut out[4..]);
    out
}

fn recv_frame_with_deadline(fd: &std::os::fd::OwnedFd, deadline: Instant) -> Option<Vec<u8>> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    let remaining = deadline - now;
    set_recv_timeout(fd, remaining);
    let header = try_recv_header(fd)?;
    let body_len = u32::from_be_bytes(header) as usize;
    let mut out = vec![0u8; 4 + body_len];
    out[..4].copy_from_slice(&header);
    recv_exact(fd, &mut out[4..]);
    Some(out)
}

fn try_recv_header(fd: &std::os::fd::OwnedFd) -> Option<[u8; 4]> {
    let mut scratch = [0u8; 4];
    match try_recv_exact(fd, &mut scratch) {
        ReadOutcome::Bytes(bytes) => Some(bytes),
        ReadOutcome::Eof | ReadOutcome::Timeout => None,
    }
}

enum ReadOutcome {
    Bytes([u8; 4]),
    Timeout,
    Eof,
}

fn try_recv_exact(fd: &std::os::fd::OwnedFd, scratch: &mut [u8]) -> ReadOutcome {
    let mut got = 0;
    while got < scratch.len() {
        match nix::sys::socket::recv(
            fd.as_raw_fd(),
            &mut scratch[got..],
            nix::sys::socket::MsgFlags::empty(),
        ) {
            Ok(0) => return ReadOutcome::Eof,
            Ok(n) => got += n,
            // EAGAIN and EWOULDBLOCK have the same numeric value on
            // macOS (and Linux); matching just one suffices.
            Err(nix::errno::Errno::EAGAIN) => {
                return ReadOutcome::Timeout;
            }
            Err(e) => panic!("recv: {e}"),
        }
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(scratch);
    ReadOutcome::Bytes(out)
}

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

/// Drain incoming HelperResponses until `pred` matches or `timeout`
/// elapses. Returns the matching response or `None` on timeout.
fn drain_until<F>(fd: &std::os::fd::OwnedFd, timeout: Duration, pred: F) -> Option<HelperResponse>
where
    F: Fn(&HelperResponse) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let bytes = recv_frame_with_deadline(fd, deadline)?;
        let resp: HelperResponse = decode_frame(&bytes).expect("decode HelperResponse");
        if pred(&resp) {
            return Some(resp);
        }
    }
    None
}

fn kill_and_dump_stderr(child: &mut std::process::Child) {
    let _ = child.kill();
    if let Some(mut s) = child.stderr.take() {
        use std::io::Read;
        let mut buf = String::new();
        let _ = s.read_to_string(&mut buf);
        eprintln!("--- helper stderr ---\n{buf}");
    }
    let _ = child.wait();
}
