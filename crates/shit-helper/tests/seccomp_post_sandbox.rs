// SPDX-License-Identifier: AGPL-3.0-or-later

//! L01.5 — post-sandbox seccomp survival test.
//!
//! Spawns the real `shit-helper` binary, completes the handshake,
//! sends a `WatchTree` request (which forces the helper to execute
//! post-sandbox code paths — fanotify mark or the degraded-mode
//! warning log path), and asserts the helper is still running after
//! the dispatch. If the seccomp allowlist is missing a syscall the
//! helper uses post-sandbox, the kernel SIGSYS-kills the process and
//! `try_wait` returns `Signaled(SIGSYS)`; the test fails with a
//! diagnostic that includes the helper's stderr.
//!
//! The existing `helper_handshake.rs` test ENDS at handshake — it
//! never drives the helper into its request loop, so a SIGSYS from
//! e.g. tokio's worker thread post-handshake doesn't surface there.
//! This test fills that gap.
//!
//! Skip behaviour:
//!   - Linux only (cfg-gated; non-Linux exits immediately).
//!   - The helper handshake itself works without caps; the WatchTree
//!     path degrades gracefully when fanotify isn't initialised. So
//!     this test runs on any Linux CI runner — no setcap needed.

#![cfg(target_os = "linux")]

use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
};
use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse, ShellKind, decode_frame,
    encode_frame,
};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::{Timestamp, Uuid};

const HELPER_SOCK_TYPE: SockType = SockType::SeqPacket;

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shit-helper"))
}

/// Drive the helper through handshake + WatchTree + UnwatchTree and
/// assert it never crashes via SIGSYS. The whole sequence runs after
/// `sandbox::enter` and `seccomp::install_filter` inside the helper.
#[test]
fn helper_survives_post_sandbox_requests() {
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
        // Test wants the production seccomp action (Kill) so a missing
        // syscall fails the test loudly. No SHIT_HELPER_SECCOMP_MODE
        // override.
        .env_remove("SHIT_HELPER_SECCOMP_MODE")
        .env_remove("LD_PRELOAD")
        .env_remove("DYLD_INSERT_LIBRARIES")
        .spawn()
        .expect("spawn helper");

    let conn_fd = accept_helper(&listener, &mut child);

    // Handshake.
    let req = HelperRequest::Handshake {
        daemon_pid,
        daemon_uid,
        protocol_version: HELPER_PROTOCOL_VERSION,
        capability_request: HelperCaps::full(),
    };
    send_frame(&conn_fd, &encode_frame(&req).unwrap());
    let resp: HelperResponse = decode_frame(&recv_frame(&conn_fd)).unwrap();
    match resp {
        HelperResponse::HandshakeAck { .. } => {}
        other => panic!("expected HandshakeAck, got {other:?}"),
    }

    // Post-sandbox: send WatchTree. The helper's request loop
    // dispatches this through code paths that spawn tokio workers,
    // hit `/proc/<pid>/cwd`, and (when fanotify is up) issue
    // `fanotify_mark`. All of those happen after the seccomp filter
    // is installed. If any syscall is missing from the allowlist the
    // helper SIGSYS-dies here.
    let watch = HelperRequest::WatchTree {
        root_pid: std::process::id(),
        descendants_too: true,
        // Workspace pins uuid with v7 (not v4); ts is a stable
        // monotonic counter for the test's lifetime.
        session: Uuid::new_v7(Timestamp::from_unix_time(0, 0, 0, 0)),
        command_seq: 1,
        shell_kind: ShellKind::Bash,
        cwd_path: std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_default(),
    };
    send_frame(&conn_fd, &encode_frame(&watch).unwrap());

    // Give the helper time to process the WatchTree end-to-end. The
    // dispatch is fire-and-forget on the wire; we observe survival
    // via try_wait instead of an ack frame.
    std::thread::sleep(Duration::from_millis(400));

    let still_alive = match child.try_wait() {
        Ok(None) => true,
        Ok(Some(status)) => {
            let stderr = read_remaining_stderr(&mut child);
            panic!(
                "helper exited unexpectedly post-WatchTree: status={status:?}\n--- helper stderr ---\n{stderr}"
            );
        }
        Err(e) => panic!("try_wait failed: {e}"),
    };
    assert!(still_alive, "helper should be running after WatchTree");

    let unwatch = HelperRequest::UnwatchTree {
        session: match &watch {
            HelperRequest::WatchTree { session, .. } => *session,
            _ => unreachable!(),
        },
        command_seq: 1,
    };
    send_frame(&conn_fd, &encode_frame(&unwatch).unwrap());

    std::thread::sleep(Duration::from_millis(200));

    match child.try_wait() {
        Ok(None) => {} // still alive — good
        Ok(Some(status)) => {
            let stderr = read_remaining_stderr(&mut child);
            panic!(
                "helper exited unexpectedly post-UnwatchTree: status={status:?}\n--- helper stderr ---\n{stderr}"
            );
        }
        Err(e) => panic!("try_wait failed: {e}"),
    }

    // Clean shutdown.
    let _ = child.kill();
    let _ = child.wait();
}

fn accept_helper(
    listener: &std::os::fd::OwnedFd,
    child: &mut std::process::Child,
) -> std::os::fd::OwnedFd {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("helper did not connect within 10s");
        }
        match nix::sys::socket::accept(listener.as_raw_fd()) {
            Ok(raw) => {
                use std::os::fd::FromRawFd;
                return unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
            Err(e) => panic!("accept failed: {e}"),
        }
    }
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

fn read_remaining_stderr(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut out);
    }
    out
}
