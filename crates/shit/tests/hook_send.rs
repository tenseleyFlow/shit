// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test of the `shit hook-send` subcommand reaching a UDS listener
//! with a valid framed `HookMessage`. Exercises the wire format end-to-end.

use shit_proto::{HookMessage, ShellKind, decode_frame};
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::time::Duration;

fn shit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shit")
}

fn listener_at(sock: &std::path::Path) -> UnixDatagram {
    let l = UnixDatagram::bind(sock).expect("bind test UDS");
    l.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    l
}

fn recv_one(l: &UnixDatagram) -> HookMessage {
    let mut buf = vec![0u8; 4096];
    let (n, _) = l.recv_from(&mut buf).expect("recv_from");
    decode_frame(&buf[..n]).expect("decode")
}

#[test]
fn preexec_round_trips_through_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("test.sock");
    let listener = listener_at(&sock);

    let status = Command::new(shit_bin())
        .args([
            "hook-send",
            "pre-exec",
            "--session",
            "00000000-0000-0000-0000-000000000001",
            "--seq",
            "42",
            "--pid",
            "1234",
            "--cwd",
        ])
        .arg(tmp.path())
        .args(["--shell", "bash", "--depth", "1", "--sock"])
        .arg(&sock)
        .status()
        .expect("spawn shit");
    assert!(status.success(), "shit hook-send pre-exec failed");

    match recv_one(&listener) {
        HookMessage::PreExec {
            seq,
            pid,
            shell_kind,
            depth,
            cwd_inode,
            cwd_dev,
            cmd_string,
            ..
        } => {
            assert_eq!(seq, 42);
            assert_eq!(pid, 1234);
            assert_eq!(shell_kind, ShellKind::Bash);
            assert_eq!(depth, 1);
            assert!(cwd_inode != 0, "cwd_inode should be populated from stat()");
            assert!(cwd_dev != 0, "cwd_dev should be populated from stat()");
            // AU26: backward-compat — omitting --cmdline produces None.
            assert_eq!(cmd_string, None, "no --cmdline should ship cmd_string=None");
        }
        m => panic!("expected PreExec, got {m:?}"),
    }
}

/// AU26: `--cmdline "git push origin main"` produces
/// `cmd_string: Some("git push origin main")` on the wire.
/// Verifies the cmdline plumbs through send.rs into the
/// HookMessage::PreExec frame without mangling.
#[test]
fn preexec_cmdline_plumbs_through_to_wire() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("test.sock");
    let listener = listener_at(&sock);

    let status = Command::new(shit_bin())
        .args([
            "hook-send",
            "pre-exec",
            "--session",
            "00000000-0000-0000-0000-000000000001",
            "--seq",
            "1",
            "--pid",
            "1234",
            "--cwd",
        ])
        .arg(tmp.path())
        .args(["--shell", "bash", "--depth", "1", "--sock"])
        .arg(&sock)
        .args(["--cmdline", "git push origin main"])
        .status()
        .expect("spawn shit");
    assert!(status.success(), "shit hook-send pre-exec --cmdline failed");

    match recv_one(&listener) {
        HookMessage::PreExec { cmd_string, .. } => {
            assert_eq!(
                cmd_string.as_deref(),
                Some("git push origin main"),
                "cmdline should ship through verbatim"
            );
        }
        m => panic!("expected PreExec, got {m:?}"),
    }
}

// AU26: truncation behavior (over-cap inputs cut at the nearest
// char boundary) is unit-tested in `shit-proto::tests`. We don't
// retest via the CLI here because macOS UDS DGRAM defaults cap
// payloads at ~2 KiB, smaller than the 4 KiB cmdline cap — going
// over UDS would conflate the cmdline cap with the kernel datagram
// limit. The unit tests in shit-proto cover the truncation in
// isolation.

#[test]
fn postexec_round_trips_through_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("test.sock");
    let listener = listener_at(&sock);

    let status = Command::new(shit_bin())
        .args([
            "hook-send",
            "post-exec",
            "--session",
            "00000000-0000-0000-0000-000000000002",
            "--seq",
            "7",
            "--exit-code",
            "1",
            "--sock",
        ])
        .arg(&sock)
        .status()
        .expect("spawn shit");
    assert!(status.success());

    match recv_one(&listener) {
        HookMessage::PostExec { seq, exit_code, .. } => {
            assert_eq!(seq, 7);
            assert_eq!(exit_code, 1);
        }
        m => panic!("expected PostExec, got {m:?}"),
    }
}

#[test]
fn session_open_close_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("test.sock");
    let listener = listener_at(&sock);

    let status = Command::new(shit_bin())
        .args([
            "hook-send",
            "session-open",
            "--session",
            "00000000-0000-0000-0000-000000000003",
            "--pid",
            "999",
            "--shell",
            "zsh",
            "--tty",
            "/dev/ttys001",
            "--sock",
        ])
        .arg(&sock)
        .status()
        .unwrap();
    assert!(status.success());

    match recv_one(&listener) {
        HookMessage::SessionOpen {
            shell_kind,
            parent_pid,
            tty,
            ..
        } => {
            assert_eq!(shell_kind, ShellKind::Zsh);
            assert_eq!(parent_pid, 999);
            assert_eq!(tty, "/dev/ttys001");
        }
        m => panic!("expected SessionOpen, got {m:?}"),
    }

    let status = Command::new(shit_bin())
        .args([
            "hook-send",
            "session-close",
            "--session",
            "00000000-0000-0000-0000-000000000003",
            "--sock",
        ])
        .arg(&sock)
        .status()
        .unwrap();
    assert!(status.success());

    match recv_one(&listener) {
        HookMessage::SessionClose { .. } => {}
        m => panic!("expected SessionClose, got {m:?}"),
    }
}
