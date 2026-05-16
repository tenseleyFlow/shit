// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test of the ctl socket: spawn `shitd`, connect to its ctl
//! socket, send a `Status` request, decode the response.

use shit_proto::{CtlRequest, CtlResponse, decode_frame, encode_frame};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn shitd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shitd")
}

fn wait_for_socket(path: &std::path::Path, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

struct Daemon {
    child: Child,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn ctl_status_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    let sock = tmp.path().join("hook.sock");
    let ctl = tmp.path().join("ctl.sock");
    let state = tmp.path().join("state");

    std::fs::write(
        &cfg,
        format!(
            r#"
idle_timeout_secs = 300
hook_socket_path = "{}"
ctl_socket_path = "{}"
state_dir = "{}"
lock_path = "{}/daemon.lock"
log_level = "warn"
"#,
            sock.display(),
            ctl.display(),
            state.display(),
            state.display(),
        ),
    )
    .unwrap();

    let stderr_path = tmp.path().join("shitd.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let child = Command::new(shitd_bin())
        .arg("--config")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .expect("spawn shitd");
    let daemon = Daemon { child };

    if !wait_for_socket(&ctl, Duration::from_secs(15)) {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!("ctl socket did not appear within 15s\n--- shitd stderr ---\n{stderr}");
    }

    // Connect, send Status, read response.
    let mut stream = UnixStream::connect(&ctl).expect("connect ctl");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let req = encode_frame(&CtlRequest::Status).unwrap();
    stream.write_all(&req).unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).unwrap();
    let resp: CtlResponse = decode_frame(&buf[..n]).expect("decode response");

    match resp {
        CtlResponse::Status(s) => {
            assert!(!s.version.is_empty());
            assert!(s.pid > 0);
            assert_eq!(s.hook_socket_path, sock.display().to_string());
            assert_eq!(s.ctl_socket_path, ctl.display().to_string());
            assert_eq!(s.hook_messages_received, 0);
            assert_eq!(s.idle_timeout_secs, 300);
        }
        other => panic!("expected Status, got {other:?}"),
    }

    // Ping should also work.
    let mut stream = UnixStream::connect(&ctl).expect("connect ctl 2");
    stream
        .write_all(&encode_frame(&CtlRequest::Ping).unwrap())
        .unwrap();
    let n = stream.read(&mut buf).unwrap();
    match decode_frame::<CtlResponse>(&buf[..n]).unwrap() {
        CtlResponse::Pong => {}
        other => panic!("expected Pong, got {other:?}"),
    }

    drop(daemon); // kills the child
}
