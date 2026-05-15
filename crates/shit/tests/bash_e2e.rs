// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test driving the bash hook through an actual bash subshell.
//!
//! Renders the bash template against a test socket, sources it inside a fresh
//! `bash -i`, runs one command, and asserts the listening UDS sees at least
//! one SessionOpen and one PreExec.
//!
//! Marked `#[ignore]` by default — bash interactive mode can be flaky in
//! headless CI containers without a tty; run locally with
//! `cargo test --package shit --test bash_e2e -- --ignored`.

use shit_proto::{HookMessage, decode_frame};
use shit_shell::{InstallParams, render_template};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn shit_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shit"))
}

fn drain_with_deadline(l: &UnixDatagram, deadline: Instant) -> Vec<HookMessage> {
    let mut out = Vec::new();
    l.set_nonblocking(true).unwrap();
    let mut buf = vec![0u8; 4096];
    while Instant::now() < deadline {
        match l.recv_from(&mut buf) {
            Ok((n, _)) => match decode_frame(&buf[..n]) {
                Ok(m) => out.push(m),
                Err(_) => continue,
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    out
}

#[test]
#[ignore]
fn bash_hook_emits_session_open_and_preexec() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("test.sock");
    let listener = UnixDatagram::bind(&sock).unwrap();

    let body = render_template(
        shit_proto::ShellKind::Bash,
        &InstallParams {
            shit_bin: shit_bin(),
            socket_path: sock.clone(),
        },
    )
    .unwrap();
    let hook = tmp.path().join("hook.bash");
    std::fs::write(&hook, body).unwrap();

    // bash -i --rcfile <hook> -c '<cmd>' interactive mode honors DEBUG trap
    // and PROMPT_COMMAND. The `true` command and immediate exit gives both
    // hook arms a chance to fire.
    let output = Command::new("bash")
        .args(["--noprofile", "--rcfile"])
        .arg(&hook)
        .args(["-i", "-c", "true"])
        .env("HOME", tmp.path())
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("TMPDIR") // force the daemon-side fallback path is irrelevant; we passed --sock
        .env("SHIT_DISABLE", "")
        .output()
        .expect("spawn bash");

    let received = drain_with_deadline(&listener, Instant::now() + Duration::from_secs(2));

    assert!(
        received
            .iter()
            .any(|m| matches!(m, HookMessage::SessionOpen { .. })),
        "expected at least one SessionOpen; bash stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        received
            .iter()
            .any(|m| matches!(m, HookMessage::PreExec { .. })),
        "expected at least one PreExec; bash stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
