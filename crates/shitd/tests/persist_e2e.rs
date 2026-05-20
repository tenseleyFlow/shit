// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end: spawn shitd, send a SessionOpen + PreExec + PostExec +
//! SessionClose via the UDS, then open the on-disk sqlite and assert the
//! command row landed with the right shape.

use shit_proto::{HookMessage, ShellKind, encode_frame};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

fn shitd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shitd")
}

fn wait_for(path: &Path, deadline: Duration) -> bool {
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
fn hook_messages_persist_to_sqlite() {
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

    let stderr_file = std::fs::File::create(tmp.path().join("shitd.stderr")).unwrap();
    let child = Command::new(shitd_bin())
        .arg("--config")
        .arg(&cfg)
        // S24.A: persist-e2e test exercises hook journaling, not the
        // helper tier.
        .env("SHIT_HELPER_DISABLED", "1")
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .unwrap();
    let _d = Daemon { child };

    assert!(
        wait_for(&sock, Duration::from_secs(30)),
        "hook sock did not appear"
    );

    // Send: SessionOpen, PreExec, PostExec, SessionClose
    let session = Uuid::from_u128(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
    let client = UnixDatagram::unbound().unwrap();

    client
        .send_to(
            &encode_frame(&HookMessage::SessionOpen {
                session,
                shell_kind: ShellKind::Bash,
                parent_pid: 4242,
                tty: "/dev/ttys999".into(),
                ts_unix_nanos: 1,
            })
            .unwrap(),
            &sock,
        )
        .unwrap();
    client
        .send_to(
            &encode_frame(&HookMessage::PreExec {
                session,
                seq: 17,
                pid: 9876,
                cwd_inode: 100,
                cwd_dev: 200,
                cwd_path: "/tmp/persist_e2e".to_string(),
                ts_unix_nanos: 2,
                shell_kind: ShellKind::Bash,
                depth: 1,
            })
            .unwrap(),
            &sock,
        )
        .unwrap();
    client
        .send_to(
            &encode_frame(&HookMessage::PostExec {
                session,
                seq: 17,
                exit_code: 0,
                ts_unix_nanos: 3,
            })
            .unwrap(),
            &sock,
        )
        .unwrap();
    client
        .send_to(
            &encode_frame(&HookMessage::SessionClose {
                session,
                ts_unix_nanos: 4,
            })
            .unwrap(),
            &sock,
        )
        .unwrap();

    // Give the daemon a moment to ingest. UDS DGRAM is fire-and-forget so we
    // can't ack-wait; poll until the row appears.
    let index_path = state.join("index.sqlite");
    assert!(wait_for(&index_path, Duration::from_secs(5)));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_state = String::new();
    while Instant::now() < deadline {
        let idx = shit_store::Index::open(&index_path).unwrap();
        use shit_planner::{CommandId, PlannerStore};
        if let Some(cmd) = idx.command_by_id(CommandId { session, seq: 17 }) {
            if cmd.exit_code == Some(0) {
                assert_eq!(cmd.pid, 9876);
                assert_eq!(cmd.shell_kind, ShellKind::Bash);
                assert!(cmd.ended_at.is_some());
                return;
            } else {
                last_state = format!("{cmd:?}");
            }
        }
        drop(idx);
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("command row never reached completed state; last={last_state}");
}
