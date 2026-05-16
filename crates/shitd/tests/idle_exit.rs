// SPDX-License-Identifier: AGPL-3.0-or-later

//! Asserts the daemon exits cleanly when no IPC arrives within its idle
//! window. Uses a 1-second idle timeout for the test.

use std::process::Command;
use std::time::{Duration, Instant};

fn shitd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shitd")
}

#[test]
fn idle_timeout_causes_exit() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    let sock = tmp.path().join("test.sock");
    let ctl = tmp.path().join("test-ctl.sock");
    let state = tmp.path().join("state");

    std::fs::write(
        &cfg,
        format!(
            r#"
idle_timeout_secs = 1
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

    let start = Instant::now();
    let status = Command::new(shitd_bin())
        .args(["--config"])
        .arg(&cfg)
        .status()
        .expect("spawn shitd");
    let elapsed = start.elapsed();

    assert!(status.success(), "shitd exit status: {status:?}");
    assert!(
        elapsed >= Duration::from_secs(1),
        "exited too fast: {elapsed:?}"
    );
    // Tick is 60s but first idle-eval can happen sooner under tokio select;
    // upper bound is generous to keep CI happy.
    assert!(
        elapsed < Duration::from_secs(90),
        "took too long to exit: {elapsed:?}"
    );
}
