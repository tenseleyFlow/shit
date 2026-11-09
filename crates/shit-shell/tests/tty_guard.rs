// SPDX-License-Identifier: AGPL-3.0-or-later

//! #255: the bash and zsh hooks must send an empty `--tty` when there is
//! no controlling tty, not the "not a tty" text `tty` prints.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use shit_proto::ShellKind;
use shit_shell::{InstallParams, render_template};

fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Run the rendered hook with no tty and return the argv the fake
/// `shit` saw for `hook-send session-open`, one argument per line.
fn session_open_args(shell: ShellKind, interp: &str, dir: &Path) -> String {
    let log = dir.join("args.log");
    let fake: PathBuf = dir.join("fake-shit");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nif [ \"$1 $2\" = \"hook-send session-open\" ]; then\n  for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\nfi\nexit 0\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let body = render_template(
        shell,
        &InstallParams {
            shit_bin: fake,
            socket_path: dir.join("sock"),
        },
    )
    .unwrap();
    let hook = dir.join("hook");
    std::fs::write(&hook, body).unwrap();
    let status = Command::new(interp)
        .arg("-c")
        .arg(format!(". '{}'", hook.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_remove("SHIT_DISABLE")
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read_to_string(&log).expect("session-open was not sent")
}

fn tty_value(args: &str) -> String {
    let lines: Vec<&str> = args.lines().collect();
    let i = lines.iter().position(|l| *l == "--tty").expect("--tty");
    lines.get(i + 1).copied().unwrap_or("<missing>").to_string()
}

fn check(shell: ShellKind, interp: &str) {
    if !have(interp) {
        eprintln!("skip: {interp} not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("shit-tty-guard-{interp}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let args = session_open_args(shell, interp, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(tty_value(&args), "", "args were:\n{args}");
}

#[test]
fn bash_hook_sends_empty_tty_without_a_tty() {
    check(ShellKind::Bash, "bash");
}

#[test]
fn zsh_hook_sends_empty_tty_without_a_tty() {
    check(ShellKind::Zsh, "zsh");
}
