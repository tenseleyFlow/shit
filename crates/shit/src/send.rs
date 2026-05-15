// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use clap::Subcommand;
use shit_proto::{HookMessage, ShellKind, encode_frame};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Subcommand)]
pub enum HookSendKind {
    SessionOpen {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        pid: u32,
        #[arg(long, value_parser = parse_shell)]
        shell: ShellKind,
        #[arg(long)]
        tty: String,
        #[arg(long)]
        sock: PathBuf,
    },
    PreExec {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long, value_parser = parse_shell)]
        shell: ShellKind,
        #[arg(long, default_value_t = 1)]
        depth: u8,
        #[arg(long)]
        sock: PathBuf,
    },
    PostExec {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        exit_code: i32,
        #[arg(long)]
        sock: PathBuf,
    },
    SessionClose {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        sock: PathBuf,
    },
}

fn parse_shell(s: &str) -> Result<ShellKind, String> {
    ShellKind::from_str(s).map_err(|e| e.to_string())
}

fn ts_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub fn run(kind: HookSendKind) -> Result<()> {
    let (msg, sock) = match kind {
        HookSendKind::SessionOpen {
            session,
            pid,
            shell,
            tty,
            sock,
        } => (
            HookMessage::SessionOpen {
                session,
                shell_kind: shell,
                parent_pid: pid,
                tty,
                ts_unix_nanos: ts_now(),
            },
            sock,
        ),
        HookSendKind::PreExec {
            session,
            seq,
            pid,
            cwd,
            shell,
            depth,
            sock,
        } => {
            let (cwd_dev, cwd_inode) = stat_cwd(&cwd).unwrap_or((0, 0));
            (
                HookMessage::PreExec {
                    session,
                    seq,
                    pid,
                    cwd_inode,
                    cwd_dev,
                    ts_unix_nanos: ts_now(),
                    shell_kind: shell,
                    depth,
                },
                sock,
            )
        }
        HookSendKind::PostExec {
            session,
            seq,
            exit_code,
            sock,
        } => (
            HookMessage::PostExec {
                session,
                seq,
                exit_code,
                ts_unix_nanos: ts_now(),
            },
            sock,
        ),
        HookSendKind::SessionClose { session, sock } => (
            HookMessage::SessionClose {
                session,
                ts_unix_nanos: ts_now(),
            },
            sock,
        ),
    };
    send_message(&sock, &msg)
}

fn stat_cwd(cwd: &std::path::Path) -> Option<(u64, u64)> {
    let md = std::fs::metadata(cwd).ok()?;
    Some((md.dev(), md.ino()))
}

fn send_message(sock_path: &std::path::Path, msg: &HookMessage) -> Result<()> {
    let frame = encode_frame(msg).context("encode frame")?;
    let client = UnixDatagram::unbound().context("UnixDatagram::unbound")?;
    client
        .send_to(&frame, sock_path)
        .with_context(|| format!("send_to {}", sock_path.display()))?;
    Ok(())
}
