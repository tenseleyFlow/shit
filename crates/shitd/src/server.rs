// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::ResolvedConfig;
use shit_proto::{HookMessage, MAX_FRAME_SIZE, decode_frame};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::net::UnixDatagram;
use tracing::{debug, info, warn};

/// Upper bound on the idle-check interval. We tick more often than this when
/// the configured timeout is small so short-timeout configs (and tests) don't
/// wait an entire ceiling-tick before noticing.
const IDLE_TICK_MAX: Duration = Duration::from_secs(60);
const IDLE_TICK_MIN: Duration = Duration::from_millis(100);

fn idle_tick(idle_timeout: Duration) -> Duration {
    (idle_timeout / 4).clamp(IDLE_TICK_MIN, IDLE_TICK_MAX)
}

pub async fn serve(cfg: ResolvedConfig) -> anyhow::Result<()> {
    if let Some(parent) = cfg.hook_socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(&cfg.state_dir)?;

    if Path::new(&cfg.hook_socket_path).exists() {
        let _ = std::fs::remove_file(&cfg.hook_socket_path);
    }
    let sock = UnixDatagram::bind(&cfg.hook_socket_path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        &cfg.hook_socket_path,
        std::fs::Permissions::from_mode(0o600),
    )?;
    info!(
        path = %cfg.hook_socket_path.display(),
        idle_timeout_secs = cfg.idle_timeout_secs,
        "listening"
    );

    let idle_timeout = Duration::from_secs(cfg.idle_timeout_secs);
    let tick = idle_tick(idle_timeout);
    let mut last_activity = Instant::now();
    let mut buf = vec![0u8; MAX_FRAME_SIZE];

    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((n, _peer)) => {
                        last_activity = Instant::now();
                        match decode_frame(&buf[..n]) {
                            Ok(msg) => handle(msg),
                            Err(e) => warn!(err = %e, len = n, "decode failed"),
                        }
                    }
                    Err(e) => warn!(err = %e, "recv_from failed"),
                }
            }
            _ = tokio::time::sleep(tick) => {
                if last_activity.elapsed() >= idle_timeout {
                    info!(
                        idle_for_secs = last_activity.elapsed().as_secs(),
                        timeout_secs = idle_timeout.as_secs(),
                        "idle timeout; exiting"
                    );
                    return Ok(());
                }
            }
        }
    }
}

fn handle(msg: HookMessage) {
    let kind = msg.kind();
    let session = msg.session();
    match &msg {
        HookMessage::SessionOpen {
            shell_kind,
            parent_pid,
            tty,
            ..
        } => info!(
            %session,
            kind,
            shell = shell_kind.as_str(),
            pid = parent_pid,
            tty,
            "session open"
        ),
        HookMessage::PreExec {
            seq,
            pid,
            cwd_inode,
            cwd_dev,
            shell_kind,
            ..
        } => info!(
            %session,
            kind,
            seq,
            pid,
            cwd_dev,
            cwd_inode,
            shell = shell_kind.as_str(),
            "pre-exec"
        ),
        HookMessage::PostExec { seq, exit_code, .. } => {
            info!(%session, kind, seq, exit_code, "post-exec")
        }
        HookMessage::SessionClose { .. } => info!(%session, kind, "session close"),
    }
    debug!(?msg, "decoded frame");
}
