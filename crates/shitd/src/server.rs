// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::ResolvedConfig;
use shit_proto::{HookMessage, MAX_FRAME_SIZE, decode_frame};
use std::path::Path;
use tokio::net::UnixDatagram;
use tracing::{debug, info, warn};

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
    info!(path = %cfg.hook_socket_path.display(), idle_timeout_secs = cfg.idle_timeout_secs, "listening");

    let mut buf = vec![0u8; MAX_FRAME_SIZE];
    loop {
        let (n, _peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "recv_from failed");
                continue;
            }
        };
        match decode_frame(&buf[..n]) {
            Ok(msg) => handle(msg),
            Err(e) => warn!(err = %e, len = n, "decode failed"),
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
