// SPDX-License-Identifier: AGPL-3.0-or-later

use shit_proto::{HookMessage, MAX_FRAME_SIZE, decode_frame};
use std::path::{Path, PathBuf};
use tokio::net::UnixDatagram;
use tracing::{debug, info, warn};

pub async fn serve(sock_path: PathBuf) -> anyhow::Result<()> {
    // Best-effort: remove a stale socket file from a prior daemon.
    if Path::new(&sock_path).exists() {
        let _ = std::fs::remove_file(&sock_path);
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sock = UnixDatagram::bind(&sock_path)?;
    // 0700 — owner-only. Defense in depth; the parent dir's perms already cover the common case.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    info!(path = %sock_path.display(), "listening");

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
