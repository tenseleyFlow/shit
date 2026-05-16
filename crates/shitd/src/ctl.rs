// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control-socket listener. SEQPACKET preserves message boundaries; one
//! request → one reply per accepted connection. Concurrent clients are each
//! served on their own tokio task.

use crate::config::ResolvedConfig;
use crate::stats::Stats;
use shit_proto::{CtlRequest, CtlResponse, DaemonStatus, decode_frame, encode_frame};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

const CTL_BUF: usize = 4096;

/// Listen on `cfg.ctl_socket_path`, serving each connection on a task.
/// `shutdown` is notified to ask the main runtime to exit; the listener
/// itself does not exit until cancelled by the runtime stopping.
pub async fn serve(
    cfg: &ResolvedConfig,
    stats: Arc<Stats>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    if let Some(parent) = cfg.ctl_socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if Path::new(&cfg.ctl_socket_path).exists() {
        let _ = std::fs::remove_file(&cfg.ctl_socket_path);
    }
    // tokio doesn't expose SEQPACKET directly; we use SOCK_STREAM here, which
    // is fine because we frame every message with the length prefix. SEQPACKET
    // would buy us boundary preservation we don't need.
    let listener = tokio::net::UnixListener::bind(&cfg.ctl_socket_path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg.ctl_socket_path, std::fs::Permissions::from_mode(0o600))?;
    info!(path = %cfg.ctl_socket_path.display(), "ctl listening");

    let cfg = cfg.clone();
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, &cfg, stats, shutdown).await {
                        debug!(err = %e, "ctl client errored");
                    }
                });
            }
            Err(e) => {
                warn!(err = %e, "ctl accept failed");
            }
        }
    }
}

async fn handle_client(
    mut stream: UnixStream,
    cfg: &ResolvedConfig,
    stats: Arc<Stats>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; CTL_BUF];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req: CtlRequest = match decode_frame(&buf[..n]) {
        Ok(r) => r,
        Err(e) => {
            let frame = encode_frame(&CtlResponse::Error(format!("decode: {e}")))?;
            stream.write_all(&frame).await?;
            return Ok(());
        }
    };

    let resp = match req {
        CtlRequest::Ping => CtlResponse::Pong,
        CtlRequest::Status => CtlResponse::Status(snapshot(cfg, &stats)),
        CtlRequest::Shutdown => {
            shutdown.notify_one();
            CtlResponse::ShutdownAcked
        }
    };
    let frame = encode_frame(&resp)?;
    stream.write_all(&frame).await?;
    Ok(())
}

fn snapshot(cfg: &ResolvedConfig, stats: &Stats) -> DaemonStatus {
    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("VERGEN_GIT_SHA").to_string(),
        // SAFETY: getpid always succeeds.
        pid: unsafe { libc::getpid() } as u32,
        uptime_secs: stats.started_at.elapsed().as_secs(),
        idle_for_secs: stats.idle_for().as_secs(),
        idle_timeout_secs: cfg.idle_timeout_secs,
        hook_socket_path: cfg.hook_socket_path.display().to_string(),
        ctl_socket_path: cfg.ctl_socket_path.display().to_string(),
        hook_messages_received: stats.hook_msgs.load(std::sync::atomic::Ordering::Relaxed),
        hook_decode_errors: stats
            .hook_decode_errors
            .load(std::sync::atomic::Ordering::Relaxed),
    }
}
