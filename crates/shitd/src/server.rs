// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::ResolvedConfig;
use crate::env_track::{self, EnvPreStash};
use crate::stats::Stats;
use shit_planner::{CommandId, CommandRecord, TimePoint};
use shit_proto::{HookMessage, MAX_FRAME_SIZE, decode_frame};
use shit_store::Index;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UnixDatagram;
use tracing::{debug, info, warn};

const IDLE_TICK_MAX: Duration = Duration::from_secs(60);
const IDLE_TICK_MIN: Duration = Duration::from_millis(100);

fn idle_tick(idle_timeout: Duration) -> Duration {
    (idle_timeout / 4).clamp(IDLE_TICK_MIN, IDLE_TICK_MAX)
}

/// Process-wide monotonic logical clock. Incremented for every event
/// ingested. Resets to 0 on daemon restart, which is fine: each restart
/// starts a fresh event sequence and the planner only orders within a
/// session anyway.
static LOGICAL_CLOCK: AtomicU64 = AtomicU64::new(1);

fn next_ts() -> TimePoint {
    let logical = LOGICAL_CLOCK.fetch_add(1, Ordering::Relaxed);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    TimePoint::new(logical, wall)
}

pub async fn serve(
    cfg: ResolvedConfig,
    stats: Arc<Stats>,
    index: Arc<Index>,
    env_stash: Arc<EnvPreStash>,
) -> anyhow::Result<()> {
    let env_filter = cfg.env.filter();
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

    let idle_disabled = cfg.idle_timeout_secs == 0;
    let idle_timeout = Duration::from_secs(cfg.idle_timeout_secs);
    let tick = if idle_disabled {
        Duration::from_secs(3600)
    } else {
        idle_tick(idle_timeout)
    };
    if idle_disabled {
        info!("idle-down disabled (idle_timeout_secs = 0)");
    }
    let mut buf = vec![0u8; MAX_FRAME_SIZE];

    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((n, _peer)) => {
                        match decode_frame::<HookMessage>(&buf[..n]) {
                            Ok(msg) => {
                                stats.note_hook_msg();
                                handle(msg, &index, &env_stash, &env_filter);
                            }
                            Err(e) => {
                                stats.note_decode_error();
                                warn!(err = %e, len = n, "decode failed");
                            }
                        }
                    }
                    Err(e) => warn!(err = %e, "recv_from failed"),
                }
            }
            _ = tokio::time::sleep(tick) => {
                if idle_disabled { continue; }
                let idle = stats.idle_for();
                if idle >= idle_timeout {
                    info!(
                        idle_for_secs = idle.as_secs(),
                        timeout_secs = idle_timeout.as_secs(),
                        "idle timeout; exiting"
                    );
                    return Ok(());
                }
            }
        }
    }
}

fn handle(
    msg: HookMessage,
    index: &Index,
    env_stash: &EnvPreStash,
    env_filter: &shit_planner::EnvFilter,
) {
    let session = msg.session();
    let kind = msg.kind();
    let ts = next_ts();

    match &msg {
        HookMessage::SessionOpen {
            shell_kind,
            parent_pid,
            tty,
            ..
        } => {
            info!(
                %session,
                kind,
                shell = shell_kind.as_str(),
                pid = parent_pid,
                tty,
                "session open"
            );
            if let Err(e) = index.put_session(
                session,
                shell_kind.as_str(),
                *parent_pid,
                Some(tty.as_str()),
                ts,
            ) {
                warn!(err = %e, "put_session failed");
            }
        }
        HookMessage::PreExec {
            seq,
            pid,
            cwd_inode,
            cwd_dev,
            shell_kind,
            ..
        } => {
            info!(
                %session,
                kind,
                seq,
                pid,
                cwd_dev,
                cwd_inode,
                shell = shell_kind.as_str(),
                "pre-exec"
            );
            let cmd = CommandRecord {
                command: CommandId { session, seq: *seq },
                cmd_string: None,
                cwd: PathBuf::from("/"),
                pid: *pid,
                shell_kind: *shell_kind,
                started_at: ts,
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            };
            if let Err(e) = index.put_command(&cmd) {
                warn!(err = %e, "put_command failed");
            }
        }
        HookMessage::PostExec { seq, exit_code, .. } => {
            info!(%session, kind, seq, exit_code, "post-exec");
            // Update via re-put: ON CONFLICT replaces ended_at + exit_code.
            // We don't know the original started_at from this side of the
            // ledger; fetch the existing command to preserve it.
            if let Some(mut existing) = <Index as shit_planner::PlannerStore>::command_by_id(
                index,
                CommandId { session, seq: *seq },
            ) {
                existing.ended_at = Some(ts);
                existing.exit_code = Some(*exit_code);
                if let Err(e) = index.put_command(&existing) {
                    warn!(err = %e, "put_command (post) failed");
                }
            }
        }
        HookMessage::PreExecEnv { seq, env_hash, .. } => {
            debug!(%session, kind, seq, hash = %hex8(env_hash), "pre-exec-env");
            env_track::handle_pre(env_stash, CommandId { session, seq: *seq }, *env_hash);
        }
        HookMessage::PostExecEnv { seq, env_block, .. } => {
            debug!(%session, kind, seq, bytes = env_block.len(), "post-exec-env");
            let _ = env_track::handle_post(
                env_stash,
                CommandId { session, seq: *seq },
                env_block,
                env_filter,
            );
            // The PostOutcome is logged inside handle_post; the
            // journal-write integration is DR-32.
        }
        HookMessage::SessionClose { .. } => {
            info!(%session, kind, "session close");
            if let Err(e) = index.close_session(session, ts) {
                warn!(err = %e, "close_session failed");
            }
        }
    }
    debug!(?msg, "decoded frame");
}

/// Stable short hash rendering for log lines — first 8 hex chars of
/// a 32-byte blake3 digest. The full digest is preserved by the
/// daemon; logs just need a glance-friendly identifier.
fn hex8(h: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &h[..4] {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
