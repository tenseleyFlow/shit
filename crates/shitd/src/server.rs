// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::active_commands::ActiveCommands;
use crate::config::ResolvedConfig;
use crate::env_track::{self, EnvPreStash};
use crate::helper_link::HelperLink;
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

pub(crate) fn next_ts() -> TimePoint {
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
    active: Arc<ActiveCommands>,
    helper_link: Option<Arc<HelperLink>>,
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
                        // S21.4 — record hook-handling latency so
                        // `shit metrics` can surface p50/p99. The
                        // timer brackets decode + handle.
                        let started = std::time::Instant::now();
                        match decode_frame::<HookMessage>(&buf[..n]) {
                            Ok(msg) => {
                                stats.note_hook_msg();
                                handle(msg, &index, &env_stash, &env_filter, &active, helper_link.as_deref());
                            }
                            Err(e) => {
                                stats.note_decode_error();
                                warn!(err = %e, len = n, "decode failed");
                            }
                        }
                        stats.note_hook_latency_us(started.elapsed().as_micros() as u64);
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
    active: &ActiveCommands,
    helper_link: Option<&HelperLink>,
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
            let command = CommandId { session, seq: *seq };
            // DR-25: register the active command so tier-event
            // handlers can attribute pkg/env/svc/net/proc/db events
            // to it. The shell-pid (`pid`) is the lookup key; tier
            // events arrive with the helper or wrapper pid and walk
            // ancestors to find this one.
            active.insert(*pid, command);
            let cmd = CommandRecord {
                command,
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
            // S24.C: tell the privileged helper to start watching the
            // command's process tree. The kqueue producer (FreeBSD)
            // and the fanotify producer (Linux) both consume this.
            if let Some(link) = helper_link {
                let req = shit_proto::HelperRequest::WatchTree {
                    root_pid: *pid,
                    descendants_too: true,
                    session: command.session,
                    command_seq: command.seq,
                    shell_kind: *shell_kind,
                };
                if let Err(e) = link.send_request(&req) {
                    warn!(err = %e, "WatchTree dispatch to helper failed");
                }
            }
        }
        HookMessage::PostExec { seq, exit_code, .. } => {
            info!(%session, kind, seq, exit_code, "post-exec");
            let command = CommandId { session, seq: *seq };
            // Update via re-put: ON CONFLICT replaces ended_at + exit_code.
            // We don't know the original started_at from this side of the
            // ledger; fetch the existing command to preserve it.
            if let Some(mut existing) =
                <Index as shit_planner::PlannerStore>::command_by_id(index, command)
            {
                // DR-25: drain the active map entry now that the
                // command is closed. `existing.pid` is the shell pid
                // from the matching PreExec.
                active.remove(existing.pid, command);
                existing.ended_at = Some(ts);
                existing.exit_code = Some(*exit_code);
                if let Err(e) = index.put_command(&existing) {
                    warn!(err = %e, "put_command (post) failed");
                }
            }
            // S24.C: tell the helper to stop watching this command's
            // tree. CapturedPreImage events for this (session, seq)
            // that arrive after the helper acks UnwatchTree are
            // dropped by the producer.
            if let Some(link) = helper_link {
                let req = shit_proto::HelperRequest::UnwatchTree {
                    session,
                    command_seq: *seq,
                };
                if let Err(e) = link.send_request(&req) {
                    warn!(err = %e, "UnwatchTree dispatch to helper failed");
                }
            }
        }
        HookMessage::PreExecEnv { seq, env_block, .. } => {
            debug!(%session, kind, seq, bytes = env_block.len(), "pre-exec-env");
            env_track::handle_pre(
                env_stash,
                CommandId { session, seq: *seq },
                env_block.clone(),
            );
        }
        HookMessage::PostExecEnv { seq, env_block, .. } => {
            debug!(%session, kind, seq, bytes = env_block.len(), "post-exec-env");
            let _ = env_track::handle_post(
                env_stash,
                CommandId { session, seq: *seq },
                env_block,
                env_filter,
                index,
            );
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
