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

/// A hook frame plus how many times it has been deferred waiting for
/// its `commands` row (see [`ROW_RETRY_MAX`]).
pub type HookEnvelope = (HookMessage, u8);

/// A frame that journals against a command (`PostExec*`) can arrive
/// before the `PreExec` that creates the row: the two travel on
/// different sockets when `PreExec` was oversize. Re-queue it every
/// `ROW_RETRY_DELAY` for up to `ROW_RETRY_MAX` times (1 s total) before
/// handling it anyway and letting the handler log the failure.
const ROW_RETRY_DELAY: Duration = Duration::from_millis(50);
const ROW_RETRY_MAX: u8 = 20;

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

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    cfg: ResolvedConfig,
    stats: Arc<Stats>,
    index: Arc<Index>,
    env_stash: Arc<EnvPreStash>,
    shell_state_stash: Arc<crate::shell_state_track::ShellStatePreStash>,
    active: Arc<ActiveCommands>,
    helper_link: Option<Arc<HelperLink>>,
    watch_ready: Option<Arc<crate::watch_ready::WatchReadyMap>>,
    live_baseline: Arc<crate::baseline::LiveBaseline>,
    hook_tx: tokio::sync::mpsc::UnboundedSender<HookEnvelope>,
    mut hook_rx: tokio::sync::mpsc::UnboundedReceiver<HookEnvelope>,
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

    // One consumer for both transports (datagram socket and
    // `CtlRequest::Hook` via `hook_rx`), so every frame is handled by
    // `handle` on this task, in arrival order, with the same stats.
    let dispatch = |msg: HookMessage, attempt: u8| {
        let started = std::time::Instant::now();
        if let Some(id) = needs_command_row(&msg)
            && !matches!(index.command_exists(id), Ok(true))
        {
            if attempt < ROW_RETRY_MAX {
                let tx = hook_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(ROW_RETRY_DELAY).await;
                    let _ = tx.send((msg, attempt + 1));
                });
                return;
            }
            warn!(
                session = %id.session,
                seq = id.seq,
                kind = msg.kind(),
                "no commands row after retries; handling anyway (journal write may fail)"
            );
        }
        stats.note_hook_msg();
        handle(
            msg,
            &index,
            &env_stash,
            &shell_state_stash,
            &env_filter,
            &active,
            helper_link.as_deref(),
            watch_ready.as_deref(),
            live_baseline.as_ref(),
        );
        stats.note_hook_latency_us(started.elapsed().as_micros() as u64);
    };

    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((n, _peer)) => match decode_frame::<HookMessage>(&buf[..n]) {
                        Ok(msg) => dispatch(msg, 0),
                        Err(e) => {
                            stats.note_decode_error();
                            warn!(err = %e, len = n, "decode failed");
                        }
                    },
                    Err(e) => warn!(err = %e, "recv_from failed"),
                }
            }
            Some((msg, attempt)) = hook_rx.recv() => dispatch(msg, attempt),
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

/// Frames whose handler journals an event against `(session, seq)`.
fn needs_command_row(msg: &HookMessage) -> Option<CommandId> {
    match msg {
        HookMessage::PostExec { session, seq, .. }
        | HookMessage::PostExecEnv { session, seq, .. }
        | HookMessage::PostExecShellState { session, seq, .. } => Some(CommandId {
            session: *session,
            seq: *seq,
        }),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle(
    msg: HookMessage,
    index: &Index,
    env_stash: &EnvPreStash,
    shell_state_stash: &crate::shell_state_track::ShellStatePreStash,
    env_filter: &shit_planner::EnvFilter,
    active: &ActiveCommands,
    helper_link: Option<&HelperLink>,
    watch_ready: Option<&crate::watch_ready::WatchReadyMap>,
    live_baseline: &crate::baseline::LiveBaseline,
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
            cwd_path,
            shell_kind,
            cmd_string,
            ..
        } => {
            info!(
                %session,
                kind,
                seq,
                pid,
                cwd_dev,
                cwd_inode,
                cwd_path = cwd_path.as_str(),
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
                // AU26: shell hooks ship `$BASH_COMMAND` (or the zsh
                // / fish equivalent) so the planner's refuse-list
                // match has the command string to operate on.
                cmd_string: cmd_string.clone(),
                cwd: PathBuf::from(cwd_path),
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
            // B05.10: forward cwd_path so the helper doesn't need
            // cross-pid sysctl(KERN_PROC_CWD) (blocked under cap_enter).
            if let Some(link) = helper_link {
                let req = shit_proto::HelperRequest::WatchTree {
                    root_pid: *pid,
                    descendants_too: true,
                    session: command.session,
                    command_seq: command.seq,
                    shell_kind: *shell_kind,
                    cwd_path: cwd_path.clone(),
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
                // W09.21.1 — daemon-side xattr post-sweep. The
                // helper can't observe xattr changes under
                // cap_enter (extattr_*_fd blocked at the syscall
                // level), so the daemon does a final diff between
                // LiveBaseline's cached xattrs and the on-disk
                // state, journaling MetadataChange events for any
                // path whose user-namespace xattrs drifted. See
                // `xattr::post_exec_sweep` for the why.
                crate::xattr::post_exec_sweep(&existing.cwd, command, live_baseline, index);
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
            // AR00.5 / task #105 — drop the readiness entry for this
            // CommandId. If no shell hook is waiting (typical case --
            // the wait completed before PostExec arrived), this is a
            // cheap map remove. If one IS waiting (stale shell hook,
            // racy teardown), its oneshot Receiver gets an Err and
            // the WaitWatchReady ctl call returns ready=false /
            // "canceled" -- the shell proceeds without waiting
            // forever.
            if let Some(map) = watch_ready {
                map.forget(CommandId { session, seq: *seq });
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
            match env_track::handle_post(
                env_stash,
                CommandId { session, seq: *seq },
                env_block,
                env_filter,
                index,
            ) {
                env_track::PostOutcome::Orphan => {
                    warn!(%session, seq, "post-exec-env dropped: no matching pre-exec-env");
                }
                outcome => debug!(%session, seq, ?outcome, "post-exec-env handled"),
            }
        }
        HookMessage::PreExecShellState {
            seq,
            pwd,
            opts,
            aliases,
            ..
        } => {
            debug!(
                %session, kind, seq,
                pwd = %pwd,
                n_opts = opts.len(),
                n_aliases = aliases.len(),
                "pre-exec-shell-state"
            );
            crate::shell_state_track::handle_pre(
                shell_state_stash,
                CommandId { session, seq: *seq },
                std::path::PathBuf::from(pwd),
                opts.clone(),
                aliases.clone(),
            );
        }
        HookMessage::PostExecShellState {
            seq,
            pwd,
            opts,
            aliases,
            ..
        } => {
            debug!(
                %session, kind, seq,
                pwd = %pwd,
                n_opts = opts.len(),
                n_aliases = aliases.len(),
                "post-exec-shell-state"
            );
            crate::shell_state_track::handle_post(
                shell_state_stash,
                CommandId { session, seq: *seq },
                std::path::PathBuf::from(pwd),
                opts.clone(),
                aliases.clone(),
                index,
                ts,
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
