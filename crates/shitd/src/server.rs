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
const UNWATCH_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Commands whose helper barrier/local finalization is still in progress.
/// Keeping this separate from `ActiveCommands` lets a later PreExec on the
/// same shell fail closed instead of racing the predecessor's xattr sweep.
#[derive(Debug, Default)]
struct ClosingCommands {
    inner: std::sync::Mutex<std::collections::BTreeMap<CommandId, u32>>,
}

/// Commands that must remain open because the daemon could not durably record
/// a pre-exec capture refusal. An open command is omitted from normal undo
/// listings, which is the only safe outcome when neither capture nor its
/// refusal can be proven durable.
#[derive(Debug, Default)]
pub(crate) struct FinalizationBlocks {
    inner: std::sync::Mutex<std::collections::BTreeMap<CommandId, String>>,
}

impl FinalizationBlocks {
    pub(crate) fn insert(&self, command: CommandId, detail: String) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(command)
            .or_insert(detail);
    }

    pub(crate) fn get(&self, command: CommandId) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&command)
            .cloned()
    }

    pub(crate) fn clear(&self, command: CommandId) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&command);
    }
}

impl ClosingCommands {
    fn begin(self: &Arc<Self>, command: CommandId, shell_pid: u32) -> Option<ClosingGuard> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.contains_key(&command) {
            return None;
        }
        inner.insert(command, shell_pid);
        Some(ClosingGuard {
            commands: Arc::clone(self),
            command,
        })
    }

    fn command_for_shell(&self, shell_pid: u32) -> Option<CommandId> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find_map(|(command, pid)| (*pid == shell_pid).then_some(*command))
    }

    fn finish(&self, command: CommandId) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&command);
    }
}

struct ClosingGuard {
    commands: Arc<ClosingCommands>,
    command: CommandId,
}

impl Drop for ClosingGuard {
    fn drop(&mut self) {
        self.commands.finish(self.command);
    }
}

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
    finalization_blocks: Arc<FinalizationBlocks>,
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
    let mut close_tasks = tokio::task::JoinSet::new();
    let closing_commands = Arc::new(ClosingCommands::default());
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
                                handle(
                                    msg,
                                    &index,
                                    &env_stash,
                                    &shell_state_stash,
                                    &env_filter,
                                    &active,
                                    helper_link.as_ref(),
                                    watch_ready.as_ref(),
                                    &live_baseline,
                                    &closing_commands,
                                    &finalization_blocks,
                                    &mut close_tasks,
                                );
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
            completed = close_tasks.join_next(), if !close_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::error!(%error, "post-exec finalization task panicked");
                }
            }
            _ = tokio::time::sleep(tick) => {
                if idle_disabled { continue; }
                let idle = stats.idle_for();
                if idle >= idle_timeout && close_tasks.is_empty() {
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

#[allow(clippy::too_many_arguments)]
fn handle(
    msg: HookMessage,
    index: &Arc<Index>,
    env_stash: &EnvPreStash,
    shell_state_stash: &crate::shell_state_track::ShellStatePreStash,
    env_filter: &shit_planner::EnvFilter,
    active: &Arc<ActiveCommands>,
    helper_link: Option<&Arc<HelperLink>>,
    watch_ready: Option<&Arc<crate::watch_ready::WatchReadyMap>>,
    live_baseline: &Arc<crate::baseline::LiveBaseline>,
    closing_commands: &Arc<ClosingCommands>,
    finalization_blocks: &Arc<FinalizationBlocks>,
    close_tasks: &mut tokio::task::JoinSet<()>,
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
                if let Some(map) = watch_ready {
                    map.mark_failed(
                        command,
                        format!("command journal initialization failed: {e}"),
                    );
                }
                active.remove_command(command);
                return;
            }
            // Do not let the next command's watch become ready while this
            // shell's predecessor is still doing its local post-capture sweep.
            // Hooks are fail-open, so the overlapping command is durably
            // refused instead of being attached across an ambiguous boundary.
            if let Some(previous) = closing_commands.command_for_shell(*pid) {
                let detail = format!(
                    "previous command {previous} is still finalizing capture; refusing overlapping command window"
                );
                if let Some(map) = watch_ready {
                    map.mark_failed(command, detail.clone());
                }
                if let Err(error) = crate::helper_link::journal_helper_capture_refused(
                    index,
                    command,
                    Some(PathBuf::from(cwd_path)),
                    detail,
                ) {
                    finalization_blocks.insert(
                        command,
                        format!("overlapping-command refusal was not durable: {error}"),
                    );
                    tracing::error!(
                        %error,
                        %command,
                        %previous,
                        "overlapping-command CaptureRefused journal failed"
                    );
                }
            // S24.C: tell the privileged helper to start watching the
            // command's process tree. The kqueue producer (FreeBSD)
            // and the fanotify producer (Linux) both consume this.
            // B05.10: forward cwd_path so the helper doesn't need
            // cross-pid sysctl(KERN_PROC_CWD) (blocked under cap_enter).
            } else if let Some(link) = helper_link {
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
                    if let Some(map) = watch_ready {
                        map.mark_failed(command, format!("WatchTree dispatch failed: {e}"));
                    }
                    if let Err(journal_err) = crate::helper_link::journal_helper_capture_refused(
                        index,
                        command,
                        Some(PathBuf::from(cwd_path)),
                        format!("capture watch dispatch failed before command execution: {e}"),
                    ) {
                        finalization_blocks.insert(
                            command,
                            format!("watch-dispatch refusal was not durable: {journal_err}"),
                        );
                        warn!(
                            err = %journal_err,
                            %session,
                            seq,
                            "WatchTree dispatch CaptureRefused journal failed"
                        );
                    }
                }
            } else {
                let detail = "no privileged capture helper was connected before command execution"
                    .to_string();
                if let Some(map) = watch_ready {
                    map.mark_failed(command, detail.clone());
                }
                if let Err(e) = crate::helper_link::journal_helper_capture_refused(
                    index,
                    command,
                    Some(PathBuf::from(cwd_path)),
                    detail,
                ) {
                    finalization_blocks.insert(
                        command,
                        format!("missing-helper refusal was not durable: {e}"),
                    );
                    warn!(
                        err = %e,
                        %session,
                        seq,
                        "no-helper CaptureRefused journal failed"
                    );
                }
            }
        }
        HookMessage::PostExec { seq, exit_code, .. } => {
            info!(%session, kind, seq, exit_code, "post-exec");
            let command = CommandId { session, seq: *seq };
            let existing =
                <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), command);
            if existing
                .as_ref()
                .is_some_and(|record| record.ended_at.is_some())
            {
                tracing::warn!(%command, "ignoring duplicate PostExec for finalized command");
            } else {
                let shell_pid = existing
                    .as_ref()
                    .map(|record| record.pid)
                    .or_else(|| active.shell_pid_for(command))
                    .unwrap_or(0);
                if let Some(closing_guard) = closing_commands.begin(command, shell_pid) {
                    // Install the waiter and write UnwatchTree synchronously in
                    // hook arrival order. Only the bounded wait/finalization
                    // moves to a task, so later PreExec datagrams remain
                    // responsive without being reordered ahead of this request.
                    let pending = helper_link.map(|link| link.begin_unwatch_tree(command));
                    close_tasks.spawn(finalize_post_exec(
                        command,
                        *exit_code,
                        existing,
                        pending,
                        Arc::clone(index),
                        Arc::clone(active),
                        watch_ready.map(Arc::clone),
                        Arc::clone(live_baseline),
                        Arc::clone(finalization_blocks),
                        closing_guard,
                    ));
                } else {
                    tracing::warn!(%command, "ignoring duplicate PostExec while close is pending");
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

#[allow(clippy::too_many_arguments)]
async fn finalize_post_exec(
    command: CommandId,
    exit_code: i32,
    mut existing: Option<CommandRecord>,
    pending: Option<
        Result<crate::helper_link::PendingUnwatch, crate::helper_link::UnwatchTreeError>,
    >,
    index: Arc<Index>,
    active: Arc<ActiveCommands>,
    watch_ready: Option<Arc<crate::watch_ready::WatchReadyMap>>,
    live_baseline: Arc<crate::baseline::LiveBaseline>,
    finalization_blocks: Arc<FinalizationBlocks>,
    _closing_guard: ClosingGuard,
) {
    let completion_error = match pending {
        Some(Ok(pending)) => pending.wait(UNWATCH_FLUSH_TIMEOUT).await.err(),
        Some(Err(error)) => Some(error),
        None => Some(crate::helper_link::UnwatchTreeError::HelperStopped(
            "no privileged capture helper was connected at command close".to_string(),
        )),
    };

    let pre_exec_durability_failure = finalization_blocks.get(command);
    let may_finalize = if let Some(detail) = pre_exec_durability_failure {
        // Retry the failed pre-exec refusal at command close. The block stays
        // sticky across duplicate PostExec datagrams until this write really
        // succeeds; consuming it before durability would allow a later retry
        // to expose an uncaptured command.
        match crate::helper_link::journal_helper_capture_refused(
            index.as_ref(),
            command,
            existing.as_ref().map(|record| record.cwd.clone()),
            detail.clone(),
        ) {
            Ok(()) => {
                finalization_blocks.clear(command);
                true
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    %command,
                    %detail,
                    "pre-exec capture refusal remains non-durable; leaving command unfinalized"
                );
                false
            }
        }
    } else if let Some(error) = completion_error {
        let detail = format!("capture completion could not be proven at command close: {error}");
        warn!(%error, %command, "UnwatchTree completion failed");
        match crate::helper_link::journal_helper_capture_refused(
            index.as_ref(),
            command,
            existing.as_ref().map(|record| record.cwd.clone()),
            detail,
        ) {
            Ok(()) => true,
            Err(journal_error) => {
                // An open command is deliberately omitted from normal undo
                // listings. Do not turn it into a seemingly complete command
                // when even the refusal could not be made durable.
                tracing::error!(
                    err = %journal_error,
                    %command,
                    "UnwatchTree refusal was not durable; leaving command unfinalized"
                );
                false
            }
        }
    } else {
        true
    };

    if may_finalize && let Some(existing) = existing.as_mut() {
        // W09.21.1 — daemon-side xattr post-sweep. This intentionally
        // runs after the helper barrier so its final comparison cannot
        // overtake queued platform capture responses.
        let sweep_durable = match crate::xattr::post_exec_sweep(
            &existing.cwd,
            command,
            live_baseline.as_ref(),
            index.as_ref(),
        ) {
            Ok(_) => true,
            Err(error) => {
                tracing::error!(
                    %error,
                    %command,
                    "xattr sweep refusal was not durable; leaving command unfinalized"
                );
                false
            }
        };

        if sweep_durable {
            // Allocate the close timestamp after the barrier so all drained
            // capture events precede durable command finalization.
            existing.ended_at = Some(next_ts());
            existing.exit_code = Some(exit_code);
            if let Err(error) = index.put_command(existing) {
                tracing::error!(%error, %command, "put_command (post) failed; command remains unfinalized");
            }
        }
    }

    active.remove_command(command);
    if let Some(map) = watch_ready {
        map.forget(command);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use uuid::Uuid;

    fn command(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    #[test]
    fn closing_gate_rejects_duplicate_and_fences_same_shell_until_drop() {
        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command(1), 4242).expect("first close");
        assert!(closing.begin(command(1), 4242).is_none());
        assert_eq!(closing.command_for_shell(4242), Some(command(1)));

        drop(guard);

        assert_eq!(closing.command_for_shell(4242), None);
        assert!(closing.begin(command(1), 4242).is_some());
    }

    #[test]
    fn finalization_block_is_sticky_until_explicitly_cleared() {
        let blocks = FinalizationBlocks::default();
        blocks.insert(command(1), "first failure".into());
        blocks.insert(command(1), "later failure".into());
        blocks.insert(command(2), "other command".into());

        assert_eq!(blocks.get(command(1)).as_deref(), Some("first failure"));
        assert_eq!(blocks.get(command(1)).as_deref(), Some("first failure"));
        blocks.clear(command(1));
        assert!(blocks.get(command(1)).is_none());
        assert_eq!(blocks.get(command(2)).as_deref(), Some("other command"));
    }
}
