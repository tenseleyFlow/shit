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
const SHIM_INGEST_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FinalizationBlockToken(u64);

#[derive(Debug, Default)]
pub(crate) struct FinalizationBlocks {
    inner: std::sync::Mutex<
        std::collections::BTreeMap<
            CommandId,
            std::collections::BTreeMap<FinalizationBlockToken, String>,
        >,
    >,
    next_token: AtomicU64,
}

impl FinalizationBlocks {
    /// Install one independently-owned close block and return the token needed
    /// to clear only that block. Capture producers can overlap for the same
    /// command, so clearing by command here would erase an unrelated failure.
    pub(crate) fn insert(&self, command: CommandId, detail: String) -> FinalizationBlockToken {
        let token = FinalizationBlockToken(self.next_token.fetch_add(1, Ordering::Relaxed));
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(command)
            .or_default()
            .insert(token, detail);
        token
    }

    pub(crate) fn get(&self, command: CommandId) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&command)
            .and_then(|blocks| blocks.values().next())
            .cloned()
    }

    pub(crate) fn clear_token(&self, command: CommandId, token: FinalizationBlockToken) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove_command = if let Some(blocks) = inner.get_mut(&command) {
            blocks.remove(&token);
            blocks.is_empty()
        } else {
            false
        };
        if remove_command {
            inner.remove(&command);
        }
    }

    /// Clear every block for `command` only after a durable command-wide
    /// refusal has been written. Normal producers should use `clear_token`.
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
/// ingested. Startup seeds it past the durable global maximum before any
/// producer starts; resetting to 1 across daemon restart would move path
/// history and cross-command journal ordering backwards.
static LOGICAL_CLOCK: AtomicU64 = AtomicU64::new(1);

/// Advance the process clock to the first logical timestamp not already used
/// by durable state. Startup recovery calls this before any producer exists,
/// preventing a daemon restart from moving global/path-history ordering
/// backwards. `fetch_max` also makes tests and any future repeated seeding
/// monotonic.
pub(crate) fn seed_logical_clock(next_logical: u64) {
    LOGICAL_CLOCK.fetch_max(next_logical, Ordering::Relaxed);
}

/// Allocate one value from the daemon-wide logical timeline.
///
/// Event ingestion and logical-time consumers such as GC must use this same
/// allocator; independent counters diverge after restart and make retention
/// or path-history comparisons depend on subsystem activity rates.
pub(crate) fn next_logical() -> u64 {
    LOGICAL_CLOCK.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn next_ts() -> TimePoint {
    let logical = next_logical();
    TimePoint::new(logical, crate::clock::now().unix_nanos)
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
    shim_ingest: Arc<crate::shim_listener::ShimIngestTracker>,
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
                                    &shim_ingest,
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
    shim_ingest: &Arc<crate::shim_listener::ShimIngestTracker>,
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
            match index.begin_command(&cmd) {
                Ok(true) => {}
                Ok(false) => {
                    // An active duplicate reuses the original watch/readiness
                    // state. A replay of a completed identity is ignored. In
                    // neither case may PreExec reopen the durable row or send
                    // a second WatchTree that resets the capture window.
                    warn!(%command, "ignoring duplicate or replayed PreExec identity");
                    return;
                }
                Err(e) => {
                    warn!(err = %e, "begin_command failed");
                    if let Some(map) = watch_ready {
                        map.mark_failed(
                            command,
                            format!("command journal initialization failed: {e}"),
                        );
                    }
                    return;
                }
            }
            // DR-25: register the active command only after its durable,
            // insert-only begin. The shell-pid (`pid`) is the lookup key;
            // tier events walk ancestors to find this command.
            if !active.insert(*pid, command) {
                let detail =
                    "command identity was already active after a fresh journal begin".to_string();
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
                        format!("duplicate-active refusal was not durable: {error}"),
                    );
                }
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
                // Hook datagrams use a fresh sender socket per message, so
                // enqueue order alone is not a receive-side fence. Older
                // installed hooks also sent PostExec before their post-state
                // companions. If a known pre-snapshot is still outstanding,
                // make that uncertainty durable before close can begin.
                let env_post_pending = env_stash.contains(command);
                let shell_state_post_pending = shell_state_stash.contains(command);
                if env_post_pending || shell_state_post_pending {
                    let pending = match (env_post_pending, shell_state_post_pending) {
                        (true, true) => "environment and shell-state",
                        (true, false) => "environment",
                        (false, true) => "shell-state",
                        (false, false) => unreachable!(),
                    };
                    refuse_post_capture_or_block(
                        index,
                        finalization_blocks,
                        command,
                        format!(
                            "PostExec arrived while {pending} post-command capture was still pending"
                        ),
                    );
                }

                // Seal the pre-execution readiness proof at the command-close
                // boundary. A reordered/late WaitWatchReady that arrives while
                // the helper drain is pending must not retroactively prove the
                // command was protected before it executed.
                let wait_was_observed =
                    watch_ready.is_some_and(|map| map.wait_was_observed(command));
                let shell_pid = existing
                    .as_ref()
                    .map(|record| record.pid)
                    .or_else(|| active.shell_pid_for(command))
                    .unwrap_or(0);
                if let Some(closing_guard) = closing_commands.begin(command, shell_pid) {
                    // Seal shim registration synchronously in hook arrival
                    // order. The close task drains every decoded ticket at or
                    // below this watermark plus all attributed command work.
                    let shim_pending = shim_ingest.seal(command);
                    // Install the waiter and write UnwatchTree synchronously in
                    // hook arrival order. Only the bounded wait/finalization
                    // moves to a task, so later PreExec datagrams remain
                    // responsive without being reordered ahead of this request.
                    let pending = helper_link.map(|link| link.begin_unwatch_tree(command));
                    close_tasks.spawn(finalize_post_exec(
                        command,
                        *exit_code,
                        wait_was_observed,
                        existing,
                        pending,
                        shim_pending,
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
            let command = CommandId { session, seq: *seq };
            match env_track::handle_post(env_stash, command, env_block, env_filter, index) {
                env_track::PostOutcome::Orphan => refuse_post_capture_or_block(
                    index,
                    finalization_blocks,
                    command,
                    "environment post-capture had no matching pre-command snapshot".to_string(),
                ),
                env_track::PostOutcome::JournalFailed(error) => refuse_post_capture_or_block(
                    index,
                    finalization_blocks,
                    command,
                    format!("environment diff was not durable: {error}"),
                ),
                env_track::PostOutcome::Unchanged | env_track::PostOutcome::Changed { .. } => {}
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
            let command = CommandId { session, seq: *seq };
            match crate::shell_state_track::handle_post(
                shell_state_stash,
                command,
                std::path::PathBuf::from(pwd),
                opts.clone(),
                aliases.clone(),
                index,
                ts,
            ) {
                crate::shell_state_track::PostOutcome::Orphan => refuse_post_capture_or_block(
                    index,
                    finalization_blocks,
                    command,
                    "shell-state post-capture had no matching pre-command snapshot".to_string(),
                ),
                crate::shell_state_track::PostOutcome::JournalFailed(error) => {
                    refuse_post_capture_or_block(
                        index,
                        finalization_blocks,
                        command,
                        format!("shell-state diff was not durable: {error}"),
                    )
                }
                crate::shell_state_track::PostOutcome::Unchanged
                | crate::shell_state_track::PostOutcome::Changed => {}
            }
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

/// Convert a post-command companion-capture failure into a durable,
/// command-atomic refusal. If even that fallback cannot be written, install a
/// sticky close block before the queued PostExec can be handled.
fn refuse_post_capture_or_block(
    index: &Index,
    finalization_blocks: &FinalizationBlocks,
    command: CommandId,
    detail: String,
) {
    let path = <Index as shit_planner::PlannerStore>::command_by_id(index, command)
        .map(|record| record.cwd);
    if let Err(error) =
        crate::helper_link::journal_helper_capture_refused(index, command, path, detail.clone())
    {
        let block = format!(
            "post-command capture refusal was not durable: {error}; intended refusal: {detail}"
        );
        finalization_blocks.insert(command, block);
        tracing::error!(
            %error,
            %command,
            %detail,
            "post-command CaptureRefused journal failed; command close is blocked"
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_post_exec(
    command: CommandId,
    exit_code: i32,
    wait_was_observed: bool,
    existing: Option<CommandRecord>,
    pending: Option<
        Result<crate::helper_link::PendingUnwatch, crate::helper_link::UnwatchTreeError>,
    >,
    shim_pending: crate::shim_listener::PendingShimDrain,
    index: Arc<Index>,
    active: Arc<ActiveCommands>,
    watch_ready: Option<Arc<crate::watch_ready::WatchReadyMap>>,
    live_baseline: Arc<crate::baseline::LiveBaseline>,
    finalization_blocks: Arc<FinalizationBlocks>,
    _closing_guard: ClosingGuard,
) {
    let helper_completion = async move {
        match pending {
            Some(Ok(pending)) => pending.wait(UNWATCH_FLUSH_TIMEOUT).await.err(),
            Some(Err(error)) => Some(error),
            None => Some(crate::helper_link::UnwatchTreeError::HelperStopped(
                "no privileged capture helper was connected at command close".to_string(),
            )),
        }
    };
    let (completion_error, shim_completion_error) = tokio::join!(
        helper_completion,
        shim_pending.wait(SHIM_INGEST_FLUSH_TIMEOUT)
    );
    let shim_completion_error = shim_completion_error.err();
    if let Some(error) = completion_error.as_ref() {
        warn!(%error, %command, "UnwatchTree completion failed");
    }
    if let Some(error) = shim_completion_error.as_ref() {
        warn!(%error, %command, "shim ingest completion failed");
    }

    let required_refusal = finalization_blocks.get(command).or_else(|| {
        (!wait_was_observed).then(|| {
            "capture readiness was not proven by a successful WaitWatchReady before command execution"
                .to_string()
        })
    }).or_else(|| {
        shim_completion_error.as_ref().map(|error| {
            format!("shim capture completion could not be proven at command close: {error}")
        })
    }).or_else(|| {
        completion_error.as_ref().map(|error| {
            format!("capture completion could not be proven at command close: {error}")
        })
    });

    let may_finalize = if let Some(detail) = required_refusal {
        // Install the close gate before attempting the refusal. This is
        // especially important for a never-issued WaitWatchReady: there was no
        // earlier ctl request that could have created a durability block.
        finalization_blocks.insert(command, detail.clone());
        match crate::helper_link::journal_helper_capture_refused(
            index.as_ref(),
            command,
            existing.as_ref().map(|record| record.cwd.clone()),
            detail.clone(),
        ) {
            Ok(()) => {
                // Any durable command-scoped refusal makes the entire undo
                // fail closed, so it also resolves an older block reason.
                finalization_blocks.clear(command);
                true
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    %command,
                    %detail,
                    "required capture refusal remains non-durable; leaving command unfinalized"
                );
                false
            }
        }
    } else {
        true
    };

    if may_finalize && let Some(existing) = existing.as_ref() {
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
            match index.finish_command(command, next_ts(), exit_code) {
                Ok(true) => {}
                Ok(false) => tracing::error!(
                    %command,
                    "finish_command found no open row; refusing to resurrect or reopen command"
                ),
                Err(error) => {
                    tracing::error!(%error, %command, "finish_command failed; command remains unfinalized");
                }
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

    fn pre_exec(command: CommandId, pid: u32, cwd: &Path) -> HookMessage {
        HookMessage::PreExec {
            session: command.session,
            seq: command.seq,
            pid,
            cwd_inode: 1,
            cwd_dev: 1,
            cwd_path: cwd.to_string_lossy().into_owned(),
            ts_unix_nanos: 1,
            shell_kind: shit_proto::ShellKind::Bash,
            depth: 1,
            cmd_string: Some("test command".to_string()),
        }
    }

    fn open_command(index: &Index, command: CommandId, cwd: &Path, pid: u32) -> CommandRecord {
        index
            .put_session(command.session, "bash", pid, None, TimePoint::new(1, 1))
            .unwrap();
        let record = CommandRecord {
            command,
            cmd_string: Some("test command".to_string()),
            cwd: cwd.to_path_buf(),
            pid,
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(2, 2),
            ended_at: None,
            exit_code: None,
            event_ids: vec![],
        };
        assert!(index.begin_command(&record).unwrap());
        record
    }

    fn drained_shim(command: CommandId) -> crate::shim_listener::PendingShimDrain {
        Arc::new(crate::shim_listener::ShimIngestTracker::new()).seal(command)
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
    fn scoped_finalization_clear_preserves_another_producers_block() {
        let blocks = FinalizationBlocks::default();
        let first = blocks.insert(command(1), "first failure".into());
        blocks.insert(command(1), "later failure".into());
        blocks.insert(command(2), "other command".into());

        assert_eq!(blocks.get(command(1)).as_deref(), Some("first failure"));
        blocks.clear_token(command(1), first);
        assert_eq!(blocks.get(command(1)).as_deref(), Some("later failure"));
        blocks.clear(command(1));
        assert!(blocks.get(command(1)).is_none());
        assert_eq!(blocks.get(command(2)).as_deref(), Some("other command"));
    }

    #[test]
    fn post_capture_failure_is_made_durably_command_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path().join("index.sqlite")).unwrap();
        let command = command(11);
        open_command(&index, command, dir.path(), 4251);
        let blocks = FinalizationBlocks::default();

        refuse_post_capture_or_block(
            &index,
            &blocks,
            command,
            "shell-state post-capture had no matching pre-command snapshot".to_string(),
        );

        assert!(blocks.get(command).is_none());
        let events = <Index as shit_planner::PlannerStore>::events_for_command(&index, command);
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("shell-state post-capture")
            )
        }));
    }

    #[tokio::test]
    async fn postexec_refuses_when_post_capture_snapshots_are_still_pending() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = command(14);
        let record = open_command(index.as_ref(), command, dir.path(), 4254);
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let env_stash = EnvPreStash::new();
        env_track::handle_pre(&env_stash, command, b"FOO=before".to_vec());
        let shell_stash = crate::shell_state_track::ShellStatePreStash::new();
        crate::shell_state_track::handle_pre(
            &shell_stash,
            command,
            dir.path().to_path_buf(),
            Vec::new(),
            Vec::new(),
        );
        let mut close_tasks = tokio::task::JoinSet::new();

        handle(
            HookMessage::PostExec {
                session: command.session,
                seq: command.seq,
                exit_code: 0,
                ts_unix_nanos: 2,
            },
            &index,
            &env_stash,
            &shell_stash,
            &shit_planner::EnvFilter::default(),
            &active,
            None,
            None,
            &Arc::new(crate::baseline::LiveBaseline::new()),
            &Arc::new(crate::shim_listener::ShimIngestTracker::new()),
            &Arc::new(ClosingCommands::default()),
            &Arc::new(FinalizationBlocks::default()),
            &mut close_tasks,
        );

        let events =
            <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), command);
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("environment and shell-state post-command capture was still pending")
            )
        }));

        while let Some(result) = close_tasks.join_next().await {
            result.unwrap();
        }
    }

    #[test]
    fn orphan_shell_state_message_is_wired_to_command_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = command(13);
        open_command(index.as_ref(), command, dir.path(), 4253);
        let mut close_tasks = tokio::task::JoinSet::new();

        handle(
            HookMessage::PostExecShellState {
                session: command.session,
                seq: command.seq,
                pwd: dir.path().to_string_lossy().into_owned(),
                opts: Vec::new(),
                aliases: Vec::new(),
                ts_unix_nanos: 1,
            },
            &index,
            &EnvPreStash::new(),
            &crate::shell_state_track::ShellStatePreStash::new(),
            &shit_planner::EnvFilter::default(),
            &Arc::new(ActiveCommands::new()),
            None,
            None,
            &Arc::new(crate::baseline::LiveBaseline::new()),
            &Arc::new(crate::shim_listener::ShimIngestTracker::new()),
            &Arc::new(ClosingCommands::default()),
            &Arc::new(FinalizationBlocks::default()),
            &mut close_tasks,
        );

        let events =
            <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), command);
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("shell-state post-capture")
            )
        }));
        assert!(close_tasks.is_empty());
    }

    #[test]
    fn failed_post_capture_refusal_blocks_command_close() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(dir.path().join("index.sqlite")).unwrap();
        let command = command(12);
        open_command(&index, command, dir.path(), 4252);
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_post_capture_refusal
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'CaptureRefused'
                 BEGIN SELECT RAISE(FAIL, 'injected post-capture refusal failure'); END;",
            )
            .unwrap();
        let blocks = FinalizationBlocks::default();

        refuse_post_capture_or_block(
            &index,
            &blocks,
            command,
            "environment diff was not durable".to_string(),
        );

        assert!(
            blocks
                .get(command)
                .is_some_and(|detail| detail.contains("environment diff was not durable"))
        );
        assert!(
            <Index as shit_planner::PlannerStore>::events_for_command(&index, command).is_empty()
        );
    }

    #[tokio::test]
    async fn late_wait_after_postexec_snapshot_cannot_authorize_close() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = CommandId {
            session: Uuid::from_u128(0x51_17_01),
            seq: 1,
        };
        let record = open_command(index.as_ref(), command, dir.path(), 4242);
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let watch_ready = Arc::new(crate::watch_ready::WatchReadyMap::new());

        // PostExec snapshots this false. A reordered WaitWatchReady succeeds
        // only afterwards, while close would normally be draining the helper.
        let observed_at_postexec = watch_ready.wait_was_observed(command);
        assert!(watch_ready.mark_ready(command));
        assert!(watch_ready.await_ready(command).await.unwrap().is_ok());
        assert!(watch_ready.mark_wait_observed(command));
        assert!(watch_ready.wait_was_observed(command));

        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command, record.pid).unwrap();
        finalize_post_exec(
            command,
            0,
            observed_at_postexec,
            Some(record),
            None,
            drained_shim(command),
            Arc::clone(&index),
            active,
            Some(watch_ready),
            Arc::new(crate::baseline::LiveBaseline::new()),
            Arc::new(FinalizationBlocks::default()),
            guard,
        )
        .await;

        let events =
            <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), command);
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("WaitWatchReady")
            )
        }));
    }

    #[tokio::test]
    async fn observed_wait_snapshot_does_not_add_readiness_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = CommandId {
            session: Uuid::from_u128(0x51_17_05),
            seq: 5,
        };
        let record = open_command(index.as_ref(), command, dir.path(), 4246);
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let watch_ready = Arc::new(crate::watch_ready::WatchReadyMap::new());
        assert!(watch_ready.mark_ready(command));
        assert!(watch_ready.await_ready(command).await.unwrap().is_ok());
        assert!(watch_ready.mark_wait_observed(command));
        let observed_at_postexec = watch_ready.wait_was_observed(command);
        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command, record.pid).unwrap();

        finalize_post_exec(
            command,
            0,
            observed_at_postexec,
            Some(record),
            None,
            drained_shim(command),
            Arc::clone(&index),
            active,
            Some(watch_ready),
            Arc::new(crate::baseline::LiveBaseline::new()),
            Arc::new(FinalizationBlocks::default()),
            guard,
        )
        .await;

        let events =
            <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), command);
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("capture completion")
            )
        }));
        assert!(!events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("WaitWatchReady")
            )
        }));
    }

    #[tokio::test]
    async fn late_shim_registration_forces_a_durable_close_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = command(15);
        let record = open_command(index.as_ref(), command, dir.path(), 4255);
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let tracker = Arc::new(crate::shim_listener::ShimIngestTracker::new());
        let pending = tracker.seal(command);
        let registration = tracker.begin_decoded().attribute(command);
        assert!(registration.is_late());
        drop(registration);
        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command, record.pid).unwrap();

        finalize_post_exec(
            command,
            0,
            true,
            Some(record),
            None,
            pending,
            Arc::clone(&index),
            active,
            None,
            Arc::new(crate::baseline::LiveBaseline::new()),
            Arc::new(FinalizationBlocks::default()),
            guard,
        )
        .await;

        let events =
            <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), command);
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                shit_planner::CaptureEventKind::CaptureRefused { detail, .. }
                    if detail.contains("shim capture completion")
            )
        }));
        let stored =
            <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), command).unwrap();
        assert!(stored.ended_at.is_some());
    }

    #[tokio::test]
    async fn failed_late_shim_refusal_leaves_command_open_and_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = command(16);
        let record = open_command(index.as_ref(), command, dir.path(), 4256);
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_late_shim_refusal
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'CaptureRefused'
                 BEGIN SELECT RAISE(FAIL, 'injected late-shim refusal failure'); END;",
            )
            .unwrap();
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let tracker = Arc::new(crate::shim_listener::ShimIngestTracker::new());
        let pending = tracker.seal(command);
        let registration = tracker.begin_decoded().attribute(command);
        assert!(registration.is_late());
        drop(registration);
        let blocks = Arc::new(FinalizationBlocks::default());
        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command, record.pid).unwrap();

        finalize_post_exec(
            command,
            0,
            true,
            Some(record),
            None,
            pending,
            Arc::clone(&index),
            active,
            None,
            Arc::new(crate::baseline::LiveBaseline::new()),
            Arc::clone(&blocks),
            guard,
        )
        .await;

        assert!(
            blocks
                .get(command)
                .is_some_and(|detail| detail.contains("shim capture completion"))
        );
        let stored =
            <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), command).unwrap();
        assert!(stored.ended_at.is_none());
    }

    #[tokio::test]
    async fn missing_wait_refusal_failure_leaves_command_open_and_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = CommandId {
            session: Uuid::from_u128(0x51_17_02),
            seq: 2,
        };
        let record = open_command(index.as_ref(), command, dir.path(), 4243);
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_close_refusal
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'CaptureRefused'
                 BEGIN SELECT RAISE(FAIL, 'injected close refusal failure'); END;",
            )
            .unwrap();
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let blocks = Arc::new(FinalizationBlocks::default());
        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command, record.pid).unwrap();

        finalize_post_exec(
            command,
            0,
            false,
            Some(record),
            None,
            drained_shim(command),
            Arc::clone(&index),
            active,
            Some(Arc::new(crate::watch_ready::WatchReadyMap::new())),
            Arc::new(crate::baseline::LiveBaseline::new()),
            Arc::clone(&blocks),
            guard,
        )
        .await;

        assert!(blocks.get(command).is_some());
        let stored =
            <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), command).unwrap();
        assert!(stored.ended_at.is_none());
    }

    #[tokio::test]
    async fn failed_redirect_refusal_cannot_publish_a_complete_command() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let blobs = shit_store::BlobStore::open(dir.path().join("blobs")).unwrap();
        let command = command(17);
        let record = open_command(index.as_ref(), command, dir.path(), 4257);
        let target = dir.path().join("redirect-target-directory");
        std::fs::create_dir(&target).unwrap();
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_redirect_and_close_refusal
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'CaptureRefused'
                 BEGIN SELECT RAISE(FAIL, 'injected redirect refusal failure'); END;",
            )
            .unwrap();
        let active = Arc::new(ActiveCommands::new());
        assert!(active.insert(record.pid, command));
        let blocks = Arc::new(FinalizationBlocks::default());

        let response = crate::redirect_track::handle(
            command.session,
            command.seq,
            vec![shit_proto::RedirectTargetWire {
                op: shit_proto::RedirectOpWire::Truncate,
                path: target.to_string_lossy().into_owned(),
            }],
            active.as_ref(),
            index.as_ref(),
            &blobs,
            blocks.as_ref(),
        );
        assert!(matches!(response, shit_proto::CtlResponse::Error(_)));
        assert!(blocks.get(command).is_some());

        let closing = Arc::new(ClosingCommands::default());
        let guard = closing.begin(command, record.pid).unwrap();
        finalize_post_exec(
            command,
            0,
            true,
            Some(record),
            None,
            drained_shim(command),
            Arc::clone(&index),
            active,
            None,
            Arc::new(crate::baseline::LiveBaseline::new()),
            Arc::clone(&blocks),
            guard,
        )
        .await;

        assert!(blocks.get(command).is_some());
        let stored =
            <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), command).unwrap();
        assert!(stored.ended_at.is_none());
    }

    #[tokio::test]
    async fn replayed_preexec_does_not_reopen_finalized_command() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = CommandId {
            session: Uuid::from_u128(0x51_17_03),
            seq: 3,
        };
        let record = open_command(index.as_ref(), command, dir.path(), 4244);
        let ended_at = TimePoint::new(3, 3);
        assert!(index.finish_command(command, ended_at, 0).unwrap());

        let active = Arc::new(ActiveCommands::new());
        let watch_ready = Arc::new(crate::watch_ready::WatchReadyMap::new());
        let mut close_tasks = tokio::task::JoinSet::new();
        handle(
            pre_exec(command, record.pid, dir.path()),
            &index,
            &EnvPreStash::new(),
            &crate::shell_state_track::ShellStatePreStash::new(),
            &shit_planner::EnvFilter::default(),
            &active,
            None,
            Some(&watch_ready),
            &Arc::new(crate::baseline::LiveBaseline::new()),
            &Arc::new(crate::shim_listener::ShimIngestTracker::new()),
            &Arc::new(ClosingCommands::default()),
            &Arc::new(FinalizationBlocks::default()),
            &mut close_tasks,
        );

        let stored =
            <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), command).unwrap();
        assert_eq!(stored.ended_at, Some(ended_at));
        assert_eq!(stored.exit_code, Some(0));
        assert_eq!(active.active_command_count(), 0);
        assert!(close_tasks.is_empty());
    }

    #[tokio::test]
    async fn duplicate_active_preexec_does_not_duplicate_registration_or_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("index.sqlite")).unwrap());
        let command = CommandId {
            session: Uuid::from_u128(0x51_17_04),
            seq: 4,
        };
        index
            .put_session(command.session, "bash", 4245, None, TimePoint::new(1, 1))
            .unwrap();
        let active = Arc::new(ActiveCommands::new());
        let watch_ready = Arc::new(crate::watch_ready::WatchReadyMap::new());
        let env_stash = EnvPreStash::new();
        let shell_stash = crate::shell_state_track::ShellStatePreStash::new();
        let env_filter = shit_planner::EnvFilter::default();
        let baseline = Arc::new(crate::baseline::LiveBaseline::new());
        let closing = Arc::new(ClosingCommands::default());
        let blocks = Arc::new(FinalizationBlocks::default());
        let mut close_tasks = tokio::task::JoinSet::new();

        for _ in 0..2 {
            handle(
                pre_exec(command, 4245, dir.path()),
                &index,
                &env_stash,
                &shell_stash,
                &env_filter,
                &active,
                None,
                Some(&watch_ready),
                &baseline,
                &Arc::new(crate::shim_listener::ShimIngestTracker::new()),
                &closing,
                &blocks,
                &mut close_tasks,
            );
        }

        assert_eq!(active.active_command_count(), 1);
        assert_eq!(
            <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), command)
                .len(),
            1,
            "duplicate PreExec must not dispatch a second missing-helper refusal"
        );
    }
}
