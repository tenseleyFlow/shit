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

/// How long command close waits for the helper's `UnwatchTreeFlushed`
/// marker before finalizing anyway.
pub const UNWATCH_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Commands whose PostExec arrived but whose close barrier has not
/// finished (helper flush pending, or finalization still running).
/// ctl handlers that read recent commands wait on this so a command
/// that just ended is not missing from `shit undo` / `shit show`.
#[derive(Default)]
pub struct ClosingCommands {
    inner: std::sync::Mutex<std::collections::BTreeSet<CommandId>>,
    changed: tokio::sync::Notify,
}

impl ClosingCommands {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `command` as closing. Returns false when it already is
    /// (duplicate PostExec).
    fn begin(&self, command: CommandId) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(command)
    }

    fn finish(&self, command: CommandId) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&command);
        self.changed.notify_waiters();
    }

    fn snapshot(&self) -> Vec<CommandId> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect()
    }

    fn any_of(&self, commands: &[CommandId]) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        commands.iter().any(|c| inner.contains(c))
    }

    /// Wait until every command that is closing at call time has been
    /// finalized, or `timeout` passes. Commands that start closing
    /// later are not waited for. Returns how many were still closing
    /// at the deadline.
    pub async fn wait_for_drain(&self, timeout: Duration) -> usize {
        // Let the hook consumer run first: a PostExec datagram that
        // arrived before this ctl request may still be queued.
        tokio::task::yield_now().await;
        let targets = self.snapshot();
        if targets.is_empty() {
            return 0;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.any_of(&targets) {
                return 0;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                return targets.iter().filter(|c| inner.contains(c)).count();
            }
        }
    }
}

/// Shared state a PostExec needs to finalize a command after the
/// helper's close barrier, off the hook-consumer task.
#[derive(Clone)]
pub struct CloseCtx {
    pub index: Arc<Index>,
    pub live_baseline: Arc<crate::baseline::LiveBaseline>,
    pub watch_ready: Option<Arc<crate::watch_ready::WatchReadyMap>>,
    pub helper_link: Option<Arc<HelperLink>>,
    pub closing: Arc<ClosingCommands>,
    pub strict_capture: bool,
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
    closing: Arc<ClosingCommands>,
    hook_tx: tokio::sync::mpsc::UnboundedSender<HookEnvelope>,
    mut hook_rx: tokio::sync::mpsc::UnboundedReceiver<HookEnvelope>,
) -> anyhow::Result<()> {
    let env_filter = cfg.env.filter();
    let close_ctx = CloseCtx {
        index: Arc::clone(&index),
        live_baseline: Arc::clone(&live_baseline),
        watch_ready: watch_ready.clone(),
        helper_link: helper_link.clone(),
        closing,
        strict_capture: cfg.strict_capture,
    };
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
            &close_ctx,
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

/// Second half of PostExec: runs once the helper flushed (or the
/// barrier failed). Writes `ended_at` + exit code, runs the xattr
/// post-sweep, and releases readers waiting in [`ClosingCommands`].
fn finalize_post_exec(
    ctx: &CloseCtx,
    command: CommandId,
    exit_code: i32,
    barrier: Result<(), crate::helper_link::UnwatchError>,
) {
    let index = ctx.index.as_ref();
    let readiness_proven = ctx
        .watch_ready
        .as_ref()
        .is_some_and(|map| map.wait_was_observed(command));
    match &barrier {
        Ok(()) => debug!(%command, readiness_proven, "close barrier flushed"),
        Err(e) => {
            warn!(%command, err = %e, readiness_proven, "close barrier failed; finalizing anyway");
            if ctx.strict_capture
                && let Err(je) = crate::helper_link::journal_capture_refused(
                    index,
                    command,
                    None,
                    format!("capture completion could not be proven at command close: {e}"),
                )
            {
                warn!(%command, err = %je, "strict close-barrier CaptureRefused journal failed");
            }
        }
    }
    // Update via re-put: ON CONFLICT replaces ended_at + exit_code.
    // Fetch the existing row to preserve started_at. The close
    // timestamp is allocated here, after the barrier, so every drained
    // capture event precedes it on the logical clock.
    if let Some(mut existing) = <Index as shit_planner::PlannerStore>::command_by_id(index, command)
    {
        existing.ended_at = Some(next_ts());
        existing.exit_code = Some(exit_code);
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
        crate::xattr::post_exec_sweep(&existing.cwd, command, &ctx.live_baseline, index);
    }
    // AR00.5 / task #105 — drop the readiness entry for this
    // CommandId. A shell hook still waiting (stale hook, racy teardown)
    // gets an Err and its WaitWatchReady returns ready=false.
    if let Some(map) = ctx.watch_ready.as_ref() {
        map.forget(command);
    }
    ctx.closing.finish(command);
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
    close_ctx: &CloseCtx,
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
            if !close_ctx.closing.begin(command) {
                warn!(%command, "ignoring duplicate PostExec while close is pending");
                return;
            }
            // DR-25: drain the active map entry now that the command is
            // closed. Tier events that arrive later no longer attribute.
            if let Some(existing) =
                <Index as shit_planner::PlannerStore>::command_by_id(index, command)
            {
                active.remove(existing.pid, command);
            }
            // R3 close barrier: tell the helper to stop watching and wait
            // for its UnwatchTreeFlushed marker before writing ended_at.
            // Capture responses for this command that were already on the
            // wire are dispatched (and journaled) before the marker, so
            // undo never plans against a command whose tail is in flight.
            match close_ctx.helper_link.as_ref() {
                Some(link) => {
                    let pending = link.begin_unwatch_tree(command);
                    let ctx = close_ctx.clone();
                    let exit_code = *exit_code;
                    tokio::spawn(async move {
                        let barrier = match pending {
                            Ok(pending) => pending.wait(UNWATCH_FLUSH_TIMEOUT).await,
                            Err(e) => Err(e),
                        };
                        finalize_post_exec(&ctx, command, exit_code, barrier);
                    });
                }
                None => finalize_post_exec(close_ctx, command, *exit_code, Ok(())),
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

#[cfg(test)]
mod close_barrier_tests {
    use super::*;
    use uuid::Uuid;

    fn cmd(seq: u64) -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq,
        }
    }

    #[tokio::test]
    async fn drain_returns_immediately_when_nothing_is_closing() {
        let closing = ClosingCommands::new();
        assert_eq!(closing.wait_for_drain(Duration::from_millis(10)).await, 0);
    }

    #[test]
    fn duplicate_begin_is_rejected() {
        let closing = ClosingCommands::new();
        assert!(closing.begin(cmd(1)));
        assert!(!closing.begin(cmd(1)));
        closing.finish(cmd(1));
        assert!(closing.begin(cmd(1)));
    }

    #[tokio::test]
    async fn drain_waits_for_finish() {
        let closing = Arc::new(ClosingCommands::new());
        assert!(closing.begin(cmd(2)));
        let c2 = Arc::clone(&closing);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            c2.finish(cmd(2));
        });
        assert_eq!(closing.wait_for_drain(Duration::from_secs(5)).await, 0);
    }

    #[tokio::test]
    async fn drain_reports_commands_left_at_timeout() {
        let closing = ClosingCommands::new();
        assert!(closing.begin(cmd(3)));
        assert!(closing.begin(cmd(4)));
        assert_eq!(closing.wait_for_drain(Duration::from_millis(20)).await, 2);
    }

    #[tokio::test]
    async fn finalize_without_helper_writes_end_time() {
        let dir = tempfile::tempdir().unwrap();
        let index = Arc::new(Index::open(dir.path().join("db.sqlite")).unwrap());
        index
            .put_session(Uuid::nil(), "bash", 1, None, TimePoint::new(0, 0))
            .unwrap();
        index
            .put_command(&CommandRecord {
                command: cmd(5),
                cmd_string: None,
                cwd: dir.path().to_path_buf(),
                pid: 7,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(1, 1),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .unwrap();
        let ctx = CloseCtx {
            index: Arc::clone(&index),
            live_baseline: Arc::new(crate::baseline::LiveBaseline::new()),
            watch_ready: None,
            helper_link: None,
            closing: Arc::new(ClosingCommands::new()),
            strict_capture: true,
        };
        assert!(ctx.closing.begin(cmd(5)));
        finalize_post_exec(&ctx, cmd(5), 3, Ok(()));
        let rec =
            <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), cmd(5)).unwrap();
        assert!(rec.ended_at.is_some());
        assert_eq!(rec.exit_code, Some(3));
        assert_eq!(
            ctx.closing.wait_for_drain(Duration::from_millis(5)).await,
            0
        );
    }

    #[tokio::test]
    async fn failed_barrier_refuses_only_in_strict_mode() {
        for strict in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let index = Arc::new(Index::open(dir.path().join("db.sqlite")).unwrap());
            index
                .put_session(Uuid::nil(), "bash", 1, None, TimePoint::new(0, 0))
                .unwrap();
            index
                .put_command(&CommandRecord {
                    command: cmd(6),
                    cmd_string: None,
                    cwd: dir.path().to_path_buf(),
                    pid: 7,
                    shell_kind: shit_proto::ShellKind::Bash,
                    started_at: TimePoint::new(1, 1),
                    ended_at: None,
                    exit_code: None,
                    event_ids: vec![],
                })
                .unwrap();
            let ctx = CloseCtx {
                index: Arc::clone(&index),
                live_baseline: Arc::new(crate::baseline::LiveBaseline::new()),
                watch_ready: None,
                helper_link: None,
                closing: Arc::new(ClosingCommands::new()),
                strict_capture: strict,
            };
            assert!(ctx.closing.begin(cmd(6)));
            finalize_post_exec(
                &ctx,
                cmd(6),
                0,
                Err(crate::helper_link::UnwatchError::Timeout(
                    UNWATCH_FLUSH_TIMEOUT,
                )),
            );
            let refusals =
                <Index as shit_planner::PlannerStore>::events_for_command(index.as_ref(), cmd(6))
                    .into_iter()
                    .filter(|ev| {
                        matches!(
                            ev.kind,
                            shit_planner::events::CaptureEventKind::CaptureRefused { .. }
                        )
                    })
                    .count();
            assert_eq!(refusals, usize::from(strict), "strict={strict}");
            let rec = <Index as shit_planner::PlannerStore>::command_by_id(index.as_ref(), cmd(6))
                .unwrap();
            assert!(rec.ended_at.is_some(), "a failed barrier still finalizes");
        }
    }
}
