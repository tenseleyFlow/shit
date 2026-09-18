// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

mod active_commands;
mod ancestry;
mod baseline;
mod clock;
mod cloud_track;
mod config;
mod container_track;
mod crash;
mod ctl;
mod db_track;
mod env_track;
mod gc;
mod helper_link;
mod lock;
mod log_setup;
mod net_track;
mod pkg;
mod priv_op_router;
mod proc_track;
mod redirect_track;
mod server;
mod shell_state_track;
mod shim_listener;
mod stats;
mod svc_track;
mod telemetry;
mod tracing_ring_layer;
mod watch_ready;
mod xattr;

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit: ",
    env!("VERGEN_GIT_SHA"),
    "\nbuilt:  ",
    env!("VERGEN_BUILD_TIMESTAMP"),
    "\nrustc:  ",
    env!("VERGEN_RUSTC_SEMVER"),
    "\ntarget: ",
    env!("VERGEN_CARGO_TARGET_TRIPLE"),
);

#[derive(Parser)]
#[command(
    name = "shitd",
    about = "shit daemon",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
)]
struct Cli {
    /// Run in the foreground. Only mode supported pre-S22.
    #[arg(long, default_value_t = true)]
    foreground: bool,

    /// Override config file location. Default: $XDG_CONFIG_HOME/shit/config.toml.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the hook socket path (overrides config and defaults).
    #[arg(long)]
    sock: Option<PathBuf>,
}

#[derive(Debug)]
struct StartupDurabilityReport {
    command_recovery: shit_store::StartupRecoveryReport,
    remaining_blob_leases_cleared: usize,
    blob_reconciliation: shit_store::StartupReconcileReport,
}

/// Repair durable state left by an earlier daemon lifetime.
///
/// This must run after opening the Index and BlobStore but before constructing
/// or spawning any capture producer, listener, or GC task. Process-lifetime
/// leases cannot survive a restart: interrupted commands consume theirs as
/// part of atomic refusal/close recovery, then any remaining stale leases are
/// cleared before the lease-free reconciliation pass.
fn recover_startup_state(
    index: &shit_store::Index,
    blob_store: &shit_store::BlobStore,
    wallclock_unix_nanos: u64,
) -> anyhow::Result<StartupDurabilityReport> {
    let command_recovery = shit_store::recover_interrupted_commands(index, wallclock_unix_nanos)
        .context("recover interrupted commands from previous daemon lifetime")?;
    let remaining_blob_leases_cleared = index
        .clear_all_blob_leases()
        .context("clear stale process-lifetime blob leases")?;
    let blob_reconciliation = shit_store::reconcile_startup(index, blob_store)
        .context("reconcile blob index and filesystem at startup")?;
    Ok(StartupDurabilityReport {
        command_recovery,
        remaining_blob_leases_cleared,
        blob_reconciliation,
    })
}

fn log_startup_durability(report: &StartupDurabilityReport) {
    let recovery = &report.command_recovery;
    let reconcile = &report.blob_reconciliation;
    tracing::info!(
        commands_recovered = recovery.recovered_commands.len(),
        confirmed_container_commands_preserved =
            recovery.preserved_confirmed_container_commands.len(),
        prepared_container_batches_refused = recovery.prepared_batches_refused,
        recovery_blob_leases_cleared = recovery.blob_leases_cleared,
        remaining_blob_leases_cleared = report.remaining_blob_leases_cleared,
        tmp_files_removed = reconcile.tmp_files_removed,
        refcount_rows_recomputed = reconcile.refcount_rows_recomputed,
        refcounts_corrected = reconcile.refcount_corrected_hashes.len(),
        metadata_corrected = reconcile.metadata_corrected_hashes.len(),
        blob_rows_repaired = reconcile.repaired_blob_rows.len(),
        blob_rows_removed = reconcile.removed_blob_rows.len(),
        canonical_files_removed = reconcile.removed_canonical_files.len(),
        ignored_paths = reconcile.ignored_paths.len(),
        missing_referenced_blobs = reconcile.missing_referenced_hashes.len(),
        corrupt_referenced_blobs = reconcile.corrupt_referenced_hashes.len(),
        "startup durability recovery complete"
    );
    let refused_commands: Vec<_> = recovery
        .recovered_commands
        .iter()
        .filter(|command| {
            !recovery
                .preserved_confirmed_container_commands
                .contains(command)
        })
        .copied()
        .collect();
    if !refused_commands.is_empty() {
        tracing::warn!(
            commands = ?refused_commands,
            synthetic_exit_code = shit_store::STARTUP_RECOVERY_EXIT_CODE,
            "interrupted commands from a previous daemon lifetime were made non-undoable"
        );
    }
    if !recovery.preserved_confirmed_container_commands.is_empty() {
        tracing::info!(
            commands = ?recovery.preserved_confirmed_container_commands,
            synthetic_exit_code = shit_store::STARTUP_RECOVERY_EXIT_CODE,
            "interrupted commands retained pre-authorized container inverses"
        );
    }
    if !reconcile.ignored_paths.is_empty() {
        tracing::warn!(
            paths = ?reconcile.ignored_paths,
            "startup reconciliation retained unrecognized blob-store paths"
        );
    }
    if !reconcile.missing_referenced_hashes.is_empty()
        || !reconcile.corrupt_referenced_hashes.is_empty()
    {
        tracing::error!(
            missing_count = reconcile.missing_referenced_hashes.len(),
            corrupt_count = reconcile.corrupt_referenced_hashes.len(),
            missing_hashes = ?reconcile.missing_referenced_hashes,
            corrupt_hashes = ?reconcile.corrupt_referenced_hashes,
            "REFERENCED BLOB EVIDENCE IS MISSING OR CORRUPT; affected undo plans will refuse"
        );
    }
}

/// DR-66: display-only per-OS default used before a helper has connected.
/// A successful helper handshake overwrites it with the producer tier that
/// actually reached its live startup boundary; doctor also checks helper-link
/// state and must not treat this disconnected default as runtime evidence.
const fn daemon_kernel_tier_default() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "fanotify"
    }
    #[cfg(target_os = "macos")]
    {
        // M01 baseline: FSEvents post-hoc tier. M03 flips the helper-
        // side classifier to "endpoint-security" at runtime when ES
        // is available; the daemon overwrites this default with the
        // helper's report on first handshake either way.
        "fsevents-degraded"
    }
    #[cfg(target_os = "freebsd")]
    {
        "kqueue"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        "unsupported"
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut resolved = config::Config::load(cli.config.as_deref())?.resolve()?;
    if let Some(s) = cli.sock {
        resolved.hook_socket_path = s;
    }

    // S21.8 — install panic hook before the log layer so a panic
    // during log_setup or any later wiring still drops a
    // canonical-format crash file under state_dir/crashes/.
    crash::install_panic_hook(&resolved.state_dir);

    // S21.3 — JSON layer to $XDG_STATE_HOME/shit/log/daemon.jsonl.*
    // (daily rotation) + a stderr fallback for warn+ events. The
    // returned guard MUST live until shutdown — dropping it stops
    // the appender's worker thread.
    // DR-68: pass the crash ring so each event also lands in the
    // panic-hook tail buffer.
    let _log_guard = log_setup::init(&resolved.state_dir, &resolved.log_level, crash::ring());

    // Installed wrapper content is part of the container authorization
    // protocol. A daemon restart after a package upgrade must atomically
    // replace opted-in stale copies before it begins serving capture requests.
    if let Ok(config_home) = config::config_home() {
        for path in shit_shell::container_wrappers::refresh_existing(&config_home)
            .context("refresh installed container wrappers")?
        {
            tracing::warn!(path = %path.display(), "refreshed stale container wrapper");
        }
    }

    // S21.6 — surface OTLP feature/config drift loudly. If the
    // operator set `[telemetry] otlp_endpoint` but the daemon wasn't
    // built with --features otel, the export silently does nothing —
    // which is exactly the kind of "thought I had observability,
    // didn't" failure mode we want to refuse to ship. Warn at startup
    // so the journal shows it.
    if let Some(endpoint) = &resolved.telemetry.otlp_endpoint {
        if cfg!(feature = "otel") {
            tracing::info!(
                endpoint = %endpoint,
                service_name = %resolved.telemetry.service_name,
                "OTLP export configured",
            );
        } else {
            tracing::warn!(
                endpoint = %endpoint,
                "OTLP endpoint set but daemon was built without --features otel; \
                 export disabled",
            );
        }
    }

    if resolved.disable {
        tracing::warn!("daemon disabled via config; exiting");
        return Ok(());
    }

    let _lock_guard = lock::DaemonLock::acquire(&resolved.lock_path)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(resolved))
}

async fn run(cfg: config::ResolvedConfig) -> anyhow::Result<()> {
    // S21.2 — root span carrying the schema-required component/pid/
    // version/commit fields. Child events inherit when the span is
    // entered. Per-subsystem child spans (ctl-listener, hook-listener,
    // command-window) open below as their work begins.
    let root_span = tracing::info_span!(
        "daemon",
        component = "daemon",
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("VERGEN_GIT_SHA"),
    );
    let _root_guard = root_span.enter();

    let stats = stats::Stats::new();
    // DR-66: prime the kernel-tier banner with the compile-time
    // expectation. When `helper_link::spawn_and_handshake` actually
    // runs (DR-01..DR-13 wiring), the helper's reported tier
    // overrides this via `Stats::set_kernel_tier` from the handshake
    // ack.
    stats.set_kernel_tier(daemon_kernel_tier_default());
    let shutdown = Arc::new(Notify::new());

    let index_path = cfg.state_dir.join("index.sqlite");
    let index = Arc::new(shit_store::Index::open(&index_path)?);
    tracing::info!(path = %index_path.display(), "index opened");

    // Establish the one daemon-lifetime wall clock before recovery writes any
    // terminal timestamps. Durable history is a read-only startup anchor: a
    // suspicious RTC jump quarantines age expiry and cannot poison the next
    // daemon lifetime by stamping recovered rows in the suspect epoch.
    let latest_durable_wall = index
        .latest_wallclock_unix_nanos()
        .context("read latest durable wall timestamp")?;
    let startup_time = clock::init(latest_durable_wall).sample();
    if !startup_time.age_expiry_safe {
        tracing::warn!(
            anchored_unix_nanos = startup_time.unix_nanos,
            latest_durable_unix_nanos = latest_durable_wall,
            "wall-clock sanity check failed; age-based retention is disabled for this daemon lifetime"
        );
    }

    let blobs_path = cfg.state_dir.join("blobs");
    let blob_store = Arc::new(shit_store::BlobStore::open(&blobs_path)?);
    tracing::info!(path = %blobs_path.display(), "blob store opened");

    // No producer may exist before this boundary. Recovery closes every
    // command whose prior capture proof died with the old process, expires
    // process-lifetime leases, and reconciles physical/index blob ownership.
    // Any failure aborts startup instead of serving from ambiguous state.
    let startup_report =
        recover_startup_state(index.as_ref(), blob_store.as_ref(), startup_time.unix_nanos)?;
    let startup_next_logical = startup_report.command_recovery.next_logical;
    server::seed_logical_clock(startup_next_logical);
    log_startup_durability(&startup_report);

    // W02.B.live-baseline — per-cwd content snapshot held in memory.
    // Populated by the helper's BaselineCaptured stream at session
    // open; consulted by the CapturedPreImage ingest path to swap
    // post-write content for the genuine pre-content captured here.
    let live_baseline = Arc::new(baseline::LiveBaseline::new());
    // DR-25 prereq: the in-memory active-command map. Construct it before the
    // helper dispatch loop so an unexpected helper disconnect can durably
    // refuse every command that was in flight at the time of the loss.
    let active = Arc::new(active_commands::ActiveCommands::new());

    // S24.A — spawn shit-helper and start its dispatch loop. Best-
    // effort: if the helper binary isn't discoverable or the
    // handshake fails, the daemon continues in helper-less mode
    // (shell-hook journaling still works; capture-tier events just
    // won't arrive). Off entirely when `SHIT_HELPER_DISABLED=1`.
    // AR00.5 / task #105 — per-CommandId readiness rendezvous shared
    // between the helper dispatch loop (writer) and the ctl
    // WaitWatchReady handler (reader). Lives even in degraded mode
    // (then no helper ever marks ready), but we only thread it into
    // CtlState when a helper is actually connected -- the ctl
    // handler returns ready=false / "no helper" early without
    // touching the map in that case.
    let watch_ready = Arc::new(watch_ready::WatchReadyMap::new());
    let finalization_blocks = Arc::new(server::FinalizationBlocks::default());
    let shim_ingest = Arc::new(shim_listener::ShimIngestTracker::new());

    let (helper_link_arc, helper_dispatch_handle): (
        Option<Arc<helper_link::HelperLink>>,
        Option<tokio::task::JoinHandle<()>>,
    ) = if std::env::var("SHIT_HELPER_DISABLED").as_deref() == Ok("1") {
        tracing::info!("SHIT_HELPER_DISABLED=1; skipping helper spawn");
        (None, None)
    } else {
        match helper_link::discover_helper_bin() {
            None => {
                tracing::warn!(
                    "shit-helper binary not found; daemon continues without capture tier. \
                     Set SHIT_HELPER_BIN or install on PATH to enable."
                );
                (None, None)
            }
            Some(bin) => {
                let helper_sock = cfg.state_dir.join("helper.sock");
                let caps = shit_proto::HelperCaps::full();
                match helper_link::spawn_and_handshake(&bin, &helper_sock, &cfg.state_dir, caps) {
                    Ok(link) => {
                        tracing::info!(
                            helper_pid = link.helper_pid,
                            kernel_tier = %link.kernel_tier,
                            "shit-helper handshake complete"
                        );
                        stats.set_kernel_tier(&link.kernel_tier);
                        stats.note_helper_connected();
                        let link = Arc::new(link);
                        let dispatch_link = Arc::clone(&link);
                        let dispatch_index = Arc::clone(&index);
                        let dispatch_blob_store = Arc::clone(&blob_store);
                        let dispatch_baseline = Arc::clone(&live_baseline);
                        let dispatch_shutdown = Arc::clone(&shutdown);
                        let dispatch_watch_ready = Arc::clone(&watch_ready);
                        let dispatch_stats = Arc::clone(&stats);
                        let dispatch_active = Arc::clone(&active);
                        let handle = tokio::spawn(async move {
                            if let Err(e) = helper_link::dispatch_loop(
                                dispatch_link,
                                dispatch_index,
                                dispatch_blob_store,
                                dispatch_baseline,
                                dispatch_shutdown,
                                dispatch_watch_ready,
                                dispatch_stats,
                                dispatch_active,
                            )
                            .await
                            {
                                tracing::error!(error = %e, "helper dispatch loop exited with error");
                            }
                        });
                        (Some(link), Some(handle))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            bin = %bin.display(),
                            "helper handshake failed; daemon continues without capture tier"
                        );
                        (None, None)
                    }
                }
            }
        }
    };

    let gc_signal = Arc::new(gc::GcSignal::new());
    let gc_handle = {
        let index = Arc::clone(&index);
        let blob_store = Arc::clone(&blob_store);
        let signal = Arc::clone(&gc_signal);
        let shutdown = Arc::clone(&shutdown);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let retention_now_fn = Arc::new(|| clock::now().retention_now())
                as Arc<dyn Fn() -> shit_store::RetentionNow + Send + Sync>;
            gc::run_loop(
                index,
                blob_store,
                gc::GcTaskConfig::default(),
                signal,
                shutdown,
                retention_now_fn,
                stats,
            )
            .await;
        })
    };

    let pkg_stash = Arc::new(pkg::PkgPreStash::new());
    let env_stash = Arc::new(env_track::EnvPreStash::new());
    let shell_state_stash = Arc::new(shell_state_track::ShellStatePreStash::new());
    let svc_stash = Arc::new(svc_track::SvcPreStash::new());
    let net_stash = Arc::new(net_track::NetPreStash::new());
    let proc_stash = Arc::new(proc_track::ProcPreStash::new());
    let db_stash = Arc::new(db_track::DbPreStash::new());
    let pkg_janitor = {
        let pkg_stash = Arc::clone(&pkg_stash);
        let env_stash = Arc::clone(&env_stash);
        let svc_stash = Arc::clone(&svc_stash);
        let net_stash = Arc::clone(&net_stash);
        let proc_stash = Arc::clone(&proc_stash);
        let db_stash = Arc::clone(&db_stash);
        let shutdown = Arc::clone(&shutdown);
        let state_dir = cfg.state_dir.clone();
        tokio::spawn(async move {
            // Sweep orphan Pre stashes every minute. The 5-minute
            // TTL lives on each stash; this task just wakes them up.
            //
            // S21.3 also folds the log-retention sweep here: the
            // appender rotates daily but doesn't prune, so we sweep
            // files older than RETENTION_DAYS on the same cadence.
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut log_sweep_counter = 0u64;
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let pkg_evicted = pkg_stash.sweep_expired();
                        let env_evicted = env_stash.sweep_expired();
                        let svc_evicted = svc_stash.sweep_expired();
                        let net_evicted = net_stash.sweep_expired();
                        let proc_evicted = proc_stash.sweep_expired();
                        let db_evicted = db_stash.sweep_expired();
                        if pkg_evicted + env_evicted + svc_evicted + net_evicted + proc_evicted + db_evicted > 0 {
                            tracing::info!(
                                pkg_evicted,
                                env_evicted,
                                svc_evicted,
                                net_evicted,
                                proc_evicted,
                                db_evicted,
                                "stash janitor: swept orphan Pre entries"
                            );
                        }
                        // Run log retention sweep once per hour
                        // (every 60 ticks at 60s cadence).
                        log_sweep_counter += 1;
                        if log_sweep_counter.is_multiple_of(60) {
                            let log_evicted = log_setup::sweep_old_logs(&state_dir);
                            if log_evicted > 0 {
                                tracing::info!(
                                    log_evicted,
                                    "log retention sweep: dropped files older than 7d"
                                );
                            }
                        }
                    }
                    _ = shutdown.notified() => return,
                }
            }
        })
    };

    let ctl_handle = {
        let cfg = cfg.clone();
        let ctl_state = ctl::CtlState {
            stats: Arc::clone(&stats),
            shutdown: Arc::clone(&shutdown),
            index: Arc::clone(&index),
            blob_store: Arc::clone(&blob_store),
            pkg_stash: Arc::clone(&pkg_stash),
            svc_stash: Arc::clone(&svc_stash),
            net_stash: Arc::clone(&net_stash),
            proc_stash: Arc::clone(&proc_stash),
            db_stash: Arc::clone(&db_stash),
            active: Arc::clone(&active),
            // Task #105 — handler only meaningful when a helper is
            // wired. Pass the map only in that case so the ctl
            // handler can short-circuit to "no helper" when we're
            // in degraded mode.
            watch_ready: helper_link_arc.as_ref().map(|_| Arc::clone(&watch_ready)),
            finalization_blocks: Arc::clone(&finalization_blocks),
            // AU28 — handle_undo wraps this in a
            // HelperLinkPrivilegedOpRouter when Some; in degraded
            // mode (None) the FileExecutor uses NoOpPrivilegedOpRouter
            // and chown-needing ops surface PermissionDenied.
            helper_link: helper_link_arc.as_ref().map(Arc::clone),
        };
        tokio::spawn(async move {
            if let Err(e) = ctl::serve(&cfg, ctl_state).await {
                tracing::error!(err = %e, "ctl listener exited");
            }
        })
    };

    // S24.D.2 — accept loop for the LD_PRELOAD shim's per-process UDS.
    // W06.A.3 plumbs `Arc<Index>` + `Arc<ActiveCommands>` through so
    // each notification can be resolved to a `CommandId` and
    // journaled.
    let shim_handle = {
        let cfg = cfg.clone();
        let shutdown = Arc::clone(&shutdown);
        let index = Arc::clone(&index);
        let blob_store = Arc::clone(&blob_store);
        let active = Arc::clone(&active);
        let live_baseline = Arc::clone(&live_baseline);
        let shim_ingest = Arc::clone(&shim_ingest);
        let finalization_blocks = Arc::clone(&finalization_blocks);
        tokio::spawn(async move {
            if let Err(e) = shim_listener::serve(
                &cfg,
                shutdown,
                index,
                blob_store,
                active,
                live_baseline,
                shim_ingest,
                finalization_blocks,
            )
            .await
            {
                tracing::error!(err = %e, "shim listener exited");
            }
        })
    };

    let stats_for_server = Arc::clone(&stats);
    let shutdown_for_server = Arc::clone(&shutdown);
    let env_stash_for_server = Arc::clone(&env_stash);
    let shell_state_stash_for_server = Arc::clone(&shell_state_stash);
    let active_for_server = Arc::clone(&active);
    let helper_link_for_server = helper_link_arc.clone();
    // Task #105 — same pattern as ctl_state: only thread the
    // readiness map when there's a helper, so PostExec's forget()
    // is a no-op in degraded mode.
    let watch_ready_for_server = helper_link_arc.as_ref().map(|_| Arc::clone(&watch_ready));
    let live_baseline_for_server = Arc::clone(&live_baseline);
    let shim_ingest_for_server = Arc::clone(&shim_ingest);
    // AU09 — capture socket paths before `cfg` moves into server::serve
    // so we can unlink them on the shutdown path below.
    let ctl_sock_path = cfg.ctl_socket_path.clone();
    let hook_sock_path = cfg.hook_socket_path.clone();
    let shim_sock_path = shim_listener::shim_socket_path(&cfg);
    let result = tokio::select! {
        r = server::serve(
            cfg,
            stats_for_server,
            index,
            env_stash_for_server,
            shell_state_stash_for_server,
            active_for_server,
            helper_link_for_server,
            watch_ready_for_server,
            live_baseline_for_server,
            shim_ingest_for_server,
            finalization_blocks,
        ) => r,
        _ = shutdown_for_server.notified() => {
            tracing::info!("shutdown requested via ctl");
            Ok(())
        }
        _ = wait_for_term_signal() => {
            tracing::info!("shutdown requested via signal");
            Ok(())
        }
    };

    ctl_handle.abort();
    shim_handle.abort();
    gc_handle.abort();
    pkg_janitor.abort();
    if let Some(h) = helper_dispatch_handle {
        h.abort();
    }

    // AU09 — kill the helper child explicitly BEFORE the tokio runtime
    // drop. The dispatch loop runs `recv_response_with_fd` inside a
    // `spawn_blocking` task that holds a blocking recv on the helper's
    // SOCK_SEQPACKET fd; `abort()` cancels the outer task but the
    // blocking thread can't be cancelled, so the runtime drop would
    // otherwise wait until the helper exits on its own (3–5s on
    // FreeBSD, observed empirically). Killing the helper now closes
    // its socket end, which unblocks the recv, which lets the runtime
    // drop in milliseconds.
    if let Some(link) = helper_link_arc.as_ref() {
        link.kill_helper();
    }

    // AU09 — unlink IPC sockets so the on-disk inode disappearance
    // is the load-bearing signal of a clean shutdown (vs. SIGKILL,
    // which leaves them dangling). Bind-time `remove_file` covers
    // the next-daemon-startup path; explicit unlink here covers the
    // same-uid "is the daemon up?" probe that just checks the
    // socket inode without trying to connect.
    let _ = std::fs::remove_file(&ctl_sock_path);
    let _ = std::fs::remove_file(&hook_sock_path);
    let _ = std::fs::remove_file(&shim_sock_path);
    result
}

/// Wait for SIGTERM or SIGINT and return when either is observed.
/// Lets the daemon shut down gracefully — the tracing-appender's
/// `WorkerGuard` drops on the return path, flushing buffered JSON
/// log lines. Without this, `kill -TERM shitd` exits the process
/// before the appender drains.
async fn wait_for_term_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        let mut intr = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = intr.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod startup_recovery_tests {
    use super::*;
    use shit_planner::{
        CaptureEvent, CaptureEventKind, CommandId, CommandRecord, EventId, FileMetadata,
        FilePreImageSource, InodeRef, PlannerStore, TimePoint,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn begin(index: &shit_store::Index, session: Uuid, seq: u64, logical: u64) -> CommandId {
        let command = CommandId { session, seq };
        assert!(
            index
                .begin_command(&CommandRecord {
                    command,
                    cmd_string: Some(format!("command-{seq}")),
                    cwd: PathBuf::from("/tmp"),
                    pid: 123,
                    shell_kind: shit_proto::ShellKind::Bash,
                    started_at: TimePoint::new(logical, logical * 10),
                    ended_at: None,
                    exit_code: None,
                    event_ids: Vec::new(),
                })
                .unwrap()
        );
        command
    }

    #[test]
    fn startup_orders_recovery_lease_expiry_reconcile_and_new_clock() {
        let dir = tempfile::tempdir().unwrap();
        let index = shit_store::Index::open(dir.path().join("index.sqlite")).unwrap();
        let blobs = shit_store::BlobStore::open(dir.path().join("blob-store")).unwrap();
        let session = Uuid::from_bytes([0x73; 16]);
        index
            .put_session(session, "bash", 1, None, TimePoint::new(1, 1))
            .unwrap();

        let interrupted = begin(&index, session, 1, 10);
        let (leased, leased_stat) = blobs.put(b"leased only by old daemon").unwrap();
        index
            .put_blob_record(
                leased,
                leased_stat.stored_bytes,
                leased_stat.compressed,
                TimePoint::new(11, 11),
            )
            .unwrap();
        index
            .create_blob_lease(leased, interrupted, TimePoint::new(12, 12))
            .unwrap();

        // A completed command owns a blob whose physical evidence is missing.
        // Reconciliation must report it loudly (the caller logs at error) and
        // preserve a conservative database row rather than deleting evidence.
        let completed = begin(&index, session, 2, 20);
        let (missing, missing_stat) = blobs.put(b"referenced then lost").unwrap();
        index
            .put_blob_record(
                missing,
                missing_stat.stored_bytes,
                missing_stat.compressed,
                TimePoint::new(21, 21),
            )
            .unwrap();
        index
            .put_event(&CaptureEvent {
                id: EventId(0),
                command: completed,
                ts: TimePoint::new(200, 2_000),
                partial: false,
                kind: CaptureEventKind::FilePreImage {
                    inode: InodeRef::new(1, 2),
                    path: PathBuf::from("/tmp/missing-evidence"),
                    blob: missing,
                    meta: FileMetadata {
                        mode: 0o100644,
                        uid: 1,
                        gid: 1,
                        size: 20,
                        mtime_unix_nanos: 0,
                        xattrs: BTreeMap::new(),
                        acl: None,
                        flags: 0,
                    },
                    post_content_hash: None,
                    source: FilePreImageSource::Other,
                },
            })
            .unwrap();
        assert!(
            index
                .finish_command(completed, TimePoint::new(201, 2_010), 0)
                .unwrap()
        );
        blobs.delete(&missing).unwrap();

        // Simulate a stale process-lifetime lease attached to an already
        // completed command. Command recovery will not own it; the explicit
        // clear-all phase before reconciliation must remove it.
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO blob_leases (hash, session, seq, created_logical)
                 VALUES (?1, ?2, ?3, 202)",
                (
                    missing.as_bytes().as_slice(),
                    completed.session.as_bytes().as_slice(),
                    completed.seq as i64,
                ),
            )
            .unwrap();

        let report = recover_startup_state(&index, &blobs, 9_000).unwrap();
        assert_eq!(
            report.command_recovery.recovered_commands,
            vec![interrupted]
        );
        assert_eq!(report.command_recovery.blob_leases_cleared, 1);
        assert_eq!(report.remaining_blob_leases_cleared, 1);
        assert_eq!(report.command_recovery.next_logical, 205);
        assert_eq!(
            report.blob_reconciliation.missing_referenced_hashes,
            vec![missing]
        );
        assert_eq!(index.clear_all_blob_leases().unwrap(), 0);

        let recovered = index.command_by_id(interrupted).unwrap();
        assert_eq!(recovered.ended_at, Some(TimePoint::new(204, 9_000)));
        assert_eq!(
            recovered.exit_code,
            Some(shit_store::STARTUP_RECOVERY_EXIT_CODE)
        );
        assert!(matches!(
            index.events_for_command(interrupted).as_slice(),
            [CaptureEvent {
                ts: TimePoint { logical: 203, .. },
                kind: CaptureEventKind::CaptureRefused { detail, .. },
                ..
            }] if detail == shit_store::STARTUP_RECOVERY_DETAIL
        ));

        // The first event produced after restart cannot move behind recovered
        // or pre-crash journal history.
        server::seed_logical_clock(report.command_recovery.next_logical);
        let first_new_timestamp = server::next_ts();
        assert!(first_new_timestamp.logical >= report.command_recovery.next_logical);
        assert!(first_new_timestamp.logical > recovered.ended_at.unwrap().logical);
        assert!(first_new_timestamp.logical > 201);
    }
}
