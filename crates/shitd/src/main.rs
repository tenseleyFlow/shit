// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

mod active_commands;
mod ancestry;
mod baseline;
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
mod proc_track;
mod server;
mod shim_listener;
mod stats;
mod svc_track;
mod telemetry;
mod tracing_ring_layer;
mod watch_ready;

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

/// DR-66: per-OS classifier the daemon uses to prime
/// `Stats::kernel_tier` at startup. Mirrors
/// `shit_helper::handshake::kernel_tier_classifier`; once the helper
/// links up it overwrites this with its own runtime probe result.
const fn daemon_kernel_tier_default() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "fanotify"
    }
    #[cfg(target_os = "macos")]
    {
        "endpoint-security"
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

    let blobs_path = cfg.state_dir.join("blobs");
    let blob_store = Arc::new(shit_store::BlobStore::open(&blobs_path)?);
    tracing::info!(path = %blobs_path.display(), "blob store opened");

    // W02.B.live-baseline — per-cwd content snapshot held in memory.
    // Populated by the helper's BaselineCaptured stream at session
    // open; consulted by the CapturedPreImage ingest path to swap
    // post-write content for the genuine pre-content captured here.
    let live_baseline = Arc::new(baseline::LiveBaseline::new());

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
                        let link = Arc::new(link);
                        let dispatch_link = Arc::clone(&link);
                        let dispatch_index = Arc::clone(&index);
                        let dispatch_blob_store = Arc::clone(&blob_store);
                        let dispatch_baseline = Arc::clone(&live_baseline);
                        let dispatch_shutdown = Arc::clone(&shutdown);
                        let dispatch_watch_ready = Arc::clone(&watch_ready);
                        let handle = tokio::spawn(async move {
                            if let Err(e) = helper_link::dispatch_loop(
                                dispatch_link,
                                dispatch_index,
                                dispatch_blob_store,
                                dispatch_baseline,
                                dispatch_shutdown,
                                dispatch_watch_ready,
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
            // Stage-1 logical clock: a monotonic counter incrementing
            // once per pass. Replaced by the daemon's real logical
            // clock once the capture-runtime pipeline lights up.
            let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
            let now_logical_fn = {
                let counter = Arc::clone(&counter);
                Arc::new(move || counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    as Arc<dyn Fn() -> u64 + Send + Sync>
            };
            gc::run_loop(
                index,
                blob_store,
                gc::GcTaskConfig::default(),
                signal,
                shutdown,
                now_logical_fn,
                stats,
            )
            .await;
        })
    };

    let pkg_stash = Arc::new(pkg::PkgPreStash::new());
    let env_stash = Arc::new(env_track::EnvPreStash::new());
    let svc_stash = Arc::new(svc_track::SvcPreStash::new());
    let net_stash = Arc::new(net_track::NetPreStash::new());
    let proc_stash = Arc::new(proc_track::ProcPreStash::new());
    let db_stash = Arc::new(db_track::DbPreStash::new());
    // DR-25 prereq: the in-memory active-command map. Owns the
    // shell_pid → (session, seq) lookup tier-event handlers use to
    // attribute pkg/env/svc/net/proc/db events to a live command.
    let active = Arc::new(active_commands::ActiveCommands::new());
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
        };
        tokio::spawn(async move {
            if let Err(e) = ctl::serve(&cfg, ctl_state).await {
                tracing::error!(err = %e, "ctl listener exited");
            }
        })
    };

    // S24.D.2 — accept loop for the LD_PRELOAD shim's per-process UDS.
    let shim_handle = {
        let cfg = cfg.clone();
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            if let Err(e) = shim_listener::serve(&cfg, shutdown).await {
                tracing::error!(err = %e, "shim listener exited");
            }
        })
    };

    let stats_for_server = Arc::clone(&stats);
    let shutdown_for_server = Arc::clone(&shutdown);
    let env_stash_for_server = Arc::clone(&env_stash);
    let active_for_server = Arc::clone(&active);
    let helper_link_for_server = helper_link_arc.clone();
    // Task #105 — same pattern as ctl_state: only thread the
    // readiness map when there's a helper, so PostExec's forget()
    // is a no-op in degraded mode.
    let watch_ready_for_server = helper_link_arc.as_ref().map(|_| Arc::clone(&watch_ready));
    let result = tokio::select! {
        r = server::serve(
            cfg,
            stats_for_server,
            index,
            env_stash_for_server,
            active_for_server,
            helper_link_for_server,
            watch_ready_for_server,
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
