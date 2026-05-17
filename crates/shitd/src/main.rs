// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

mod config;
mod ctl;
mod env_track;
mod gc;
mod helper_link;
mod lock;
mod pkg;
mod server;
mod stats;
mod svc_track;

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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut resolved = config::Config::load(cli.config.as_deref())?.resolve()?;
    if let Some(s) = cli.sock {
        resolved.hook_socket_path = s;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&resolved.log_level)),
        )
        .with_writer(std::io::stderr)
        .init();

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
    let stats = stats::Stats::new();
    let shutdown = Arc::new(Notify::new());

    let index_path = cfg.state_dir.join("index.sqlite");
    let index = Arc::new(shit_store::Index::open(&index_path)?);
    tracing::info!(path = %index_path.display(), "index opened");

    let blobs_path = cfg.state_dir.join("blobs");
    let blob_store = Arc::new(shit_store::BlobStore::open(&blobs_path)?);
    tracing::info!(path = %blobs_path.display(), "blob store opened");

    let gc_signal = Arc::new(gc::GcSignal::new());
    let gc_handle = {
        let index = Arc::clone(&index);
        let blob_store = Arc::clone(&blob_store);
        let signal = Arc::clone(&gc_signal);
        let shutdown = Arc::clone(&shutdown);
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
            )
            .await;
        })
    };

    let pkg_stash = Arc::new(pkg::PkgPreStash::new());
    let env_stash = Arc::new(env_track::EnvPreStash::new());
    let svc_stash = Arc::new(svc_track::SvcPreStash::new());
    let pkg_janitor = {
        let pkg_stash = Arc::clone(&pkg_stash);
        let env_stash = Arc::clone(&env_stash);
        let svc_stash = Arc::clone(&svc_stash);
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            // Sweep orphan Pre stashes every minute. The 5-minute
            // TTL lives on each stash; this task just wakes them up.
            // pkg + env + svc share the same TTL, so a single
            // janitor is cheaper than three timers.
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let pkg_evicted = pkg_stash.sweep_expired();
                        let env_evicted = env_stash.sweep_expired();
                        let svc_evicted = svc_stash.sweep_expired();
                        if pkg_evicted > 0 || env_evicted > 0 || svc_evicted > 0 {
                            tracing::info!(
                                pkg_evicted,
                                env_evicted,
                                svc_evicted,
                                "stash janitor: swept orphan Pre entries"
                            );
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
        };
        tokio::spawn(async move {
            if let Err(e) = ctl::serve(&cfg, ctl_state).await {
                tracing::error!(err = %e, "ctl listener exited");
            }
        })
    };

    let stats_for_server = Arc::clone(&stats);
    let shutdown_for_server = Arc::clone(&shutdown);
    let env_stash_for_server = Arc::clone(&env_stash);
    let result = tokio::select! {
        r = server::serve(cfg, stats_for_server, index, env_stash_for_server) => r,
        _ = shutdown_for_server.notified() => {
            tracing::info!("shutdown requested via ctl");
            Ok(())
        }
    };

    ctl_handle.abort();
    gc_handle.abort();
    pkg_janitor.abort();
    result
}
