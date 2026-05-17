// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

mod config;
mod ctl;
mod lock;
mod server;
mod stats;

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

    let ctl_handle = {
        let cfg = cfg.clone();
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            if let Err(e) = ctl::serve(&cfg, stats, shutdown).await {
                tracing::error!(err = %e, "ctl listener exited");
            }
        })
    };

    let stats_for_server = Arc::clone(&stats);
    let shutdown_for_server = Arc::clone(&shutdown);
    let result = tokio::select! {
        r = server::serve(cfg, stats_for_server, index) => r,
        _ = shutdown_for_server.notified() => {
            tracing::info!("shutdown requested via ctl");
            Ok(())
        }
    };

    ctl_handle.abort();
    result
}
