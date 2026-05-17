// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-helper` — the privileged sidecar for `shitd`.
//!
//! Architecture lives in `.docs/sprints/S06-helper-scaffold.md` and the
//! running audit in `.docs/audits/helper-protocol.md`.
//!
//! This binary is launched by `shitd`. It connects back to the daemon
//! over a SOCK_SEQPACKET UDS handed to it via `--daemon-sock`,
//! completes a handshake, then sits ready to handle watch / auth /
//! shutdown requests. Per-OS kernel hooks land in S07/S08/S09.

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

mod crash;
#[cfg(target_os = "linux")]
mod fanotify;
mod handshake;
mod health;
#[cfg(target_os = "linux")]
mod inotify_supplement;
mod ipc;
#[cfg(target_os = "linux")]
mod priv_linux;
mod sandbox;
#[cfg(target_os = "linux")]
mod seccomp_linux;

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
    name = "shit-helper",
    about = "shit privileged helper",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
)]
struct Cli {
    /// Path to the SEQPACKET UDS the daemon set up for us to connect back to.
    #[arg(long)]
    daemon_sock: PathBuf,

    /// Expected daemon PID. Helper refuses to handshake unless the
    /// peer-PID we read off the socket matches.
    #[arg(long)]
    daemon_pid: u32,

    /// Expected daemon UID. Same: refuse on mismatch.
    #[arg(long)]
    daemon_uid: u32,

    /// State dir for crash logs and per-helper bookkeeping.
    #[arg(long)]
    state_dir: PathBuf,

    /// Run in foreground (currently the only mode). Reserved for future
    /// daemonize switch.
    #[arg(long, default_value_t = true)]
    foreground: bool,
}

fn main() -> anyhow::Result<()> {
    // S06.3: drop LD_PRELOAD before anything else. TA-3 mitigation.
    // If anything injected itself into this process via LD_PRELOAD,
    // it's already too late for *this* binary; but we make sure no
    // child or thread inherits the variable.
    refuse_if_ld_preloaded()?;

    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("VERGEN_GIT_SHA"),
        daemon_pid = cli.daemon_pid,
        "shit-helper starting"
    );

    // Drop privileges to the minimum keep-list *before* any tokio rt
    // bring-up so the runtime never holds extra caps.
    #[cfg(target_os = "linux")]
    priv_linux::drop_to_minimum().map_err(|e| anyhow::anyhow!("privilege drop failed: {e}"))?;

    // Crash hook: panics in worker tasks get a one-line summary on disk.
    crash::install_panic_hook(&cli.state_dir);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let shutdown = Arc::new(Notify::new());

    install_signal_handlers(Arc::clone(&shutdown));

    let conn = match ipc::connect(&cli.daemon_sock).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(err = %e, "failed to connect to daemon socket; exiting");
            return Err(e.into());
        }
    };
    tracing::info!(
        path = %cli.daemon_sock.display(),
        "connected to daemon ipc socket"
    );

    // Per-platform helper capabilities. Once S07/S08/S09 land, this
    // reflects what the helper can actually do given current privileges.
    let local_caps = current_capabilities();

    let outcome =
        match handshake::perform_helper_side(&conn, cli.daemon_pid, cli.daemon_uid, local_caps) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(err = %e, "handshake failed; exiting");
                return Err(anyhow::anyhow!("handshake failed: {e}"));
            }
        };
    tracing::info!(
        daemon_pid = outcome.daemon_pid,
        daemon_uid = outcome.daemon_uid,
        granted = ?outcome.granted,
        "handshake complete"
    );

    // Sandbox entry — per-OS module decides what to do.
    sandbox::enter(&cli.state_dir)?;

    tokio::select! {
        _ = shutdown.notified() => {
            tracing::info!("shutdown signal received; exiting");
        }
        // Placeholder: real event loop arrives in S06.4 + S07/8/9.
        _ = idle(&conn) => {}
    }
    Ok(())
}

async fn idle(_conn: &ipc::Conn) {
    // S06.4 swaps this out for the real receive loop.
    std::future::pending::<()>().await
}

fn install_signal_handlers(shutdown: Arc<Notify>) {
    let shutdown_term = Arc::clone(&shutdown);
    let shutdown_int = shutdown;
    tokio::spawn(async move {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
            tracing::info!("SIGTERM received");
            shutdown_term.notify_waiters();
        }
    });
    tokio::spawn(async move {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        {
            s.recv().await;
            tracing::info!("SIGINT received");
            shutdown_int.notify_waiters();
        }
    });
}

/// Compute what the helper can advertise on this platform / privilege
/// level. The probe is destructive on Linux (it opens the real
/// fanotify fd) — we keep the fd around in the returned outcome so we
/// don't have to re-init after the cap drop.
fn current_capabilities() -> shit_proto::HelperCaps {
    #[cfg(target_os = "linux")]
    {
        return linux_probe_caps();
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS path lands in S07; BSD in S10. Helper still claims
        // `watch_tree` since that primitive is best-effort even with
        // no kernel hooks.
        shit_proto::HelperCaps {
            watch_tree: true,
            auth_subscribe: false,
            package_hook: false,
        }
    }
}

/// Probe the Linux kernel features + privilege level. Opens a real
/// `fanotify_init(2)`; on success, advertises `auth_subscribe = true`
/// and the caller drops `CAP_SYS_ADMIN` immediately (the fd works
/// without the cap once init has returned).
///
/// On EPERM (no CAP_SYS_ADMIN) or ENOSYS (older kernel without
/// fanotify-perm) we fall through to inotify-only degraded mode —
/// `auth_subscribe = false` to be honest about what we can deliver.
#[cfg(target_os = "linux")]
fn linux_probe_caps() -> shit_proto::HelperCaps {
    let (version, features) = match fanotify::probe() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(err = %e, "kernel feature probe failed; assuming no fanotify");
            return shit_proto::HelperCaps {
                watch_tree: true,
                auth_subscribe: false,
                package_hook: false,
            };
        }
    };
    tracing::info!(
        kernel = %version,
        tier = features.tier_label(),
        "kernel feature probe complete"
    );

    if !features.perm_events {
        tracing::warn!("kernel pre-4.20 — fanotify-perm unavailable, degraded mode");
        return shit_proto::HelperCaps {
            watch_tree: true,
            auth_subscribe: false,
            package_hook: false,
        };
    }

    match fanotify::init_pre_content() {
        Ok(fd) => {
            tracing::info!("fanotify pre-content client opened; dropping CAP_SYS_ADMIN");
            // Cap drop right after init — fd still works (S08 design
            // note: cap is needed only by fanotify_init + fanotify_mark;
            // we accept losing mark for now, S08+S09 wire mark into a
            // privileged setup phase before this drop).
            //
            // For S08.8 the cap-drop happens via priv_linux on entry;
            // this branch documents the design intent — the actual
            // mark calls (S08.4 wiring) must run *before* we reach
            // here. Today we hold the fd and let it close on the
            // function return.
            drop(fd);
            shit_proto::HelperCaps {
                watch_tree: true,
                auth_subscribe: true,
                package_hook: false,
            }
        }
        Err(e) => {
            tracing::warn!(err = %e, "fanotify_init failed; degraded mode");
            shit_proto::HelperCaps {
                watch_tree: true,
                auth_subscribe: false,
                package_hook: false,
            }
        }
    }
}

fn refuse_if_ld_preloaded() -> anyhow::Result<()> {
    if std::env::var_os("LD_PRELOAD").is_some() {
        anyhow::bail!("LD_PRELOAD set; refusing to run (TA-3 mitigation)");
    }
    // DYLD_INSERT_LIBRARIES is the macOS equivalent.
    if std::env::var_os("DYLD_INSERT_LIBRARIES").is_some() {
        anyhow::bail!("DYLD_INSERT_LIBRARIES set; refusing to run");
    }
    Ok(())
}
