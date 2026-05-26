// SPDX-License-Identifier: AGPL-3.0-or-later

//! B07 perf gate — `shit-helper pkg-event apt pre` invocation
//! latency. Mirrors what runs inline with `apt`/`pkg`/`systemctl`
//! when a user installs/removes a package: the PATH-prepended
//! wrapper exec's `shit-helper pkg-event ...` to snapshot state.
//!
//! Budget (per B07 sprint): p50 ≤ 20 ms, p99 ≤ 100 ms, 2x ceiling
//! 200 ms. The dominant cost is fork+exec + ctl-socket connect;
//! daemon-side ack is fire-and-forget so doesn't show up here.
//!
//! Spins up an isolated `shitd` so the bench runs against a known
//! daemon (rather than whatever's on the user's box).

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "hook-helper-bench",
    about = "B07 perf gate: shit-helper pkg-event latency"
)]
struct Args {
    #[arg(long, default_value_t = 200)]
    n: usize,
    /// Warmup iters (default 20).
    #[arg(long, default_value_t = 20)]
    warmup: usize,
    #[arg(long)]
    out: Option<PathBuf>,
    /// Override the `shitd` binary. Defaults to env `SHITD_BIN`,
    /// then `target/release/shitd`.
    #[arg(long)]
    shitd: Option<PathBuf>,
    /// Override the `shit-helper` binary. Defaults to env
    /// `SHIT_HELPER_BIN`, then `target/release/shit-helper`.
    #[arg(long)]
    helper: Option<PathBuf>,
}

struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(
    bin: &std::path::Path,
    state_dir: &std::path::Path,
    sock: &std::path::Path,
) -> Result<DaemonGuard> {
    let child = Command::new(bin)
        .arg("--foreground")
        .arg("--sock")
        .arg(sock)
        .env("XDG_STATE_HOME", state_dir)
        .env("XDG_RUNTIME_DIR", state_dir)
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    Ok(DaemonGuard { child })
}

fn wait_for_socket(path: &std::path::Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    bail!("socket {} not ready within {:?}", path.display(), timeout);
}

fn main() -> Result<()> {
    let args = Args::parse();

    let shitd_bin: PathBuf = args
        .shitd
        .or_else(|| std::env::var_os("SHITD_BIN").map(Into::into))
        .unwrap_or_else(|| "target/release/shitd".into());
    let helper_bin: PathBuf = args
        .helper
        .or_else(|| std::env::var_os("SHIT_HELPER_BIN").map(Into::into))
        .unwrap_or_else(|| "target/release/shit-helper".into());
    for (label, p) in [("shitd", &shitd_bin), ("helper", &helper_bin)] {
        if !p.exists() {
            bail!("{label} binary not found at {}", p.display());
        }
    }

    let tmp = tempfile::tempdir().context("create bench tempdir")?;
    let state_dir = tmp.path().to_path_buf();
    let hook_sock = state_dir.join("hook.sock");
    let ctl_sock = state_dir.join("shit-ctl.sock");

    let _daemon = spawn_daemon(&shitd_bin, &state_dir, &hook_sock)?;
    // ctl socket has its own name; wait for it (the daemon creates
    // both on startup but ctl can lag a tick behind hook).
    wait_for_socket(&ctl_sock, Duration::from_secs(5))?;

    let run_helper = |i: usize| -> u64 {
        let start = Instant::now();
        let _ = Command::new(&helper_bin)
            .args(["pkg-event", "apt", "pre", "--ctl-sock"])
            .arg(&ctl_sock)
            // The pkg-event handler reads a small env block from
            // SHIT_PKG_EVENT_* env vars to identify the
            // transaction. Wire enough that the helper considers
            // the invocation well-formed.
            .env("SHIT_PKG_EVENT_TXID", format!("bench-{i}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        start.elapsed().as_micros() as u64
    };

    // Warmup.
    for i in 0..args.warmup {
        let _ = run_helper(i);
    }

    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let r =
        shit_regression_bench::collect("hook-helper", args.n, host_os, host_arch, || run_helper(0));

    let json = shit_regression_bench::to_json(&r);
    match args.out {
        Some(p) => std::fs::write(p, json)?,
        None => println!("{json}"),
    }
    Ok(())
}
