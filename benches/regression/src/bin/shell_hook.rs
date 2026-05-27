// SPDX-License-Identifier: AGPL-3.0-or-later

//! B07 perf gate — shell hook UDS round-trip latency.
//!
//! Measures the per-frame `send(2)` latency a shell hook pays to
//! deliver a PreExec frame to the daemon over the SOCK_DGRAM the
//! daemon listens on. This is the cost the user's shell actually
//! pays *per command* — kernel datagram buffer copy + (when full)
//! daemon-side drain pressure.
//!
//! Budget (per B07 sprint): p50 ≤ 1 ms, p99 ≤ 5 ms, 2x ceiling
//! 10 ms. SOCK_DGRAM AF_UNIX should sit well under that on an
//! unloaded host; the budget catches backpressure regressions
//! (daemon falling behind → kernel buffer fills → send() blocks).
//!
//! The bench spins up an isolated `shitd` against a tempdir so
//! parallel CI jobs don't collide. Honors `SHITD_BIN` to point at
//! the release build under test.
//!
//! Cross-platform: works on Linux/macOS/FreeBSD; the budget is
//! BSD-specific (lives in `tools/perf/budgets.toml`).

use anyhow::{Context, Result, bail};
use clap::Parser;
use shit_proto::{HookMessage, ShellKind, encode_frame};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "shell-hook-bench",
    about = "B07 perf gate: hook UDS send latency"
)]
struct Args {
    /// Outer iterations after warmup (default 200). Each iteration
    /// sends `--batch` frames; the reported per-iter latency is
    /// the burst total, in microseconds.
    #[arg(long, default_value_t = 200)]
    n: usize,
    /// Frames per outer iteration (default 100). SOCK_DGRAM
    /// AF_UNIX send is sub-microsecond on a healthy host; batching
    /// lifts the measurement above the 1µs harness floor and
    /// catches kernel-buffer-fill backpressure across a contiguous
    /// burst (which is what a real shell session looks like — many
    /// frames close in time).
    #[arg(long, default_value_t = 100)]
    batch: usize,
    /// Warmup outer iterations discarded before measurement
    /// (default 20). Hides cold-cache effects + first-touch UDS
    /// allocation.
    #[arg(long, default_value_t = 20)]
    warmup: usize,
    #[arg(long)]
    out: Option<PathBuf>,
    /// Override the `shitd` binary. Defaults to env `SHITD_BIN`,
    /// then `target/release/shitd`.
    #[arg(long)]
    shitd: Option<PathBuf>,
}

struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // SIGTERM, then SIGKILL after a short grace.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
    let p = path.display();
    bail!("hook socket {p} not ready within {timeout:?}");
}

fn pre_exec_frame(session: Uuid, seq: u64, cwd: &str) -> Result<Vec<u8>> {
    let msg = HookMessage::PreExec {
        session,
        seq,
        pid: std::process::id(),
        cwd_inode: 0,
        cwd_dev: 0,
        cwd_path: cwd.to_string(),
        ts_unix_nanos: unix_nanos(),
        shell_kind: ShellKind::Bash,
        depth: 0,
        cmd_string: None,
    };
    let frame = encode_frame(&msg)?;
    Ok(frame)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let shitd_bin: PathBuf = args
        .shitd
        .or_else(|| std::env::var_os("SHITD_BIN").map(Into::into))
        .unwrap_or_else(|| "target/release/shitd".into());
    if !shitd_bin.exists() {
        bail!(
            "shitd binary not found at {}; set --shitd or SHITD_BIN",
            shitd_bin.display()
        );
    }

    let tmp = tempfile::tempdir().context("create bench tempdir")?;
    let state_dir = tmp.path().to_path_buf();
    let sock_path = state_dir.join("hook.sock");

    let _daemon = spawn_daemon(&shitd_bin, &state_dir, &sock_path)?;
    wait_for_socket(&sock_path, Duration::from_secs(5))?;

    // Connect SOCK_DGRAM to the daemon's listening socket. Once
    // connected, send(2) avoids the per-call address resolution
    // and matches what the shell hook does over its persistent fd.
    let client = UnixDatagram::unbound().context("UnixDatagram::unbound")?;
    client
        .connect(&sock_path)
        .with_context(|| format!("connect to {}", sock_path.display()))?;

    // Workspace uuid is configured with v7 only. v7 carries a ms
    // timestamp; for the bench a single session ID is enough.
    let session = Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext));
    let cwd = state_dir.to_string_lossy().into_owned();

    // Warmup: prime kernel buffers + daemon-side decode path.
    // Same shape as the measured loop (batch sends) so cache state
    // matches.
    for outer in 0..args.warmup {
        for inner in 0..args.batch {
            let seq = (outer * args.batch + inner) as u64;
            let frame = pre_exec_frame(session, seq, &cwd)?;
            let _ = client.send(&frame);
        }
    }

    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;

    let mut seq: u64 = (args.warmup * args.batch) as u64;
    let batch = args.batch;
    let r = shit_regression_bench::collect("shell-hook", args.n, host_os, host_arch, || {
        let start = Instant::now();
        for _ in 0..batch {
            let frame = pre_exec_frame(session, seq, &cwd).expect("encode PreExec");
            let _ = client.send(&frame);
            seq += 1;
        }
        start.elapsed().as_micros() as u64
    });

    let json = shit_regression_bench::to_json(&r);
    match args.out {
        Some(p) => std::fs::write(p, json)?,
        None => println!("{json}"),
    }
    Ok(())
}
