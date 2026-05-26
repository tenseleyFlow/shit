// SPDX-License-Identifier: AGPL-3.0-or-later

//! B07 perf gate — `shit doctor --json` total runtime.
//!
//! Measures end-to-end latency of the doctor pre-flight CI gate.
//! Doctor is invoked by every freebsd-smoke CI job before any
//! smoke runs (B04 wiring), so if its latency regresses past the
//! budget the whole CI matrix slows down.
//!
//! Default budget (per B07 sprint): p50 ≤ 500 ms, p99 ≤ 1500 ms,
//! 2x ceiling 2000 ms.
//!
//! Honors `SHIT_BIN` to point at a release build under test;
//! defaults to `shit` on PATH.

use anyhow::Result;
use clap::Parser;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "doctor",
    about = "B07 perf gate: shit doctor --json total runtime"
)]
struct Args {
    /// Number of iterations (default 100). Doctor is heavier than
    /// the shell-hook bench, so 100 is a reasonable wall-clock vs.
    /// signal trade.
    #[arg(long, default_value_t = 100)]
    n: usize,
    /// Output file for the JSON result.
    #[arg(long)]
    out: Option<std::path::PathBuf>,
    /// Override the `shit` binary path. Defaults to env `SHIT_BIN`
    /// or `shit` on PATH.
    #[arg(long)]
    bin: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let shit_bin: std::path::PathBuf = args
        .bin
        .or_else(|| std::env::var_os("SHIT_BIN").map(Into::into))
        .unwrap_or_else(|| "shit".into());

    // Sanity-run once before measurement so the bin can fail loudly
    // (missing daemon, broken config) instead of polluting the
    // histogram with bogus near-zero exits.
    let probe = Command::new(&shit_bin)
        .args(["doctor", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !probe.success() {
        let bin = shit_bin.display();
        anyhow::bail!("{bin} doctor --json exited non-zero on warmup; refusing to bench");
    }

    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let r = shit_regression_bench::collect("doctor", args.n, host_os, host_arch, || {
        let start = Instant::now();
        let _ = Command::new(&shit_bin)
            .args(["doctor", "--json"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        start.elapsed().as_micros() as u64
    });
    let json = shit_regression_bench::to_json(&r);
    match args.out {
        Some(p) => std::fs::write(p, json)?,
        None => println!("{json}"),
    }
    Ok(())
}
