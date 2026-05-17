// SPDX-License-Identifier: AGPL-3.0-or-later

//! `find -exec` style workload: measures per-event auth-event handling
//! latency rather than per-command latency. Drives a `find` over a
//! small fixture tree to generate many syscall events without the
//! tree being so large that GC kicks in mid-run.
//!
//! CI builds the fixture tree once and passes it via `--root`.

use anyhow::Result;
use clap::Parser;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "find-workload",
    about = "shit perf bench: find auth-event flood"
)]
struct Args {
    /// Number of repetitions of the full `find` invocation (default 10).
    /// Each repetition is one sample; per-event latency is amortised
    /// by the test, not measured directly.
    #[arg(long, default_value_t = 10)]
    n: usize,
    /// Root directory to walk.
    #[arg(long)]
    root: std::path::PathBuf,
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let root = args.root.clone();
    if !root.exists() {
        anyhow::bail!("--root {} does not exist", root.display());
    }
    let r = shit_regression_bench::collect("find-workload", args.n, host_os, host_arch, || {
        let start = Instant::now();
        let _ = Command::new("find")
            .arg(&root)
            .arg("-type")
            .arg("f")
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
