// SPDX-License-Identifier: AGPL-3.0-or-later

//! Baseline bench: shell-hook-free measurement of the bare command
//! overhead. Subtracted from the hooked benches to give a stable
//! comparison.
//!
//! This runner is the simplest of the five: spawn `/bin/sh -c ':'`
//! N times with NO shell hooks installed, time each invocation.
//! The result is the floor below which we can't drive the hooked
//! latency — process spawn + libc init is the cost the OS imposes,
//! not the cost of our hook.
//!
//! CI uses the baseline as a sanity-check: if `tight_loop` median
//! drops below the baseline median, something is wrong with the
//! measurement.

use anyhow::Result;
use clap::Parser;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "baseline", about = "shit perf bench: no-hook baseline")]
struct Args {
    /// Number of iterations (default 1000).
    #[arg(long, default_value_t = 1000)]
    n: usize,
    /// Output file for the JSON result.
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let r = shit_regression_bench::collect("baseline", args.n, host_os, host_arch, || {
        let start = Instant::now();
        let _ = Command::new("/bin/sh")
            .arg("-c")
            .arg(":")
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
