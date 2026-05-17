// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tight-loop bench: the canonical "10k commands in a row" workload
//! from the project perf budget. Measures end-to-end wall clock of
//! `: ` invocations *with* shell hooks installed, then divides by N
//! to get amortised per-command latency.
//!
//! The bench process does NOT install hooks itself. CI installs hooks
//! via `shit hooks install --shell sh --no-rc` (or equivalent for the
//! environment under test) before invoking this binary. That keeps
//! the bench focused on measurement and lets the workflow control
//! the surface under test.

use anyhow::Result;
use clap::Parser;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "tight-loop", about = "shit perf bench: tight :-loop")]
struct Args {
    /// Number of iterations (default 1000).
    #[arg(long, default_value_t = 1000)]
    n: usize,
    /// Path to /bin/sh override (for testing alternate shells).
    #[arg(long, default_value = "/bin/sh")]
    shell: String,
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let shell = args.shell.clone();
    let r = shit_regression_bench::collect("tight-loop", args.n, host_os, host_arch, || {
        let start = Instant::now();
        let _ = Command::new(&shell)
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
