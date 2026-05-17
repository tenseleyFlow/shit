// SPDX-License-Identifier: AGPL-3.0-or-later

//! `cargo build` workload: the heaviest bench, stress-tests the auth
//! event volume rate ("~100k events/sec under cargo build" from the
//! project plan). Per-command latency isn't the headline — what we
//! care about is that the daemon stays responsive and doesn't drop
//! events under sustained pressure.
//!
//! CI passes a `--manifest` pointing at a small fixture crate. The
//! bench runs `cargo build --release --manifest-path X` N times,
//! cleaning between runs.

use anyhow::Result;
use clap::Parser;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "cargo-build",
    about = "shit perf bench: cargo build event flood"
)]
struct Args {
    /// Number of build-and-clean cycles (default 3 — each cycle is slow).
    #[arg(long, default_value_t = 3)]
    n: usize,
    /// Path to the fixture crate's Cargo.toml.
    #[arg(long)]
    manifest: std::path::PathBuf,
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let manifest = args.manifest.clone();
    if !manifest.exists() {
        anyhow::bail!("--manifest {} does not exist", manifest.display());
    }
    let r = shit_regression_bench::collect("cargo-build", args.n, host_os, host_arch, || {
        // Clean first so each run starts from the same state. We don't
        // measure the clean — only the build wall-clock.
        let _ = Command::new("cargo")
            .arg("clean")
            .arg("--manifest-path")
            .arg(&manifest)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let start = Instant::now();
        let _ = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--manifest-path")
            .arg(&manifest)
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
