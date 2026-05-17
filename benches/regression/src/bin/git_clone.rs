// SPDX-License-Identifier: AGPL-3.0-or-later

//! `git clone` workload: lots of small writes plus a final rename.
//! Different shape from cargo-build's many small reads — clones
//! stress the daemon's IPC throughput from a single producer
//! generating a burst of events.
//!
//! CI passes a `--source` (a bare local repo, served via file://)
//! and `--dest` (a tmpdir, removed between runs).

use anyhow::Result;
use clap::Parser;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "git-clone", about = "shit perf bench: git clone burst")]
struct Args {
    #[arg(long, default_value_t = 5)]
    n: usize,
    /// Source repo URL (typically `file:///path/to/bare.git` in CI).
    #[arg(long)]
    source: String,
    /// Dest directory prefix. Suffixed with iteration number; removed
    /// between runs.
    #[arg(long)]
    dest_prefix: std::path::PathBuf,
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let source = args.source.clone();
    let dest_prefix = args.dest_prefix.clone();
    let mut iter = 0usize;
    let r = shit_regression_bench::collect("git-clone", args.n, host_os, host_arch, || {
        let dest = dest_prefix.with_extension(format!("clone-{iter}"));
        iter += 1;
        // If a stale dir exists from a prior crashed run, remove it.
        let _ = std::fs::remove_dir_all(&dest);
        let start = Instant::now();
        let _ = Command::new("git")
            .arg("clone")
            .arg("--quiet")
            .arg(&source)
            .arg(&dest)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let elapsed = start.elapsed().as_micros() as u64;
        // Tidy: drop the cloned tree so subsequent runs have the
        // same blob-store starting weight.
        let _ = std::fs::remove_dir_all(&dest);
        elapsed
    });
    let json = shit_regression_bench::to_json(&r);
    match args.out {
        Some(p) => std::fs::write(p, json)?,
        None => println!("{json}"),
    }
    Ok(())
}
