// SPDX-License-Identifier: AGPL-3.0-or-later

//! B07 perf gate — per-event pre-image read.
//!
//! The kqueue capture tier's hot path on every NOTE_WRITE /
//! NOTE_DELETE is: `kqueue::capture::read_pre_image(fd)` against the
//! helper's already-held O_RDONLY fd. This bin times that single
//! call against a population of "the file's been unlinked, but the
//! helper still has the fd" — the exact state shape the production
//! capture path hits when the user runs `rm`.
//!
//! Why this matters: read_pre_image is the load-bearing function
//! behind every "shit undo restores the file byte-identical" claim.
//! If it regresses past the budget, undo latency on any
//! file-mutating command goes up across the board.
//!
//! Budget (per B07 sprint): p50 ≤ 5 ms, p99 ≤ 25 ms, fail-at 50 ms
//! for a typical small-file pre-image. The bench writes a fixed-
//! size payload (default 64 KiB) so the measurement is stable;
//! larger files traverse `stream_copy_to_staging` instead, which is
//! a separate code path with its own budget (not gated yet).
//!
//! FreeBSD-only — `kqueue::capture::read_pre_image` lives behind
//! the BSD-cfg gate. Other platforms emit a skip placeholder.

#[cfg(target_os = "freebsd")]
mod inner {
    use anyhow::{Context, Result};
    use clap::Parser;
    use shit_helper::capture::read_pre_image;
    use std::io::Write;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::PathBuf;
    use std::time::Instant;

    #[derive(Parser)]
    #[command(
        name = "per-event-capture-bench",
        about = "B07 perf gate: kqueue read_pre_image latency"
    )]
    pub struct Args {
        /// Iterations (default 1000).
        #[arg(long, default_value_t = 1000)]
        pub n: usize,
        /// Payload size in bytes (default 65536 = 64 KiB). Stays
        /// below PRE_IMAGE_INLINE_CAP so the bench rides the
        /// inline path; larger files take stream_copy_to_staging.
        #[arg(long, default_value_t = 65536)]
        pub bytes: usize,
        /// Warmup iters (default 50).
        #[arg(long, default_value_t = 50)]
        pub warmup: usize,
        #[arg(long)]
        pub out: Option<PathBuf>,
    }

    /// Open a temp file, write `payload`, return the still-open O_RDONLY
    /// fd, then unlink the path. The fd keeps the inode reachable —
    /// this mirrors the production capture state immediately after a
    /// `rm` on a watched file.
    fn open_and_unlink(dir: &std::path::Path, idx: usize, payload: &[u8]) -> Result<OwnedFd> {
        let path = dir.join(format!("f{idx}"));
        {
            let mut f = std::fs::File::create(&path)
                .with_context(|| format!("create {}", path.display()))?;
            f.write_all(payload)
                .with_context(|| format!("write {}", path.display()))?;
            f.sync_all().ok();
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| format!("open(O_RDONLY) {}", path.display()))?;
        let owned: OwnedFd = f.into();
        // Now unlink the path — fd keeps the inode alive.
        std::fs::remove_file(&path).with_context(|| format!("unlink {}", path.display()))?;
        Ok(owned)
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        let host_os = std::env::consts::OS;
        let host_arch = std::env::consts::ARCH;

        let tmp = tempfile::tempdir().context("tempdir")?;
        let payload = vec![0xa5u8; args.bytes];

        // Pre-stage fds across (warmup + n) iters so each
        // measurement reads a fresh, unique fd. This avoids any
        // kernel-cache effects from re-reading the same inode
        // many times.
        let total = args.warmup + args.n;
        let fds: Vec<OwnedFd> = (0..total)
            .map(|i| open_and_unlink(tmp.path(), i, &payload))
            .collect::<Result<Vec<_>>>()?;

        // Warmup.
        for f in fds.iter().take(args.warmup) {
            let _ = read_pre_image(f.as_raw_fd());
        }

        let mut idx = args.warmup;
        let r =
            shit_regression_bench::collect("per-event-capture", args.n, host_os, host_arch, || {
                let f = &fds[idx];
                idx += 1;
                let start = Instant::now();
                let _ = read_pre_image(f.as_raw_fd());
                start.elapsed().as_micros() as u64
            });

        let json = shit_regression_bench::to_json(&r);
        match args.out {
            Some(p) => std::fs::write(p, json)?,
            None => println!("{json}"),
        }
        Ok(())
    }
}

#[cfg(not(target_os = "freebsd"))]
fn main() {
    println!(r#"{{"workload":"per-event-capture","skipped":"non-freebsd"}}"#);
}

#[cfg(target_os = "freebsd")]
fn main() -> anyhow::Result<()> {
    inner::main()
}
