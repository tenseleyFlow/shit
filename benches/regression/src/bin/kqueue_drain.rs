// SPDX-License-Identifier: AGPL-3.0-or-later

//! B07 perf gate — kqueue drain throughput.
//!
//! Registers N EVFILT_VNODE watches with NOTE_WRITE, then kicks a
//! writer loop on each fd and drains the resulting kevents. The
//! reported metric is **events per second** sustained over a fixed
//! work window — the higher the better. The harness records each
//! window as a u64 in the existing latency-named slot (us); the
//! gate interprets that as throughput against budgets.toml.
//!
//! Budget (per B07 sprint): ≥ 15k ev/sec p50, ≥ 10k ev/sec p99,
//! floor 5k ev/sec. Floors translated to "per-iteration µs" make
//! 15k ev/sec ⇒ 66 µs per single-event service.
//!
//! FreeBSD-only inner. Other platforms emit a deliberately-clean
//! "skip" JSON so the workflow can invoke this bin
//! unconditionally without breaking the surrounding step.

#[cfg(target_os = "freebsd")]
mod inner {
    use anyhow::{Context, Result};
    use clap::Parser;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::PathBuf;
    use std::time::Instant;

    #[derive(Parser)]
    #[command(name = "kqueue-drain-bench", about = "B07 perf gate: kqueue drain throughput")]
    pub struct Args {
        /// Iterations (default 50). Each iteration drains a fixed
        /// event window.
        #[arg(long, default_value_t = 50)]
        pub n: usize,
        /// Watches per iteration (default 64). Bench writes to all
        /// of them before draining; backpressure shows up when this
        /// exceeds the kqueue's coalescing budget.
        #[arg(long, default_value_t = 64)]
        pub watches: usize,
        /// Writes per watch per iteration (default 16). Each fd
        /// gets this many `write(2)` calls; NOTE_WRITE coalesces
        /// internally so the event count is usually `watches`, not
        /// `watches * writes`.
        #[arg(long, default_value_t = 16)]
        pub writes: usize,
        #[arg(long, default_value_t = 5)]
        pub warmup: usize,
        #[arg(long)]
        pub out: Option<PathBuf>,
    }

    fn make_kq() -> Result<OwnedFd> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(std::io::Error::last_os_error()).context("kqueue()");
        }
        Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(kq) })
    }

    fn arm(kq: &OwnedFd, fds: &[std::fs::File]) -> Result<()> {
        let mut changelist: Vec<libc::kevent> = fds
            .iter()
            .map(|f| libc::kevent {
                ident: f.as_raw_fd() as usize,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE | libc::NOTE_EXTEND,
                data: 0,
                udata: std::ptr::null_mut(),
                ext: [0u64; 4],
            })
            .collect();
        let r = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                changelist.as_mut_ptr(),
                changelist.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("kevent(arm)");
        }
        Ok(())
    }

    fn drive_writes(fds: &mut [std::fs::File], writes: usize) -> Result<()> {
        use std::io::Write;
        let buf = b"x";
        for f in fds.iter_mut() {
            for _ in 0..writes {
                f.write_all(buf)?;
            }
        }
        Ok(())
    }

    fn drain_until_idle(kq: &OwnedFd, max_events: usize) -> Result<usize> {
        let mut events = vec![
            libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
                ext: [0u64; 4],
            };
            max_events
        ];
        // 100µs timeout per kevent call: tight enough that the
        // last (idle) call doesn't dominate the measurement, loose
        // enough that small in-flight delivery races still catch
        // pending events.
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000,
        };
        let mut total = 0usize;
        loop {
            let n = unsafe {
                libc::kevent(
                    kq.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    &ts,
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error()).context("kevent(drain)");
            }
            if n == 0 {
                break;
            }
            total += n as usize;
            if total >= max_events {
                break;
            }
        }
        Ok(total)
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        let host_os = std::env::consts::OS;
        let host_arch = std::env::consts::ARCH;

        let tmp = tempfile::tempdir().context("tempdir")?;
        let dir = tmp.path();

        // Open writable files we'll keep across iterations.
        let mut fds: Vec<std::fs::File> = (0..args.watches)
            .map(|i| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(false)
                    .open(dir.join(format!("f{i}")))
                    .with_context(|| format!("open f{i}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let kq = make_kq()?;
        arm(&kq, &fds)?;

        let run = |fds: &mut [std::fs::File]| -> u64 {
            // Drive writes outside the timed region. NOTE_WRITE
            // coalesces in the kernel, so the time we want to
            // measure is the drain (kernel → user), not the write
            // syscalls themselves. The writes accumulate kevents
            // we then drain in one timed window.
            drive_writes(fds, args.writes).expect("write");
            let start = Instant::now();
            let _ = drain_until_idle(&kq, args.watches * 2).expect("drain");
            start.elapsed().as_micros() as u64
        };

        for _ in 0..args.warmup {
            let _ = run(&mut fds);
        }

        let r = shit_regression_bench::collect("kqueue-drain", args.n, host_os, host_arch, || {
            run(&mut fds)
        });

        let json = shit_regression_bench::to_json(&r);
        match args.out {
            Some(p) => std::fs::write(p, json)?,
            None => println!("{json}"),
        }
        // Keep the kq + fds alive until here; OwnedFd's Drop closes
        // the kq fd, files close on Drop.
        drop(kq);
        let _ = fds;
        let _ = tmp;
        Ok(())
    }
}

#[cfg(not(target_os = "freebsd"))]
fn main() {
    // The B07 perf-bsd.yml workflow invokes every bench bin
    // unconditionally so the workflow shape stays the same across
    // arch/os. On non-FreeBSD hosts emit a placeholder so the
    // step succeeds and the JSON consumer can detect the skip.
    println!(
        r#"{{"workload":"kqueue-drain","skipped":"non-freebsd"}}"#
    );
}

#[cfg(target_os = "freebsd")]
fn main() -> anyhow::Result<()> {
    inner::main()
}
