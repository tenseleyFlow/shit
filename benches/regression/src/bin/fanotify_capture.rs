// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fanotify-perm capture-loop bench: measures kernel→userspace
//! responder round-trip latency under fanotify_perm. This is the
//! floor below which L01's capture-then-ALLOW path cannot land —
//! whatever budget the L01 implementation has on the wall clock,
//! the kernel + fanotify-fd + read/write costs eat into it before
//! a single byte of pre-image bytes has been read.
//!
//! Bench shape:
//! 1. fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_NONBLOCK = 0)
//! 2. fanotify_mark(... | FAN_MARK_FILESYSTEM, FAN_OPEN_PERM, scratch_dir)
//! 3. Spawn a child that loops `open(O_RDONLY)` N times.
//! 4. In the main thread, drain fanotify events: per event, record
//!    Instant::now() at read-completion, write the FAN_ALLOW
//!    response, record Instant::now() again. Per-event sample
//!    is the responder-loop microsecond span.
//!
//! What this measures: the kernel-roundtrip + read/write syscalls
//! over the fanotify fd. NOT the L01 capture cost — that's measured
//! by a future bench that drops in the real `capture/linux.rs`
//! handler between read and write. This baseline establishes how
//! much of the CAPTURE_TO_ALLOW budget is already spent before any
//! `shit` code runs.
//!
//! Skip behaviour: if `fanotify_init` returns EPERM (no
//! CAP_SYS_ADMIN), the bench writes a `RunResult` with
//! `n_total=0, n_kept=0, median_us=0, p99_us=0` and exits 0. CI
//! treats this as "test environment skipped" not a failure — the
//! perf gate only meaningfully runs on a privileged Linux runner.
//! macOS / FreeBSD invocations land in the same skip path via the
//! cfg-gated stub `main()`.

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser;

    #[derive(Parser)]
    struct Args {
        #[arg(long, default_value_t = 1000)]
        #[allow(dead_code)]
        n: usize,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    }
    let args = Args::parse();
    // Emit an empty RunResult so the workflow's compare step has
    // something well-formed to read. n_total=0 is the "skip" signal.
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;
    let r = shit_regression_bench::summarize("fanotify-capture", host_os, host_arch, &[], 0);
    let json = shit_regression_bench::to_json(&r);
    eprintln!("fanotify-capture: skipping ({host_os} is not Linux)");
    match args.out {
        Some(p) => std::fs::write(p, json)?,
        None => println!("{json}"),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux_impl::run()
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use anyhow::{Context, Result};
    use clap::Parser;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::PathBuf;
    use std::time::Instant;

    #[derive(Parser)]
    #[command(
        name = "fanotify-capture",
        about = "Linux perf bench: fanotify-perm responder-loop baseline (L01)"
    )]
    struct Args {
        /// Number of FAN_OPEN_PERM events to drive (default 1000).
        #[arg(long, default_value_t = 1000)]
        n: usize,
        /// Output file for the JSON result.
        #[arg(long)]
        out: Option<PathBuf>,
    }

    pub fn run() -> Result<()> {
        let args = Args::parse();
        let host_os = std::env::consts::OS;
        let host_arch = std::env::consts::ARCH;

        let scratch = tempfile::tempdir().context("create scratch tempdir")?;
        let target_file = scratch.path().join("probe");
        std::fs::write(&target_file, b"x").context("seed target file")?;

        // fanotify_init. EPERM here is the documented skip signal.
        let fan_fd = match unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_PRE_CONTENT | libc::FAN_CLOEXEC,
                libc::O_RDONLY as u32,
            )
        } {
            -1 => {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    return emit_skip(&args, host_os, host_arch, "fanotify_init EPERM");
                }
                return Err(err).context("fanotify_init");
            }
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };

        // Mark the scratch dir (NOT FAN_MARK_FILESYSTEM — we want a
        // narrow blast radius). FAN_OPEN_PERM gives us pre-content
        // permission events the responder must ack within the
        // kernel-buffer budget.
        let cpath = std::ffi::CString::new(scratch.path().as_os_str().as_encoded_bytes())
            .context("build CString for scratch path")?;
        let rc = unsafe {
            libc::fanotify_mark(
                fan_fd.as_raw_fd(),
                libc::FAN_MARK_ADD,
                libc::FAN_OPEN_PERM as u64,
                libc::AT_FDCWD,
                cpath.as_ptr(),
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return emit_skip(&args, host_os, host_arch, "fanotify_mark EPERM");
            }
            return Err(err).context("fanotify_mark");
        }

        // Spawn the workload child *first* so the responder can
        // start draining as soon as we begin opening files. Use a
        // shell loop for portability — keeps the bench dep-light.
        let target_path = target_file.to_string_lossy().into_owned();
        let n = args.n;
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "for _ in $(seq 1 {n}); do cat {} >/dev/null; done",
                shell_quote(&target_path)
            ))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("spawn fanotify workload child")?;

        // Responder loop. Per event: time the read-to-write span.
        // The bench's job is to never block the kernel queue, so we
        // ack ALLOW immediately and only afterwards record latency.
        // The closure inside `collect` is given a clock-only
        // measurement; the read happens before, the write inside.
        let mut samples = Vec::with_capacity(args.n);
        let mut fan = unsafe { std::fs::File::from_raw_fd(fan_fd.as_raw_fd()) };
        // Don't let the File drop close the fd while we still hold
        // OwnedFd — std::mem::forget the OwnedFd ownership.
        std::mem::forget(fan_fd);

        let metadata_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = vec![0u8; metadata_size * 16];
        let mut got = 0usize;
        while got < args.n {
            let read_at = Instant::now();
            let n_bytes = match fan.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => continue,
                Err(e) => return Err(e).context("fanotify fd read"),
            };
            let mut off = 0usize;
            while off + metadata_size <= n_bytes && got < args.n {
                // SAFETY: kernel-validated event header, length-bounded.
                let md: &libc::fanotify_event_metadata =
                    unsafe { &*(buf[off..].as_ptr() as *const libc::fanotify_event_metadata) };
                if md.event_len < metadata_size as u32 {
                    break;
                }
                // The fd in `md.fd` is owned by us now; close after ACK.
                let response = libc::fanotify_response {
                    fd: md.fd,
                    response: libc::FAN_ALLOW,
                };
                let resp_bytes = unsafe {
                    std::slice::from_raw_parts(
                        (&response as *const libc::fanotify_response).cast::<u8>(),
                        std::mem::size_of::<libc::fanotify_response>(),
                    )
                };
                fan.write_all(resp_bytes)
                    .context("write fanotify_response")?;
                let wrote_at = Instant::now();
                if md.fd >= 0 {
                    unsafe { libc::close(md.fd) };
                }
                samples.push((wrote_at - read_at).as_micros() as u64);
                got += 1;
                off += md.event_len as usize;
            }
        }

        let _ = child.wait();

        let summary =
            shit_regression_bench::summarize("fanotify-capture", host_os, host_arch, &samples, 0);
        let json = shit_regression_bench::to_json(&summary);
        match args.out {
            Some(p) => std::fs::write(p, json)?,
            None => println!("{json}"),
        }
        Ok(())
    }

    fn emit_skip(args: &Args, host_os: &str, host_arch: &str, reason: &str) -> Result<()> {
        eprintln!("fanotify-capture: skipping ({reason}) — run via setcap or sudo");
        let r = shit_regression_bench::summarize("fanotify-capture", host_os, host_arch, &[], 0);
        let json = shit_regression_bench::to_json(&r);
        match &args.out {
            Some(p) => std::fs::write(p, json)?,
            None => println!("{json}"),
        }
        Ok(())
    }

    fn shell_quote(s: &str) -> String {
        // POSIX-safe single-quoting: replace ' with '\'' and wrap.
        let mut out = String::with_capacity(s.len() + 2);
        out.push('\'');
        for ch in s.chars() {
            if ch == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(ch);
            }
        }
        out.push('\'');
        out
    }
}
