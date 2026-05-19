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
        // Accepted for CLI parity with the Linux build (perf.yml passes
        // the same args on every platform leg). Ignored in the stub.
        #[arg(long, default_value_t = 30)]
        #[allow(dead_code)]
        deadline_secs: u64,
        #[arg(long, default_value_t = false)]
        #[allow(dead_code)]
        full_capture: bool,
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
        /// Hard deadline on the responder loop in seconds. If the
        /// workload finishes (or never fires events) before reaching
        /// N samples, we exit cleanly with whatever we collected.
        /// Without this, a misconfigured fanotify mark (or a kernel
        /// that doesn't support fanotify-perm on the test fs) would
        /// block the bench forever — surfaced on a CI runner where
        /// the workflow hung 49 minutes on the bare `fan.read`.
        #[arg(long, default_value_t = 30)]
        deadline_secs: u64,
        /// L01 chunk 6: when set, perform the SAME load-bearing capture
        /// work between read and ALLOW that `shit-helper`'s
        /// `LinuxCaptureRuntime::handle_event` does — dup the fd, read
        /// the pre-image bytes, blake3-hash them, write a staging file,
        /// then ack ALLOW. Measures the realistic capture-to-ALLOW
        /// p99 against the CAPTURE_TO_ALLOW BudgetGate (5ms/10ms).
        /// Without this flag the bench measures only the kernel
        /// fanotify-fd round-trip baseline (the floor below the
        /// budget).
        #[arg(long, default_value_t = false)]
        full_capture: bool,
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
        // kernel-buffer budget. FAN_EVENT_ON_CHILD is what makes the
        // events fire for direct children of the marked dir; without
        // it only opens of the dir inode itself fire and we'd see
        // zero events from a `cat $dir/file` workload (surfaced on
        // hasu run, deadline saved us from another hang).
        let cpath = std::ffi::CString::new(scratch.path().as_os_str().as_encoded_bytes())
            .context("build CString for scratch path")?;
        let rc = unsafe {
            libc::fanotify_mark(
                fan_fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_ONLYDIR,
                libc::FAN_OPEN_PERM | libc::FAN_EVENT_ON_CHILD,
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

        // Staging dir for the full-capture mode's write-then-ack flow.
        // Created once; files are written under it and cleaned up via
        // the TempDir drop at end of run.
        let staging = tempfile::tempdir().context("create staging dir")?;

        let metadata_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = vec![0u8; metadata_size * 16];
        let mut got = 0usize;
        let deadline = Instant::now() + std::time::Duration::from_secs(args.deadline_secs);
        let fan_raw = fan.as_raw_fd();
        while got < args.n {
            // Wait for the fd to be readable, bounded by the
            // remaining deadline. poll(2) returns 0 on timeout, >0
            // when ready, -1 on error. Without this gate the bare
            // `read` blocks indefinitely when no events arrive,
            // wedging the bench (the CI runner hang root cause).
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                eprintln!(
                    "fanotify-capture: deadline reached at {got}/{} events; emitting partial sample",
                    args.n
                );
                break;
            }
            let mut pfd = libc::pollfd {
                fd: fan_raw,
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout_ms = remaining.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
            let pr = unsafe { libc::poll(&mut pfd as *mut _, 1, timeout_ms) };
            if pr < 0 {
                return Err(std::io::Error::last_os_error()).context("poll fanotify fd");
            }
            if pr == 0 {
                eprintln!(
                    "fanotify-capture: poll timeout at {got}/{} events; emitting partial sample",
                    args.n
                );
                break;
            }
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
                //
                // L01 chunk 6 — full-capture mode performs the same
                // work-between-read-and-ALLOW that the helper's
                // LinuxCaptureRuntime::handle_event does: fstat → dup →
                // read pre-image → blake3 → staging-write. The SCM_RIGHTS
                // send_response_with_fd is NOT replayed (no daemon here);
                // its cost is in the same order as the `fan.write_all`
                // below, both being short kernel-side IPC writes.
                if args.full_capture && md.fd >= 0 {
                    simulate_capture_work(md.fd, staging.path()).context("capture work")?;
                }

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

        // Best-effort child cleanup. If we hit the deadline before the
        // child's `for` loop drained, the child is still running and
        // `wait` would block; kill it first.
        let _ = child.kill();
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

    /// Reproduces the load-bearing work of
    /// `shit-helper::capture::linux::LinuxCaptureRuntime::handle_event`
    /// step-for-step so the bench measures the realistic cost of the
    /// CAPTURE_TO_ALLOW hot path. If this drifts from the helper's
    /// implementation, the bench drifts too — that's the trade-off for
    /// keeping the bench dep-light (no shit-helper crate dependency).
    fn simulate_capture_work(event_fd: i32, staging_dir: &std::path::Path) -> Result<()> {
        use std::io::{Read, Write};

        // 1. fstat — get (dev, inode) + size. Same as runtime's
        //    fstat_dev_inode_kind + fstat_meta.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(event_fd, &mut st) } != 0 {
            return Err(std::io::Error::last_os_error()).context("fstat");
        }
        // 2. dup the fd so we can read without disturbing the kernel's
        //    fanotify-owned position. Runtime does the same.
        let dup_fd = unsafe { libc::dup(event_fd) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("dup");
        }
        let owned = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(dup_fd) };
        // 3. Read the pre-image. Bounded read to mirror MAX_PRE_IMAGE_BYTES.
        let size = (st.st_size as usize).min(256 * 1024 * 1024);
        let mut bytes = Vec::with_capacity(size);
        let mut f = owned;
        f.read_to_end(&mut bytes).context("read pre-image")?;
        // 4. blake3 the bytes. Same algorithm + same single-threaded
        //    path the runtime uses.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let _hash = *hasher.finalize().as_bytes();
        // 5. Staging-write. Same unique-name + create_new + write_all
        //    pattern as runtime's write_to_staging.
        let name = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        let staging_path = staging_dir.join(&name);
        let mut sf = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .context("staging open")?;
        sf.write_all(&bytes).context("staging write")?;
        drop(sf);
        // 6. Reopen read-only — the runtime hands this fd to the daemon
        //    via SCM_RIGHTS. Here we just open and immediately close;
        //    measures the same fs metadata-update cost.
        let _ro = std::fs::OpenOptions::new()
            .read(true)
            .open(&staging_path)
            .context("staging reopen")?;
        // Clean up so the staging dir doesn't grow unbounded across N events.
        let _ = std::fs::remove_file(&staging_path);
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
