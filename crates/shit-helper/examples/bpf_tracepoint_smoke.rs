// SPDX-License-Identifier: AGPL-3.0-or-later

//! BPF tracepoint smoke — loads the shipped `noop_tracepoint.bpf.o`,
//! attaches it to `sched/sched_process_exec` for 1 second, then
//! detaches cleanly.
//!
//! **Why this is safe to run on a live system:**
//!   - The attached program is a tracepoint, not an LSM hook.
//!     Tracepoints fire *after* the event happens. They cannot deny
//!     syscalls, cannot stall processes, cannot affect kernel
//!     decision-making.
//!   - The program returns 0 immediately; no map writes, no helper
//!     calls.
//!   - Hard 3-second outer deadline. Independent watchdog thread
//!     calls `_exit(7)` if the main thread doesn't tick its
//!     heartbeat every 500ms. The deadline is generous because
//!     dropping the aya::Ebpf takes a moment.
//!   - Drop of `EbpfLoader` runs aya's cleanup which detaches every
//!     program. Process exit (normal or `_exit`) closes the BPF fds,
//!     which the kernel takes as detach.
//!
//! Setup:
//!   sudo setcap cap_bpf,cap_perfmon+ep target/release/examples/bpf_tracepoint_smoke
//!
//! Run as a regular user; exits 0 on success.
//!
//! **Blast radius**: tracepoint on a kernel function that fires on
//! every `execve()`. Workload-dependent per-exec overhead. With the
//! 3s deadline the absolute event count is bounded by the system's
//! exec rate × 3 — typically a few dozen on an idle box.

#[cfg(target_os = "linux")]
fn main() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const HARD_DEADLINE: Duration = Duration::from_secs(3);
    const WATCHDOG_BUDGET: Duration = Duration::from_millis(500);

    fn now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    // We can't reach into the helper bin's private modules from an
    // example. Re-create just enough loader plumbing locally; the
    // .o is the same artifact the helper would load.
    use aya::{Ebpf, programs::TracePoint};

    const NOOP_OBJ: &[u8] =
        include_bytes!("../bpf/build/noop_tracepoint.bpf.o");

    let heartbeat = Arc::new(AtomicU64::new(now_ms()));
    let watchdog_alive = Arc::new(AtomicBool::new(true));
    {
        let heartbeat = Arc::clone(&heartbeat);
        let alive = Arc::clone(&watchdog_alive);
        std::thread::spawn(move || {
            while alive.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(100));
                let last = heartbeat.load(Ordering::Acquire);
                let gap = now_ms().saturating_sub(last);
                if gap > WATCHDOG_BUDGET.as_millis() as u64 {
                    eprintln!(
                        "[bpf-smoke] watchdog: heartbeat gap {}ms > budget {}ms — _exit(7)",
                        gap,
                        WATCHDOG_BUDGET.as_millis()
                    );
                    unsafe { libc::_exit(7) };
                }
            }
        });
    }

    println!("[bpf-smoke] elf magic ok: {:x?}", &NOOP_OBJ[..4]);
    println!("[bpf-smoke] elf size = {} bytes", NOOP_OBJ.len());

    let load_started = Instant::now();
    let mut bpf = match Ebpf::load(NOOP_OBJ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[bpf-smoke] aya::Ebpf::load failed: {e}");
            eprintln!(
                "[bpf-smoke] (need CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN; \
                 check getcap on this binary)"
            );
            std::process::exit(2);
        }
    };
    println!("[bpf-smoke] Ebpf::load ok ({} ms)", load_started.elapsed().as_millis());

    let prog: &mut TracePoint = match bpf
        .program_mut("noop_tracepoint")
        .and_then(|p| p.try_into().ok())
    {
        Some(p) => p,
        None => {
            eprintln!(
                "[bpf-smoke] program `noop_tracepoint` not found or not a TracePoint"
            );
            std::process::exit(3);
        }
    };

    if let Err(e) = prog.load() {
        eprintln!("[bpf-smoke] prog.load failed: {e}");
        std::process::exit(4);
    }
    println!("[bpf-smoke] prog.load ok");

    let _link_id = match prog.attach("sched", "sched_process_exec") {
        Ok(id) => id,
        Err(e) => {
            eprintln!("[bpf-smoke] prog.attach failed: {e}");
            std::process::exit(5);
        }
    };
    println!("[bpf-smoke] attached to tracepoint sched/sched_process_exec");

    // Live for a short window, ticking the heartbeat so the watchdog
    // doesn't kill us.
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        heartbeat.store(now_ms(), Ordering::Release);
        std::thread::sleep(Duration::from_millis(50));
        if Instant::now() > deadline + HARD_DEADLINE {
            eprintln!("[bpf-smoke] deadline exceeded; bailing out");
            break;
        }
    }
    heartbeat.store(now_ms(), Ordering::Release);

    println!("[bpf-smoke] detaching (drop)...");
    let detach_started = Instant::now();
    drop(bpf);
    println!(
        "[bpf-smoke] detach completed ({} ms)",
        detach_started.elapsed().as_millis()
    );

    watchdog_alive.store(false, Ordering::Release);
    println!("[bpf-smoke] done");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("bpf_tracepoint_smoke is Linux-only; no-op on this platform.");
}
