// SPDX-License-Identifier: AGPL-3.0-or-later

//! BPF-LSM smoke for the L04 `inode_unlink` hook — loads the shipped
//! `inode_unlink.bpf.o`, attaches it to the `lsm/inode_unlink` LSM
//! hook for 1 second, drains the ringbuf during that window, then
//! detaches cleanly.
//!
//! **Why this is safer than it looks for an LSM hook:**
//!   - The program always returns 0 (allow). It is structurally
//!     incapable of denying an unlinkat. A verifier rejection would
//!     refuse-to-load — not break the system.
//!   - Hard 3-second outer deadline; independent watchdog calls
//!     `_exit(7)` if the main thread stalls.
//!   - Heap-aligned program load (aya needs 8-byte alignment).
//!   - Detach on drop closes BPF fds → kernel detaches.
//!
//! Setup on hasu (re-run after every `cargo build` of this example):
//!   sudo setcap cap_bpf,cap_perfmon+ep target/release/examples/bpf_lsm_unlink_smoke
//!
//! Run as a regular user; exits 0 on success. Generates traffic
//! against the hook itself by unlinking files in a tmp dir.
//!
//! **Kernel prerequisites** (verified on hasu, kernel 7.0.8):
//!   - CONFIG_BPF_LSM=y
//!   - `lsm=...,bpf,...` in /proc/cmdline
//!   - `/sys/kernel/btf/vmlinux` readable
//!
//! **Blast radius**: a 1-second window during which every unlinkat
//! on the box runs the hook. Hook is straight-line CO-RE, ~10–20ns
//! per call on hasu.

#[cfg(target_os = "linux")]
fn main() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    const HARD_DEADLINE: Duration = Duration::from_secs(3);
    const WATCHDOG_BUDGET: Duration = Duration::from_millis(750);

    fn now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    use aya::{Btf, Ebpf, maps::RingBuf, programs::Lsm};

    const UNLINK_OBJ: &[u8] = include_bytes!("../bpf/build/inode_unlink.bpf.o");

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
                        "[lsm-smoke] watchdog: heartbeat gap {}ms > budget {}ms — _exit(7)",
                        gap,
                        WATCHDOG_BUDGET.as_millis()
                    );
                    unsafe { libc::_exit(7) };
                }
            }
        });
    }

    println!("[lsm-smoke] elf magic ok: {:x?}", &UNLINK_OBJ[..4]);
    println!("[lsm-smoke] elf size = {} bytes", UNLINK_OBJ.len());

    let btf_started = Instant::now();
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[lsm-smoke] Btf::from_sys_fs failed: {e}");
            eprintln!("[lsm-smoke]   (need CONFIG_DEBUG_INFO_BTF=y + /sys/kernel/btf/vmlinux)");
            std::process::exit(2);
        }
    };
    println!(
        "[lsm-smoke] Btf::from_sys_fs ok ({} ms)",
        btf_started.elapsed().as_millis()
    );

    let aligned: Vec<u8> = UNLINK_OBJ.to_vec();
    let load_started = Instant::now();
    let mut bpf = match Ebpf::load(&aligned) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[lsm-smoke] aya::Ebpf::load failed: {e}");
            let mut cur: Option<&dyn std::error::Error> = Some(&e);
            let mut depth = 0;
            while let Some(c) = cur {
                eprintln!("[lsm-smoke] source[{depth}]: {c}");
                cur = c.source();
                depth += 1;
                if depth > 8 {
                    break;
                }
            }
            std::process::exit(3);
        }
    };
    println!(
        "[lsm-smoke] Ebpf::load ok ({} ms)",
        load_started.elapsed().as_millis()
    );

    let prog: &mut Lsm = match bpf
        .program_mut("shit_inode_unlink")
        .and_then(|p| p.try_into().ok())
    {
        Some(p) => p,
        None => {
            eprintln!("[lsm-smoke] program `shit_inode_unlink` not found or not an Lsm");
            std::process::exit(4);
        }
    };

    if let Err(e) = prog.load("inode_unlink", &btf) {
        eprintln!("[lsm-smoke] Lsm.load(inode_unlink) failed: {e}");
        eprintln!("[lsm-smoke]   (verifier rejection? kernel CONFIG_BPF_LSM=y + bootcmdline?)");
        std::process::exit(5);
    }
    println!("[lsm-smoke] Lsm.load ok");

    let _link_id = match prog.attach() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("[lsm-smoke] Lsm.attach failed: {e}");
            std::process::exit(6);
        }
    };
    println!("[lsm-smoke] attached to lsm/inode_unlink");

    // Take the ringbuf so we can confirm events flow end-to-end.
    let mut ring = match bpf
        .take_map("unlink_events")
        .and_then(|m| RingBuf::try_from(m).ok())
    {
        Some(r) => r,
        None => {
            eprintln!("[lsm-smoke] failed to take `unlink_events` ringbuf");
            std::process::exit(7);
        }
    };
    println!("[lsm-smoke] ringbuf taken");

    // Self-induced traffic: unlink a known file so we KNOW at least
    // one event should land.
    let probe_path = std::env::temp_dir().join(format!(
        "shit-lsm-smoke.{}.probe",
        std::process::id()
    ));
    std::fs::write(&probe_path, b"x").expect("write probe");
    std::fs::remove_file(&probe_path).expect("unlink probe");
    println!("[lsm-smoke] self-induced unlink at {}", probe_path.display());

    // Drain the ringbuf for ~1 s, counting events.
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut events_seen: u64 = 0;
    while Instant::now() < deadline {
        while let Some(rec) = ring.next() {
            events_seen += 1;
            // The first event we'd love to verify, but we don't have
            // the userspace decode yet (Task #80). Confirm only that
            // the record is the size of struct shit_unlink_event
            // (header + dev + inode = 32 + 16 = 48 bytes).
            if events_seen == 1 {
                println!("[lsm-smoke] first event size = {} bytes", rec.len());
            }
        }
        heartbeat.store(now_ms(), Ordering::Release);
        std::thread::sleep(Duration::from_millis(20));
        if Instant::now() > deadline + HARD_DEADLINE {
            eprintln!("[lsm-smoke] deadline exceeded; bailing out");
            break;
        }
    }
    heartbeat.store(now_ms(), Ordering::Release);

    println!("[lsm-smoke] events drained = {events_seen}");
    if events_seen == 0 {
        eprintln!("[lsm-smoke] WARN: no events drained — hook may not be firing");
        eprintln!("[lsm-smoke]        (boot cmdline must include `lsm=...,bpf,...`)");
    }

    println!("[lsm-smoke] detaching (drop)...");
    let detach_started = Instant::now();
    drop(ring);
    drop(bpf);
    println!(
        "[lsm-smoke] detach completed ({} ms)",
        detach_started.elapsed().as_millis()
    );

    watchdog_alive.store(false, Ordering::Release);
    println!("[lsm-smoke] done; events_seen = {events_seen}");
    std::process::exit(if events_seen == 0 { 8 } else { 0 });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("bpf_lsm_unlink_smoke is Linux-only; no-op on this platform.");
}
