// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fanotify event-loop smoke — **tightly scoped** version.
//!
//! Past incident (2026-05-17, HP-18): an earlier draft marked the
//! user's entire `$HOME` filesystem and stalled the box until reboot
//! when the read+ALLOW loop fell behind. This rewrite contains the
//! blast radius:
//!
//! - Mark a single file we just created, **not a filesystem or mount**.
//!   `FAN_MARK_INODE` (default) on one file means only that file's
//!   open/access can be queued for permission.
//! - Hard 2-second outer deadline; the smoke exits and closes its fd
//!   before the kernel can build a meaningful event backlog.
//! - The read+ALLOW loop is a tight syscall pair — no allocations, no
//!   logging in the hot path. We tally to a counter and print at the
//!   end.
//! - Independent **watchdog thread** that calls `_exit` if the main
//!   thread doesn't tick a heartbeat every 500ms. Defends against
//!   any bug where the main thread blocks on a syscall the kernel
//!   itself is queueing.
//!
//! Setup:
//!   sudo setcap cap_sys_admin+ep target/release/examples/fanotify_loop_smoke
//!
//! Run as a regular user. Exits non-zero on failure, including:
//!   - missing CAP_SYS_ADMIN
//!   - zero events observed (trigger didn't reach the marked inode)

#[cfg(target_os = "linux")]
fn main() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const HARD_DEADLINE: Duration = Duration::from_secs(2);
    const WATCHDOG_BUDGET: Duration = Duration::from_millis(500);

    // Tempdir + target file. Both unlinked on exit. Worst-case "we
    // mark this file and never close the fd" only affects this one
    // file — no other process is touching it.
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tempdir: {e}");
            std::process::exit(2);
        }
    };
    let target = tmp.path().join("target");
    if let Err(e) = std::fs::File::create(&target).and_then(|mut f| f.write_all(b"hello")) {
        eprintln!("create target: {e}");
        std::process::exit(2);
    }
    println!("[smoke] target = {}", target.display());

    // --- privileged phase: init + per-inode mark ---
    let fd = match fanotify_init_pre_content() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("fanotify_init failed (need CAP_SYS_ADMIN): {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = mark_inode(fd, &target) {
        eprintln!("fanotify_mark INODE failed: {e}");
        unsafe { libc::close(fd) };
        std::process::exit(3);
    }

    // --- watchdog: kills the process if the main loop falls behind ---
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
                        "[smoke] watchdog: heartbeat gap {}ms > budget {}ms — _exit(7)",
                        gap,
                        WATCHDOG_BUDGET.as_millis()
                    );
                    // _exit closes fds without running destructors;
                    // kernel auto-ALLOWs all queued events when our
                    // fanotify fd closes.
                    unsafe { libc::_exit(7) };
                }
            }
        });
    }

    // --- trigger child ---
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "for i in 1 2 3 4 5; do cat {} > /dev/null; done",
            target.display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn trigger");

    // --- hot read/ALLOW loop ---
    let deadline = Instant::now() + HARD_DEADLINE;
    let mut buf = vec![0u8; 16 * 1024];
    let mut events_seen: u64 = 0;
    let mut responses_sent: u64 = 0;

    while Instant::now() < deadline {
        heartbeat.store(now_ms(), Ordering::Release);
        if !poll_readable(fd, 100) {
            continue;
        }
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EAGAIN)
                || e.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                continue;
            }
            eprintln!("read failed: {e}");
            break;
        }
        let bytes = &buf[..n as usize];
        let mut offset = 0usize;
        let header_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        while offset + header_len <= bytes.len() {
            let h = &bytes[offset..];
            let event_len = u32::from_ne_bytes([h[0], h[1], h[2], h[3]]) as usize;
            let mask = u64::from_ne_bytes([
                h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
            ]);
            let ev_fd = i32::from_ne_bytes([h[16], h[17], h[18], h[19]]);
            events_seen += 1;
            let needs_perm = (mask
                & (libc::FAN_OPEN_PERM
                    | libc::FAN_ACCESS_PERM
                    | libc::FAN_OPEN_EXEC_PERM))
                != 0;
            if needs_perm {
                let resp = libc::fanotify_response {
                    fd: ev_fd,
                    response: libc::FAN_ALLOW,
                };
                let rc = unsafe {
                    libc::write(
                        fd,
                        (&resp as *const libc::fanotify_response).cast::<libc::c_void>(),
                        std::mem::size_of::<libc::fanotify_response>(),
                    )
                };
                if rc >= 0 {
                    responses_sent += 1;
                }
            }
            unsafe { libc::close(ev_fd) };
            if event_len == 0 {
                break;
            }
            offset += event_len;
        }
    }

    // --- teardown ---
    // Close the fanotify fd FIRST. The kernel auto-ALLOWs every
    // pending event on close, so this is also the panic exit.
    unsafe { libc::close(fd) };
    watchdog_alive.store(false, Ordering::Release);
    let _ = child.wait_with_output();
    drop(tmp);

    println!("[smoke] events_seen    = {events_seen}");
    println!("[smoke] responses_sent = {responses_sent}");
    if events_seen == 0 {
        eprintln!("[smoke] WARNING: zero events — trigger child may have failed");
        std::process::exit(4);
    }
}

#[cfg(target_os = "linux")]
fn fanotify_init_pre_content() -> std::io::Result<libc::c_int> {
    let flags = libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_CLASS_PRE_CONTENT;
    let event_f_flags = (libc::O_RDONLY | libc::O_LARGEFILE) as u32;
    let rc = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(rc)
}

/// `FAN_MARK_ADD` on a single inode (default, no `FAN_MARK_FILESYSTEM`
/// or `FAN_MARK_MOUNT`). Events only fire for this one file.
#[cfg(target_os = "linux")]
fn mark_inode(fd: libc::c_int, path: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mask = libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM;
    let flags = libc::FAN_MARK_ADD; // per-inode
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fd,
            flags as libc::c_uint,
            mask,
            libc::AT_FDCWD,
            cpath.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn poll_readable(fd: libc::c_int, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, timeout_ms) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

#[cfg(target_os = "linux")]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("fanotify_loop_smoke is Linux-only; no-op on this platform.");
}
