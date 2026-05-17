// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone capability probe. Exercises the same kernel-feature
//! detection + `fanotify_init` smoke that the helper does at startup,
//! but without connecting to a daemon. Useful for:
//!   - validating a fresh setcap install (`getcap` says one thing,
//!     `probe_caps` says another → mismatch)
//!   - confirming the degraded-mode path on an unprivileged user.
//!
//! Run: `cargo run --example probe_caps -p shit-helper`

#[cfg(target_os = "linux")]
fn main() {
    use shit_capture::linux_kernel;

    println!("== shit-helper capability probe ==");
    println!("euid = {}", unsafe { libc::geteuid() });

    match linux_kernel::probe() {
        Ok((v, features)) => {
            println!("kernel: {v}");
            println!("feature tier: {}", features.tier_label());
            println!("  perm_events:     {}", features.perm_events);
            println!("  filesystem_mark: {}", features.filesystem_mark);
            println!("  report_fid:      {}", features.report_fid);
            println!("  report_dir_fid:  {}", features.report_dir_fid);
            println!("  report_pidfd:    {}", features.report_pidfd);
        }
        Err(e) => {
            println!("kernel probe error: {e}");
            std::process::exit(1);
        }
    }

    println!();
    println!("attempting fanotify_init (FAN_CLASS_PRE_CONTENT)...");
    // Re-implement the same call the helper makes at startup; we don't
    // depend on shit-helper's internal `fanotify` module because it's
    // private to the bin crate. The numbers match
    // `crates/shit-helper/src/fanotify/init.rs`.
    let flags = libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_CLASS_PRE_CONTENT;
    let event_f_flags = (libc::O_RDONLY | libc::O_LARGEFILE) as u32;
    let rc = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EPERM) => {
                println!("  result: EPERM — no CAP_SYS_ADMIN, degraded mode");
                println!("  advertised auth_subscribe = false");
            }
            Some(libc::ENOSYS) => {
                println!("  result: ENOSYS — kernel too old for fanotify");
            }
            _ => {
                println!("  result: {err}");
            }
        }
    } else {
        println!("  result: success (fd = {rc})");
        println!("  advertised auth_subscribe = true");
        unsafe { libc::close(rc) };
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("probe_caps is Linux-only; no-op on this platform.");
}
