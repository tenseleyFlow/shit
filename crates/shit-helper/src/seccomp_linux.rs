// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux seccomp policy. Allowlist sourced from
//! `.docs/audits/seccomp-policy.md` — keep them in sync.
//!
//! Action on disallowed syscall is configurable via
//! `SHIT_HELPER_SECCOMP_MODE` (see [`SeccompMode`]); the production
//! default is `kill` (SCMP_ACT_KILL_PROCESS), louder than `errno`.
//! `log` is the diagnostic mode for audit work — kernel logs the
//! violation to the audit subsystem without acting, letting a
//! developer enumerate the helper's actual syscall surface end-to-end
//! in one run.

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("seccompiler: {0}")]
    Compiler(String),
    #[error("apply: {0}")]
    Apply(String),
}

/// Action taken on a syscall outside the allowlist. Configurable via
/// the `SHIT_HELPER_SECCOMP_MODE` env var; default is `Kill`.
///
/// Production must run `Kill`. The other modes exist so an operator
/// (or our own audit script) can iterate quickly without rebuilding:
/// `Log` walks the helper through one full request lifecycle while
/// the kernel records every blocked syscall to the audit subsystem —
/// the result is the complete syscall surface we need to allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    /// Production. Kernel kills the helper with SIGSYS on first
    /// disallowed syscall.
    Kill,
    /// Diagnostic: kernel logs the violation to the audit subsystem
    /// (visible via `journalctl -k`) and allows the syscall. The
    /// helper continues running. Use for audit sweeps and when
    /// adding new code paths.
    Log,
    /// Disallowed syscalls return `EPERM` to userspace. The helper
    /// keeps running and downstream code paths see a recoverable
    /// error rather than a sudden death. Useful when investigating
    /// "did this fail because of seccomp or some other reason?"
    Errno,
    /// Skip filter installation entirely. Loud warning emitted.
    /// Last-resort dev escape hatch; never for prod.
    Off,
}

impl SeccompMode {
    fn from_env() -> Self {
        match std::env::var("SHIT_HELPER_SECCOMP_MODE")
            .as_deref()
            .map(str::trim)
        {
            Ok("log") => Self::Log,
            Ok("errno") => Self::Errno,
            Ok("off") => Self::Off,
            Ok("kill") => Self::Kill,
            Ok(other) if !other.is_empty() => {
                tracing::warn!(
                    mode = %other,
                    "unknown SHIT_HELPER_SECCOMP_MODE; falling back to kill"
                );
                Self::Kill
            }
            // unset or empty → production default
            _ => Self::Kill,
        }
    }

    fn to_action(self) -> SeccompAction {
        match self {
            Self::Kill => SeccompAction::KillProcess,
            Self::Log => SeccompAction::Log,
            Self::Errno => SeccompAction::Errno(libc::EPERM as u32),
            // `Off` never reaches this — `install_filter` returns early.
            Self::Off => SeccompAction::Allow,
        }
    }
}

/// Install the seccomp filter for the current thread / process.
///
/// **One-way (in `Kill` mode):** after this returns Ok, the kernel
/// kills the process on the first disallowed syscall. Run *after*
/// every privileged setup; any code path that needs new syscalls
/// must update the allowlist (and `seccomp-policy.md`) in the same
/// PR.
pub fn install_filter() -> Result<(), SeccompError> {
    let mode = SeccompMode::from_env();
    if mode == SeccompMode::Off {
        tracing::warn!(
            "SHIT_HELPER_SECCOMP_MODE=off → seccomp filter NOT INSTALLED. \
             Dev-only diagnostic; never in production."
        );
        return Ok(());
    }
    let filter = build_filter_with_action(mode.to_action())?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::Compiler(e.to_string()))?;
    seccompiler::apply_filter(&program).map_err(|e| SeccompError::Apply(e.to_string()))?;
    match mode {
        SeccompMode::Kill => tracing::info!("seccomp filter installed (mode=kill)"),
        SeccompMode::Log => tracing::warn!(
            "seccomp filter installed in LOG MODE — violations recorded to audit \
             subsystem but NOT blocked. Diagnostic only."
        ),
        SeccompMode::Errno => tracing::warn!(
            "seccomp filter installed in ERRNO MODE — violations return EPERM. \
             Diagnostic only."
        ),
        SeccompMode::Off => unreachable!(), // returned early
    }
    Ok(())
}

/// Build the filter with the production default (`KillProcess`).
/// Used by tests + audit tooling that don't go through the env var.
pub fn build_filter() -> Result<SeccompFilter, SeccompError> {
    build_filter_with_action(SeccompAction::KillProcess)
}

/// Build the filter with an explicit fallback action. Internal —
/// `install_filter` reads the env var and passes the resolved action.
fn build_filter_with_action(mismatch_action: SeccompAction) -> Result<SeccompFilter, SeccompError> {
    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        return Err(SeccompError::Compiler(
            "unsupported architecture for seccomp filter".into(),
        ));
    };

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for syscall in ALLOWED_SYSCALLS.iter().chain(ALLOWED_SYSCALLS_ARCH.iter()) {
        rules.insert(*syscall, vec![]);
    }
    SeccompFilter::new(rules, mismatch_action, SeccompAction::Allow, arch)
        .map_err(|e| SeccompError::Compiler(e.to_string()))
}

/// Allowed syscall numbers. Mirrors `.docs/audits/seccomp-policy.md`.
///
/// Numbers come from libc's syscall constants and vary by arch; we
/// avoid hard-coding by using libc::SYS_*.
const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    // L01 chunk 5: tokio-rt-worker also issues recvfrom/sendto on its
    // internal eventfd/pipe surfaces; both must be allowed.
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_statx, // glibc fs::metadata on modern kernels; pre-image read path
    libc::SYS_openat,
    libc::SYS_pread64, // file read via dup'd fd in capture/linux::read_pre_image
    libc::SYS_dup,     // capture/linux::read_pre_image dup's fd
    libc::SYS_dup3,    // glibc dup variant
    libc::SYS_pipe2,   // pipes for internal tokio signal/wake paths
    // SYS_readlink is x86_64-only; aarch64 dropped the bare form in
    // favor of readlinkat. Always allow readlinkat; conditionally
    // allow readlink below.
    libc::SYS_readlinkat,
    libc::SYS_lseek,     // File reads sometimes seek
    libc::SYS_ftruncate, // staging file ops
    libc::SYS_fsync,     // staging file durability (we removed but be defensive)
    libc::SYS_unlinkat,  // staging cleanup
    libc::SYS_mkdirat,   // create_dir_all uses mkdirat
    libc::SYS_renameat2, // staging atomic rename if used
    libc::SYS_fcntl,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_brk,
    libc::SYS_mremap,
    // pthread_create's syscall surface on modern glibc. Without these
    // allowed, any thread spawn post-sandbox (tokio's spawn_blocking,
    // blake3 worker, etc.) SIGSYS-kills the helper. Surfaced by L01
    // chunk 5's first end-to-end run on hasu.
    libc::SYS_madvise,         // stack page hints (MADV_DONTFORK etc.)
    libc::SYS_clone3,          // primary thread-spawn syscall on glibc >= 2.34
    libc::SYS_clone,           // fallback when clone3 returns ENOSYS
    libc::SYS_rseq,            // restartable sequences (kernel >= 4.18)
    libc::SYS_set_robust_list, // robust futex list init per-thread
    libc::SYS_clock_gettime,
    libc::SYS_clock_nanosleep,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    // SYS_epoll_wait (the bare, non-`p` variant) is x86_64-only;
    // aarch64 dropped it. Conditionally allowed below — tokio's
    // mio backend uses it on x86_64 kernel/glibc pairings where
    // epoll_pwait2 isn't available (surfaced by L01 chunk 5 on
    // hasu, syscall=232 SIGSYS).
    libc::SYS_eventfd2,
    libc::SYS_futex,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigreturn,
    libc::SYS_tgkill,
    libc::SYS_exit_group,
    libc::SYS_prctl,
    libc::SYS_seccomp,
    libc::SYS_getrandom, // SP-04: needed by libstd RNG seeding.
    // Tokio worker-thread runtime surface, surfaced by L01 chunk 5.
    // Each worker thread queries CPU affinity to size its work-steal
    // ring; thread identity + sigaltstack + sched_yield round out the
    // common spawn-time and runtime calls.
    libc::SYS_sched_getaffinity, // tokio worker CPU-count probe (204)
    libc::SYS_sched_yield,
    libc::SYS_sigaltstack, // glibc per-thread signal stack init
    libc::SYS_gettid,
    libc::SYS_getpid,
    // Phase-2 (S08/S09):
    libc::SYS_fanotify_init,
    libc::SYS_fanotify_mark,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
];

/// x86_64-only syscalls. aarch64's Linux ABI dropped these in favor
/// of newer variants we already allow above (readlinkat, epoll_pwait).
/// The two slices are concatenated in [`build_filter`].
#[cfg(target_arch = "x86_64")]
const ALLOWED_SYSCALLS_ARCH: &[i64] = &[libc::SYS_readlink, libc::SYS_epoll_wait];

#[cfg(not(target_arch = "x86_64"))]
const ALLOWED_SYSCALLS_ARCH: &[i64] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_compiles_clean() {
        let filter = build_filter().unwrap();
        let _: BpfProgram = filter.try_into().expect("filter compiles to BPF program");
    }

    #[test]
    fn allowlist_has_no_dupes() {
        let mut seen = std::collections::HashSet::new();
        for s in ALLOWED_SYSCALLS.iter().chain(ALLOWED_SYSCALLS_ARCH.iter()) {
            assert!(seen.insert(*s), "duplicate syscall {s}");
        }
    }

    /// Each mode parses from the env var as expected. The test mutates
    /// process env so it can't run in parallel with other env-touching
    /// tests; cargo test runs tests in the same module serially.
    #[test]
    fn seccomp_mode_parses_each_value() {
        // Save + restore the env var so we don't leak between tests.
        let prev = std::env::var_os("SHIT_HELPER_SECCOMP_MODE");
        // SAFETY: single-threaded test mod, no concurrent env access.
        unsafe {
            std::env::remove_var("SHIT_HELPER_SECCOMP_MODE");
        }
        assert_eq!(SeccompMode::from_env(), SeccompMode::Kill);
        for (val, want) in [
            ("kill", SeccompMode::Kill),
            ("log", SeccompMode::Log),
            ("errno", SeccompMode::Errno),
            ("off", SeccompMode::Off),
            ("nonsense", SeccompMode::Kill), // fallback
            ("", SeccompMode::Kill),         // empty -> default
        ] {
            // SAFETY: see above.
            unsafe {
                std::env::set_var("SHIT_HELPER_SECCOMP_MODE", val);
            }
            assert_eq!(SeccompMode::from_env(), want, "value={val:?}");
        }
        // Restore.
        // SAFETY: see above.
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("SHIT_HELPER_SECCOMP_MODE", v);
            } else {
                std::env::remove_var("SHIT_HELPER_SECCOMP_MODE");
            }
        }
    }

    /// Building with each non-Off action produces a valid BPF program.
    /// `Off` doesn't go through `build_filter_with_action` (it returns
    /// early from `install_filter`), so we don't include it here.
    #[test]
    fn each_mode_compiles_clean() {
        for action in [
            SeccompAction::KillProcess,
            SeccompAction::Log,
            SeccompAction::Errno(libc::EPERM as u32),
        ] {
            let filter = build_filter_with_action(action).unwrap();
            let _: BpfProgram = filter
                .try_into()
                .expect("filter with each action compiles to BPF");
        }
    }
}
