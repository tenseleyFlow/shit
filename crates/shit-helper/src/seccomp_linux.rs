// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux seccomp policy. Allowlist sourced from
//! `.docs/audits/seccomp-policy.md` — keep them in sync.
//!
//! Action on disallowed syscall: `SCMP_ACT_KILL_PROCESS` (kernel kills
//! the helper). Louder than `SCMP_ACT_ERRNO`; we want crashes-on-policy
//! during development. Re-evaluate before v1.0.

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("seccompiler: {0}")]
    Compiler(String),
    #[error("apply: {0}")]
    Apply(String),
}

/// Install the seccomp filter for the current thread / process.
///
/// **One-way:** after this returns Ok, the kernel kills the process on
/// the first disallowed syscall. Run *after* every privileged setup;
/// any code path that needs new syscalls must update the allowlist
/// (and `seccomp-policy.md`) in the same PR.
pub fn install_filter() -> Result<(), SeccompError> {
    // Dev-mode bypass for L01 chunk 5 iteration. NOT for production —
    // documented as such. The allowlist is still being audited against
    // tokio's full worker-thread syscall surface; until that audit
    // closes, SHIT_HELPER_NO_SECCOMP=1 lets the helper run unfiltered
    // so end-to-end work can proceed in parallel.
    if std::env::var_os("SHIT_HELPER_NO_SECCOMP").is_some() {
        tracing::warn!(
            "SHIT_HELPER_NO_SECCOMP=1 → seccomp filter SKIPPED (dev mode; never in prod)"
        );
        return Ok(());
    }
    let filter = build_filter()?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::Compiler(e.to_string()))?;
    seccompiler::apply_filter(&program).map_err(|e| SeccompError::Apply(e.to_string()))?;
    tracing::info!("seccomp filter installed");
    Ok(())
}

/// Build the filter without applying it. Used by tests + audit tooling.
pub fn build_filter() -> Result<SeccompFilter, SeccompError> {
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
    for syscall in ALLOWED_SYSCALLS {
        rules.insert(*syscall, vec![]);
    }
    SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
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
    libc::SYS_pread64,    // file read via dup'd fd in capture/linux::read_pre_image
    libc::SYS_dup,        // capture/linux::read_pre_image dup's fd
    libc::SYS_dup3,       // glibc dup variant
    libc::SYS_pipe2,      // pipes for internal tokio signal/wake paths
    libc::SYS_readlink,   // /proc/<pid>/cwd resolution
    libc::SYS_readlinkat, // glibc variant
    libc::SYS_lseek,      // File reads sometimes seek
    libc::SYS_ftruncate,  // staging file ops
    libc::SYS_fsync,      // staging file durability (we removed but be defensive)
    libc::SYS_unlinkat,   // staging cleanup
    libc::SYS_mkdirat,    // create_dir_all uses mkdirat
    libc::SYS_renameat2,  // staging atomic rename if used
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
    // tokio's mio backend uses bare epoll_wait on some kernel/glibc
    // pairings (it falls back when epoll_pwait2 isn't available).
    // Surfaced by L01 chunk 5: syscall=232 SIGSYS on hasu (kernel 7.0.8).
    libc::SYS_epoll_wait,
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
        for s in ALLOWED_SYSCALLS {
            assert!(seen.insert(*s), "duplicate syscall {s}");
        }
    }
}
