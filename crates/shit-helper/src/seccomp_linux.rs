// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux seccomp policy. Allowlist sourced from
//! `.docs/audits/seccomp-policy.md` — keep them in sync.
//!
//! Action on disallowed syscall: `SCMP_ACT_KILL_PROCESS` (kernel kills
//! the helper). Louder than `SCMP_ACT_ERRNO`; we want crashes-on-policy
//! during development. Re-evaluate before v1.0.

#![cfg(target_os = "linux")]

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
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_openat,
    libc::SYS_fcntl,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_brk,
    libc::SYS_mremap,
    libc::SYS_clock_gettime,
    libc::SYS_clock_nanosleep,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
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
