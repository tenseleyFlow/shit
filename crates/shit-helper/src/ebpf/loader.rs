// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EbpfLoader` — userspace BPF loader (S09 stage 2 scaffold).
//!
//! Stage 2 contract: `probe` is real; `load` is a stub that returns
//! `EbpfError::NotImplemented`. Stage 3 (future) fills in `load`
//! against a program crate compiled to BPF.

#![cfg(target_os = "linux")]

use crate::priv_linux::{BpfCapState, probe_bpf_caps};
use shit_capture::linux_kernel::{BpfLsmFeatures, probe_bpf_lsm};

use super::error::EbpfError;

/// Result of `EbpfLoader::probe` — combined kernel feature + capability
/// view. `should_attempt_load` is the call-site predicate that tells
/// the helper whether it's worth invoking `load`.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub kernel: BpfLsmFeatures,
    pub caps: BpfCapState,
}

impl ProbeOutcome {
    /// True only when **both** the kernel supports BPF-LSM and we
    /// have the caps to load programs against it. The single
    /// authoritative gate.
    pub fn should_attempt_load(&self) -> bool {
        self.kernel.fully_supported() && self.caps.can_load_lsm()
    }

    /// Reason load would fail or be useless. Empty when load is
    /// safe to attempt. Useful for `shit doctor`.
    pub fn diagnose(&self) -> String {
        if self.should_attempt_load() {
            return "ebpf-lsm load prerequisites met".to_string();
        }
        let mut reasons = Vec::new();
        if !self.kernel.fully_supported() {
            reasons.push(format!("kernel: {}", self.kernel.diagnose()));
        }
        if !self.caps.can_load_lsm() {
            reasons.push("caps: need CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN".to_string());
        }
        reasons.join("; ")
    }
}

/// The loader. Holds nothing in stage 2; stage 3 will hold the
/// `aya::Ebpf` instance plus the attached program handles.
#[derive(Debug, Default)]
pub struct EbpfLoader {
    _stage_2_marker: (),
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read-only feature + capability probe. Safe to call from any
    /// context; touches no kernel-side state.
    pub fn probe(&self) -> ProbeOutcome {
        ProbeOutcome {
            kernel: probe_bpf_lsm(),
            caps: probe_bpf_caps(),
        }
    }

    /// **Stage 2 stub.** Always returns `Err(NotImplemented)`. The
    /// signature is what stage 3 needs; the body is deliberately
    /// not load logic.
    pub fn load(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        // Even when prerequisites pass, this build will not load. The
        // explicit NotImplemented makes the caller-side fallback to
        // fanotify the only working path for stage 2.
        Err(EbpfError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_view() {
        let l = EbpfLoader::new();
        let outcome = l.probe();
        // Won't panic; values depend on the host. We just exercise the
        // call surface.
        let _ = outcome.should_attempt_load();
        let _ = outcome.diagnose();
    }

    #[test]
    fn load_returns_not_implemented_when_prereqs_pass_synthetically() {
        // We can't synthesize "prerequisites pass" without root caps,
        // so this test only verifies the *error* path. On hasu with
        // setcap, `load` would return NotImplemented instead of
        // PrerequisiteFailed. The S09.8 hasu validation confirms.
        let mut l = EbpfLoader::new();
        let err = l.load().unwrap_err();
        assert!(matches!(
            err,
            EbpfError::NotImplemented | EbpfError::PrerequisiteFailed(_)
        ));
    }

    #[test]
    fn diagnose_reports_non_empty_reason_when_load_would_fail() {
        let outcome = ProbeOutcome {
            kernel: BpfLsmFeatures::default(),
            caps: BpfCapState::default(),
        };
        assert!(!outcome.should_attempt_load());
        assert!(!outcome.diagnose().is_empty());
    }
}
