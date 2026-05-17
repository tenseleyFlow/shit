// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EbpfLoader` — userspace BPF loader (S09 stage 3).
//!
//! Stage 3 contract: `probe` is real; `load` loads + attaches a single
//! minimal tracepoint program (`noop_tracepoint.bpf.o`, see
//! `crates/shit-helper/bpf/`). On `drop`, aya detaches every program
//! and frees the BPF map fds — so the load is reversible by the type
//! system.
//!
//! **What stage 3 deliberately does NOT do:**
//!   - No LSM hooks. Tracepoints can't deny syscalls; LSM hooks can.
//!   - No map writes. The tracepoint is purely observational.
//!   - No daemon-side decision plumbing. Stage 4+ wires that.
//!
//! Standing rule (HP-18 in helper-protocol.md): any future addition
//! that loads an LSM hook MUST be reviewed for blast radius and paired
//! with a watchdog. See `crates/shit-helper/examples/bpf_tracepoint_smoke.rs`
//! for the watchdog pattern.

#![cfg(target_os = "linux")]

use crate::priv_linux::{BpfCapState, probe_bpf_caps};
use shit_capture::linux_kernel::{BpfLsmFeatures, probe_bpf_lsm};

use super::error::EbpfError;

/// The BPF program bytes shipped in tree. Compiled from
/// `crates/shit-helper/bpf/src/noop_tracepoint.bpf.c` per the
/// Makefile next to it. Two instructions: `w0 = 0; exit`.
const NOOP_TRACEPOINT_OBJ: &[u8] =
    include_bytes!("../../bpf/build/noop_tracepoint.bpf.o");

/// Section name inside the .o that aya looks up to find the program.
/// Matches the `__attribute__((section(...)))` in the .c source.
const NOOP_TRACEPOINT_SECTION: &str = "noop_tracepoint";

/// Tracepoint category + name the program attaches to. Read-only —
/// the program fires *after* `sched_process_exec` happens.
const TRACEPOINT_CATEGORY: &str = "sched";
const TRACEPOINT_NAME: &str = "sched_process_exec";

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
    /// safe to attempt.
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

/// The loader. Holds the `aya::Ebpf` instance once loaded; dropping
/// it auto-detaches every program. We never hold a `LinkId` directly
/// — the aya `Ebpf` owns the link lifetime, and drop is our detach.
pub struct EbpfLoader {
    bpf: Option<aya::Ebpf>,
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EbpfLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfLoader")
            .field("loaded", &self.bpf.is_some())
            .finish()
    }
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self { bpf: None }
    }

    /// Read-only feature + capability probe. Safe to call from any
    /// context; touches no kernel-side state.
    pub fn probe(&self) -> ProbeOutcome {
        ProbeOutcome {
            kernel: probe_bpf_lsm(),
            caps: probe_bpf_caps(),
        }
    }

    /// Whether a program is currently loaded + attached.
    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Load + attach the shipped noop tracepoint program. Returns
    /// `Err(PrerequisiteFailed)` when the kernel or our caps say no.
    ///
    /// **Tracepoint-only.** This entry point will never load an LSM
    /// program. A future S09 stage that introduces LSM hooks must
    /// add a separate method (with its own review).
    pub fn load(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.bpf.is_some() {
            tracing::warn!("EbpfLoader::load called while already loaded; ignoring");
            return Ok(());
        }

        // `include_bytes!` returns a `[u8; N]` with alignment 1; the
        // `object` crate's ELF header cast requires 8-byte alignment.
        // Copy through a `Vec` (heap-aligned) before handing to aya.
        let aligned: Vec<u8> = NOOP_TRACEPOINT_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("load: {e}")))?;

        let prog: &mut aya::programs::TracePoint = bpf
            .program_mut(NOOP_TRACEPOINT_SECTION)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{NOOP_TRACEPOINT_SECTION}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected TracePoint: {e}"))
            })?;

        prog.load()
            .map_err(|e| EbpfError::Aya(format!("prog.load: {e}")))?;

        let _link_id = prog
            .attach(TRACEPOINT_CATEGORY, TRACEPOINT_NAME)
            .map_err(|e| EbpfError::Aya(format!("prog.attach: {e}")))?;

        tracing::info!(
            category = TRACEPOINT_CATEGORY,
            name = TRACEPOINT_NAME,
            "ebpf tracepoint loaded and attached"
        );
        self.bpf = Some(bpf);
        Ok(())
    }

    /// Explicit detach. Calling drop is equivalent (aya handles
    /// cleanup), but this lets the caller force it without dropping
    /// the loader (e.g. for graceful shutdown sequencing).
    pub fn detach(&mut self) {
        if self.bpf.take().is_some() {
            tracing::info!("ebpf tracepoint detached");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_view() {
        let l = EbpfLoader::new();
        let _ = l.probe().diagnose();
    }

    #[test]
    fn new_loader_is_not_loaded() {
        let l = EbpfLoader::new();
        assert!(!l.is_loaded());
    }

    #[test]
    fn load_returns_prerequisite_failed_without_caps() {
        // Unit-test environment is unprivileged; load must refuse.
        let mut l = EbpfLoader::new();
        match l.load() {
            Err(EbpfError::PrerequisiteFailed(_)) => {} // expected
            Err(EbpfError::Aya(_)) => {
                // If the test runner is somehow capability-rich we
                // accept this — it means the load actually attempted
                // and aya reported an error (still validates the path).
            }
            Ok(()) => {
                // Surprising: we loaded a real program in a test. Detach
                // immediately to clean up.
                l.detach();
                panic!("load succeeded in unit-test environment — unexpected");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!l.is_loaded());
    }

    #[test]
    fn detach_when_not_loaded_is_noop() {
        let mut l = EbpfLoader::new();
        l.detach();
        l.detach();
        assert!(!l.is_loaded());
    }

    #[test]
    fn embedded_object_is_a_valid_elf() {
        // The .o must at least start with the ELF magic. Catches a
        // build-time mistake where the include_bytes! path points at
        // the wrong file.
        assert_eq!(&NOOP_TRACEPOINT_OBJ[..4], b"\x7fELF");
        assert!(NOOP_TRACEPOINT_OBJ.len() > 100);
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
