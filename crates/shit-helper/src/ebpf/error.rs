// SPDX-License-Identifier: AGPL-3.0-or-later

//! eBPF error taxonomy.

#![cfg(target_os = "linux")]

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    /// Stage 2 placeholder — real load happens in stage 3.
    #[error("ebpf load not implemented in this build (stage 2 scaffold)")]
    NotImplemented,

    /// The probe found a missing prerequisite: no BTF, no
    /// `bpf` in active lsm, kernel too old, or insufficient caps.
    /// Includes the diagnosis string from
    /// `shit_capture::linux_kernel::BpfLsmFeatures::diagnose`.
    #[error("ebpf prerequisite not met: {0}")]
    PrerequisiteFailed(String),

    /// Aya / kernel returned an error during a real load. Reserved for
    /// stage 3 — currently unused.
    #[error("aya: {0}")]
    Aya(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
