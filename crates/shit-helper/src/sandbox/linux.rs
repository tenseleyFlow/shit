// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux sandbox entry.
//!
//! Phase 1 (S06.6): install seccomp filter — see `seccomp_linux.rs`.
//! Phase 2 (S08): tighten allowlist for fanotify.
//! Phase 3 (S09): add eBPF map ops to allowlist.

use std::path::Path;

pub fn enter(_state_dir: &Path) -> anyhow::Result<()> {
    crate::seccomp_linux::install_filter()
        .map_err(|e| anyhow::anyhow!("seccomp filter install failed: {e}"))?;
    Ok(())
}
