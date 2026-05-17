// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS sandbox entry. Full `sandbox_init_with_parameters` profile
//! lands in S07 once the ES client surface is known. The profile will
//! restrict file access to:
//!
//! - read: anywhere (we need to capture pre-images everywhere)
//! - write: only `$XDG_STATE_HOME/shit/` subtree
//! - network: none
//! - exec: none
//! - mach: only `com.apple.endpointsecurity` (S07)

use std::path::Path;

pub fn enter(_state_dir: &Path) -> anyhow::Result<()> {
    tracing::debug!("macos sandbox stub (S07 fills in sandbox_init)");
    Ok(())
}
