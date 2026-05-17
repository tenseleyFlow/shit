// SPDX-License-Identifier: AGPL-3.0-or-later

//! BSD sandbox entry. Full capsicum `cap_enter` lands in S10. After
//! cap_enter the helper can only operate on already-opened fds — no
//! `open(2)` of new paths, no `connect(2)`, etc. We must pre-open
//! everything we'll need before this call.

use std::path::Path;

pub fn enter(_state_dir: &Path) -> anyhow::Result<()> {
    tracing::debug!("bsd sandbox stub (S10 fills in capsicum)");
    Ok(())
}
