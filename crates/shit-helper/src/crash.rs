// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash log writer. Full implementation in S06.9.

use std::path::Path;

/// Install a panic hook that writes a one-line crash log to
/// `$state_dir/crashes/helper-<unix_ts>.txt`. Lossy on best-effort
/// failure — we never want a panic hook to itself panic.
pub fn install_panic_hook(_state_dir: &Path) {
    // S06.9 wires this up. For now leave the default panic handler.
}
