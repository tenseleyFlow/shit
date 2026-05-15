// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

/// Pick the socket path. Prefers `$XDG_RUNTIME_DIR/shit.sock`; falls back to
/// `$TMPDIR/shit-$(uid).sock` when `XDG_RUNTIME_DIR` is unset (common on macOS).
pub fn default_socket_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("shit.sock");
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    // SAFETY: getuid is documented as always-succeeds; no async-signal concerns here.
    let uid = unsafe { libc::getuid() };
    tmp.join(format!("shit-{uid}.sock"))
}
