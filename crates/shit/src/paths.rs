// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

pub fn default_socket_path() -> PathBuf {
    runtime_path("shit.sock", "shit")
}

pub fn default_ctl_socket_path() -> PathBuf {
    runtime_path("shit-ctl.sock", "shit-ctl")
}

fn runtime_path(xdg_name: &str, tmp_stem: &str) -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join(xdg_name);
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    // SAFETY: getuid always succeeds.
    let uid = unsafe { libc::getuid() };
    tmp.join(format!("{tmp_stem}-{uid}.sock"))
}
