// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

/// System-scope directories that hold `libshit_preload_shim.{so,dylib}`, in
/// search order. `/usr/local/lib/shit` is `make install` and the BSD ports;
/// `/usr/lib/shit` is the deb, rpm and AUR packages. Every shim lookup goes
/// through [`system_shim_candidates`] so the two stay in sync.
pub const SYSTEM_SHIM_DIRS: [&str; 2] = ["/usr/local/lib/shit", "/usr/lib/shit"];

/// Shim file name for this platform.
pub fn shim_file_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libshit_preload_shim.dylib"
    } else {
        "libshit_preload_shim.so"
    }
}

/// The system-scope shim candidates, in search order.
pub fn system_shim_candidates() -> Vec<PathBuf> {
    SYSTEM_SHIM_DIRS
        .iter()
        .map(|d| PathBuf::from(d).join(shim_file_name()))
        .collect()
}

/// The installed system shim if one exists, else the first candidate (the
/// canonical `make install` location).
pub fn default_system_shim() -> PathBuf {
    let c = system_shim_candidates();
    c.iter()
        .find(|p| p.is_file())
        .cloned()
        .unwrap_or_else(|| c[0].clone())
}

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
