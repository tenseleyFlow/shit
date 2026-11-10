// SPDX-License-Identifier: AGPL-3.0-or-later

//! M4: which common commands the macOS DYLD shim can load into.
//!
//! On a default macOS install (no EndpointSecurity) the shim is the
//! only capture that takes a pre-image. dyld drops
//! `DYLD_INSERT_LIBRARIES` for SIP-protected binaries (`/bin`, `/sbin`,
//! `/usr` outside `/usr/local`, `/System`) and for setuid or setgid
//! binaries, and a statically linked binary never runs dyld at all.
//! Changes made by those binaries are not captured, so undo cannot
//! reverse them. `shit doctor` resolves each probed command the way
//! the shell would (first match on `$PATH`) and says which side of
//! that line it falls on.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Commands doctor resolves. These are the ones users most expect undo
/// to cover.
pub const PROBED_COMMANDS: [&str; 4] = ["rm", "mv", "cp", "chmod"];

/// One probed command.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimReachEntry {
    /// The command name, e.g. `rm`.
    pub command: String,
    /// The first match on `$PATH`, as the shell resolves it (aliases
    /// and functions aside). `None` when nothing matched.
    pub resolved: Option<String>,
    /// `resolved` with symlinks followed, when that differs.
    pub target: Option<String>,
    /// True when the shim can load into the binary.
    pub shim_sees: bool,
    /// Why not, or `"dyld loads the shim"`.
    pub reason: String,
}

/// Whether macOS SIP protects `path` from modification, which also
/// makes dyld ignore `DYLD_*` variables for binaries there.
pub fn sip_protected(path: &Path) -> bool {
    if path.starts_with("/usr/local") {
        return false;
    }
    ["/bin", "/sbin", "/usr", "/System"]
        .iter()
        .any(|p| path.starts_with(p))
}

/// The first executable regular file named `command` on `path_var`
/// (a `$PATH` value).
pub fn resolve_in_path(command: &str, path_var: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(command))
        .find(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// Whether the shim can load into `binary` and why. `sip_enforced` is
/// false only when SIP is known to be off.
pub fn classify(
    binary: &Path,
    sip_enforced: bool,
    setid: bool,
    is_static: Option<bool>,
) -> (bool, String) {
    if sip_enforced && sip_protected(binary) {
        return (
            false,
            "NOT captured: SIP-protected, dyld drops DYLD_INSERT_LIBRARIES".to_string(),
        );
    }
    if setid {
        return (
            false,
            "NOT captured: setuid/setgid, dyld drops DYLD_INSERT_LIBRARIES".to_string(),
        );
    }
    if is_static == Some(true) {
        return (
            false,
            "NOT captured: statically linked, dyld never runs".to_string(),
        );
    }
    (true, "dyld loads the shim".to_string())
}

fn is_setid(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.mode() & 0o6000 != 0)
        .unwrap_or(false)
}

/// Probe [`PROBED_COMMANDS`] against `path_var`.
pub fn probe(path_var: &str, sip_enforced: bool) -> Vec<ShimReachEntry> {
    PROBED_COMMANDS
        .iter()
        .map(|cmd| probe_one(cmd, path_var, sip_enforced))
        .collect()
}

fn probe_one(command: &str, path_var: &str, sip_enforced: bool) -> ShimReachEntry {
    let Some(resolved) = resolve_in_path(command, path_var) else {
        return ShimReachEntry {
            command: command.to_string(),
            resolved: None,
            target: None,
            shim_sees: false,
            reason: "not found on $PATH".to_string(),
        };
    };
    let real = std::fs::canonicalize(&resolved).unwrap_or_else(|_| resolved.clone());
    let (shim_sees, reason) = classify(
        &real,
        sip_enforced,
        is_setid(&real),
        super::visibility::is_statically_linked(&real),
    );
    ShimReachEntry {
        command: command.to_string(),
        resolved: Some(resolved.display().to_string()),
        target: (real != resolved).then(|| real.display().to_string()),
        shim_sees,
        reason,
    }
}

/// The doctor's fixed statement of what a default macOS install does
/// not capture.
pub const UNCAPTURED_SUMMARY: &str = "Not captured on a default install (no EndpointSecurity): \
     SIP-protected binaries in /bin, /sbin, /usr (outside /usr/local) and /System, \
     setuid/setgid binaries, and statically linked binaries. Undo cannot reverse their changes.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn sip_paths() {
        for p in ["/bin/rm", "/sbin/mount", "/usr/bin/install", "/System/x"] {
            assert!(sip_protected(Path::new(p)), "{p}");
        }
        for p in [
            "/usr/local/bin/rm",
            "/opt/homebrew/bin/gchmod",
            "/Users/me/bin/rm",
            "/binx/rm",
        ] {
            assert!(!sip_protected(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn classify_names_the_reason() {
        let (sees, why) = classify(Path::new("/bin/rm"), true, false, Some(false));
        assert!(!sees);
        assert!(why.contains("SIP"), "{why}");
        // SIP off: the same binary loads the shim.
        assert!(classify(Path::new("/bin/rm"), false, false, Some(false)).0);
        let (sees, why) = classify(Path::new("/opt/x/su"), true, true, Some(false));
        assert!(!sees && why.contains("setuid"), "{why}");
        let (sees, why) = classify(Path::new("/opt/x/go-tool"), true, false, Some(true));
        assert!(!sees && why.contains("statically"), "{why}");
        assert!(classify(Path::new("/opt/homebrew/bin/gchmod"), true, false, None).0);
    }

    #[test]
    fn resolves_the_first_executable_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        // Not executable: skipped, as the shell skips it.
        std::fs::write(a.join("rm"), b"").unwrap();
        std::fs::write(b.join("rm"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(b.join("rm"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path_var = format!("{}::{}", a.display(), b.display());
        assert_eq!(resolve_in_path("rm", &path_var), Some(b.join("rm")));
        assert_eq!(resolve_in_path("mv", &path_var), None);

        let entries = probe(&path_var, true);
        assert_eq!(entries.len(), PROBED_COMMANDS.len());
        let rm = &entries[0];
        assert_eq!(rm.command, "rm");
        assert_eq!(rm.resolved.as_deref(), Some(b.join("rm").to_str().unwrap()));
        assert!(rm.shim_sees, "{rm:?}");
        assert!(!entries[1].shim_sees);
        assert_eq!(entries[1].reason, "not found on $PATH");
    }
}
